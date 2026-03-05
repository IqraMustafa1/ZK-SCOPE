# ======================= scope_end2end.ps1 =======================
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$ProgressPreference = "SilentlyContinue"

# ---------- CONFIG ----------
$JsonApiUrl = "http://localhost:7576"
$FlaskUrl   = "http://localhost:5000"
$AppId      = "scope-app"
$LedgerId   = "local"
$ParticipantId = "local"
$JsonApiSecret  = "secret"
$OperatorJwtPath = ".\operator.jwt"  # must exist
$DeviceName  = "Device1"

# ---------- HELPERS ----------
function B64Url([byte[]]$b){ ([Convert]::ToBase64String($b)).TrimEnd("=") -replace "\+","-" -replace "/","_" }
function B64UrlText([string]$s){ B64Url ([Text.Encoding]::UTF8.GetBytes($s)) }
function HmacSha256([string]$data,[string]$secret){
  $k=[Text.Encoding]::UTF8.GetBytes($secret)
  $d=[Text.Encoding]::UTF8.GetBytes($data)
  try { $h=[System.Security.Cryptography.HMACSHA256]::new([byte[]]$k) } catch { $h=New-Object System.Security.Cryptography.HMACSHA256 -ArgumentList (,[byte[]]$k) }
  B64Url ($h.ComputeHash($d))
}
function NewJwt([string[]]$actAs,[int]$ttl=3600){
  $hdr=@{alg="HS256";typ="JWT"}|ConvertTo-Json -Compress
  $pl=@{
    iss="local"; aud="json-api"; exp=([int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()+$ttl)
    "https://daml.com/ledger-api"=@{
      ledgerId=$LedgerId; participantId=$ParticipantId; applicationId=$AppId
      admin=$true; actAs=$actAs; readAs=$actAs
    }
  }|ConvertTo-Json -Compress
  $h=B64UrlText $hdr; $p=B64UrlText $pl; $s=HmacSha256 "$h.$p" $JsonApiSecret
  "$h.$p.$s"
}
function PostJson($url,$headers,$obj){
  $body = $obj | ConvertTo-Json -Compress
  try {
    Invoke-RestMethod -Method Post -Uri $url -Headers $headers -ContentType application/json -Body $body -TimeoutSec 60
  } catch {
    $respText = ""
    if ($_.Exception -and $_.Exception.Response) {
      try { $respText = (New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())).ReadToEnd() } catch {}
    }
    Write-Host "----- POST FAILED -----" -ForegroundColor Red
    Write-Host "URL: $url" -ForegroundColor Red
    Write-Host "BODY: $body" -ForegroundColor DarkRed
    if ($respText) { Write-Host "SERVER: $respText" -ForegroundColor Red }
    throw
  }
}

function Get-Prop($obj, $name){
  if ($null -ne $obj -and $obj.PSObject -and ($obj.PSObject.Properties.Name -contains $name)) { $obj.$name } else { "<missing>" }
}

# ---------- LOAD CONFIG / IDS ----------
Write-Host "Reading package id from Flask..." -ForegroundColor Cyan
$cfg = Invoke-RestMethod "$FlaskUrl/debug/config"
$pkg = "$($cfg.daml_pkg_id)".Trim()
$TDevice        = "{0}:Main:Device"          -f $pkg
$TSigAtt        = "{0}:Main:SigAttestation"  -f $pkg
$TTaSnapshot    = "{0}:Main:TaSnapshot"      -f $pkg

$op = Get-Content $OperatorJwtPath -Raw
$H  = @{ Authorization="Bearer $op"; "Content-Type"="application/json" }

Write-Host "Resolving parties..." -ForegroundColor Cyan
$parties = (Invoke-RestMethod "$JsonApiUrl/v1/parties" -Headers $H).result
$Operator      = ($parties | ? displayName -eq "Operator"        | Select-Object -First 1).identifier
$Edge1         = ($parties | ? displayName -eq "EdgeNode1"       | Select-Object -First 1).identifier
$Edge2         = ($parties | ? displayName -eq "EdgeNode2"       | Select-Object -First 1).identifier
$ServiceProv   = ($parties | ? displayName -eq "ServiceProvider1"| Select-Object -First 1).identifier
$IoTDevice1    = ($parties | ? displayName -eq "IoTDevice1"      | Select-Object -First 1).identifier

# ---------- ENSURE / GENERATE KEYS ----------
# SP Ed25519: sp_ed25519_priv.pem + sp_ed25519_pub.hex
if (!(Test-Path .\sp_ed25519_priv.pem) -or !(Test-Path .\sp_ed25519_pub.hex)) {
  Write-Host "Generating SP Ed25519 keys..." -ForegroundColor Yellow
  @"
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
sk = ed25519.Ed25519PrivateKey.generate()
open("sp_ed25519_priv.pem","wb").write(
    sk.private_bytes(encoding=serialization.Encoding.PEM,
                     format=serialization.PrivateFormat.PKCS8,
                     encryption_algorithm=serialization.NoEncryption()))
open("sp_ed25519_pub.hex","w").write(
    sk.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                 format=serialization.PublicFormat.Raw).hex())
"@ | Set-Content -Encoding ASCII .\gen_sp_key.py
  py -3 .\gen_sp_key.py | Out-Null
}
$sp_pub_hex = (Get-Content .\sp_ed25519_pub.hex).Trim().ToLower()
if ($sp_pub_hex -notmatch '^[0-9a-f]{64}$') { throw "SP public key must be 64 hex" }

# Device X25519: dev1_x25519_priv.pem + dev1_x25519_pub.hex
if (!(Test-Path .\dev1_x25519_priv.pem) -or !(Test-Path .\dev1_x25519_pub.hex)) {
  Write-Host "Generating Device X25519 keys..." -ForegroundColor Yellow
  @"
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization as s
sk = x25519.X25519PrivateKey.generate()
open("dev1_x25519_priv.pem","wb").write(
    sk.private_bytes(encoding=s.Encoding.PEM,
                     format=s.PrivateFormat.PKCS8,
                     encryption_algorithm=s.NoEncryption()))
open("dev1_x25519_pub.hex","w").write(
    sk.public_key().public_bytes(encoding=s.Encoding.Raw,
                                 format=s.PublicFormat.Raw).hex())
"@ | Set-Content -Encoding ASCII .\gen_dev_key.py
  py -3 .\gen_dev_key.py | Out-Null
}
$devicePublicKey = (Get-Content .\dev1_x25519_pub.hex).Trim().ToLower()
if ($devicePublicKey -notmatch '^[0-9a-f]{64}$') { throw "Device public key must be 64 hex" }

# ---------- CREATE / REPLACE Device ----------
Write-Host "Creating (or replacing) Device contract..." -ForegroundColor Cyan
$H_combo = @{ Authorization="Bearer " + (NewJwt @($IoTDevice1,$Operator)); "Content-Type"="application/json" }

# Archive prior device for this owner (if any)
$qs = @{ templateIds=@($TDevice); query=@{} }
$rs = PostJson "$JsonApiUrl/v1/query" $H $qs
$old = $rs.result | ? { $_.payload.owner -eq $IoTDevice1 } | Select-Object -First 1
if ($old) {
  try {
    $arch = @{ templateId=$TDevice; contractId=$old.contractId; choice="Archive"; argument=@{} }
    PostJson "$JsonApiUrl/v1/exercise" $H_combo $arch | Out-Null
  } catch { Write-Host "Archive old device skipped/warn: $($_.Exception.Message)" -ForegroundColor DarkYellow }
}

$devPayload = @{
  templateId = $TDevice
  payload    = @{
    owner      = $IoTDevice1
    broker     = $Operator
    name       = $DeviceName
    publicKey  = $devicePublicKey
    attributes = @()
  }
}
$devRes = PostJson "$JsonApiUrl/v1/create" $H_combo $devPayload
$devCid = $devRes.result.contractId
Write-Host "Device CID: $devCid" -ForegroundColor Green

# ---------- ENCRYPT MESSAGE & SIGN DIGEST ----------
Write-Host "Encrypting sample message and signing digest..." -ForegroundColor Cyan
$encReq = @{
  devicePublicKey = $devicePublicKey
  plaintext       = "hello-device"
  aad             = "demo"
  ctx             = @{ purpose="demo" }
}
$enc = PostJson "$FlaskUrl/crypto/encrypt_to_device" @{} $encReq
$cipher_b64 = $enc.ciphertext_b64
$nonce_b64  = $enc.nonce_b64
$eph_hex    = $enc.ephemeral_x25519_hex
$counter    = [int]$enc.counter
$digest_hex = "$($enc.digest_hex)".ToLower()

# signer (creates sign_sp.py if missing)
if (!(Test-Path .\sign_sp.py)) {
@"
import sys, base64, json
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
digest_hex = sys.argv[1]
priv_path  = sys.argv[2]
sk = serialization.load_pem_private_key(open(priv_path,'rb').read(), password=None)
sig = sk.sign(bytes.fromhex(digest_hex))
pk  = sk.public_key().public_bytes(encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw).hex()
print(json.dumps({"sp_pub_hex":pk, "sp_signature_b64": base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}))
"@ | Set-Content -Encoding ASCII .\sign_sp.py
}
$S = py -3 .\sign_sp.py $digest_hex .\sp_ed25519_priv.pem | ConvertFrom-Json
$sp_pub_hex       = $S.sp_pub_hex.ToLower()
$sp_signature_b64 = $S.sp_signature_b64

# ---------- CREATE (or reuse) TWO SigAttestations ----------
Write-Host "Ensuring 2 SigAttestation exist (one per edge)..." -ForegroundColor Cyan
$nowIso     = (Get-Date).ToUniversalTime().ToString("s") + "Z"
$expiresIso = (Get-Date).ToUniversalTime().AddDays(7).ToString("s") + "Z"

# Pull all SigAttestations and filter locally
$existing = PostJson "$JsonApiUrl/v1/query" $H @{ templateIds=@($TSigAtt); query=@{} }

$match = @(
  $existing.result | Where-Object {
    ($_.payload.senderPublicKey  -as [string]).ToLower() -eq $sp_pub_hex.ToLower()    -and
    ($_.payload.deviceOwner      -as [string])           -eq $IoTDevice1              -and
    ($_.payload.devicePublicKey  -as [string]).ToLower() -eq $devicePublicKey.ToLower() -and
    ($_.payload.digest           -as [string]).ToLower() -eq $digest_hex.ToLower()
  }
)

Write-Host ("Matched attestations already on-ledger: {0}" -f $match.Count) -ForegroundColor Yellow
$match | ForEach-Object {
  $issuer = Get-Prop $_.payload 'issuer'
  $cid    = Get-Prop $_ 'contractId'
  Write-Host ("  issuer={0}  cid={1}" -f $issuer, $cid) -ForegroundColor DarkYellow
}

function Ensure-Att([string]$issuer, [hashtable]$Hauth){
  $already = $match | Where-Object { $_.payload.issuer -eq $issuer } | Select-Object -First 1
  if ($already) { return $already.contractId }
  $payload = @{
    templateId = $TSigAtt
    payload = @{
      operator        = $Operator
      issuer          = $issuer
      sp              = $ServiceProv
      senderPublicKey = $sp_pub_hex
      deviceOwner     = $IoTDevice1
      devicePublicKey = $devicePublicKey
      digest          = $digest_hex
      ts              = $nowIso
      expires         = $expiresIso
    }
  }
  (PostJson "$JsonApiUrl/v1/create" $Hauth $payload).result.contractId
}

# Use issuer-auth tokens (edge must authorize create)
$H_e1 = @{ Authorization="Bearer " + (NewJwt @($Edge1)); "Content-Type"="application/json" }
$H_e2 = @{ Authorization="Bearer " + (NewJwt @($Edge2)); "Content-Type"="application/json" }

# Create or reuse the two attestations
$attCids = @(
  (Ensure-Att -issuer $Edge1 -Hauth $H_e1),
  (Ensure-Att -issuer $Edge2 -Hauth $H_e2)
)

Write-Host "Attestation CIDs:" -ForegroundColor Green
$attCids | ForEach-Object { Write-Host "  $_" }

foreach($p in @{"Operator"=$Operator;"Edge1"=$Edge1;"Edge2"=$Edge2;"ServiceProv"=$ServiceProv;"IoTDevice1"=$IoTDevice1}){
  if (-not $p.Values) { throw "Missing party id for $($p.Keys)" }
}

# ---------- SNAPSHOT ----------
Write-Host "Fetching latest policy snapshot..." -ForegroundColor Cyan
$snaps = PostJson "$JsonApiUrl/v1/query" $H @{ templateIds=@($TTaSnapshot); query=@{} }
$latest = $snaps.result | Sort-Object { $_.payload.epoch } | Select-Object -Last 1
$epoch  = [int]$latest.payload.epoch
$revH   = $latest.payload.revocationHash
Write-Host ("Digest bundle: {0}" -f $digest_hex) -ForegroundColor Yellow

# ---------- RELAY ----------
Write-Host "Relaying message via Edge1..." -ForegroundColor Cyan
$edgeTok = NewJwt @($Edge1)
$operatorJwt = [string](Get-Content $OperatorJwtPath -Raw).Trim()
$edgeTok     = [string](NewJwt @($Edge1))

$bodyRelay = @{
  edge_token           = $edgeTok             # string
  operator_token       = $operatorJwt         # string
  edge                 = $Edge1
  sp                   = $ServiceProv
  targetDevice         = $devCid

  encryptedMessage_b64 = $cipher_b64
  nonce_b64            = $nonce_b64
  ephemeral_x25519_hex = $eph_hex
  counter              = [int]$counter
  devicePublicKey      = $devicePublicKey
  digest_hex           = $digest_hex
  aad                  = "demo"

  sp_ed25519_pub_hex   = $sp_pub_hex
  sp_signature_b64     = $sp_signature_b64

  msgTimestamp         = [int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  epoch                = [int]$epoch
  revocationHash       = $revH
  attestation_cids     = @($attCids)
}

# Optional: fetch & log attestation payloads safely
$attT = "{0}:Main:SigAttestation" -f $pkg
$check = @()
foreach($cid in $attCids){
  try {
    $resp = PostJson "$JsonApiUrl/v1/fetch" $H @{ templateId=$attT; contractId=$cid }
    if ($resp) { $check += $resp }
  } catch {
    # FIX: wrap $cid since a colon right after a variable breaks parsing
    Write-Host "Fetch failed for ${cid}: $($_.Exception.Message)" -ForegroundColor DarkYellow
  }
}
$payloads = @()
if ($check) { $payloads = $check | ForEach-Object { $_.result.payload } | Where-Object { $_ } }

foreach($pl in $payloads){
  $line = "{0} | issuer={1} | digest={2}" -f (Get-Prop $pl 'sp'), (Get-Prop $pl 'issuer'), (Get-Prop $pl 'digest')
  Write-Host $line
}

if ($payloads.Count -gt 0) {
  $uniqueDigests = $payloads | Select-Object -ExpandProperty digest -Unique
  if ($uniqueDigests -ne $digest_hex) {
    throw "Digest mismatch: bundle=$digest_hex vs attestation(s)=$(($uniqueDigests -join ','))"
  }
}

try {
  $relayRes = PostJson "$FlaskUrl/relay_message" @{} $bodyRelay
  Write-Host "Relay result:" -ForegroundColor Green
  $relayRes | ConvertTo-Json
} catch {
  $msg = if ($_.Exception) { $_.Exception.Message } else { "$_" }
  Write-Host "Relay failed:" -ForegroundColor Red
  Write-Host $msg -ForegroundColor Red
  return
}

Write-Host "DONE." -ForegroundColor Green
# =================== end of scope_end2end.ps1 =======================
