param(
  [string]$OutFile = ".\token.txt",
  [string]$Secret  = "secret",                 # must match json-api --auth-jwt-hs256-unsafe
  [string[]]$ActAs = @("Operator"),
  [string[]]$ReadAs = @("Operator"),
  [switch]$Admin = $true,
  [int]$Hours = 12,
  [string]$LedgerId = "*",
  [string]$ParticipantId = "*",
  [string]$ApplicationId = "scope-dev"
)

$ErrorActionPreference = "Stop"

# --- JSON pieces ---
$header = @{ alg="HS256"; typ="JWT" } | ConvertTo-Json -Compress
$payload = @{
  exp = [int]([DateTimeOffset]::UtcNow.AddHours($Hours).ToUnixTimeSeconds())
  "https://daml.com/ledger-api" = @{
    ledgerId      = $LedgerId
    participantId = $ParticipantId
    applicationId = $ApplicationId
    actAs  = $ActAs
    readAs = $ReadAs
    admin  = [bool]$Admin
  }
} | ConvertTo-Json -Compress

function B64UrlBytes([byte[]]$b) {
  [Convert]::ToBase64String($b).TrimEnd('=').Replace('+','-').Replace('/','_')
}
function B64Url([string]$s) { B64UrlBytes ([Text.Encoding]::UTF8.GetBytes($s)) }

$h = B64Url $header
$p = B64Url $payload
$toSign = "$h.$p"

# --- HMAC-SHA256 (PS5-safe & PS7) ---
$keyBytes = [Text.Encoding]::UTF8.GetBytes($Secret)
try {
  if ([System.Environment]::Version.Major -ge 6) {
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($keyBytes)
  } else {
    # PS5 needs the leading comma to pass the byte[] as a single argument
    $hmac = New-Object System.Security.Cryptography.HMACSHA256 (,$keyBytes)
  }
} catch {
  throw "Failed to construct HMACSHA256: $($_.Exception.Message)"
}

$raw = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($toSign))
$sig = B64UrlBytes $raw
$jwt = "$toSign.$sig"

Set-Content -NoNewline -Encoding ASCII -Path $OutFile -Value $jwt
Write-Host "Wrote $OutFile (actAs=$($ActAs -join ','), readAs=$($ReadAs -join ','), admin=$([bool]$Admin))."
