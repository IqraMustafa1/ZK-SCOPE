````markdown
# SCOPE++ (ZK-PAC + Hybrid PQ) — Mandatory End-to-End Runbook (Windows + WSL)

Nothing is optional in this runbook. Follow in order.  
Topology: Windows runs Canton + Ledger + JSON-API + PowerShell harness; WSL (Ubuntu) runs Flask (OQS PQ support).

## STEP 1 — Start Canton + Connect Domain + Upload DAR (Windows PowerShell)

Open **PowerShell** and run Canton:

```powershell
PS C:\canton\canton\bin> .\canton.bat -c "C:\canton\canton\bin\canton.conf"
````

Then in the Canton console, run these commands:

```text
participants.local.head.domains.connect_local(domains.local.head)
participants.local.head.domains.is_connected(domains.local.head)

participants.local.head.dars.upload("""C:\Users\mustafai\Desktop\ZK-SCOPE\SCOPE-Framework-main\SCOPE-Framework-main\.daml\dist\test-0.0.1.dar""")
participants.local.head.dars.list()
```

---

## STEP 2 — Start DAML JSON-API (Windows PowerShell, NEW window)

Open **another PowerShell window**:

```powershell
$TOK = "$PWD\bootstrap.jwt"

daml json-api `
  --ledger-host localhost `
  --ledger-port 6866 `
  --address 0.0.0.0 `
  --http-port 7576 `
  --allow-insecure-tokens `
  --access-token-file $TOK
```

Keep this window running.

---

## STEP 3 — Run DAML↔Flask Bridge Trigger (Windows PowerShell, NEW window)

Open **another PowerShell window** and run:

```powershell
py http_trigger.py
```

Keep it running if it is designed to stay active.

---

## STEP 4 — Build DAR + Upload + Run Scripts (Windows PowerShell)

From repo root:

```powershell
PS C:\Users\mustafai\Desktop\ZK-SCOPE\SCOPE-Framework-main\SCOPE-Framework-main>

daml build

daml ledger upload-dar .\.daml\dist\test-0.0.1.dar --host localhost --port 6866

daml script --dar ".\.daml\dist\test-0.0.1.dar" --script-name Main:setupFresh --ledger-host localhost --ledger-port 6866

daml script --dar ".\.daml\dist\test-0.0.1.dar" --script-name RunAll:seedRelayLogs --ledger-host localhost --ledger-port 6866

daml script --dar ".\.daml\dist\test-0.0.1.dar" --script-name RunAll:calcMedianRelayCounters --ledger-host localhost --ledger-port 6866
```

---

## STEP 5 — Remove Existing Tokens (Windows PowerShell)

Run in repo root:

```powershell
Remove-Item .\operator.jwt, .\bootstrap.jwt -Force -ErrorAction SilentlyContinue
Remove-Item .\daml\token.txt -Force -ErrorAction SilentlyContinue
```

---

## STEP 6 — Generate NEW Operator Token (Windows PowerShell)

Run exactly (update OPERATOR_ID if it changes):

```powershell
$env:JSON_API_SECRET = "my-super-secret"
$env:OPERATOR_ID     = "Operator::1220f92a5ed02962896e6317fb53268e6e9ce363c9fc0e902d239208890405b0066a"
$env:APPLICATION_ID  = "scope-app"
$env:LEDGER_ID       = "local"
$env:PARTICIPANT_ID  = "local"
$env:JWT_AUDIENCE    = "json-api"

# IMPORTANT: write token to THIS exact file (match WSL step)
$env:TOKEN_PATH      = "C:\Users\mustafai\Desktop\ZK-SCOPE\SCOPE-Framework-main\SCOPE-Framework-main\operator.jwt"

py .\generate_jwt.py
```

✅ This forces the token filename to be **operator.jwt** so WSL uses the same file (no confusion).

---

## STEP 7 — Run Flask in WSL (Ubuntu) — OQS PQ support is here

Open **WSL Ubuntu** terminal:

```bash
# Go to DAML folder (WSL path)
cd /mnt/c/Users/mustafai/Desktop/SCOPE-Framework-main/SCOPE-Framework-main/daml

# Activate venv (mandatory)
source .venv/bin/activate

# Token file (WSL path) — MUST exist from STEP 6
export TOKEN_PATH="/mnt/c/Users/mustafai/Desktop/ZK-SCOPE/SCOPE-Framework-main/SCOPE-Framework-main/operator.jwt"

# Package Id (NO '=')
export DAML_PKG_ID="ff264bf406bfb527d00ab1abe172e93b1b4a317a7a6508c7d5d226e5454d3361"

# Operator party id (forces DAML_PARTY selection inside Flask)
export OPERATOR="Operator::1220f92a5ed02962896e6317fb53268e6e9ce363c9fc0e902d239208890405b0066a"

# JSON-API endpoint from WSL -> Windows host
WIN_HOST_IP="$(awk '/nameserver/ {print $2; exit}' /etc/resolv.conf)"
export JSON_API="http://${WIN_HOST_IP}:7576"

# Flask port
export FLASK_PORT=5000

# Run Flask
python3 flask_app.py
```

Keep Flask running.

---

## STEP 8 — Run PowerShell Test Harness (Windows PowerShell)

From repo root in **Windows PowerShell**:

```powershell
.\test_flask_operator.ps1 `
  -FlaskMode External `
  -FlaskHost 127.0.0.1 `
  -FlaskPort 5000 `
  -ForceSetup:$true `
  -RunRunAll:$true `
  -RunHybridRelay `
  -UseZkPac:$true `
  -PolicyId "POLICY_DEMO_V1" `
  -TargetDeviceDisplay 'Device1' `
  -Epoch 0 `
  -DeviceKyberPubB64 $StoredKyber_1linefor_scope++
```

---

## Quick Mandatory Sanity (optional outputs, not optional steps)

If you need a fast check (do not skip the steps above), you can confirm Flask config:

```bash
curl -s http://127.0.0.1:5000/debug/config | jq
```

And confirm JSON-API reachable from WSL:

```bash
curl -s "${JSON_API}/v1/packages" | head
```

```
```

