````markdown
# ScopeSecure — IoT Communication & Policy Enforcement Framework (SCOPE)

SCOPE separates **on-ledger authorization** from **end-to-end encryption** for time-sensitive IoT. A Broker Smart Contract (BSC) enforces RBAC/ABAC policy, committee attestations, and **epoch-scoped revocation** with immutable audit logs, while **edge relays** verify and forward **without decrypting**. Devices use a pairing-free channel (X25519 → HKDF → AEAD) with Ed25519 signatures, disciplined nonces/counters, and explicit freshness/replay bounds. The design is ledger-agnostic and ready for drop-in PQ KEM+AEAD if required.

## Features

- DAML smart contracts (`BrokerContract`, `LogRequest`)
- Edge-node relay with policy checks and immutable audit
- IoT device registration & management
- Flask edge service: caching, compression, crypto, JSON-API client
- X25519 + HKDF for key agreement; AEAD for confidentiality/integrity
- Ed25519 for signatures and verification
- Role/attribute-based access control on-ledger
- Comprehensive logging via `LogRequest` contracts

## Dependencies

### System

- **DAML SDK** ≥ 2.x  
- **Canton** (protocol version **7**)  
- **Java** 11+ (for Canton)  
- **Python** 3.7+  
- `curl`, `grpcurl`  
- **PowerShell Core** (Windows users)

### Python packages

```bash
pip install \
  flask \
  flask-caching \
  flask-compress \
  cryptography \
  requests
````

## Quick Start

### 0) Prepare `canton.conf`

Place the file below as `canton.conf` in your Canton `bin/` folder.

<details>
<summary><code>canton.conf</code></summary>

```hocon
canton {
  parameters { non-standard-config = yes }
  features   { enable-testing-commands = yes }

  participants {
    local {
      storage.type = memory
      admin-api  { address = "127.0.0.1"; port = 6865 }
      ledger-api { address = "127.0.0.1"; port = 6866 }
    }
  }

  domains {
    myLocalDomain {
      init { domain-parameters { protocol-version = 7 } }
      storage.type = memory
      admin-api  { address = "127.0.0.1"; port = 7500 }
      public-api { address = "127.0.0.1"; port = 7575 }
    }
  }

  # Optional: bootstrap = "bootstrap.canton"
}
```

</details>

### 1) Start Canton

**Windows (PowerShell)**

```powershell
cd C:\path\to\canton\bin
.\canton.bat -c .\canton.conf
```

In the Canton console:

```scala
participants.local.head.domains.connect_local(domains.local.head)
participants.local.head.domains.is_connected(domains.local.head)
```

(Optional) Upload your DAR directly from the Canton REPL:

```scala
participants.local.head.dars.upload("C:/path/to/repo/daml/.daml/dist/test-0.0.1.dar")
participants.local.head.dars.list()
```



### 2) Start the DAML JSON-API (separate shell)

**Option A — allow insecure tokens (easiest for local):**

```bash
daml json-api --ledger-host localhost --ledger-port 6866 --http-port 7575 --allow-insecure-tokens
```

**Option B — HS256 JWT secret:**

```bash
# PowerShell
$env:DAML_JSON_HTTP_AUTH_JWT_HS256_HS_SECRET = 'my-super-secret'
daml json-api --ledger-host localhost --ledger-port 6866 --http-port 7575
```

> If you choose port **7576** instead of **7575**, keep it consistent in the steps below.



### 3) Build and run DAML scripts (separate shell)

```bash
# From the repo root
daml build
daml ledger upload-dar .daml/dist/test-0.0.1.dar --host localhost --port 6866

# Initialize on-ledger state
daml script --dar .daml/dist/test-0.0.1.dar --script-name Main:setup --ledger-host localhost --ledger-port 6866

# Optional demo/test scripts
daml script --dar .daml/dist/test-0.0.1.dar --script-name Main:testList  --ledger-host localhost --ledger-port 6866
daml script --dar .daml/dist/test-0.0.1.dar --script-name Main:testRelay --ledger-host localhost --ledger-port 6866
```



### 4) Run the Flask edge service

```bash
python3 flask_app.py
```

You should see:

```
 * Serving Flask app "flask_app"
 * Running on http://0.0.0.0:5000 (Press CTRL+C to quit)
```



### 5) One-button local demo (PowerShell)

A script is provided to bootstrap parties/tokens, discover the active package ID, run setup/demo scripts, start Flask, send demo `LogRequest`s, and print inventory:

```powershell
# From the script directory in the repo
.\test_flask_operator.ps1 `
  -LedgerHost localhost `
  -LedgerHttpPort 7575 `  # <- use 7576 here if you started JSON-API on 7576
  -DarPath .\.daml\dist\*.dar `
  -OperatorTokenPath .\operator.jwt `
  -BootstrapTokenPath .\bootstrap.jwt `
  -JsonApiSecret "secret" `
  -RunSetup `
  -RunRunAll `
  -StartFlask `
  -AckLatestRelay
```

(There’s also a small timing/crypto sanity script you can run: `py sen.py`.)



### 6) Manual testing (if not using the script)

Start components:

```bash
# Flask backend
python3 flask_app.py

# (Optional) Operator JWT
python3 generate_jwt.py > token.txt

# HTTP trigger bridge
python3 http_trigger.py
```

Inspect the DAR/package ID:

```bash
daml damlc inspect-dar ".daml/dist/test-0.0.1.dar"
```

Fetch a `BrokerContract` by key (replace placeholders):

```bash
curl -X POST http://localhost:7575/v1/fetch \
  -H "Authorization: Bearer $(< token.txt)" \
  -H "Content-Type: application/json" \
  -d '{
    "templateId":"<DAR_ID>:Main:BrokerContract",
    "key":"Operator::<operator_party_id>"
  }'
```

Generate UI bindings (optional):

```bash
daml codegen js .daml/dist/test-0.0.1.dar -o ui
```



## How it fits together

* **Canton + DAML**: Hosts smart contracts for access control, attestation, device records, and append-only logging (`LogRequest`).
* **JSON-API**: Bridges the ledger with the edge service (Flask) using JWT-authenticated REST calls.
* **Flask edge relay**: Verifies device signatures, enforces freshness, creates/reads contracts, and **relays without decrypting**.
* **Crypto**: Devices establish a symmetric channel with X25519/HKDF/AEAD; all messages are signed with Ed25519.



## Troubleshooting

* **Ports busy**

  ```powershell
  netstat -ano | findstr :7575
  netstat -ano | findstr :6865
  taskkill /PID <pid> /F
  ```

* **Canton not connected**

  ```scala
  participants.local.head.domains.is_connected(domains.local.head)  // must be true
  ```

* **JWT/Authorization**

  * If using `--allow-insecure-tokens`, ensure your client actually sends a token (even a dummy).
  * If using HS256, confirm the secret in `daml json-api` matches the one used to mint tokens.

* **Template/Package ID**

  * Verify the active package ID with `daml damlc inspect-dar ...`.
  * Mismatch will cause `templateId`/`choice` errors via JSON-API.

* **JSON payloads**

  * Ensure valid JSON and correct `Content-Type: application/json`.



## Artifact availability

If still having trouble running, you can drop me an email or contact me on LinkedIn
```
```
