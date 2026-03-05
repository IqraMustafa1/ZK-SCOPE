#!/usr/bin/env python3
# make_operator_jwt.py
# Generates an HS256 Operator JWT for DAML JSON-API / Ledger API auth.

import os, sys, time, json, re
import jwt  # pip install PyJWT


def getenv(k, d=None):
    v = os.getenv(k)
    return v if v is not None and v != "" else d


def die(msg: str, code: int = 1):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def load_secret() -> str:
    # Prefer file if provided (avoids copy/paste mistakes)
    secret_file = getenv("JSON_API_SECRET_FILE")
    if secret_file:
        try:
            return open(secret_file, "r", encoding="utf-8").read().strip()
        except OSError as e:
            die(f"Failed to read JSON_API_SECRET_FILE={secret_file}: {e}")

    secret = getenv("JSON_API_SECRET")
    if not secret:
        # If your JSON-API was started with --allow-insecure-tokens, signature isn't checked,
        # but we still require a secret here to avoid accidentally producing nonsense tokens.
        die("Set JSON_API_SECRET (or JSON_API_SECRET_FILE). Must match JSON-API --jwt-secret.")
    return secret


def normalize_party(p: str) -> str:
    p = p.strip()
    if not p:
        die("OPERATOR_ID is empty.")
    # Expect "Operator::..." (your project uses this pattern)
    if "::" not in p:
        die(f"OPERATOR_ID must be full party id like 'Operator::1220...'. Got: {p}")
    return p


# REQUIRED: full party identifier
OPERATOR_ID = normalize_party(getenv("OPERATOR_ID", ""))
JSON_API_SECRET = load_secret()

LEDGER_ID      = getenv("LEDGER_ID", "local")
PARTICIPANT_ID = getenv("PARTICIPANT_ID", "local")
APP_ID         = getenv("APP_ID", "scope-operator")
AUD            = getenv("JWT_AUD", "json-api")  # keep consistent with your setup
LIFETIME_SECS  = int(getenv("JWT_LIFETIME_SECS", "86400"))  # 24h
CLOCK_SKEW     = int(getenv("JWT_CLOCK_SKEW_SECS", "30"))   # helps if clocks drift

now = int(time.time())
claims = {
    "iss": getenv("JWT_ISS", "local-script"),
    "aud": AUD,
    "sub": OPERATOR_ID,                  # optional but useful
    "iat": now,
    "nbf": now - CLOCK_SKEW,
    "exp": now + LIFETIME_SECS,
    "https://daml.com/ledger-api": {
        "ledgerId": LEDGER_ID,
        "participantId": PARTICIPANT_ID, # OK if your stack expects it
        "applicationId": APP_ID,
        "actAs":  [OPERATOR_ID],
        "readAs": [OPERATOR_ID],
        "admin": True,
    },
}

token = jwt.encode(claims, JSON_API_SECRET, algorithm="HS256")
if isinstance(token, bytes):  # PyJWT v1 compatibility
    token = token.decode("utf-8")

out_path = sys.argv[1] if len(sys.argv) > 1 else None
if out_path:
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        f.write(token)
        f.write("\n")
    print(f"Wrote JWT -> {out_path}")
else:
    print(token)

# Optional: quick sanity print (set JWT_DEBUG=1)
if getenv("JWT_DEBUG", "0") == "1":
    print("\n== Claims ==")
    print(json.dumps(claims, indent=2))
