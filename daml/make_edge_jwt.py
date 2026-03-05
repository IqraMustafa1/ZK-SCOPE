#!/usr/bin/env python3
# make_edge_jwt.py
# Generates an HS256 Edge JWT for DAML JSON-API (Option C).

import os, sys, time
import jwt  # pip install PyJWT


def getenv(k, d=None):
    v = os.getenv(k)
    return v if v is not None else d


EDGE_ID = getenv("EDGE_ID")
OPERATOR_ID = getenv("OPERATOR_ID")

if not EDGE_ID or not OPERATOR_ID:
    print("ERROR: EDGE_ID and OPERATOR_ID must be set to full party identifiers.", file=sys.stderr)
    sys.exit(1)

JSON_API_SECRET = getenv("JSON_API_SECRET", "secret")

LEDGER_ID      = getenv("LEDGER_ID", "local")
PARTICIPANT_ID = getenv("PARTICIPANT_ID", "local")
APP_ID         = getenv("APP_ID", "scope-edge")
LIFETIME_SECS  = int(getenv("JWT_LIFETIME_SECS", "86400"))

now = int(time.time())
claims = {
    "iss": "local-script",
    "aud": "json-api",
    "exp": now + LIFETIME_SECS,
    "https://daml.com/ledger-api": {
        "ledgerId": LEDGER_ID,
        "participantId": PARTICIPANT_ID,
        "applicationId": APP_ID,
        # *** Option C: edge can actAs itself, readAs Operator ***
        "actAs":  [EDGE_ID],
        "readAs": [OPERATOR_ID],
        "admin": False,
    },
}

token = jwt.encode(claims, JSON_API_SECRET, algorithm="HS256")

out_path = sys.argv[1] if len(sys.argv) > 1 else "edge.jwt"
with open(out_path, "w", newline="") as f:
    f.write(token)

print(f"Wrote Edge JWT for {EDGE_ID} (readAs {OPERATOR_ID}) to {out_path}")
