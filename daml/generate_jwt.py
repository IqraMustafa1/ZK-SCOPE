#!/usr/bin/env python3
# generate_jwt.py - JWT generator for Daml JSON-API (HS256)
#
# Supports multi-party actAs/readAs:
#   --act-as  Party1 --act-as Party2
#   --read-as PartyA,PartyB
#
# IMPORTANT:
# - admin=true does NOT bypass DAML visibility; you must include the right readAs parties.

import os, sys, time, json, argparse
import jwt  # pip install PyJWT


def getenv_any(keys, default=None):
    for k in keys:
        v = os.getenv(k)
        if v not in (None, ""):
            return v
    return default


def die(msg: str, code: int = 1):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def load_secret() -> str:
    secret_file = getenv_any(["JSON_API_SECRET_FILE"])
    if secret_file:
        try:
            with open(secret_file, "r", encoding="utf-8") as f:
                s = f.read().strip()
            if not s:
                die(f"JSON_API_SECRET_FILE is empty: {secret_file}")
            return s
        except OSError as e:
            die(f"Failed to read JSON_API_SECRET_FILE={secret_file}: {e}")

    secret = getenv_any(["JSON_API_SECRET"])
    if not secret:
        die("Set JSON_API_SECRET (or JSON_API_SECRET_FILE). Must match JSON-API --jwt-secret.")
    return secret


def normalize_party(p: str) -> str:
    p = (p or "").strip()
    if not p:
        die("Missing party id.")
    if "::" not in p:
        die(f"Party must be a FULL party id like 'Operator::1220...'. Got: {p}")
    return p


def parse_party_list(values):
    """
    Accept:
      - repeated args: ["A::..", "B::.."]
      - comma-separated: ["A::..,B::.."]
      - mixed
    Returns normalized list with stable order and de-duplication.
    """
    out = []
    seen = set()
    if not values:
        return out

    if isinstance(values, str):
        values = [values]

    for v in values:
        if v is None:
            continue
        s = str(v).strip()
        if not s:
            continue
        parts = [x.strip() for x in s.split(",") if x.strip()]
        for p in parts:
            p2 = normalize_party(p)
            if p2 not in seen:
                seen.add(p2)
                out.append(p2)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--act-as", dest="act_as", action="append", default=None,
                    help="Full party id to actAs. Repeatable or comma-separated.")
    ap.add_argument("--read-as", dest="read_as", action="append", default=None,
                    help="Full party id(s) to readAs. Repeatable or comma-separated. "
                         "If omitted, defaults to actAs list.")
    ap.add_argument("--out", dest="out_path", default=None, help="Write token to file (overrides TOKEN_PATH)")
    ap.add_argument("--lifetime", dest="lifetime", type=int, default=None, help="Token lifetime seconds")
    ap.add_argument("--admin", dest="admin", action="store_true", help="Set admin=true")
    ap.add_argument("--no-admin", dest="admin", action="store_false", help="Set admin=false")
    ap.set_defaults(admin=None)
    ap.add_argument("--debug", dest="debug", action="store_true", help="Print claims JSON to stderr")
    args = ap.parse_args()

    # Backward compatible env-based single-party if --act-as missing
    env_party = getenv_any(["OPERATOR_ID", "ACT_AS"])
    act_as_list = parse_party_list(args.act_as or ([env_party] if env_party else None))
    if not act_as_list:
        die("Provide at least one --act-as or set OPERATOR_ID/ACT_AS.")

    read_as_list = parse_party_list(args.read_as) if args.read_as else list(act_as_list)

    secret = load_secret()

    ledger_id = getenv_any(["LEDGER_ID"], "local")
    participant_id = getenv_any(["PARTICIPANT_ID"], "local")

    app_id = getenv_any(["APP_ID", "APPLICATION_ID"], "scope-app")
    aud = getenv_any(["JWT_AUD", "JWT_AUDIENCE"], "json-api")
    iss = getenv_any(["JWT_ISS"], "local-script")

    lifetime = args.lifetime if args.lifetime is not None else int(getenv_any(["JWT_LIFETIME_SECS"], "86400"))
    clock_skew = int(getenv_any(["JWT_CLOCK_SKEW_SECS"], "30"))

    if args.admin is None:
        admin_env = getenv_any(["JWT_ADMIN"], "true").lower()
        admin = admin_env in ("1", "true", "yes", "y")
    else:
        admin = args.admin

    now = int(time.time())

    claims = {
        "iss": iss,
        "aud": aud,
        "sub": act_as_list[0],  # keep sub as first party for compatibility
        "iat": now,
        "nbf": now - clock_skew,
        "exp": now + lifetime,
        "https://daml.com/ledger-api": {
            "ledgerId": ledger_id,
            "participantId": participant_id,
            "applicationId": app_id,
            "actAs": act_as_list,
            "readAs": read_as_list,
            "admin": admin,
        },
    }

    token = jwt.encode(claims, secret, algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode("utf-8")

    out_path = args.out_path or getenv_any(["TOKEN_PATH"])
    if out_path:
        try:
            with open(out_path, "w", encoding="utf-8", newline="") as f:
                f.write(token)
                f.write("\n")
            print(f"Wrote JWT -> {out_path}")
        except OSError as e:
            die(f"Failed to write token to {out_path}: {e}")
    else:
        print(token)

    if args.debug or getenv_any(["JWT_DEBUG"], "0") == "1":
        print("\n== Claims ==", file=sys.stderr)
        print(json.dumps(claims, indent=2), file=sys.stderr)


if __name__ == "__main__":
    main()
