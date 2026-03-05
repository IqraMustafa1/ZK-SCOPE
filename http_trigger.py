#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HTTP trigger for Main:LogRequest
- Auto-discovers DAML_PKG_ID (module `Main`) from JSON-API, unless provided.
- Finds JWT via: --token / env / --token-file / TOKEN_PATH / common filenames.
- Polls LogRequest, POSTs to its endpoint, then Archives the contract.
"""

import os
import sys
import time
import json
import argparse
import requests
from typing import Optional, List, Any

# =================== CONFIG (defaults) ===================
LEDGER_HOST        = os.getenv("LEDGER_HOST", "localhost")
LEDGER_HTTP_PORT   = os.getenv("LEDGER_HTTP_PORT", "7576")
JSON_API           = f"http://{LEDGER_HOST}:{LEDGER_HTTP_PORT}"
POLL_INTERVAL_SEC  = int(os.getenv("POLL_INTERVAL", "2"))
REQUEST_TIMEOUT_S  = int(os.getenv("REQUEST_TIMEOUT", "8"))
DAML_PKG_ID        = (os.getenv("DAML_PKG_ID") or "").strip()
STRICT_DELIVERY    = os.getenv("STRICT_DELIVERY", "0") == "1"  # archive only on POST success if true

# =================== UTIL =====================
def pretty_json(x: Any) -> str:
    try:
        return json.dumps(x, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    except Exception:
        return str(x)

def load_text_file(path: str) -> Optional[str]:
    try:
        raw = open(path, "rb").read()
    except Exception:
        return None
    for enc in ("utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "ascii", "utf-8"):
        try:
            text = raw.decode(enc).strip()
            if text and "\x00" not in text:
                return text
        except Exception:
            continue
    return None

def find_jwt_from_args_env_or_files(args) -> (Optional[str], str):
    """
    Returns (jwt, source_description)
    Precedence:
      1) --token raw value
      2) env JSON_API_JWT / JWT_TOKEN / DAML_JWT
      3) --token-file path
      4) TOKEN_PATH env
      5) common filenames in cwd
    """
    # 1) raw token on CLI
    if args.token:
        return args.token.strip(), "--token (raw)"

    # 2) env vars with raw token
    for env_key in ("JSON_API_JWT", "JWT_TOKEN", "DAML_JWT"):
        v = os.getenv(env_key)
        if v:
            return v.strip(), f"env:{env_key}"

    # 3) explicit token file
    search_files = []
    if args.token_file:
        search_files.append(args.token_file)
    # 4) TOKEN_PATH env
    tp = os.getenv("TOKEN_PATH")
    if tp:
        search_files.append(tp)
    # 5) common local filenames
    search_files.extend(["operator.jwt", "token.txt", "token.jwt", "jwt.txt"])

    for path in search_files:
        token = load_text_file(path)
        if token:
            return token, f"file:{os.path.abspath(path)}"

    return None, ""

def bprint_cfg(token_src: str):
    print("──────── trigger config ────────")
    print(f" JSON_API       : {JSON_API}")
    print(f" DAML_PKG_ID    : {DAML_PKG_ID or '(auto-discover)'}")
    print(f" POLL_INTERVAL  : {POLL_INTERVAL_SEC}s")
    print(f" TIMEOUT        : {REQUEST_TIMEOUT_S}s")
    print(f" STRICT_DELIVERY: {STRICT_DELIVERY}")
    print(f" JWT source     : {token_src or '(not found)'}")
    print("────────────────────────────────")

def make_session(jwt: str) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "Authorization": f"Bearer {jwt}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    })
    return s

def _coerce_packages_list(obj: Any) -> List[str]:
    # Accept {"result":[...]} or raw [...]
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict) and "result" in obj and isinstance(obj["result"], list):
        return obj["result"]
    return []

def _package_modules_for(sess: requests.Session, pid: str) -> List[str]:
    r = sess.get(f"{JSON_API}/v1/packages/{pid}", timeout=REQUEST_TIMEOUT_S)
    r.raise_for_status()
    info = r.json() or {}
    mods = info.get("modules", [])
    names: List[str] = []
    for m in mods:
        if isinstance(m, str):
            names.append(m)
        elif isinstance(m, dict) and "name" in m:
            names.append(str(m["name"]))
    return names

def discover_package_id(sess: requests.Session) -> Optional[str]:
    try:
        rr = sess.get(f"{JSON_API}/v1/packages", timeout=REQUEST_TIMEOUT_S)
        rr.raise_for_status()
        ids = _coerce_packages_list(rr.json())
        # Prefer explicit module match
        for pid in ids:
            try:
                mods = _package_modules_for(sess, pid)
                if "Main" in mods:
                    return pid
            except Exception:
                continue
        # Fallback: probe query
        for pid in ids:
            body = {"templateIds": [f"{pid}:Main:LogRequest"], "query": {}}
            try:
                r = sess.post(f"{JSON_API}/v1/query", json=body, timeout=REQUEST_TIMEOUT_S)
                if r.status_code < 400:
                    return pid
            except Exception:
                pass
    except Exception as e:
        print(f"⚠️  Package discovery failed: {e}", file=sys.stderr)
    return None

def tid(entity: str) -> str:
    return f"{DAML_PKG_ID}:Main:{entity}"

# =================== JSON-API HELPERS ========
def _post_json_api(sess: requests.Session, path: str, body: dict) -> dict:
    r = sess.post(f"{JSON_API}{path}", json=body, timeout=REQUEST_TIMEOUT_S)
    if r.status_code >= 400:
        print(f"❌ {path} {r.status_code}: {r.text.strip()}  body={pretty_json(body)}", file=sys.stderr)
    r.raise_for_status()
    return r.json()

def query_log_requests(sess: requests.Session, template_id: str) -> List[dict]:
    body = {"templateIds": [template_id], "query": {}}
    res = _post_json_api(sess, "/v1/query", body)
    return res.get("result", [])

def exercise_archive(sess: requests.Session, template_id: str, contract_id: str) -> dict:
    body = {
        "templateId": template_id,
        "contractId": contract_id,
        "choice": "Archive",
        "argument": {},
    }
    return _post_json_api(sess, "/v1/exercise", body)

# =================== MAIN LOOP ==============
def process_logrequest(ledger_sess: requests.Session, ext_sess: requests.Session, template_id: str, row: dict) -> None:
    cid     = row.get("contractId")
    payload = row.get("payload") or {}
    if not cid or not isinstance(payload, dict):
        return

    raw_log  = payload.get("logData", "{}")
    endpoint = (payload.get("endpoint") or "").strip()

    # Parse JSON logData gracefully
    try:
        log_json = json.loads(raw_log if isinstance(raw_log, str) else "{}")
    except Exception as e:
        print(f"❌ Invalid JSON in logData for {cid}: {e}")
        try:
            exercise_archive(ledger_sess, template_id, cid)
            print(f"🗑 Archived (bad logData) {cid}")
        except Exception as e2:
            print(f"⚠️  Archive failed for {cid}: {e2}")
        return

    if not endpoint:
        print(f"⚠️  Missing endpoint in payload for {cid}, archiving.")
        try:
            exercise_archive(ledger_sess, template_id, cid)
            print(f"🗑 Archived {cid}")
        except Exception as e2:
            print(f"⚠️  Archive failed for {cid}: {e2}")
        return

    # Ship the payload
    print(f"📡 POST {endpoint} ← {pretty_json(log_json)}")
    post_ok = True
    try:
        r = ext_sess.post(endpoint, json=log_json, timeout=REQUEST_TIMEOUT_S)
        r.raise_for_status()
        print(f"✅ External POST {r.status_code}: {r.text.strip()[:200]}")
    except Exception as e:
        post_ok = False
        print(f"❌ HTTP error sending to {endpoint}: {e}")

    # Archive (always by default; honor STRICT_DELIVERY if set)
    if post_ok or not STRICT_DELIVERY:
        try:
            exercise_archive(ledger_sess, template_id, cid)
            print(f"🗑 Archived {cid}")
        except Exception as e2:
            print(f"⚠️  Archive failed for {cid}: {e2}")
    else:
        print(f"⏸ Not archiving {cid} due to STRICT_DELIVERY=1 and failed POST")

def main():
    # CLI
    ap = argparse.ArgumentParser(description="SCOPE LogRequest HTTP trigger")
    ap.add_argument("--token-file", help="Path to JWT file (e.g., operator.jwt)")
    ap.add_argument("--token", help="Raw JWT string")
    args = ap.parse_args()

    # Find JWT
    jwt_token, token_src = find_jwt_from_args_env_or_files(args)
    if not jwt_token:
        print("❌ No JWT found.", file=sys.stderr)
        print("   Options:", file=sys.stderr)
        print("     - pass --token-file operator.jwt", file=sys.stderr)
        print("     - or set $env:TOKEN_PATH='operator.jwt' (PowerShell) / export TOKEN_PATH=operator.jwt (bash)", file=sys.stderr)
        print("     - or set JSON_API_JWT / JWT_TOKEN / DAML_JWT env to the raw token", file=sys.stderr)
        print("     - or write the token to one of: operator.jwt, token.txt, token.jwt, jwt.txt", file=sys.stderr)
        sys.exit(1)

    bprint_cfg(token_src)

    ledger_sess = make_session(jwt_token)
    ext_sess    = requests.Session()
    ext_sess.headers.update({"Content-Type": "application/json", "Accept": "application/json"})

    # Preflight JSON-API
    try:
        ping = ledger_sess.get(f"{JSON_API}/v1/packages", timeout=REQUEST_TIMEOUT_S)
        ping.raise_for_status()
    except Exception as e:
        print(f"❌ JSON-API not reachable or token rejected: {e}", file=sys.stderr)
        print("   Ensure JSON-API is up and the token's ledgerId matches.", file=sys.stderr)
        sys.exit(2)

    # Discover package id if needed
    global DAML_PKG_ID
    if not DAML_PKG_ID or DAML_PKG_ID.lower() in {"<your-package-id>", "your-package-id"}:
        found = discover_package_id(ledger_sess)
        if not found:
            sys.exit("❌ DAML_PKG_ID not set and could not be discovered from /v1/packages.")
        DAML_PKG_ID = found
        print(f"✅ Discovered DAML_PKG_ID = {DAML_PKG_ID}")

    LOGREQUEST_TEMPLATE = tid("LogRequest")
    print(f"🔁 Polling template {LOGREQUEST_TEMPLATE}")

    # Loop with backoff
    backoff = POLL_INTERVAL_SEC
    max_backoff = min(60, POLL_INTERVAL_SEC * 10)

    while True:
        try:
            rows = query_log_requests(ledger_sess, LOGREQUEST_TEMPLATE)
            backoff = POLL_INTERVAL_SEC  # reset on success
        except Exception as e:
            print(f"⚠️  Polling error: {e}")
            time.sleep(backoff)
            backoff = min(max_backoff, max(POLL_INTERVAL_SEC, backoff * 2))
            continue

        if rows:
            print(f"🔎 Found {len(rows)} LogRequest(s)")
        for row in rows:
            try:
                process_logrequest(ledger_sess, ext_sess, LOGREQUEST_TEMPLATE, row)
            except Exception as e:
                print(f"⚠️  Unexpected processing error: {e}")

        time.sleep(POLL_INTERVAL_SEC)

if __name__ == "__main__":
    main()
