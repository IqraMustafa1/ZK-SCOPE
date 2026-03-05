#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SCOPE client bench — end-to-end Flask/JSON-API timing

What it collects (one row per trial):
- scenario: cold/warm (warm follows cold for cache effects)
- attrs:      synthetic attribute-count dimension for plots (1,2,4,8,16,21)
- msg_bytes:  payload length
- keygen_ms:  X25519 key gen timing
- sign_ms:    Ed25519 sign
- verify_ms:  Ed25519 verify
- enc_ms:     local AES-GCM encrypt
- dec_ms:     local AES-GCM decrypt
- http_encrypt_ms: Flask /crypto/encrypt_to_device latency
- http_log_ms:     Flask /log_batch_activity latency
- jsonapi_query_ms: JSON-API query latency (Device/LogRequest) if a JWT is available
- total_ms:   sum of above local crypto + HTTPs for quick comparisons
- digest_hex: SHA-256 digest (server-side) (prefix in CSV)
- sig_b64:    signature b64 (prefix in CSV)
- ct_b64:     ciphertext b64 (prefix in CSV)
- device_pub_source: where the device X25519 key came from (override/ledger/fallback)
- ok:         true/false (whether everything went fine)

Env / CLI
---------
FLASK_URL             default http://127.0.0.1:5000
SP_PARTY              default ServiceProvider1           (informational)
EDGE_PARTY            default EdgeNode1                  (informational)
DEVICE_PUB_HEX        override device X25519 public key (raw hex/PEM/base64)

OPERATOR_JWT          full JWT for JSON-API, else OPERATOR_TOKEN_PATH
OPERATOR_TOKEN_PATH   path to operator jwt (default .\operator.jwt)
MULTI_TOKEN_PATH      path to multi-party jwt (edge/sp/operator) (default .\multiparty.jwt)

Args:
  --attrs  "1,2,4,8,16,21"    which attribute-counts to run
  --reps   3                  repetitions per attr & scenario
  --msg    2048               payload size in bytes
  --csv    execution_results.csv
  --device-pub-hex  <hex/pem/b64>  same as env override
  --no-remote-encrypt          skip calling /crypto/encrypt_to_device
  --no-jsonapi                 skip JSON-API device/query steps
"""

import os, sys, csv, time, base64, json, argparse
import requests
from typing import Any, Dict, Optional, Tuple, List

from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# -------- CLI / ENV ----------------------------------------------------------

def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--attrs", default="1,2,4,8,16,21")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--msg", type=int, default=2048)
    ap.add_argument("--csv", default="execution_results.csv")
    ap.add_argument("--device-pub-hex", type=str, default=None)
    ap.add_argument("--no-remote-encrypt", action="store_true")
    ap.add_argument("--no-jsonapi", action="store_true")
    return ap.parse_args()

FLASK_URL  = os.environ.get("FLASK_URL", "http://127.0.0.1:5000").rstrip("/")
SP_PARTY   = os.environ.get("SP_PARTY", "ServiceProvider1")
EDGE_PARTY = os.environ.get("EDGE_PARTY", "EdgeNode1")

# JWTs for JSON-API
OP_JWT = os.environ.get("OPERATOR_JWT")
if not OP_JWT:
    tok_path = os.environ.get("OPERATOR_TOKEN_PATH", "./operator.jwt")
    if os.path.isfile(tok_path):
        try:
            OP_JWT = open(tok_path,"rb").read().decode("utf-8").strip()
        except Exception:
            OP_JWT = None

MULTI_JWT = None
mp_path = os.environ.get("MULTI_TOKEN_PATH","./multiparty.jwt")
if os.path.isfile(mp_path):
    try:
        MULTI_JWT = open(mp_path,"rb").read().decode("utf-8").strip()
    except Exception:
        MULTI_JWT = None

# -------- HTTP helpers -------------------------------------------------------

def getj(url: str, timeout=20) -> Dict[str, Any]:
    r = requests.get(url, timeout=timeout)
    if r.status_code >= 400:
        try: detail = r.json()
        except Exception: detail = r.text
        raise requests.HTTPError(f"{r.status_code} {r.reason} GET {url} :: {detail}", response=r)
    return r.json()

def postj(url: str, body: Dict[str, Any], timeout=60) -> Dict[str, Any]:
    r = requests.post(url, json=body, timeout=timeout)
    if r.status_code >= 400:
        try: detail = r.json()
        except Exception: detail = r.text
        raise requests.HTTPError(f"{r.status_code} {r.reason} for {url} :: {detail}", response=r)
    return r.json()

def json_api_headers(jwt: Optional[str]) -> Dict[str,str]:
    return {"Authorization": f"Bearer {jwt}", "Content-Type": "application/json"}

def json_api_post(api: str, path: str, body: Dict[str, Any], jwt: Optional[str]) -> Tuple[float, Dict[str, Any]]:
    if not jwt:
        raise RuntimeError("JSON-API call requested but no JWT available")
    t0 = time.perf_counter()
    r = requests.post(f"{api}{path}", headers=json_api_headers(jwt), json=body, timeout=30)
    dt = (time.perf_counter() - t0) * 1000.0
    if r.status_code >= 400:
        try: detail = r.json()
        except Exception: detail = r.text
        raise requests.HTTPError(f"{r.status_code} {r.reason} POST {api}{path} :: {detail}", response=r)
    return dt, r.json()

# -------- Key normalization --------------------------------------------------

def _is_hex(s: str, n: int = None) -> bool:
    try:
        bytes.fromhex(s)
        return (n is None) or (len(s) == n)
    except Exception:
        return False

def normalize_x25519_pub(pub_any: str) -> Tuple[str, str]:
    """
    Coerce pub_any to raw-hex X25519 (64 hex chars).
    Returns (hex_or_empty, how).
    """
    if not pub_any: return "", "empty"
    s = pub_any.strip()

    # raw hex candidate
    if _is_hex(s, 64):
        try:
            x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(s))
            return s, "hex_raw"
        except Exception:
            pass  # 32 bytes but wrong curve

    # PEM?
    if s.startswith("-----BEGIN"):
        try:
            pk = serialization.load_pem_public_key(s.encode("utf-8"))
            if isinstance(pk, x25519.X25519PublicKey):
                raw = pk.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                ).hex()
                return raw, "pem_x25519"
            else:
                return "", "pem_not_x25519"
        except Exception as e:
            return "", f"pem_error:{e}"

    # base64 of raw?
    try:
        raw = base64.b64decode(s, validate=True)
        if len(raw) == 32:
            try:
                x25519.X25519PublicKey.from_public_bytes(raw)
                return raw.hex(), "b64_raw_x25519"
            except Exception:
                return "", "b64_raw_not_x25519"
    except Exception:
        pass

    return "", "unrecognized"

# -------- Crypto helpers -----------------------------------------------------

def sha256_hex(b: bytes) -> str:
    h = hashes.Hash(hashes.SHA256())
    h.update(b)
    return h.finalize().hex()

def local_encrypt_decrypt_roundtrip(ptxt: bytes) -> Tuple[float,float, str, str, bool]:
    """
    AES-GCM with fresh key & 12B nonce, returns (enc_ms, dec_ms, ct_b64, sig_b64, ok)
    The signature is Ed25519 over plaintext (for demo / timing).
    """
    key = os.urandom(32)
    nonce = os.urandom(12)
    aes = AESGCM(key)
    t0 = time.perf_counter()
    ct = aes.encrypt(nonce, ptxt, None)
    enc_ms = (time.perf_counter() - t0) * 1000.0

    # Ed25519 sign verify on plaintext for “pass/enc/dec” visibility
    sk = ed25519.Ed25519PrivateKey.generate()
    sig = sk.sign(ptxt)
    sig_b64 = base64.b64encode(sig).decode()

    t1 = time.perf_counter()
    try:
        p2 = AESGCM(key).decrypt(nonce, ct, None)
        ok = (p2 == ptxt)
    except Exception:
        ok = False
    dec_ms = (time.perf_counter() - t1) * 1000.0

    return enc_ms, dec_ms, base64.b64encode(ct).decode(), sig_b64, ok

# -------- Bench core ---------------------------------------------------------

def discover_config() -> Dict[str, Any]:
    cfg = getj(f"{FLASK_URL}/debug/config")
    json_api = (cfg.get("json_api") or "http://localhost:7576").rstrip("/")
    daml_pkg = cfg.get("daml_pkg_id") or ""
    daml_party = cfg.get("daml_party") or "Operator"
    print(f"FLASK_URL={FLASK_URL}  SP={SP_PARTY}  EDGE={EDGE_PARTY}")
    print(f"json_api={json_api}  pkg={daml_pkg}  party={daml_party}")
    return {"json_api":json_api, "pkg":daml_pkg, "party":daml_party}

def discover_device_key(cfg: Dict[str, Any], args) -> Tuple[str, str, Optional[str]]:
    """
    Returns (device_pub_hex, source, device_cid_or_None)
    Tries: CLI/env override -> JSON-API Device.publicKey -> /health/keys fallback
    """
    # 1) CLI/ENV override
    override = args.device_pub_hex or os.environ.get("DEVICE_PUB_HEX")
    if override:
        h, how = normalize_x25519_pub(override)
        if h:
            print(f"[device key] from OVERRIDE ({how}) OK")
            return h, f"override:{how}", None
        else:
            print(f"[device key] override unusable ({how}), continuing…")

    # 2) Ledger query
    device_cid = None
    if not args.no_jsonapi and (OP_JWT or MULTI_JWT):
        jwt = OP_JWT or MULTI_JWT
        try:
            tid = f"{cfg['pkg']}:Main:Device"
            dt, res = json_api_post(cfg["json_api"], "/v1/query", {"templateIds":[tid], "query": {}}, jwt)
            items = res.get("result", [])
            if items:
                dev = items[0]
                device_cid = dev.get("contractId")
                ledger_pub = (dev.get("payload") or {}).get("publicKey","")
                h, how = normalize_x25519_pub(ledger_pub)
                if h:
                    print(f"[device key] from LEDGER ({how}) OK  cid={device_cid}")
                    return h, f"ledger:{how}", device_cid
                else:
                    print(f"[device key] ledger value unusable for X25519 ({how}), continuing…")
        except Exception as e:
            print(f"[device key] ledger query failed: {e}")

    # 3) Fallback to Flask node x25519 (good enough for /crypto/encrypt_to_device bench)
    try:
        hk = getj(f"{FLASK_URL}/health/keys")
        node_hex = hk.get("x25519_hex","")
        if _is_hex(node_hex, 64):
            print("[device key] fallback to Flask node /health/keys x25519_hex")
            return node_hex, "fallback:flask_node", None
    except Exception as e:
        print(f"[device key] fallback /health/keys failed: {e}")

    raise RuntimeError("Could not determine a usable X25519 device public key")

def bench_once(payload: bytes, attrs: int, scenario: str, cfg: Dict[str,Any], dev_pub_hex: str) -> Dict[str, Any]:
    row: Dict[str, Any] = {
        "scenario": scenario, "attrs": attrs, "msg_bytes": len(payload),
        "keygen_ms": 0.0, "sign_ms": 0.0, "verify_ms": 0.0,
        "enc_ms": 0.0, "dec_ms": 0.0,
        "http_encrypt_ms": 0.0, "http_log_ms": 0.0, "jsonapi_query_ms": 0.0,
        "total_ms": 0.0, "digest_hex": "", "sig_b64": "", "ct_b64": "",
        "ok": False,
    }

    # X25519 gen (timing)
    t0 = time.perf_counter()
    _ = x25519.X25519PrivateKey.generate()
    row["keygen_ms"] = (time.perf_counter() - t0) * 1000.0

    # Ed25519 sign + verify on payload (for visibility/timing)
    sk = ed25519.Ed25519PrivateKey.generate()
    t1 = time.perf_counter()
    sig = sk.sign(payload)
    row["sign_ms"] = (time.perf_counter() - t1) * 1000.0
    t2 = time.perf_counter()
    sk.public_key().verify(sig, payload)
    row["verify_ms"] = (time.perf_counter() - t2) * 1000.0
    row["sig_b64"] = base64.b64encode(sig).decode()[:24] + "…"

    # Local AES-GCM roundtrip
    e_ms, d_ms, ct_b64, sig_b64_local, ok_local = local_encrypt_decrypt_roundtrip(payload)
    row["enc_ms"] = e_ms; row["dec_ms"] = d_ms
    row["ct_b64"] = ct_b64[:32] + "…"

    # Server-side encrypt (Flask) — includes devicePublicKey normalization
    ctx = {"attrs": attrs, "scenario": scenario}
    aad = f"scope:{attrs}:{scenario}"
    http_encrypt_ms = 0.0
    digest_hex = ""
    try:
        t3 = time.perf_counter()
        enc_req = {
            "devicePublicKey": dev_pub_hex,
            "plaintext": base64.b64encode(payload).decode(),
            "plaintext_is_b64": True,
            "aad": aad,
            "ctx": ctx,
        }
        enc_res = postj(f"{FLASK_URL}/crypto/encrypt_to_device", enc_req)
        http_encrypt_ms = (time.perf_counter() - t3) * 1000.0
        digest_hex = enc_res.get("digest_hex","")
        row["http_encrypt_ms"] = http_encrypt_ms
        row["digest_hex"] = (digest_hex[:24] + "…") if digest_hex else ""
    except Exception as e:
        print(f"❌ /crypto/encrypt_to_device failed: {e}")

    # Log via Flask (creates a LogRequest on-ledger with Operator party from server env)
    http_log_ms = 0.0
    try:
        demo = {
            "op": "bench",
            "attrs": attrs,
            "scenario": scenario,
            "ts": int(time.time()),
            "digest": digest_hex,
            "sp": SP_PARTY,
            "edge": EDGE_PARTY,
        }
        t4 = time.perf_counter()
        lr = postj(f"{FLASK_URL}/log_batch_activity", {"logs":[demo]})
        http_log_ms = (time.perf_counter() - t4) * 1000.0
        row["http_log_ms"] = http_log_ms
    except Exception as e:
        print(f"⚠️  /log_batch_activity failed: {e}")

    # Optional JSON-API quick query (LogRequest count) if we have a JWT
    jsonapi_ms = 0.0
    if OP_JWT and cfg.get("pkg"):
        try:
            tid = f"{cfg['pkg']}:Main:LogRequest"
            t5, rj = json_api_post(cfg["json_api"], "/v1/query", {"templateIds":[tid], "query": {}}, OP_JWT)
            jsonapi_ms = t5
            n = len(rj.get("result", []))
            # print(f"🔎 JSON-API: {n} LogRequest visible.")
            row["jsonapi_query_ms"] = jsonapi_ms
        except Exception as e:
            print(f"⚠️  JSON-API verify failed: {e}")

    # Total “composed” time metric
    row["total_ms"] = (
        row["keygen_ms"] + row["sign_ms"] + row["verify_ms"]
        + row["enc_ms"] + row["dec_ms"]
        + row["http_encrypt_ms"] + row["http_log_ms"]
    )
    row["ok"] = ok_local
    return row

# -------- Runner -------------------------------------------------------------

CSV_HEADER = [
    "scenario","attrs","msg_bytes",
    "keygen_ms","sign_ms","verify_ms",
    "enc_ms","dec_ms",
    "http_encrypt_ms","http_log_ms","jsonapi_query_ms",
    "total_ms","digest_hex","sig_b64","ct_b64",
    "device_pub_source","device_cid","ok"
]

def main():
    args = parse_args()
    if args.device_pub_hex:
        os.environ["DEVICE_PUB_HEX"] = args.device_pub_hex

    cfg = discover_config()

    # Resolve a usable device X25519 public key
    dev_pub_hex, dev_source, device_cid = discover_device_key(cfg, args)

    # Prepare CSV
    new_file = not os.path.isfile(args.csv)
    with open(args.csv, "a", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        if new_file:
            w.writerow(CSV_HEADER)

        # Build attr set
        try:
            attr_list = [int(x.strip()) for x in args.attrs.split(",") if x.strip()]
        except Exception:
            print("Bad --attrs argument; fallback to 1,2,4,8,16,21")
            attr_list = [1,2,4,8,16,21]

        for attrs in attr_list:
            for scenario in ("cold","warm"):   # warm follows cold to show cache benefits server-side
                for rep in range(args.reps):
                    # payload per trial
                    payload = os.urandom(args.msg)

                    row = bench_once(payload, attrs, scenario, cfg, dev_pub_hex)

                    # print concise pass/enc/dec info
                    print(f"[{scenario}][attrs={attrs}][rep={rep+1}/{args.reps}] "
                          f"keygen={row['keygen_ms']:.2f}ms sign={row['sign_ms']:.2f}ms "
                          f"verify={row['verify_ms']:.2f}ms enc={row['enc_ms']:.2f}ms "
                          f"dec={row['dec_ms']:.2f}ms http_enc={row['http_encrypt_ms']:.2f}ms "
                          f"http_log={row['http_log_ms']:.2f}ms total={row['total_ms']:.2f}ms "
                          f"ok={'✅' if row['ok'] else '❌'} "
                          f"ct={row['ct_b64']} sig={row['sig_b64']} digest={row['digest_hex']}")

                    w.writerow([
                        row["scenario"], row["attrs"], row["msg_bytes"],
                        f"{row['keygen_ms']:.3f}", f"{row['sign_ms']:.3f}", f"{row['verify_ms']:.3f}",
                        f"{row['enc_ms']:.3f}", f"{row['dec_ms']:.3f}",
                        f"{row['http_encrypt_ms']:.3f}", f"{row['http_log_ms']:.3f}", f"{row['jsonapi_query_ms']:.3f}",
                        f"{row['total_ms']:.3f}", row["digest_hex"], row["sig_b64"], row["ct_b64"],
                        dev_source, device_cid or "", "true" if row["ok"] else "false"
                    ])
                    fh.flush()
        print(f"\n✅ Done. Results appended to {args.csv}")

if __name__ == "__main__":
    main()
