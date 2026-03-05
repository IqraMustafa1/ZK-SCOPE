#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SCOPE Extended Bench — paper-ready version
------------------------------------------
Adds reporting-critical metadata + fixes methodology weak points:

✅ Adds run_id + trial_uid (multi-run traceability)
✅ Adds deterministic payload option (--deterministic-payload + --seed) for fair comparisons
✅ Makes cold/warm definition explicit in-data (scenario_mode column)
✅ Records epoch, ratchet counter, attestation count, relay path used
✅ Adds NA (-1) for non-applicable endpoint statuses (classic vs hybrid fields)
✅ Adds environment metadata columns (python/os/platform)
✅ Adds failure flags and response timing fields if returned by relay
✅ Optional: attestation policy control (--attestation-policy = reuse|require|ignore)

NOTE: "local crypto timings" are microbench baselines; paper conclusions should focus on HTTP + E2E.
"""

import os
import csv
import json
import time
import base64
import argparse
import random
import hashlib
import platform
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Tuple, List, Optional

import requests
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    import oqs  # type: ignore
    HAS_OQS = True
except Exception:
    HAS_OQS = False


# -------------------------- CLI --------------------------
def parse_args():
    ap = argparse.ArgumentParser()

    ap.add_argument("--attrs", default="1,2,4,8,16,21")
    ap.add_argument("--reps", type=int, default=30)
    ap.add_argument("--warmup", type=int, default=5)
    ap.add_argument("--sleep-ms", type=int, default=0)

    ap.add_argument("--msg", type=int, default=2048)
    ap.add_argument("--csv", default="execution_results.csv")
    ap.add_argument("--fresh-csv", action="store_true")

    ap.add_argument("--mode", choices=["classic", "hybrid", "both"], default="both")
    ap.add_argument("--with-relay", action="store_true")
    ap.add_argument("--attestations-n", type=int, default=0)

    # Paper/reporting controls
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--deterministic-payload", action="store_true",
                    help="Use deterministic payload per (approach,scenario,attrs,rep,warmup) for controlled experiments.")
    ap.add_argument("--run-id", default="",
                    help="Optional explicit run_id. If blank, generated once at start (UTC).")
    ap.add_argument("--attestation-policy", choices=["reuse", "require", "ignore"], default="reuse",
                    help="reuse: use existing if available; require: error if none; ignore: send empty attestations always.")

    ap.add_argument("--flask-url", default=os.environ.get("FLASK_URL", "http://127.0.0.1:5000"))
    ap.add_argument("--json-api-url", default=os.environ.get("JSON_API_URL", ""))

    ap.add_argument("--operator-jwt-file", default=os.environ.get("OPERATOR_TOKEN_PATH", "./operator.jwt"))
    ap.add_argument("--operator-jwt", default=os.environ.get("OPERATOR_JWT", ""))

    ap.add_argument("--edge-jwt-file", default=os.environ.get("EDGE_TOKEN_PATH", "./edge.jwt"))
    ap.add_argument("--edge-jwt", default=os.environ.get("EDGE_JWT", ""))

    ap.add_argument("--edge-party", default=os.environ.get("EDGE_PARTY", "EdgeNode1"))
    ap.add_argument("--sp-party", default=os.environ.get("SP_PARTY", "ServiceProvider1"))
    ap.add_argument("--operator-party", default=os.environ.get("OP_PARTY", "Operator"))

    ap.add_argument("--sender-public-key", default=os.environ.get("SENDER_PUBLIC_KEY", "OperatorPublicKey"))
    ap.add_argument("--device-name", default=os.environ.get("DEVICE_NAME", ""))

    # endpoints
    ap.add_argument("--ep-classic-encrypt", default="/crypto/encrypt_to_device")
    ap.add_argument("--ep-hybrid-prepare", default="/crypto/prepare_hybrid")
    ap.add_argument("--ep-relay", default="/relay_message")  # fallback "/relay/message"
    ap.add_argument("--ep-log", default="/log_batch_activity")

    # toggles
    ap.add_argument("--no-jsonapi", action="store_true")
    ap.add_argument("--no-log", action="store_true")

    return ap.parse_args()


# -------------------------- helpers --------------------------
def iso_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _read_text_file(path: str) -> str:
    try:
        if path and os.path.isfile(path):
            return open(path, "r", encoding="utf-8").read().strip()
    except Exception:
        return ""
    return ""


def load_operator_jwt(args) -> str:
    return (args.operator_jwt.strip() or _read_text_file(args.operator_jwt_file)).strip()


def load_edge_jwt(args) -> str:
    return (args.edge_jwt.strip() or _read_text_file(args.edge_jwt_file)).strip()


def _json_bytes(obj: Any) -> int:
    try:
        return len(json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    except Exception:
        return 0


def postj_metrics(session: requests.Session, url: str, body: Dict[str, Any], timeout=60) -> Tuple[float, int, int, int, Dict[str, Any]]:
    up_bytes = _json_bytes(body)
    t0 = time.perf_counter()
    r = session.post(url, json=body, timeout=timeout)
    dt_ms = (time.perf_counter() - t0) * 1000.0
    down_bytes = len(r.content or b"")
    sc = r.status_code
    try:
        js = r.json()
    except Exception:
        js = {"raw": (r.text or "")[:2000]}
    return dt_ms, sc, up_bytes, down_bytes, js


def getj(session: requests.Session, url: str, timeout=20) -> Dict[str, Any]:
    r = session.get(url, timeout=timeout)
    r.raise_for_status()
    return r.json()


def json_api_headers(jwt: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {jwt}", "Content-Type": "application/json"}


def _jsonapi_post(session: requests.Session, api: str, path: str, body: Dict[str, Any], jwt: str, timeout=45):
    url = f"{api}{path}"
    up_bytes = _json_bytes(body)
    t0 = time.perf_counter()
    r = session.post(url, headers=json_api_headers(jwt), json=body, timeout=timeout)
    dt_ms = (time.perf_counter() - t0) * 1000.0
    down_bytes = len(r.content or b"")
    sc = r.status_code
    try:
        js = r.json()
    except Exception:
        js = {"raw": (r.text or "")[:2000]}
    return dt_ms, sc, up_bytes, down_bytes, js


def _jsonapi_get(session: requests.Session, api: str, path: str, jwt: str, timeout=30):
    url = f"{api}{path}"
    up_bytes = 0
    t0 = time.perf_counter()
    r = session.get(url, headers=json_api_headers(jwt), timeout=timeout)
    dt_ms = (time.perf_counter() - t0) * 1000.0
    down_bytes = len(r.content or b"")
    sc = r.status_code
    try:
        js = r.json()
    except Exception:
        js = {"raw": (r.text or "")[:2000]}
    return dt_ms, sc, up_bytes, down_bytes, js


def daml_variant(tag: str) -> Dict[str, Any]:
    return {"tag": tag, "value": {}}


def relay_with_backoff(call_fn, max_tries=6, base_sleep=0.25):
    last = (0.0, 0, 0, 0, {"error": "no_attempt"})
    for i in range(max_tries):
        dt, sc, upb, downb, js = call_fn()
        last = (dt, sc, upb, downb, js)
        if sc == 429 or (isinstance(js, dict) and str(js.get("error", "")).lower() == "rate_limited"):
            time.sleep(base_sleep * (2 ** i) + random.random() * 0.05)
            continue
        return last
    return last


def _prefix(s: Any, n: int = 24) -> str:
    if not s:
        return ""
    t = str(s)
    return t[:n] + ("…" if len(t) > n else "")


def _safe_num(x: Any) -> float:
    try:
        return float(x)
    except Exception:
        return 0.0


def get_field(d: Dict[str, Any], names: List[str], default: str = "") -> str:
    for n in names:
        if n in d and d[n] not in (None, ""):
            return str(d[n])
    return default


def post_try_paths(session: requests.Session, flask_url: str, paths: List[str], body: Dict[str, Any], timeout=180):
    last = (0.0, 0, 0, 0, {"error": "no_attempt"}, "")
    for p in paths:
        dt, sc, up, down, js = postj_metrics(session, f"{flask_url}{p}", body, timeout=timeout)
        last = (dt, sc, up, down, js, p)
        if sc < 400:
            return last
    return last


# -------------------------- deterministic payload --------------------------
def make_payload(msg_len: int, seed: int, run_id: str, approach: str, scenario: str, attrs: int, rep: int, warmup: int) -> bytes:
    """
    Deterministic payload bytes for controlled comparisons.
    Expands SHA-256 stream over labeled inputs.
    """
    label = f"{seed}|{run_id}|{approach}|{scenario}|{attrs}|{rep}|{warmup}".encode("utf-8")
    out = bytearray()
    ctr = 0
    while len(out) < msg_len:
        h = hashlib.sha256(label + b"|" + str(ctr).encode("utf-8")).digest()
        out.extend(h)
        ctr += 1
    return bytes(out[:msg_len])


# -------------------------- JSON-API helpers (PS1 parity) --------------------------
def query_active(session: requests.Session, json_api: str, jwt: str, template_id: str) -> List[Dict[str, Any]]:
    body = {"templateIds": [template_id], "query": {}}
    _dt, sc, _upb, _downb, res = _jsonapi_post(session, json_api, "/v1/query", body, jwt, timeout=45)
    if sc >= 400:
        raise RuntimeError(f"/v1/query failed tid={template_id} status={sc} res={json.dumps(res)[:500]}")
    items = res.get("result", []) if isinstance(res, dict) else []
    return items if isinstance(items, list) else [items]


def resolve_party_id(session: requests.Session, json_api: str, jwt: str, display_name: str) -> str:
    _dt, sc, _upb, _downb, res = _jsonapi_get(session, json_api, "/v1/parties", jwt, timeout=30)
    if sc >= 400:
        raise RuntimeError(f"/v1/parties failed status={sc} res={json.dumps(res)[:600]}")
    rows = res.get("result", res) if isinstance(res, dict) else res
    if not isinstance(rows, list):
        rows = [rows]
    want = display_name.strip()
    for p in rows:
        if isinstance(p, dict) and str(p.get("displayName", "")).strip() == want:
            pid = str(p.get("identifier", "")).strip()
            if pid:
                return pid
    available = sorted({str(p.get("displayName", "")).strip() for p in rows if isinstance(p, dict) and p.get("displayName")})
    raise RuntimeError(f"Party displayName '{display_name}' not found. Available: {available[:30]}")


def latest_epoch_and_merkle(session: requests.Session, json_api: str, jwt: str, pkg: str) -> Tuple[int, str]:
    tid = f"{pkg}:Main:TaSnapshot"
    rows = query_active(session, json_api, jwt, tid)
    if not rows:
        return 0, "genesis"
    rows = [r for r in rows if isinstance(r, dict) and isinstance(r.get("payload"), dict)]
    if not rows:
        return 0, "genesis"
    rows.sort(key=lambda r: int((r["payload"].get("epoch") or 0)), reverse=True)
    p = rows[0]["payload"]
    epoch = int(p.get("epoch") or 0)
    mr = str(p.get("merkleRoot") or "genesis")
    return epoch, mr


def next_ratchet_counter(
    session: requests.Session,
    json_api: str,
    jwt: str,
    pkg: str,
    edge_id: str,
    device_key_hex: str,
    sender_id: str,
    epoch: int
) -> int:
    tid = f"{pkg}:Main:RatchetState"
    rows = query_active(session, json_api, jwt, tid)
    best = 0
    for r in rows:
        p = (r.get("payload") or {}) if isinstance(r, dict) else {}
        if (p.get("edge") == edge_id and
            p.get("deviceKey") == device_key_hex and
            p.get("senderId") == sender_id and
            int(p.get("epoch") or 0) == int(epoch)):
            best = max(best, int(p.get("lastCtr") or 0))
    return best + 1


def find_attestations_for_digest(
    session: requests.Session,
    json_api: str,
    jwt: str,
    pkg: str,
    digest_hex: str,
    device_owner: str,
    device_pub_hex: str,
    operator_id: str,
    alg_id_tag: str,
    limit: int = 2
) -> List[str]:
    tid = f"{pkg}:Main:SigAttestation"
    rows = query_active(session, json_api, jwt, tid)
    hits: List[str] = []
    for r in rows:
        p = (r.get("payload") or {}) if isinstance(r, dict) else {}
        if (p.get("digest") == digest_hex and
            p.get("deviceOwner") == device_owner and
            p.get("devicePublicKey") == device_pub_hex and
            p.get("operator") == operator_id and
            p.get("algId") == alg_id_tag):
            cid = r.get("contractId")
            if cid:
                hits.append(str(cid))
    return hits[:max(1, int(limit))]


def sp_sign_digest(session: requests.Session, flask_url: str, digest_hex: str) -> Tuple[str, str, float, int, int, int]:
    body = {"digest_hex": digest_hex}
    dt, sc, up, down, js = postj_metrics(session, f"{flask_url}/sp/ed25519/sign_digest", body, timeout=60)
    if sc >= 400:
        raise RuntimeError(f"SP sign_digest failed status={sc} res={json.dumps(js)[:400]}")
    pub_hex = str(js.get("sp_ed25519_pub_hex", "")).strip()
    sig_b64 = str(js.get("sp_signature_b64", "")).strip()
    if not pub_hex or not sig_b64:
        raise RuntimeError("SP sign_digest missing sp_ed25519_pub_hex / sp_signature_b64")
    return pub_hex, sig_b64, dt, sc, up, down


# -------------------------- discovery --------------------------
def discover_config(session: requests.Session, flask_url: str) -> Dict[str, Any]:
    try:
        return getj(session, f"{flask_url}/debug/config")
    except Exception:
        return {}


def query_devices(session: requests.Session, json_api: str, pkg: str, jwt: str) -> List[Dict[str, Any]]:
    tid_full = f"{pkg}:Main:Device"
    body = {"templateIds": [tid_full], "query": {}}
    _dt, sc, _upb, _downb, res = _jsonapi_post(session, json_api, "/v1/query", body, jwt, timeout=45)
    if sc >= 400:
        raise RuntimeError(f"JSON-API /v1/query Device failed status={sc} res={json.dumps(res)[:800]}")
    items = (res.get("result", []) if isinstance(res, dict) else []) or []
    out = []
    for it in items:
        if isinstance(it, dict) and it.get("contractId") and isinstance(it.get("payload"), dict):
            out.append(it)
    return out


def choose_device_for_run(devices: List[Dict[str, Any]], device_name: str) -> Dict[str, Any]:
    if not devices:
        return {}
    if device_name:
        hits = [d for d in devices if str((d.get("payload") or {}).get("name", "")).strip() == device_name.strip()]
        if hits:
            return hits[0]
        return {}
    return devices[0]


def discover_device_info(
    session: requests.Session,
    json_api: str,
    pkg: str,
    operator_jwt: str,
    device_name: str,
) -> Dict[str, Any]:
    devs = query_devices(session, json_api, pkg, operator_jwt)
    chosen = choose_device_for_run(devs, device_name=device_name)
    if not chosen:
        raise RuntimeError("No matching Device visible to operator token.")
    p = chosen.get("payload") or {}
    pq_b64 = (p.get("pqPubKey") or p.get("pqPubKeyB64") or p.get("pq_pub_b64") or "").strip()
    return {
        "device_cid": str(chosen.get("contractId", "")),
        "device_name": str(p.get("name") or "").strip(),
        "device_edge": str(p.get("edge") or "").strip(),
        "device_owner": str(p.get("owner") or "").strip(),
        "device_pub_hex": str(p.get("publicKey") or "").strip(),
        "device_pq_b64": pq_b64,
        "device_alg": p.get("algId") or "",
    }


# -------------------------- local crypto timings --------------------------
def local_x25519_keygen_ms() -> float:
    t0 = time.perf_counter()
    _ = x25519.X25519PrivateKey.generate()
    return (time.perf_counter() - t0) * 1000.0


def local_ed25519_sign_verify_ms(payload: bytes) -> Tuple[float, float, str]:
    sk = ed25519.Ed25519PrivateKey.generate()
    t1 = time.perf_counter()
    sig = sk.sign(payload)
    sign_ms = (time.perf_counter() - t1) * 1000.0
    t2 = time.perf_counter()
    sk.public_key().verify(sig, payload)
    verify_ms = (time.perf_counter() - t2) * 1000.0
    sig_b64 = base64.b64encode(sig).decode()
    return sign_ms, verify_ms, sig_b64


def local_aesgcm_enc_dec_ms(payload: bytes) -> Tuple[float, float, str, bool]:
    key = os.urandom(32)
    nonce = os.urandom(12)
    aes = AESGCM(key)
    t0 = time.perf_counter()
    ct = aes.encrypt(nonce, payload, None)
    enc_ms = (time.perf_counter() - t0) * 1000.0
    t1 = time.perf_counter()
    ok = True
    try:
        pt = AESGCM(key).decrypt(nonce, ct, None)
        ok = (pt == payload)
    except Exception:
        ok = False
    dec_ms = (time.perf_counter() - t1) * 1000.0
    ct_b64 = base64.b64encode(ct).decode()
    return enc_ms, dec_ms, ct_b64, ok


def local_oqs_mlkem768_timings_ms() -> Tuple[float, float, float]:
    if not HAS_OQS:
        return 0.0, 0.0, 0.0
    try:
        kem = oqs.KeyEncapsulation("ML-KEM-768")
        t0 = time.perf_counter()
        pk = kem.generate_keypair()
        kem_keygen_ms = (time.perf_counter() - t0) * 1000.0

        t1 = time.perf_counter()
        ct, ss1 = kem.encap_secret(pk)
        kem_encap_ms = (time.perf_counter() - t1) * 1000.0

        t2 = time.perf_counter()
        ss2 = kem.decap_secret(ct)
        kem_decap_ms = (time.perf_counter() - t2) * 1000.0

        _ = (ss1 == ss2)
        kem.free()
        return kem_keygen_ms, kem_encap_ms, kem_decap_ms
    except Exception:
        return 0.0, 0.0, 0.0


# -------------------------- optional JSON-API verify --------------------------
def jsonapi_query_ms(session: requests.Session, json_api: str, pkg: str, jwt: str, template: str) -> Tuple[float, int]:
    try:
        tid = f"{pkg}:{template}"
        body = {"templateIds": [tid], "query": {}}
        dt, sc, _up, _down, res = _jsonapi_post(session, json_api, "/v1/query", body, jwt, timeout=30)
        if sc >= 400:
            return 0.0, 0
        items = (res.get("result", []) if isinstance(res, dict) else []) or []
        return dt, len(items)
    except Exception:
        return 0.0, 0


# -------------------------- remote bench calls --------------------------
def call_classic_encrypt(session: requests.Session, flask_url: str, ep: str, device_pub_hex: str, payload: bytes, aad: str, ctx: Dict[str, Any]):
    body = {
        "devicePublicKey": device_pub_hex,
        "plaintext": base64.b64encode(payload).decode(),
        "plaintext_is_b64": True,
        "aad": aad,
        "ctx": ctx,
    }
    return postj_metrics(session, f"{flask_url}{ep}", body, timeout=120)


def call_hybrid_prepare(
    session: requests.Session,
    flask_url: str,
    ep: str,
    device_pub_hex: str,
    device_pq_b64: str,
    payload: bytes,
    attrs: int,
    scenario: str,
    epoch: int
):
    body: Dict[str, Any] = {
        "kem": "ML-KEM-768",
        "sig_alg": "ed25519",
        "device_public_key_hex": device_pub_hex,
        "plaintext": base64.b64encode(payload).decode(),
        "plaintext_is_b64": True,
        "aad": f"scope:{attrs}:{scenario}",
        "ctx": {"attrs": attrs, "scenario": scenario},
        "epoch": int(epoch),
    }
    if device_pq_b64:
        body["device_pq_pub_b64"] = device_pq_b64
    return postj_metrics(session, f"{flask_url}{ep}", body, timeout=180)


def call_log(session: requests.Session, flask_url: str, ep: str, attrs: int, scenario: str, digest_hex: str, sp: str, edge: str):
    demo = {"op": "bench", "attrs": attrs, "scenario": scenario, "ts": int(time.time()),
            "digest": digest_hex, "sp": sp, "edge": edge}
    return postj_metrics(session, f"{flask_url}{ep}", {"logs": [demo]}, timeout=120)


# -------------------------- CSV --------------------------
CSV_HEADER = [
    # run identity
    "run_id", "trial_uid", "ts_utc",
    "approach", "scenario", "scenario_mode", "attrs", "rep", "warmup",
    "msg_bytes", "seed", "deterministic_payload",

    # environment
    "python_version", "platform", "machine", "processor",

    # derived protocol context
    "epoch", "merkle_root_prefix", "ratchet_counter", "attestation_n", "relay_path",

    # local timings (microbench baselines)
    "x25519_keygen_ms",
    "ed25519_sign_ms", "ed25519_verify_ms",
    "aesgcm_enc_ms", "aesgcm_dec_ms",
    "oqs_kem_keygen_ms", "oqs_kem_encap_ms", "oqs_kem_decap_ms",

    # remote timings
    "http_encrypt_ms", "http_encrypt_status", "http_encrypt_up_bytes", "http_encrypt_down_bytes",
    "http_prepare_ms", "http_prepare_status", "http_prepare_up_bytes", "http_prepare_down_bytes",
    "http_sp_sign_ms", "http_sp_sign_status", "http_sp_sign_up_bytes", "http_sp_sign_down_bytes",
    "http_relay_ms", "http_relay_status", "http_relay_up_bytes", "http_relay_down_bytes",
    "http_log_ms", "http_log_status", "http_log_up_bytes", "http_log_down_bytes",

    # relay-returned (if provided by server)
    "relay_policy_ms", "relay_verify_ms", "relay_total_ms",

    # optional jsonapi
    "jsonapi_device_ms", "jsonapi_device_n",
    "jsonapi_logreq_ms", "jsonapi_logreq_n",

    # totals
    "total_local_ms", "total_remote_ms", "total_end2end_ms",

    # debug
    "digest_hex_prefix", "sig_b64_prefix", "ct_b64_prefix",
    "note", "error_prefix",

    # config snapshot
    "flask_url", "json_api", "pkg",
    "device_name", "device_edge", "device_cid"
]


def write_row(path: str, row: Dict[str, Any], fresh: bool):
    exists = os.path.isfile(path)
    mode = "w" if (fresh or not exists) else "a"
    with open(path, mode, newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_HEADER)
        if mode == "w":
            w.writeheader()
        w.writerow(row)


# -------------------------- main bench --------------------------
def run_trial(
    session_http: requests.Session,
    session_jsonapi: requests.Session,
    args,
    cfg: Dict[str, Any],
    device_info: Dict[str, Any],
    operator_jwt: str,
    edge_jwt: str,
    party_ids: Dict[str, str],
    run_id: str,
    approach: str,
    scenario: str,
    attrs: int,
    rep: int,
    warmup: int,
) -> Dict[str, Any]:

    # Explicit scenario meaning for papers:
    # scenario_mode = "batch_first" for "cold", "batch_followup" for "warm"
    scenario_mode = "batch_first" if scenario == "cold" else "batch_followup"

    if args.deterministic_payload:
        payload = make_payload(int(args.msg), args.seed, run_id, approach, scenario, attrs, rep, warmup)
    else:
        payload = os.urandom(int(args.msg))

    aad = f"scope:{attrs}:{scenario}"
    ctx = {"attrs": attrs, "scenario": scenario}

    trial_uid = f"{run_id}|{approach}|{scenario}|{attrs}|{rep}|w{warmup}"

    # environment snapshot
    pyver = sys.version.split()[0]
    plat = platform.platform()
    mach = platform.machine()
    proc = platform.processor() or ""

    # local microbench timings
    x25519_ms = local_x25519_keygen_ms()
    sign_ms, verify_ms, sig_b64 = local_ed25519_sign_verify_ms(payload)
    enc_ms, dec_ms, ct_b64, ok_local = local_aesgcm_enc_dec_ms(payload)

    kem_k_ms = kem_e_ms = kem_d_ms = 0.0
    if approach.startswith("hybrid"):
        kem_k_ms, kem_e_ms, kem_d_ms = local_oqs_mlkem768_timings_ms()

    # remote placeholders (NA = -1 for statuses not used by approach)
    http_encrypt_ms = http_prepare_ms = http_sp_sign_ms = http_relay_ms = http_log_ms = 0.0
    http_encrypt_sc = http_prepare_sc = http_sp_sign_sc = http_relay_sc = http_log_sc = -1
    http_encrypt_up = http_prepare_up = http_sp_sign_up = http_relay_up = http_log_up = 0
    http_encrypt_down = http_prepare_down = http_sp_sign_down = http_relay_down = http_log_down = 0

    relay_policy_ms = relay_verify_ms = relay_total_ms = 0.0

    digest_hex = ""
    note = ""
    errp = ""

    # derived protocol context
    epoch = 0
    merkle_root = "genesis"
    ratchet_ctr = 0
    att_n_used = 0
    relay_path_used = ""

    sender_id = "Sender1"

    try:
        epoch, merkle_root = latest_epoch_and_merkle(session_jsonapi, cfg["json_api"], operator_jwt, cfg["pkg"])

        if approach == "classic":
            http_encrypt_ms, http_encrypt_sc, http_encrypt_up, http_encrypt_down, j1 = call_classic_encrypt(
                session_http,
                args.flask_url.rstrip("/"),
                args.ep_classic_encrypt,
                device_info.get("device_pub_hex", ""),
                payload,
                aad,
                ctx,
            )
            digest_hex = (j1.get("digest_hex") if isinstance(j1, dict) else "") or ""
            if http_encrypt_sc >= 400:
                errp = _prefix(j1.get("raw") if isinstance(j1, dict) else j1, 220)

        else:
            http_prepare_ms, http_prepare_sc, http_prepare_up, http_prepare_down, j2 = call_hybrid_prepare(
                session_http,
                args.flask_url.rstrip("/"),
                args.ep_hybrid_prepare,
                device_info.get("device_pub_hex", ""),
                device_info.get("device_pq_b64", ""),
                payload,
                attrs,
                scenario,
                epoch=epoch,
            )

            if http_prepare_sc >= 400:
                errp = _prefix(j2.get("raw") if isinstance(j2, dict) else j2, 220)

            if isinstance(j2, dict):
                digest_hex = str(j2.get("digest_hex") or j2.get("digest") or "").strip()

            if approach == "hybrid+relay":
                if not edge_jwt:
                    note = "edge_jwt_missing"
                else:
                    if not isinstance(j2, dict):
                        j2 = {}

                    enc_b64 = get_field(j2, ["encryptedMessage_b64", "encrypted_message_b64", "ciphertext_b64", "ciphertext_b64u"])
                    eph_x = get_field(j2, ["ephemeral_x25519_hex", "eph_x25519_hex", "ephX25519Hex"])
                    ky_ct = get_field(j2, ["kyberCiphertextB64", "kyber_ciphertext_b64", "kyber_ciphertext_b64u", "kyberCiphertext_b64"])
                    pq_sig = get_field(j2, ["pqSignatureB64", "pq_signature_b64", "pq_signature_b64u", "pqSignature_b64"])
                    pq_pub = get_field(j2, ["pqPubKey", "pq_pub_key_b64", "pq_pub_b64", "device_pq_pub_b64", "device_pq_pub_b64u"])

                    ratchet_ctr = next_ratchet_counter(
                        session_jsonapi,
                        cfg["json_api"],
                        operator_jwt,
                        cfg["pkg"],
                        edge_id=party_ids["edge_id"],
                        device_key_hex=device_info["device_pub_hex"],
                        sender_id=sender_id,
                        epoch=epoch,
                    )

                    sp_pub_hex, sp_sig_b64, http_sp_sign_ms, http_sp_sign_sc, http_sp_sign_up, http_sp_sign_down = sp_sign_digest(
                        session_http, args.flask_url.rstrip("/"), digest_hex
                    )

                    alg_tag = "ALG_HYBRID_X25519_KYBER_AESGCM_HYBRID_SIG"
                    att_n = int(args.attestations_n) if int(args.attestations_n or 0) > 0 else 2

                    att_cids: List[str] = []
                    if args.attestation_policy == "ignore":
                        att_cids = []
                    else:
                        att_cids = find_attestations_for_digest(
                            session_jsonapi, cfg["json_api"], operator_jwt, cfg["pkg"],
                            digest_hex=digest_hex,
                            device_owner=device_info["device_owner"],
                            device_pub_hex=device_info["device_pub_hex"],
                            operator_id=party_ids["op_id"],
                            alg_id_tag=alg_tag,
                            limit=att_n,
                        )

                        if not att_cids and args.attestation_policy == "require":
                            raise RuntimeError("attestation_policy=require but no attestations found for digest (controlled experiment violated).")
                        if not att_cids:
                            note = (note + " no_attestations_for_digest").strip()

                    att_n_used = len(att_cids)

                    relay_body = {
                        "edge_token": edge_jwt,

                        "edge": party_ids["edge_id"],
                        "sp": party_ids["sp_id"],
                        "operator": party_ids["op_id"],

                        "senderId": sender_id,
                        "counter": int(ratchet_ctr),

                        "targetDevice": device_info.get("device_cid", ""),
                        "epoch": int(epoch),
                        "merkleRoot": merkle_root,
                        "msgTimestamp": iso_utc_now(),

                        "encryptedMessage_b64": enc_b64,
                        "digest_hex": digest_hex,
                        "digest": digest_hex,
                        "devicePublicKey": device_info.get("device_pub_hex", ""),
                        "ephemeral_x25519_hex": eph_x,
                        "aad": aad,
                        "kyberCiphertextB64": ky_ct,
                        "pqSignatureB64": pq_sig,
                        "pqPubKey": pq_pub,

                        "algId": daml_variant(alg_tag),
                        "algId_tag": alg_tag,

                        "attestation_cids": att_cids,
                        "attestations": att_cids,

                        "sp_ed25519_pub_hex": sp_pub_hex,
                        "sp_signature_b64": sp_sig_b64,

                        "use_zkpac": False,
                        "attrs": attrs,
                    }

                    paths = [args.ep_relay, "/relay/message"]

                    def _do():
                        (dt, sc, up, down, js, used_path) = post_try_paths(
                            session_http, args.flask_url.rstrip("/"), paths, relay_body, timeout=180
                        )
                        if isinstance(js, dict) and sc < 400:
                            js["_used_path"] = used_path
                        return dt, sc, up, down, js

                    http_relay_ms, http_relay_sc, http_relay_up, http_relay_down, j3 = relay_with_backoff(_do)

                    if isinstance(j3, dict):
                        relay_path_used = str(j3.get("_used_path") or "")
                        relay_policy_ms = _safe_num(j3.get("policy_ms") or j3.get("policyVerifyMs") or j3.get("policy_verification_ms") or 0)
                        relay_verify_ms = _safe_num(j3.get("verify_ms") or 0)
                        relay_total_ms = _safe_num(j3.get("relay_total_ms") or j3.get("e2e_ms") or j3.get("total_ms") or 0)

                    if http_relay_sc >= 400:
                        errp = (errp + " | " if errp else "") + _prefix(j3.get("raw") if isinstance(j3, dict) else j3, 220)

        # log step
        if not args.no_log:
            http_log_ms, http_log_sc, http_log_up, http_log_down, jl = call_log(
                session_http,
                args.flask_url.rstrip("/"),
                args.ep_log,
                attrs,
                scenario,
                digest_hex,
                party_ids.get("sp_id", args.sp_party),
                party_ids.get("edge_id", args.edge_party),
            )
            if http_log_sc >= 400 and isinstance(jl, dict):
                errp = (errp + " | " if errp else "") + _prefix(jl.get("raw"), 220)

    except Exception as e:
        errp = _prefix(str(e), 220)

    # optional jsonapi
    jdev_ms = jlog_ms = 0.0
    jdev_n = jlog_n = 0
    if (not args.no_jsonapi) and operator_jwt and cfg.get("pkg"):
        jdev_ms, jdev_n = jsonapi_query_ms(session_jsonapi, cfg["json_api"], cfg["pkg"], operator_jwt, "Main:Device")
        jlog_ms, jlog_n = jsonapi_query_ms(session_jsonapi, cfg["json_api"], cfg["pkg"], operator_jwt, "Main:LogRequest")

    total_local = x25519_ms + sign_ms + verify_ms + enc_ms + dec_ms + kem_k_ms + kem_e_ms + kem_d_ms
    total_remote = http_encrypt_ms + http_prepare_ms + http_sp_sign_ms + http_relay_ms + http_log_ms
    total_e2e = total_local + total_remote

    row = {
        "run_id": run_id,
        "trial_uid": trial_uid,
        "ts_utc": iso_utc_now(),

        "approach": approach,
        "scenario": scenario,
        "scenario_mode": scenario_mode,
        "attrs": attrs,
        "rep": rep,
        "warmup": warmup,
        "msg_bytes": len(payload),
        "seed": args.seed,
        "deterministic_payload": 1 if args.deterministic_payload else 0,

        "python_version": pyver,
        "platform": plat,
        "machine": mach,
        "processor": proc,

        "epoch": int(epoch),
        "merkle_root_prefix": _prefix(merkle_root, 24),
        "ratchet_counter": int(ratchet_ctr),
        "attestation_n": int(att_n_used),
        "relay_path": relay_path_used,

        "x25519_keygen_ms": round(x25519_ms, 3),
        "ed25519_sign_ms": round(sign_ms, 3),
        "ed25519_verify_ms": round(verify_ms, 3),
        "aesgcm_enc_ms": round(enc_ms, 3),
        "aesgcm_dec_ms": round(dec_ms, 3),
        "oqs_kem_keygen_ms": round(kem_k_ms, 3),
        "oqs_kem_encap_ms": round(kem_e_ms, 3),
        "oqs_kem_decap_ms": round(kem_d_ms, 3),

        "http_encrypt_ms": round(http_encrypt_ms, 3),
        "http_encrypt_status": http_encrypt_sc,
        "http_encrypt_up_bytes": http_encrypt_up,
        "http_encrypt_down_bytes": http_encrypt_down,

        "http_prepare_ms": round(http_prepare_ms, 3),
        "http_prepare_status": http_prepare_sc,
        "http_prepare_up_bytes": http_prepare_up,
        "http_prepare_down_bytes": http_prepare_down,

        "http_sp_sign_ms": round(http_sp_sign_ms, 3),
        "http_sp_sign_status": http_sp_sign_sc,
        "http_sp_sign_up_bytes": http_sp_sign_up,
        "http_sp_sign_down_bytes": http_sp_sign_down,

        "http_relay_ms": round(http_relay_ms, 3),
        "http_relay_status": http_relay_sc,
        "http_relay_up_bytes": http_relay_up,
        "http_relay_down_bytes": http_relay_down,

        "http_log_ms": round(http_log_ms, 3),
        "http_log_status": http_log_sc,
        "http_log_up_bytes": http_log_up,
        "http_log_down_bytes": http_log_down,

        "relay_policy_ms": round(relay_policy_ms, 3),
        "relay_verify_ms": round(relay_verify_ms, 3),
        "relay_total_ms": round(relay_total_ms, 3),

        "jsonapi_device_ms": round(jdev_ms, 3),
        "jsonapi_device_n": jdev_n,
        "jsonapi_logreq_ms": round(jlog_ms, 3),
        "jsonapi_logreq_n": jlog_n,

        "total_local_ms": round(total_local, 3),
        "total_remote_ms": round(total_remote, 3),
        "total_end2end_ms": round(total_e2e, 3),

        "digest_hex_prefix": _prefix(digest_hex, 24),
        "sig_b64_prefix": _prefix(sig_b64, 24),
        "ct_b64_prefix": _prefix(ct_b64, 32),

        "note": (note or ("ok_local" if ok_local else "local_dec_fail")),
        "error_prefix": errp,

        "flask_url": args.flask_url.rstrip("/"),
        "json_api": cfg.get("json_api", ""),
        "pkg": cfg.get("pkg", ""),

        "device_name": device_info.get("device_name", ""),
        "device_edge": device_info.get("device_edge", ""),
        "device_cid": device_info.get("device_cid", ""),
    }
    return row


def main():
    args = parse_args()

    flask_url = args.flask_url.rstrip("/")
    operator_jwt = load_operator_jwt(args)
    if not operator_jwt:
        raise SystemExit("Operator JWT missing. Set OPERATOR_TOKEN_PATH or pass --operator-jwt-file/--operator-jwt.")

    edge_jwt = load_edge_jwt(args) if args.with_relay else ""
    if args.with_relay and not edge_jwt:
        raise SystemExit("Relay enabled but Edge JWT missing. Set EDGE_TOKEN_PATH or pass --edge-jwt-file/--edge-jwt.")

    # run_id generated once per run (important for paper traceability)
    run_id = (args.run_id.strip() or iso_utc_now().replace(":", "").replace("-", "").replace("Z", "Z"))

    # attrs list
    try:
        attrs_list = [int(x.strip()) for x in args.attrs.split(",") if x.strip()]
    except Exception:
        attrs_list = [1, 2, 4, 8, 16, 21]

    # approaches
    approaches: List[str] = []
    if args.mode in ("classic", "both"):
        approaches.append("classic")
    if args.mode in ("hybrid", "both"):
        approaches.append("hybrid+relay" if args.with_relay else "hybrid")

    # sessions
    s_boot = requests.Session()
    cfg0 = discover_config(s_boot, flask_url)
    json_api = (args.json_api_url.strip() or cfg0.get("json_api") or "http://localhost:7576").rstrip("/")
    pkg = (cfg0.get("daml_pkg_id") or "").strip()
    if not pkg:
        raise SystemExit("Could not discover daml_pkg_id from /debug/config. Check Flask is running and exposes /debug/config.")
    cfg = {"json_api": json_api, "pkg": pkg}

    device_info = discover_device_info(s_boot, json_api, pkg, operator_jwt, args.device_name.strip())

    edge_id = resolve_party_id(s_boot, json_api, operator_jwt, args.edge_party)
    sp_id = resolve_party_id(s_boot, json_api, operator_jwt, args.sp_party)
    op_id = resolve_party_id(s_boot, json_api, operator_jwt, args.operator_party)
    party_ids = {"edge_id": edge_id, "sp_id": sp_id, "op_id": op_id}

    s_boot.close()

    print("=== CONFIG ===")
    print(f"RUN_ID={run_id}")
    print(f"FLASK_URL={flask_url}")
    print(f"JSON_API={json_api}")
    print(f"PKG={pkg}")
    print(f"DeviceCID={device_info.get('device_cid','')}")
    print(f"DeviceName={device_info.get('device_name','')}")
    print(f"DeviceEdge={device_info.get('device_edge','')}")
    print(f"Party(edge)={edge_id}  Party(sp)={sp_id}  Party(op)={op_id}")
    print(f"Relay={'ON' if args.with_relay else 'OFF'}  attestations_per_msg={(args.attestations_n if args.attestations_n>0 else 2) if args.with_relay else 0}")
    print(f"DeterministicPayload={'ON' if args.deterministic_payload else 'OFF'} seed={args.seed}")
    print(f"AttestationPolicy={args.attestation_policy}")
    print("==============")

    if args.fresh_csv and os.path.isfile(args.csv):
        os.remove(args.csv)

    s_http = requests.Session()
    s_json = requests.Session()

    # For each attrs: run cold then warm (batch-first vs batch-followup), warmup then reps
    for attrs in attrs_list:
        for scenario in ("cold", "warm"):
            for approach in approaches:
                # warmup
                for w in range(int(args.warmup)):
                    row = run_trial(
                        session_http=s_http,
                        session_jsonapi=s_json,
                        args=args,
                        cfg=cfg,
                        device_info=device_info,
                        operator_jwt=operator_jwt,
                        edge_jwt=edge_jwt,
                        party_ids=party_ids,
                        run_id=run_id,
                        approach=approach,
                        scenario=scenario,
                        attrs=attrs,
                        rep=w + 1,
                        warmup=1,
                    )
                    write_row(args.csv, row, fresh=False)
                    if args.sleep_ms > 0:
                        time.sleep(args.sleep_ms / 1000.0)

                # measured reps
                for rep in range(int(args.reps)):
                    row = run_trial(
                        session_http=s_http,
                        session_jsonapi=s_json,
                        args=args,
                        cfg=cfg,
                        device_info=device_info,
                        operator_jwt=operator_jwt,
                        edge_jwt=edge_jwt,
                        party_ids=party_ids,
                        run_id=run_id,
                        approach=approach,
                        scenario=scenario,
                        attrs=attrs,
                        rep=rep + 1,
                        warmup=0,
                    )
                    write_row(args.csv, row, fresh=False)

                    # cleaner progress per approach (no misleading zeros)
                    if approach == "classic":
                        print(
                            f"[{approach}][{scenario}][attrs={attrs}][rep={rep+1}/{args.reps}] "
                            f"e2e={row['total_end2end_ms']:.2f}ms encrypt={row['http_encrypt_status']} log={row['http_log_status']} "
                            f"digest={row['digest_hex_prefix']} err={row['error_prefix']}"
                        )
                    elif approach == "hybrid":
                        print(
                            f"[{approach}][{scenario}][attrs={attrs}][rep={rep+1}/{args.reps}] "
                            f"e2e={row['total_end2end_ms']:.2f}ms prepare={row['http_prepare_status']} log={row['http_log_status']} "
                            f"digest={row['digest_hex_prefix']} err={row['error_prefix']}"
                        )
                    else:
                        print(
                            f"[{approach}][{scenario}][attrs={attrs}][rep={rep+1}/{args.reps}] "
                            f"e2e={row['total_end2end_ms']:.2f}ms prepare={row['http_prepare_status']} "
                            f"spSign={row['http_sp_sign_status']} relay={row['http_relay_status']} log={row['http_log_status']} "
                            f"attN={row['attestation_n']} ctr={row['ratchet_counter']} path={row['relay_path']} "
                            f"digest={row['digest_hex_prefix']} err={row['error_prefix']}"
                        )

                    if args.sleep_ms > 0:
                        time.sleep(args.sleep_ms / 1000.0)

    s_http.close()
    s_json.close()
    print(f"\n✅ Done. Detailed results saved to: {args.csv}")
    print("Tip: filter warmup=0 for plots/tables.")


if __name__ == "__main__":
    main()
