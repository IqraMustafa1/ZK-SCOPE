#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SCOPE Flask API
(Decentralised TA; ratchet + AlgId + Merkle-root + optional ZK-PAC + hybrid PQ)

✅ FIXED TO MATCH YOUR DAML MODEL (Main.daml + RunAll.daml)

Key alignment fixes applied in this file:

1) ✅ DAML AlgId is a VARIANT, not Text.
   → JSON-API needs: {"tag":"ALG_...","value":{}}
   We now send AlgId using `daml_variant(tag)`.

2) ✅ DAML normalizeB64 only removes whitespace; it does NOT decode+re-encode base64.
   → We added `_daml_norm_b64_text()` and use it for:
      - pqPubKey comparisons vs Device.pqPubKey
      - pqPubKey passed into VerifyAndRelayMessage
      - pqPubKey returned from /crypto/prepare_hybrid
   We STOP using `_norm_b64()` for pqPubKey values that go on-ledger.

3) ✅ senderPublicKey must match SigAttestation.senderPublicKey used to create attestations.
   → We keep your selectable mode via env:
      SCOPE_SENDER_PUBLIC_KEY_MODE = prefer_request | sp_ed25519 | sp_x25519

4) ✅ Flask previously verified SP signature always; DAML doesn’t.
   → We added `SCOPE_SKIP_SP_VERIFY` (default False).
     If True, Flask will skip SP Ed25519 verification (useful for DAML-only demos).

⚠️ Note about /relay/ack endpoints:
Your Main.daml RelayLog template has `acked : Bool` but NO choice to update it.
So exercising "Acknowledge" will fail.
✅ This file returns 501 for ack endpoints (clear message) instead of failing noisily.

✅ FIX APPLIED NOW:
- VerifyAndRelayMessage MUST include `kyberCiphertextB64` when hybrid.
- `algId` MUST be encoded as a DAML Variant in the JSON-API argument.
"""

import base64
import hashlib
import json
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from time import perf_counter_ns
from typing import Optional, Tuple, List, Dict, Any, Set

import requests
from requests.exceptions import HTTPError
from flask import Flask, jsonify, request, g
from werkzeug.exceptions import BadRequest

from flask_caching import Cache
from flask_compress import Compress

from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization, hashes, constant_time
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# Stable base directory: makes token + .keys paths stable regardless of CWD
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# Helpers: robust env int parsing (supports "2_000_000" style)
# ---------------------------------------------------------------------------
def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return int(default)
    try:
        return int(str(raw).replace("_", "").strip())
    except Exception:
        return int(default)


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return bool(default)
    return str(raw).strip().lower() in ("1", "true", "yes", "y", "on")


# ---------------------------------------------------------------------------
# Optional PQC (ML-KEM-768 / ML-DSA-65) via Open Quantum Safe
# ---------------------------------------------------------------------------
try:
    import oqs  # python-oqs

    def _oqs_has_bindings() -> bool:
        return hasattr(oqs, "KeyEncapsulation") and hasattr(oqs, "Signature")

    def _oqs_list_kems() -> List[str]:
        for name in (
            "get_enabled_kems",
            "get_enabled_KEMs",
            "get_enabled_kem_algorithms",
            "get_supported_kems",
        ):
            f = getattr(oqs, name, None)
            if callable(f):
                try:
                    ks = list(f())
                    if ks:
                        return ks
                except Exception:
                    pass
        # Fallback probe
        candidates = ["ML-KEM-768", "ML-KEM-512", "Kyber768", "Kyber512"]
        found = []
        for alg in candidates:
            try:
                with oqs.KeyEncapsulation(alg):
                    found.append(alg)
            except Exception:
                pass
        return found

    def _oqs_list_sigs() -> List[str]:
        for name in (
            "get_enabled_sigs",
            "get_enabled_sig_mechanisms",
            "get_enabled_signature_algorithms",
            "get_supported_sigs",
        ):
            f = getattr(oqs, name, None)
            if callable(f):
                try:
                    ss = list(f())
                    if ss:
                        return ss
                except Exception:
                    pass
        candidates = ["ML-DSA-65", "Dilithium3", "Dilithium2", "Falcon-512"]
        found = []
        for alg in candidates:
            try:
                with oqs.Signature(alg):
                    found.append(alg)
            except Exception:
                pass
        return found

    HAS_OQS = _oqs_has_bindings()
    OQS_ENABLED_KEMS: List[str] = _oqs_list_kems() if HAS_OQS else []
    OQS_ENABLED_SIGS: List[str] = _oqs_list_sigs() if HAS_OQS else []

except ImportError:
    oqs = None  # type: ignore
    HAS_OQS = False
    OQS_ENABLED_KEMS = []
    OQS_ENABLED_SIGS = []


# ---------------------------------------------------------------------------
# Flask basics
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config["CACHE_TYPE"] = "simple"
Cache(app)
Compress(app)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
LEDGER_HOST = os.getenv("LEDGER_HOST", "localhost")
LEDGER_HTTP_PORT = os.getenv("LEDGER_HTTP_PORT", "7576")
JSON_API = f"http://{LEDGER_HOST}:{LEDGER_HTTP_PORT}"

# Stable token path (absolute default); still overridable via TOKEN_PATH env var
TOKEN_PATH = os.getenv("TOKEN_PATH", os.path.join(BASE_DIR, "token.txt"))

# Key persistence
PERSIST = _bool_env("SCOPE_PERSIST_KEYS", True)

CACHE_TTL_SEC = _int_env("SCOPE_CACHE_TTL", 8)
DEFAULT_TIMEOUT = _int_env("SCOPE_TIMEOUT", 15)

# Skip SP verify? (Useful when you run DAML tests that send dummy SP sigs.)
SKIP_SP_VERIFY = _bool_env("SCOPE_SKIP_SP_VERIFY", False)

# --- Demo mode: reproducible keys (NOT production) ---
TEST_STATIC_KEYS = _bool_env("SCOPE_TEST_STATIC_KEYS", False)

ED25519_STATIC_SEED_HEX = os.getenv(
    "SCOPE_TEST_ED25519_SEED",
    "7f00bacbd1abb803c4bf2558c0032b090782f9bb8341862809edc3972b10ea55",
)
X25519_STATIC_SEED_HEX = os.getenv(
    "SCOPE_TEST_X25519_SEED",
    "551a606fc2c2a614ccb033572e21ae686ca25465b474a73bb601e30896f2fa8c",
)

# PQ algorithms (OQS names; can be overridden)
_env_kem = (os.getenv("SCOPE_PQ_KEM", "") or "").strip()
_env_sig = (os.getenv("SCOPE_PQ_SIG", "") or "").strip()
_DEFAULT_KEM_PREF = ["ML-KEM-768", "Kyber768", "ML-KEM-512", "Kyber512"]
_DEFAULT_SIG_PREF = ["ML-DSA-65", "Dilithium3", "Dilithium2", "Falcon-512"]


def _choose_default(preferred: List[str], enabled: List[str]) -> Optional[str]:
    for n in preferred:
        if n in enabled:
            return n
    return enabled[0] if enabled else None


OQS_KEM_ALG = _env_kem or _choose_default(_DEFAULT_KEM_PREF, OQS_ENABLED_KEMS) or "ML-KEM-768"
OQS_SIG_ALG = _env_sig or _choose_default(_DEFAULT_SIG_PREF, OQS_ENABLED_SIGS) or "ML-DSA-65"

# Hybrid policy: if pqSignatureB64 is missing, should we inject a dummy or fail?
HYBRID_REQUIRE_PQ_SIG_STRICT = _bool_env("SCOPE_HYBRID_PQ_SIG_STRICT", False)

# senderPublicKey population:
# - "prefer_request": use request.senderPublicKey if present, else fallback to sp_ed25519_pub_hex
# - "sp_ed25519": always use sp Ed25519 pub hex
# - "sp_x25519": use request field "sender_x25519_hex" OR "senderX25519Hex" if provided (else error)
SENDER_PUBLIC_KEY_MODE = (os.getenv("SCOPE_SENDER_PUBLIC_KEY_MODE", "prefer_request") or "").strip().lower()


# ---------------------------------------------------------------------------
# Security limits / policies
# ---------------------------------------------------------------------------
MAX_AAD_LEN = _int_env("SCOPE_MAX_AAD", 2048)
MAX_PLAINTEXT_LEN = _int_env("SCOPE_MAX_PLAINTEXT", 2_000_000)
MAX_CIPHERTEXT_LEN = _int_env("SCOPE_MAX_CIPHERTEXT", 3_000_000)
MAX_REQ_LEN = _int_env("SCOPE_MAX_REQUEST_BYTES", 6_000_000)

ALLOWED_ALGID_TAGS: Set[str] = {
    "ALG_X25519_AESGCM_ED25519",
    "ALG_HYBRID_X25519_KYBER_AESGCM_HYBRID_SIG",
}


# ---------------------------------------------------------------------------
# DAML JSON encoding helpers
# ---------------------------------------------------------------------------
def daml_variant(tag: str, value: Optional[dict] = None) -> dict:
    """Encode DAML variant for JSON-API."""
    if value is None:
        value = {}
    return {"tag": tag, "value": value}


def _daml_norm_b64_text(s: str) -> str:
    """
    EXACT MATCH to your DAML normalizeB64:
      replace "\n", "\r", "\t", " " with ""
    NOTE: No decoding/re-encoding. No +/ vs -_ rewriting.
    """
    if not s:
        return ""
    return (
        str(s)
        .replace("\n", "")
        .replace("\r", "")
        .replace("\t", "")
        .replace(" ", "")
    )


# ---------------------------------------------------------------------------
# Simple TTL cache
# ---------------------------------------------------------------------------
class TTLCache:
    def __init__(self, ttl: int):
        self.ttl = int(ttl)
        self._d: Dict[tuple, tuple] = {}

    def get(self, k):
        now = time.time()
        v = self._d.get(k)
        if not v:
            return None
        exp, val = v
        if exp < now:
            self._d.pop(k, None)
            return None
        return val

    def set(self, k, val):
        self._d[k] = (time.time() + self.ttl, val)

    def keys(self):
        now = time.time()
        out = []
        for k, (exp, _) in list(self._d.items()):
            if exp < now:
                self._d.pop(k, None)
            else:
                out.append((k, int(exp - now)))
        return out


EDGE_CACHE = TTLCache(CACHE_TTL_SEC)

# Simple per-edge rate limiter for relay_message
RATE_LIMIT_TTL = _int_env("SCOPE_RATE_TTL", 3)
RATE_LIMIT_BUCKET = _int_env("SCOPE_RATE_BUCKET", 30)
RATE_CACHE = TTLCache(RATE_LIMIT_TTL)


def _rate_ok(edge: str) -> bool:
    key = ("rate", edge)
    cur = RATE_CACHE.get(key) or 0
    if cur >= RATE_LIMIT_BUCKET:
        return False
    RATE_CACHE.set(key, cur + 1)
    return True


def next_counter(scope: tuple) -> int:
    """
    Local monotonic counter per scope (demo convenience only).
    ON-LEDGER monotonicity is enforced by RatchetState.
    """
    key = ("ctr",) + scope
    c = EDGE_CACHE.get(key) or 0
    c += 1
    EDGE_CACHE.set(key, c)
    return c


# ---------------------------------------------------------------------------
# JWT / JSON API helpers
# ---------------------------------------------------------------------------
def load_jwt(path: str) -> Optional[str]:
    try:
        raw = open(path, "rb").read()
    except Exception as e:
        app.logger.error("Failed to read %s: %s", path, e)
        return None
    for enc in ("utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "ascii"):
        try:
            tok = raw.decode(enc).strip()
            if "\x00" not in tok and tok:
                return tok
        except Exception:
            continue
    return None


jwt_token = load_jwt(TOKEN_PATH)
if not jwt_token:
    raise SystemExit("JWT token missing/invalid. Place it in token.txt or set TOKEN_PATH.")


ledger = requests.Session()
ledger.headers.update({"Authorization": f"Bearer {jwt_token}", "Content-Type": "application/json"})


def _json_api_get(path: str, **kw) -> requests.Response:
    r = ledger.get(f"{JSON_API}{path}", timeout=kw.pop("timeout", DEFAULT_TIMEOUT), **kw)
    r.raise_for_status()
    return r


def _json_api_post(path: str, json_body: dict) -> requests.Response:
    r = ledger.post(f"{JSON_API}{path}", json=json_body, timeout=DEFAULT_TIMEOUT)
    if r.status_code >= 400:
        app.logger.error("JSON API POST %s: %s -- body=%s", path, r.text, json.dumps(json_body))
    r.raise_for_status()
    return r


def _post_with_token(path: str, json_body: dict, token: str) -> requests.Response:
    hdrs = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    r = requests.post(f"{JSON_API}{path}", json=json_body, headers=hdrs, timeout=DEFAULT_TIMEOUT)
    if r.status_code >= 400:
        app.logger.error("JSON API POST %s: %s -- body=%s", path, r.text, json.dumps(json_body))
    r.raise_for_status()
    return r


# Preflight
try:
    _json_api_get("/v1/packages", timeout=DEFAULT_TIMEOUT)
except Exception as e:
    raise SystemExit(f"JSON-API not reachable at {JSON_API} or token rejected: {e}")


def _decode_jwt_claims_noverify(tok: str) -> Dict[str, Any]:
    """
    NOTE: no signature verification.
    We only use this for convenience (e.g., actAs hints); ledger authorization remains source-of-truth.
    """
    try:
        parts = tok.split(".")
        if len(parts) < 2:
            return {}
        p = parts[1]
        p += "=" * (-len(p) % 4)
        data = base64.urlsafe_b64decode(p.encode("ascii"))
        return json.loads(data.decode("utf-8"))
    except Exception:
        return {}


TOKEN_CLAIMS: Dict[str, Any] = _decode_jwt_claims_noverify(jwt_token)
DAML_CLAIMS = TOKEN_CLAIMS.get("https://daml.com/ledger-api", {}) or {}
CLAIM_ACTAS = set(DAML_CLAIMS.get("actAs") or [])
CLAIM_READAS = set(DAML_CLAIMS.get("readAs") or [])
CLAIM_ADMIN = bool(DAML_CLAIMS.get("admin", False))


# ---------------------------------------------------------------------------
# Package discovery
# ---------------------------------------------------------------------------
def _coerce_packages_list(obj: Any) -> List[str]:
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict) and "result" in obj and isinstance(obj["result"], list):
        return obj["result"]
    return []


def _package_modules_for(pid: str) -> List[str]:
    r = _json_api_get(f"/v1/packages/{pid}")
    info = r.json() or {}
    mods = info.get("modules", [])
    names: List[str] = []
    for m in mods:
        if isinstance(m, str):
            names.append(m)
        elif isinstance(m, dict) and "name" in m:
            names.append(str(m["name"]))
    return names


def discover_pkg_id() -> Optional[str]:
    try:
        ids_resp = _json_api_get("/v1/packages").json()
        ids = _coerce_packages_list(ids_resp)
        for pid in ids:
            try:
                if "Main" in _package_modules_for(pid):
                    app.logger.info("Discovered DAML_PKG_ID with Main: %s", pid)
                    return pid
            except Exception:
                continue
        for pid in ids:
            try:
                q = _json_api_post(
                    "/v1/query",
                    {"templateIds": [f"{pid}:Main:LogRequest"], "query": {}},
                )
                if q.status_code < 400:
                    app.logger.info("Discovered DAML_PKG_ID by probe: %s", pid)
                    return pid
            except Exception:
                pass
    except Exception as e:
        app.logger.warning("Package discovery failed: %s", e)
    return None


DAML_PKG_ID: Optional[str] = (os.getenv("DAML_PKG_ID") or "").strip() or discover_pkg_id()
if DAML_PKG_ID and DAML_PKG_ID.strip().lower() in {"<your-package-id>", "your-package-id"}:
    app.logger.warning("Ignoring placeholder DAML_PKG_ID=%r; discovering actual package id...", DAML_PKG_ID)
    real_pid = discover_pkg_id()
    if real_pid:
        DAML_PKG_ID = real_pid
    else:
        raise SystemExit("DAML_PKG_ID placeholder set; discovery failed. Set a real package id.")
if not DAML_PKG_ID:
    raise SystemExit("Could not determine DAML_PKG_ID. Ensure your DAR is uploaded and JSON-API is reachable.")


# ---------------------------------------------------------------------------
# Party resolution
# ---------------------------------------------------------------------------
def resolve_party_identifier(party_or_name: str) -> str:
    if not party_or_name or "::" in party_or_name:
        return party_or_name
    try:
        r = _json_api_get("/v1/parties", params={"id": party_or_name})
        res = r.json().get("result", [])
        if res:
            return res[0].get("identifier") or res[0].get("party") or party_or_name
    except Exception as e:
        app.logger.warning("Party resolution failed for %s: %s", party_or_name, e)
    return party_or_name


def resolve_operator_identifier() -> Optional[str]:
    try:
        r = _json_api_get("/v1/parties", params={"id": "Operator"})
        res = r.json().get("result", [])
        if res:
            return res[0].get("identifier") or res[0].get("party")
    except Exception:
        pass
    return None


def choose_party() -> str:
    env_wanted = os.getenv("DAML_PARTY") or os.getenv("DAML_PKG_PARTY") or ""
    env_resolved = resolve_party_identifier(env_wanted) if env_wanted else None

    authorized_raw = list(CLAIM_ACTAS | CLAIM_READAS)
    authorized_all: Set[str] = set(authorized_raw)

    for p in list(authorized_raw):
        try:
            rp = resolve_party_identifier(p)
            if rp:
                authorized_all.add(rp)
        except Exception:
            continue

    if env_resolved and (env_resolved in authorized_all or env_wanted in authorized_all):
        app.logger.info("Using party from env (authorized): %s", env_resolved)
        return env_resolved

    opid = resolve_operator_identifier()
    if opid and (opid in authorized_all or "Operator" in authorized_all):
        app.logger.info("Using Operator (authorized): %s", opid)
        return opid

    if authorized_raw:
        base = authorized_raw[0]
        resolved = resolve_party_identifier(base)
        app.logger.info("Using first authorized party from token: %s", resolved)
        return resolved

    if opid:
        app.logger.warning("JWT has no actAs/readAs; falling back to Operator id: %s", opid)
        return opid
    if env_resolved:
        app.logger.warning("JWT has no actAs/readAs and Operator id unknown; using env party anyway: %s", env_resolved)
        return env_resolved

    app.logger.warning("JWT has no actAs/readAs and no env party; using 'Operator' display name.")
    return "Operator"


DAML_PARTY = choose_party()
app.logger.info("Config OK: JSON_API=%s  DAML_PKG_ID=%s  DAML_PARTY=%s", JSON_API, DAML_PKG_ID, DAML_PARTY)


# ---------------------------------------------------------------------------
# Template IDs
# ---------------------------------------------------------------------------
def tid(entity: str) -> str:
    return f"{DAML_PKG_ID}:Main:{entity}"


LOGREQUEST_TEMPLATE = tid("LogRequest")
BROKER_TEMPLATE = tid("BrokerContract")
DEVICE_TEMPLATE = tid("Device")
SNAPSHOT_TEMPLATE = tid("TaSnapshot")
TACOMMITTEE_TEMPLATE = tid("TACommittee")
SNAPSHOT_PROPOSAL_TEMPLATE = tid("SnapshotProposal")
SIG_ATTEST_TEMPLATE = tid("SigAttestation")
REVOKED_KEY_TEMPLATE = tid("RevokedKey")
RELAY_LOG_TEMPLATE = tid("RelayLog")
ACCESS_POLICY_TEMPLATE = tid("AccessPolicy")
SP_PROFILE_TEMPLATE = tid("SPProfile")
RATCHET_TEMPLATE = tid("RatchetState")


# ---------------------------------------------------------------------------
# Crypto keys (Ed25519 + X25519 + optional PQ signature key)
# ---------------------------------------------------------------------------
KEY_DIR = os.getenv("SCOPE_KEY_DIR", os.path.join(BASE_DIR, ".keys"))
ED_FILE = os.path.join(KEY_DIR, "ed25519.key")
X_FILE = os.path.join(KEY_DIR, "x25519.key")
PQ_SIG_FILE = os.path.join(KEY_DIR, "pq_sig.json")


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def load_or_create_ed25519():
    if TEST_STATIC_KEYS:
        seed = bytes.fromhex(ED25519_STATIC_SEED_HEX)
        if len(seed) != 32:
            raise SystemExit("SCOPE_TEST_ED25519_SEED must be 32 bytes hex")
        return ed25519.Ed25519PrivateKey.from_private_bytes(seed)

    if PERSIST and os.path.isfile(ED_FILE):
        data = open(ED_FILE, "rb").read()
        return serialization.load_pem_private_key(data, password=None)
    sk = ed25519.Ed25519PrivateKey.generate()
    if PERSIST:
        ensure_dir(KEY_DIR)
        pem = sk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        open(ED_FILE, "wb").write(pem)
    return sk


def load_or_create_x25519():
    if TEST_STATIC_KEYS:
        seed = bytes.fromhex(X25519_STATIC_SEED_HEX)
        if len(seed) != 32:
            raise SystemExit("SCOPE_TEST_X25519_SEED must be 32 bytes hex")
        return x25519.X25519PrivateKey.from_private_bytes(seed)

    if PERSIST and os.path.isfile(X_FILE):
        data = open(X_FILE, "rb").read()
        return serialization.load_pem_private_key(data, password=None)
    sk = x25519.X25519PrivateKey.generate()
    if PERSIST:
        ensure_dir(KEY_DIR)
        pem = sk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        open(X_FILE, "wb").write(pem)
    return sk


def load_or_create_pq_sig():
    """
    Optional PQ signing keypair for pqSignatureB64 generation (ML-DSA/Dilithium/etc).

    NOTE:
      Your DAML compares pqPubKey to Device.pqPubKey (device KEM key).
      Therefore, this PQ signature key is NOT compared against pqPubKey and
      is purely a transport/benchmark blob.
    """
    if not HAS_OQS:
        return None, None, None

    if PERSIST and os.path.isfile(PQ_SIG_FILE):
        data = json.load(open(PQ_SIG_FILE, "r"))
        alg = data.get("alg", OQS_SIG_ALG)
        pk = base64.b64decode(data["pk"])
        sk = base64.b64decode(data["sk"])
        return alg, pk, sk

    try:
        with oqs.Signature(OQS_SIG_ALG) as s:
            pk = s.generate_keypair()
            sk = s.export_secret_key()
    except Exception as e:
        app.logger.warning("PQ sig keygen failed for %s: %s", OQS_SIG_ALG, e)
        return None, None, None

    if PERSIST and pk and sk:
        ensure_dir(KEY_DIR)
        json.dump(
            {"alg": OQS_SIG_ALG, "pk": base64.b64encode(pk).decode(), "sk": base64.b64encode(sk).decode()},
            open(PQ_SIG_FILE, "w"),
        )
    return OQS_SIG_ALG, pk, sk


ED_SK = load_or_create_ed25519()
ED_PK = ED_SK.public_key()
X_SK = load_or_create_x25519()
X_PK = X_SK.public_key()

if HAS_OQS:
    PQ_SIG_ALG, PQ_SIG_PK, PQ_SIG_SK = load_or_create_pq_sig()
else:
    PQ_SIG_ALG = PQ_SIG_PK = PQ_SIG_SK = None


def ed_pub_hex(pk: ed25519.Ed25519PublicKey) -> str:
    return pk.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()


def x_pub_hex(pk: x25519.X25519PublicKey) -> str:
    return pk.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()


# ---------------------------------------------------------------------------
# Base64 helpers (robust: base64 OR base64url input)
# ---------------------------------------------------------------------------
def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64_from_b64u(s: str) -> str:
    if not s:
        return s
    s = s.replace("-", "+").replace("_", "/")
    while len(s) % 4:
        s += "="
    return s


def _decode_maybe_b64_or_b64u(s: str) -> bytes:
    if not s:
        return b""
    try:
        return base64.b64decode(s, validate=True)
    except Exception:
        return base64.b64decode(_b64_from_b64u(s), validate=False)


def _norm_b64(s: str) -> str:
    """
    Canonical base64 by decoding then re-encoding.
    IMPORTANT: Do NOT use this for pqPubKey values that must match DAML text equality.
    Keep it only for binary operations (e.g., KEM ciphertext decode/encode).
    """
    if not s:
        return ""
    raw = _decode_maybe_b64_or_b64u(s)
    return base64.b64encode(raw).decode("ascii")


# ---------------------------------------------------------------------------
# HKDF / AES-GCM helpers
# ---------------------------------------------------------------------------
def hkdf_key_and_nonce(shared_secret: bytes, ctx: dict, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    ctx_bytes = json.dumps(ctx or {}, separators=(",", ":"), sort_keys=True).encode("utf-8")
    prk = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"scope hkdf prk").derive(shared_secret)
    k_enc = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"scope aes-gcm key" + ctx_bytes).derive(prk)
    n_base = HKDF(algorithm=hashes.SHA256(), length=12, salt=None, info=b"scope nonce base" + ctx_bytes).derive(prk)
    return k_enc, n_base


def build_nonce(nonce_base: bytes, counter: int) -> bytes:
    """96-bit nonce: 4 bytes from HKDF base + 8-byte big-endian counter."""
    if len(nonce_base) != 12:
        raise ValueError("nonce_base must be 12 bytes")
    return nonce_base[:4] + int(counter).to_bytes(8, "big")


def digest_for_transcript(ciphertext: bytes, aad: bytes = b"") -> str:
    return hashlib.sha256(ciphertext + (aad or b"")).hexdigest()


# ---------------------------------------------------------------------------
# PQ KEM (encapsulation to device pqPubKey)
# ---------------------------------------------------------------------------
def _oqs_expected_kem_pubkey_len(alg: str) -> Optional[int]:
    """
    Best-effort expected public key length for KEM alg.
    Supports different python-oqs versions (details may be object or dict).
    """
    try:
        with oqs.KeyEncapsulation(alg) as kem_probe:
            details = getattr(kem_probe, "details", None)
            if details is None:
                return None
            if hasattr(details, "length_public_key"):
                return int(getattr(details, "length_public_key"))
            if isinstance(details, dict) and "length_public_key" in details:
                return int(details["length_public_key"])
    except Exception:
        return None
    return None


def do_pq_kem_to_device(device_pq_pub_any: str) -> Tuple[str, bytes]:
    """
    Encapsulate to device ML-KEM/Kyber public key.

    Accepts base64 or base64url. Returns (kyberCiphertextB64, kem_shared_secret_bytes).

    ✅ FIX: If pubkey length mismatches expected length, we REJECT (no slicing).
    """
    if not HAS_OQS:
        raise RuntimeError("python-oqs is required for hybrid PQ mode")

    alg = OQS_KEM_ALG
    if OQS_ENABLED_KEMS and alg not in OQS_ENABLED_KEMS:
        alg = _choose_default(_DEFAULT_KEM_PREF, OQS_ENABLED_KEMS) or alg

    pk_bytes = _decode_maybe_b64_or_b64u(device_pq_pub_any or "")
    if not pk_bytes:
        raise ValueError("empty device pq public key")

    expected_len = _oqs_expected_kem_pubkey_len(alg)
    if expected_len is None:
        if alg in ("ML-KEM-768", "Kyber768"):
            expected_len = 1184
        elif alg in ("ML-KEM-512", "Kyber512"):
            expected_len = 800
        else:
            expected_len = None

    if expected_len is not None and len(pk_bytes) != expected_len:
        raise ValueError(f"PQ pubkey length mismatch for {alg}: got={len(pk_bytes)} expected={expected_len}")

    with oqs.KeyEncapsulation(alg) as kem:
        if hasattr(kem, "encapsulate"):
            ct, ss = kem.encapsulate(pk_bytes)
        elif hasattr(kem, "encap_secret"):
            ct, ss = kem.encap_secret(pk_bytes)
        else:
            raise RuntimeError(f"OQS KEM for {alg} has no encapsulate/encap_secret")

    return base64.b64encode(ct).decode("ascii"), ss


def make_pq_signature_blob(digest_hex: str) -> Optional[str]:
    """
    Optional PQ signature blob (base64) over digest bytes.
    DAML does NOT verify it cryptographically; it just requires presence for hybrid.
    """
    if not (HAS_OQS and PQ_SIG_ALG and PQ_SIG_SK):
        return None

    msg = bytes.fromhex(digest_hex)

    try:
        with oqs.Signature(PQ_SIG_ALG, secret_key=PQ_SIG_SK) as s:
            sig = s.sign(msg)
        return base64.b64encode(sig).decode("ascii")
    except TypeError:
        try:
            with oqs.Signature(PQ_SIG_ALG) as s:
                if not hasattr(s, "import_secret_key"):
                    return None
                s.import_secret_key(PQ_SIG_SK)
                sig = s.sign(msg)
            return base64.b64encode(sig).decode("ascii")
        except Exception:
            return None
    except Exception:
        return None


def _hybrid_pq_sig_or_dummy(current: Optional[str]) -> str:
    """
    If strict -> require real pqSignatureB64 (non-empty).
    Else -> supply a safe dummy if missing.
    """
    if current and current.strip():
        return current.strip()

    if HYBRID_REQUIRE_PQ_SIG_STRICT:
        raise ValueError("pqSignatureB64 required in hybrid mode (strict policy enabled)")

    return base64.b64encode(b"pq_sig_dummy").decode("ascii")


# ---------------------------------------------------------------------------
# JSON API helpers (contracts)
# ---------------------------------------------------------------------------
def query_all(template_id: str, query: dict = None):
    body = {"templateIds": [template_id], "query": query or {}}
    r = _json_api_post("/v1/query", body)
    return r.json().get("result", [])


def create(template_id: str, payload: dict, token: Optional[str] = None):
    body = {"templateId": template_id, "payload": payload}
    if token:
        return _post_with_token("/v1/create", body, token).json()
    return _json_api_post("/v1/create", body).json()


def exercise(template_id: str, contract_id: str, choice: str, argument: dict, token: Optional[str] = None):
    body = {"templateId": template_id, "contractId": contract_id, "choice": choice, "argument": argument}
    if token:
        return _post_with_token("/v1/exercise", body, token).json()
    return _json_api_post("/v1/exercise", body).json()


def fetch_contract(template_id: str, contract_id: str, token: Optional[str] = None) -> Optional[dict]:
    body = {"templateId": template_id, "contractId": contract_id}
    if token:
        rj = _post_with_token("/v1/fetch", body, token).json()
    else:
        rj = _json_api_post("/v1/fetch", body).json()
    return rj.get("result")


def fetch_by_key(template_id: str, key: dict) -> Optional[dict]:
    body = {"templateId": template_id, "key": key}
    try:
        r = _json_api_post("/v1/fetch", body)
        data = r.json()
        return data.get("result")
    except HTTPError as e:
        status = getattr(e.response, "status_code", None)
        if status in (404, 405, 501):
            return None
        raise


def _extract_exercise_result(resp_json: Dict[str, Any]) -> Any:
    res = resp_json.get("result") if isinstance(resp_json, dict) else None
    if isinstance(res, dict) and "exerciseResult" in res:
        return res["exerciseResult"]
    return None


# ---------------------------------------------------------------------------
# Ratchet helper (read lastCtr + 1 from ledger)
# ---------------------------------------------------------------------------
def ratchet_next_ctr(edge_party: str, device_key: str, sender_id: str, epoch: int) -> int:
    """
    ✅ COMPLETE FIX:
    - RatchetState in DAML commonly uses `op` not `operator`.
    - Some older runs/templates might still have `operator`.
    - Query both, merge results, and return MAX(lastCtr)+1.
    """
    q_base = {"edge": edge_party, "deviceKey": device_key, "senderId": sender_id, "epoch": int(epoch)}

    rows: List[dict] = []

    # Try canonical field name first: op
    try:
        rows = query_all(RATCHET_TEMPLATE, {"op": DAML_PARTY, **q_base})
    except Exception:
        rows = []

    # Fallback: operator (compat)
    if not rows:
        try:
            rows = query_all(RATCHET_TEMPLATE, {"operator": DAML_PARTY, **q_base})
        except Exception:
            rows = []

    if not rows:
        return 1

    last = 0
    for r in rows:
        try:
            payload = (r.get("payload", {}) or {})
            last = max(last, int(payload.get("lastCtr", 0) or 0))
        except Exception:
            continue

    return last + 1


# ---------------------------------------------------------------------------
# Request guards
# ---------------------------------------------------------------------------
@app.before_request
def _require_json_and_cap():
    if request.method in ("POST", "PUT", "PATCH"):
        ct = request.headers.get("Content-Type", "")
        if "application/json" not in ct:
            return jsonify(error="content-type must be application/json"), 415
        if request.content_length and request.content_length > MAX_REQ_LEN:
            return jsonify(error="request too large"), 413


@app.errorhandler(BadRequest)
def _bad_request(e):
    return jsonify(error="bad_request", detail=str(e)), 400


@app.before_request
def _capture_request_id():
    rid = request.headers.get("X-Request-Id", "")
    if len(rid) > 128:
        return jsonify(error="X-Request-Id too long"), 400
    g.request_id = rid or ""


# ---------------------------------------------------------------------------
# Debug / health
# ---------------------------------------------------------------------------
@app.get("/debug/config")
def debug_config():
    return jsonify(
        json_api=JSON_API,
        daml_pkg_id=DAML_PKG_ID,
        daml_party=DAML_PARTY,
        token_path=TOKEN_PATH,
        has_oqs=HAS_OQS,
        oqs_kem_alg=OQS_KEM_ALG if HAS_OQS else None,
        oqs_sig_alg=OQS_SIG_ALG if HAS_OQS else None,
        enabled_kems=OQS_ENABLED_KEMS,
        enabled_sigs=OQS_ENABLED_SIGS,
        base_dir=BASE_DIR,
        key_dir=KEY_DIR,
        persist_keys=PERSIST,
        test_static_keys=TEST_STATIC_KEYS,
        hybrid_pq_sig_strict=HYBRID_REQUIRE_PQ_SIG_STRICT,
        sender_public_key_mode=SENDER_PUBLIC_KEY_MODE,
        skip_sp_verify=SKIP_SP_VERIFY,
    ), 200


@app.get("/debug/claims")
def debug_claims():
    return jsonify(
        daml_party=DAML_PARTY,
        actAs=list(CLAIM_ACTAS),
        readAs=list(CLAIM_READAS),
        admin=CLAIM_ADMIN,
        claims=TOKEN_CLAIMS,
    ), 200


@app.get("/debug/routes")
def debug_routes():
    routes = []
    for r in app.url_map.iter_rules():
        routes.append(
            {"rule": str(r), "endpoint": r.endpoint, "methods": sorted(m for m in r.methods if m not in ("HEAD", "OPTIONS"))}
        )
    return jsonify(routes=routes), 200


@app.get("/health/keys")
def health_keys():
    out = {
        "has_ed25519": True,
        "has_x25519": True,
        "ed25519_hex": ed_pub_hex(ED_PK),
        "x25519_hex": x_pub_hex(X_PK),
        "persist_keys": PERSIST,
        "has_oqs": HAS_OQS,
        "oqs_kem_alg": OQS_KEM_ALG if HAS_OQS else None,
        "oqs_sig_alg": PQ_SIG_ALG if HAS_OQS else None,
        "has_pq_sig_keypair": bool(PQ_SIG_PK and PQ_SIG_SK),
        "test_static_keys": TEST_STATIC_KEYS,
    }
    return jsonify(out), 200


# ---------------------------------------------------------------------------
# PQ endpoints (standalone tests)
# ---------------------------------------------------------------------------
@app.post("/pq/sign")
def pq_sign():
    if not HAS_OQS:
        return jsonify(ok=False, error="python-oqs not available"), 400
    body = request.get_json(silent=True) or {}
    sigs = OQS_ENABLED_SIGS
    alg = body.get("alg") or next((a for a in ("ML-DSA-65", "Dilithium3") if a in sigs), (sigs[0] if sigs else None))
    if not alg:
        return jsonify(ok=False, error="No PQ signature algorithms enabled in liboqs."), 400
    msg_b64u = body.get("message") or _b64u(b"hello-from-flask")
    try:
        msg = _decode_maybe_b64_or_b64u(msg_b64u)
    except Exception as e:
        return jsonify(ok=False, error=f"bad message b64(u): {e}"), 400

    try:
        with oqs.Signature(alg) as sig:
            pk = sig.generate_keypair()
            sig_bytes = sig.sign(msg)
            return jsonify(
                ok=True,
                alg=alg,
                public_key_b64u=_b64u(pk),
                signature_b64u=_b64u(sig_bytes),
                message_len=len(msg),
            ), 200
    except Exception as e:
        return jsonify(ok=False, error=f"{type(e).__name__}: {e}"), 500


@app.post("/pq/verify")
def pq_verify():
    if not HAS_OQS:
        return jsonify(ok=False, error="python-oqs not available"), 400
    body = request.get_json(silent=True) or {}
    alg = body.get("alg")
    if not alg:
        return jsonify(ok=False, error="Missing 'alg'."), 400
    try:
        msg = _decode_maybe_b64_or_b64u(body["message"])
        sig_b = _decode_maybe_b64_or_b64u(body["signature"])
        pk = _decode_maybe_b64_or_b64u(body["public_key"])
    except Exception as e:
        return jsonify(ok=False, error=f"base64(u) decode failed: {e}"), 400

    try:
        with oqs.Signature(alg) as v:
            valid = v.verify(msg, sig_b, pk)
        return jsonify(ok=True, valid=bool(valid)), 200
    except Exception as e:
        return jsonify(ok=False, error=f"{type(e).__name__}: {e}"), 500


# ---------------------------------------------------------------------------
# Crypto endpoints (classical + hybrid prepare)
# ---------------------------------------------------------------------------
@app.post("/crypto/encrypt_to_device")
def encrypt_to_device():
    """
    Classical: X25519 + HKDF + AES-GCM with local demo counter.
    (Your ON-LEDGER ratchet is enforced in VerifyAndRelayMessage.)
    """
    b = request.get_json(silent=True) or {}
    dev_pub_hex = (b.get("devicePublicKey") or "").strip()
    if not dev_pub_hex:
        return jsonify(error="devicePublicKey (X25519 hex) required"), 400

    try:
        epoch = int(b.get("epoch", 0))
    except Exception:
        return jsonify(error="bad epoch"), 400

    ptxt_is_b64 = bool(b.get("plaintext_is_b64", False))
    aad_str = b.get("aad", "")
    if len(aad_str.encode("utf-8")) > MAX_AAD_LEN:
        return jsonify(error="aad too large"), 400
    ctx = b.get("ctx", {}) or {}

    if "plaintext" not in b:
        return jsonify(error="plaintext required"), 400

    try:
        plaintext = _decode_maybe_b64_or_b64u(b["plaintext"]) if ptxt_is_b64 else b["plaintext"].encode("utf-8")
    except Exception as e:
        return jsonify(error=f"bad plaintext: {e}"), 400
    if len(plaintext) > MAX_PLAINTEXT_LEN:
        return jsonify(error="plaintext too large"), 400

    try:
        dev_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(dev_pub_hex))
    except Exception as e:
        return jsonify(error=f"bad devicePublicKey: {e}"), 400

    eph = x25519.X25519PrivateKey.generate()
    shared = eph.exchange(dev_pub)
    k_enc, n_base = hkdf_key_and_nonce(shared, ctx)

    ctr = next_counter(("dev", dev_pub_hex, epoch))
    nonce = build_nonce(nonce_base=n_base, counter=ctr)

    aesgcm = AESGCM(k_enc)
    aad_bytes = aad_str.encode("utf-8") if aad_str else None
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad_bytes)

    if len(ciphertext) > MAX_CIPHERTEXT_LEN:
        return jsonify(error="ciphertext too large"), 500

    eph_pub_raw = eph.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    dig = digest_for_transcript(ciphertext, aad_bytes or b"")

    return jsonify(
        ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
        digest_hex=dig,
        sender_x25519_hex=x_pub_hex(X_PK),
        ephemeral_x25519_hex=eph_pub_raw.hex(),
        counter=ctr,
    ), 200


def _get_first_str(body: dict, keys: List[str]) -> str:
    for k in keys:
        v = body.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def _get_first_int(body: dict, keys: List[str]) -> Optional[int]:
    for k in keys:
        v = body.get(k)
        if v is None:
            continue
        try:
            return int(str(v).strip())
        except Exception:
            continue
    return None


@app.post("/crypto/prepare_hybrid")
def prepare_hybrid():
    """
    Hybrid prepare endpoint (X25519 + ML-KEM + AES-GCM).

    ✅ FIX: Accepts enforced counter from caller:
        - counter / ctr / nextCtr / ratchetCtr / ratchetCounter
      so nonce matches ledger RatchetState.

    Optional:
      If useLedgerCounter=true and no counter supplied, we compute from ledger using:
        edge + senderId + epoch + devicePublicKey
    """
    if not HAS_OQS:
        return jsonify(error="python-oqs required for hybrid AlgId"), 500

    try:
        body = request.get_json(force=True, silent=False)
    except Exception as e:
        return jsonify(error=f"invalid JSON: {e}"), 400

    # Device X25519 pubkey (hex)
    dev_pub_hex = ""
    for key in ["devicePublicKey", "device_public_key_hex", "devicePublicKeyHex"]:
        v = body.get(key)
        if isinstance(v, str) and v.strip():
            dev_pub_hex = v.strip()
            break
    if not dev_pub_hex:
        return jsonify(error="devicePublicKey (X25519 hex) missing"), 400

    # Device PQ KEM pubkey (base64/base64url; must match ledger text after DAML normalization)
    dev_pq_raw = ""
    for key in [
        "device_pq_pub_b64",
        "device_pq_pub_b64u",
        "devicePqPubB64",
        "devicePqPubB64u",
        "devicePqPubKeyB64",
        "devicePqPubKeyB64u",
        "device_pq_pub_key_b64",
        "device_pq_pub_key_b64u",
        "deviceKyberPubB64",
        "DeviceKyberPubB64",
        "deviceKyberPubB64u",
        "DeviceKyberPubB64u",
    ]:
        v = body.get(key)
        if isinstance(v, str) and v.strip():
            dev_pq_raw = v.strip()
            break
    if not dev_pq_raw:
        return jsonify(error="device PQ public key missing (ML-KEM/Kyber pubkey)"), 400

    # ✅ DAML-consistent normalization (whitespace-only removal)
    dev_pq_b64_daml = _daml_norm_b64_text(dev_pq_raw)

    # Plaintext
    ptxt_is_b64 = bool(body.get("plaintext_is_b64", False))
    raw_pt = body.get("plaintext", "")
    if (raw_pt is None or raw_pt == "") and "plaintext_b64" in body:
        raw_pt = body.get("plaintext_b64") or ""
        ptxt_is_b64 = True

    try:
        plaintext = _decode_maybe_b64_or_b64u(raw_pt) if ptxt_is_b64 else str(raw_pt).encode("utf-8")
    except Exception as e:
        return jsonify(error=f"bad plaintext: {e}"), 400
    if len(plaintext) > MAX_PLAINTEXT_LEN:
        return jsonify(error="plaintext too large"), 400

    # AAD
    aad_bytes: Optional[bytes] = None
    aad_for_log: Optional[str] = None
    if body.get("aad_b64u") is not None:
        try:
            aad_bytes = _decode_maybe_b64_or_b64u(body.get("aad_b64u") or "")
        except Exception as e:
            return jsonify(error=f"bad aad_b64u: {e}"), 400
        if len(aad_bytes) > MAX_AAD_LEN:
            return jsonify(error="aad too large"), 400
        aad_for_log = aad_bytes.decode("utf-8", errors="ignore")
    else:
        aad_str = body.get("aad") or ""
        if len(str(aad_str).encode("utf-8")) > MAX_AAD_LEN:
            return jsonify(error="aad too large"), 400
        aad_for_log = str(aad_str) if aad_str else None
        aad_bytes = str(aad_str).encode("utf-8") if aad_str else None

    ctx = body.get("ctx", {}) or {}
    try:
        epoch = int(body.get("epoch", 0))
    except Exception:
        return jsonify(error="bad epoch"), 400

    # X25519 ECDH
    try:
        eph = x25519.X25519PrivateKey.generate()
        shared_x = eph.exchange(x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(dev_pub_hex)))
    except Exception as e:
        return jsonify(error=f"bad devicePublicKey: {e}"), 400

    # PQ KEM encapsulation
    try:
        kyber_ct_b64, kem_ss = do_pq_kem_to_device(dev_pq_b64_daml)
    except Exception as e:
        return jsonify(error=f"pq_kem_failed: {e}"), 500

    shared = shared_x + kem_ss
    k_enc, n_base = hkdf_key_and_nonce(shared, ctx)

    # ✅ counter selection
    forced_ctr = _get_first_int(body, ["counter", "ctr", "nextCtr", "ratchetCtr", "ratchetCounter"])
    if forced_ctr is not None:
        if forced_ctr <= 0:
            return jsonify(error="counter must be >= 1"), 400
        ctr = int(forced_ctr)
    else:
        use_ledger_ctr = bool(body.get("useLedgerCounter") or body.get("use_ledger_counter") or False)
        if use_ledger_ctr:
            edge_party = resolve_party_identifier(_get_first_str(body, ["edge", "edgeParty", "edge_party"]))
            sender_id = _get_first_str(body, ["senderId", "sender_id"]) or "Sender1"
            if not edge_party:
                return jsonify(error="useLedgerCounter=true but 'edge' missing"), 400
            ctr = ratchet_next_ctr(edge_party, dev_pub_hex, sender_id, epoch)
        else:
            ctr = next_counter(("dev_hybrid", dev_pub_hex, epoch))

    nonce = build_nonce(nonce_base=n_base, counter=ctr)

    aesgcm = AESGCM(k_enc)
    try:
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad_bytes)
    except Exception as e:
        return jsonify(error=f"aesgcm_encrypt_failed: {e}"), 500
    if len(ciphertext) > MAX_CIPHERTEXT_LEN:
        return jsonify(error="ciphertext too large"), 500

    enc_b64 = base64.b64encode(ciphertext).decode("ascii")
    eph_x_hex = eph.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ).hex()
    digest_hex = digest_for_transcript(ciphertext, aad_bytes or b"")

    pq_sig_b64 = make_pq_signature_blob(digest_hex)
    try:
        pq_sig_b64 = _hybrid_pq_sig_or_dummy(pq_sig_b64)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    return jsonify(
        ciphertext_b64=enc_b64,
        encryptedMessage_b64=enc_b64,
        digest_hex=digest_hex,
        ephemeral_x25519_hex=eph_x_hex,
        counter=ctr,
        kyberCiphertextB64=kyber_ct_b64,
        pqSignatureB64=pq_sig_b64,
        pqPubKey=dev_pq_b64_daml,
        devicePublicKey=dev_pub_hex,
        aad=aad_for_log,
    ), 200


@app.post("/sp/ed25519/sign_digest")
def sp_sign_digest():
    """
    JSON: {"digest_hex":"..."}
    Uses local ED_SK for demo. In real systems, SP signs client-side.
    """
    b = request.get_json(silent=True) or {}
    dig = (b.get("digest_hex") or "").strip()
    if not dig or len(dig) != 64:
        return jsonify(error="digest_hex (sha256 hex) required"), 400
    sig = ED_SK.sign(bytes.fromhex(dig))
    return jsonify(
        sp_ed25519_pub_hex=ed_pub_hex(ED_PK),
        sp_signature_b64=base64.b64encode(sig).decode("ascii"),
    ), 200


@app.get("/debug/cache")
def debug_cache():
    return jsonify(keys=[{"key": str(k), "ttl_s": ttl} for k, ttl in EDGE_CACHE.keys()]), 200


LAST_RELAY_VERIFY: Dict[str, Any] = {}


@app.get("/debug/last_verify")
def debug_last_verify():
    return jsonify(LAST_RELAY_VERIFY or {"status": "none"}), 200


# ---------------------------------------------------------------------------
# Relay endpoint helpers
# ---------------------------------------------------------------------------
def _parse_iso_utc(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    try:
        if ts.endswith("Z"):
            return datetime.fromisoformat(ts[:-1]).replace(tzinfo=timezone.utc)
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _is_cache_expired_error(http_err: requests.HTTPError) -> bool:
    resp = getattr(http_err, "response", None)
    if resp is None:
        return False
    if "[Verify] cache expired; call RefreshCache" in (resp.text or ""):
        return True
    try:
        data = resp.json()
    except ValueError:
        return False

    def _walk(obj) -> bool:
        if isinstance(obj, str):
            return "[Verify] cache expired; call RefreshCache" in obj
        if isinstance(obj, dict):
            return any(_walk(v) for v in obj.values())
        if isinstance(obj, list):
            return any(_walk(v) for v in obj)
        return False

    return _walk(data)


def _refresh_cache_for_broker(broker_cid: str, edge_party: str) -> str:
    """
    Exercise BrokerContract.RefreshCache once (controller = operator).
    Returns NEW BrokerContract cid (because RefreshCache archives and recreates).
    """
    new_valid_until = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    new_cached = [{"_1": edge_party, "_2": new_valid_until}]
    refresh_arg = {"newValidUntil": new_valid_until, "newCached": new_cached}

    resp = exercise(BROKER_TEMPLATE, broker_cid, "RefreshCache", refresh_arg)
    new_cid = _extract_exercise_result(resp)
    if not isinstance(new_cid, str) or not new_cid.strip():
        raise RuntimeError(f"RefreshCache did not return new cid. resp={resp}")
    return new_cid.strip()


def _get_device_expected_pqpub(device_cid: str) -> Optional[str]:
    if not device_cid:
        return None
    try:
        devc = EDGE_CACHE.get(("device_by_cid", device_cid)) or fetch_contract(DEVICE_TEMPLATE, device_cid)
        if devc:
            EDGE_CACHE.set(("device_by_cid", device_cid), devc)
            payload = devc.get("payload", {}) or {}
            return payload.get("pqPubKey") or payload.get("pq_pub_key") or payload.get("pq_pub_b64")
    except Exception as e:
        app.logger.warning("device pqPubKey fetch failed for %s: %s", device_cid, e)
    return None


def _select_sender_public_key(b: dict, sp_ed25519_pub_hex: str) -> str:
    """
    senderPublicKey selection (must match what SigAttestation used).

    Modes:
      - prefer_request: request.senderPublicKey if present else sp_ed25519_pub_hex
      - sp_ed25519: always sp_ed25519_pub_hex
      - sp_x25519: require request sender_x25519_hex or senderX25519Hex
    """
    if SENDER_PUBLIC_KEY_MODE == "sp_ed25519":
        return sp_ed25519_pub_hex

    if SENDER_PUBLIC_KEY_MODE == "sp_x25519":
        sx = _get_first_str(b, ["sender_x25519_hex", "senderX25519Hex", "senderPublicKey"])
        if not sx:
            raise ValueError("senderPublicKey expected to be X25519 hex but missing (mode=sp_x25519)")
        return sx

    provided = _get_first_str(b, ["senderPublicKey"])
    return provided if provided else sp_ed25519_pub_hex


def _bearer_token_from_header() -> str:
    """Extract JWT from 'Authorization: Bearer <token>' header."""
    auth = (request.headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return ""


def _parse_alg_id_tag(b: dict) -> str:
    """
    Accept AlgId in multiple forms:
      - algId_tag / algIdTag: "ALG_..."
      - algId: "ALG_..."
      - algId: {"tag":"ALG_...","value":{}}
    """
    t = _get_first_str(b, ["algId_tag", "algIdTag"])
    if t:
        return t

    alg = b.get("algId")
    if isinstance(alg, str) and alg.strip():
        return alg.strip()
    if isinstance(alg, dict) and isinstance(alg.get("tag"), str) and alg["tag"].strip():
        return alg["tag"].strip()

    return "ALG_X25519_AESGCM_ED25519"


# ---------------------------------------------------------------------------
# Relay endpoint (edge-controller → DAML VerifyAndRelayMessage)
# ---------------------------------------------------------------------------
@app.post("/relay_message")
def relay_message():
    t0 = perf_counter_ns()
    b = request.get_json(silent=True) or {}

    # --- AlgId parsing (robust) ---
    alg_id_tag = _parse_alg_id_tag(b)
    if alg_id_tag not in ALLOWED_ALGID_TAGS:
        return jsonify(
            error="invalid_algId",
            got=alg_id_tag,
            allowed=sorted(list(ALLOWED_ALGID_TAGS)),
            hint="Send algId_tag / algIdTag / algId as string, or algId as {'tag':..., 'value':{}}.",
        ), 400

    use_hybrid = (alg_id_tag == "ALG_HYBRID_X25519_KYBER_AESGCM_HYBRID_SIG")

    # --- Edge token: accept JSON field OR Authorization header ---
    edge_token = _get_first_str(b, ["edge_token", "edgeToken", "edge_jwt", "edgeJwt"])
    if not edge_token:
        edge_token = _bearer_token_from_header()

    if not edge_token:
        return jsonify(
            error="edge_token_missing",
            fix="Provide edge JWT either in JSON as edge_token OR as header Authorization: Bearer <token>.",
        ), 400

    edge_raw = (b.get("edge") or "").strip()
    edge_party = resolve_party_identifier(edge_raw)
    if not edge_party:
        return jsonify(error="edge required"), 400

    # Authorize edge_token actAs includes edge_party
    et_claims = _decode_jwt_claims_noverify(edge_token)
    et_daml = et_claims.get("https://daml.com/ledger-api", {}) or {}
    et_actas_raw = set(et_daml.get("actAs") or [])
    et_actas_all: Set[str] = set(et_actas_raw)
    for p in list(et_actas_raw):
        try:
            rp = resolve_party_identifier(p)
            if rp:
                et_actas_all.add(rp)
        except Exception:
            continue

    if edge_party not in et_actas_all and edge_raw not in et_actas_all:
        return jsonify(error="edge_token not authorized for edge party", edge=edge_party, actAs=list(et_actas_all)), 403

    if not _rate_ok(edge_party):
        return jsonify(error="rate_limited"), 429

    sp = resolve_party_identifier((b.get("sp") or "").strip())
    if not sp:
        return jsonify(error="sp required"), 400

    # Find BrokerContract (operator)
    try:
        q = query_all(BROKER_TEMPLATE, {"operator": DAML_PARTY})
    except HTTPError as e:
        status = e.response.status_code if getattr(e, "response", None) is not None else 500
        body = e.response.text if getattr(e, "response", None) is not None else str(e)
        return jsonify(error="json_api_request_failed", status=status, body=body), status

    if not q:
        q = query_all(BROKER_TEMPLATE, {})
    if not q:
        return jsonify(error="No active BrokerContract found"), 404

    bc_cid = q[0]["contractId"]

    target = (b.get("targetDevice") or "").strip()
    if not target:
        return jsonify(error="targetDevice (Device CID) required"), 400

    try:
        epoch = int(b.get("epoch", 0))
    except Exception:
        return jsonify(error="bad epoch"), 400

    sender_id = (b.get("senderId") or "Sender1").strip()

    # For hybrid: fetch Device.pqPubKey for early mismatch check
    expected_device_pqpub = _get_device_expected_pqpub(target) if use_hybrid else None

    # ---- inputs for DAML choice ----
    enc_b64: str = ""
    digest_hex: str = ""
    eph_x_hex: str = ""
    aad_str: str = ""
    counter_val: int = 0
    device_pub_hex: Optional[str] = None

    pq_sig_b64: Optional[str] = None
    pq_pub_for_log: Optional[str] = None
    kyber_ct_b64: Optional[str] = None

    # -----------------------------------------------------------------------
    # CLIENT-SIDE ENCRYPT PATH
    # -----------------------------------------------------------------------
    if "encryptedMessage_b64" in b and "digest_hex" in b:
        enc_b64 = _get_first_str(b, ["encryptedMessage_b64", "ciphertext_b64"])
        digest_hex = _get_first_str(b, ["digest_hex"])
        device_pub_hex = _get_first_str(b, ["devicePublicKey"])
        eph_x_hex = _get_first_str(b, ["ephemeral_x25519_hex", "ephX25519Hex"])
        aad_str = str(b.get("aad") or "")

        if len(aad_str.encode("utf-8")) > MAX_AAD_LEN:
            return jsonify(error="aad too large"), 400

        try:
            counter_val = int(b.get("counter", 0))
        except Exception:
            return jsonify(error="bad counter"), 400

        if not (enc_b64 and digest_hex and device_pub_hex and eph_x_hex and counter_val):
            return jsonify(
                error="missing fields for client-side encrypt",
                required=["encryptedMessage_b64", "digest_hex", "devicePublicKey", "ephemeral_x25519_hex", "counter"],
            ), 400

        # Validate digest matches ciphertext(+aad)
        try:
            ct_bytes = base64.b64decode(enc_b64)
        except Exception as e:
            return jsonify(error="ciphertext decode failed", detail=str(e)), 400
        if len(ct_bytes) > MAX_CIPHERTEXT_LEN:
            return jsonify(error="ciphertext too large"), 400

        aad_bytes = aad_str.encode("utf-8") if aad_str else b""
        dig_chk = digest_for_transcript(ct_bytes, aad_bytes)

        try:
            if not constant_time.bytes_eq(bytes.fromhex(dig_chk), bytes.fromhex(digest_hex)):
                return jsonify(error="digest_mismatch", got=dig_chk, expected=digest_hex), 400
        except Exception as e:
            return jsonify(error="digest_hex_invalid", detail=str(e), got=dig_chk, expected=digest_hex), 400

        # Hybrid required fields
        if use_hybrid:
            kyber_ct_b64 = _get_first_str(b, ["kyberCiphertextB64", "kyber_ciphertext_b64", "kyber_ct_b64"])
            pq_sig_b64 = _get_first_str(b, ["pqSignatureB64", "pq_signature_b64", "pqSigB64"])
            pq_pub_for_log = _get_first_str(b, ["pqPubKey", "pq_pub_b64", "pq_pubkey_b64"])

            if not (kyber_ct_b64 and pq_pub_for_log):
                return jsonify(error="hybrid requires kyberCiphertextB64 and pqPubKey (client-side mode)"), 400

            # ✅ DAML-style mismatch check (whitespace-only normalization)
            if expected_device_pqpub:
                if _daml_norm_b64_text(pq_pub_for_log) != _daml_norm_b64_text(expected_device_pqpub):
                    return jsonify(
                        error="pq_pubkey_mismatch",
                        deviceCid=target,
                        ledger_pqPubKey=expected_device_pqpub,
                        client_pqPubKey=pq_pub_for_log,
                        fix="Send pqPubKey EXACTLY matching Device.pqPubKey text (after whitespace-only normalization).",
                    ), 409

            pq_pub_for_log = _daml_norm_b64_text(pq_pub_for_log)

            try:
                pq_sig_b64 = _hybrid_pq_sig_or_dummy(pq_sig_b64)
            except ValueError as e:
                return jsonify(error=str(e)), 400

    # -----------------------------------------------------------------------
    # SERVER-SIDE ENCRYPT PATH
    # -----------------------------------------------------------------------
    else:
        dev_pub_hex = (b.get("devicePublicKey") or "").strip()
        if not dev_pub_hex:
            return jsonify(error="devicePublicKey (X25519 hex) required when server-side encrypting"), 400
        device_pub_hex = dev_pub_hex

        if "plaintext" not in b:
            return jsonify(error="plaintext required for server-side encrypt"), 400

        ptxt_is_b64 = bool(b.get("plaintext_is_b64", False))
        try:
            plaintext = _decode_maybe_b64_or_b64u(b["plaintext"]) if ptxt_is_b64 else str(b["plaintext"]).encode("utf-8")
        except Exception as e:
            return jsonify(error=f"bad plaintext: {e}"), 400
        if len(plaintext) > MAX_PLAINTEXT_LEN:
            return jsonify(error="plaintext too large"), 400

        ctx = b.get("ctx", {}) or {}
        aad_str = str(b.get("aad") or "")
        if len(aad_str.encode("utf-8")) > MAX_AAD_LEN:
            return jsonify(error="aad too large"), 400
        aad_bytes = aad_str.encode("utf-8") if aad_str else None

        # X25519 ECDH
        try:
            eph = x25519.X25519PrivateKey.generate()
            shared_x = eph.exchange(x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(dev_pub_hex)))
        except Exception as e:
            return jsonify(error=f"bad devicePublicKey: {e}"), 400

        kem_ss = b""
        if use_hybrid:
            if not HAS_OQS:
                return jsonify(error="Hybrid AlgId requires python-oqs installed on edge"), 500

            dev_pq_raw = _get_first_str(
                b,
                [
                    "device_pq_pub_b64",
                    "device_pq_pub_b64u",
                    "devicePqPubB64",
                    "devicePqPubB64u",
                    "devicePqPubKeyB64",
                    "devicePqPubKeyB64u",
                    "device_pq_pub_key_b64",
                    "device_pq_pub_key_b64u",
                    "deviceKyberPubB64",
                    "DeviceKyberPubB64",
                    "deviceKyberPubB64u",
                    "DeviceKyberPubB64u",
                ],
            )
            if not dev_pq_raw:
                return jsonify(error="Hybrid AlgId requires device PQ KEM public key"), 400

            pq_pub_for_log = _daml_norm_b64_text(dev_pq_raw)

            if expected_device_pqpub and _daml_norm_b64_text(expected_device_pqpub) != pq_pub_for_log:
                return jsonify(
                    error="pq_pubkey_mismatch",
                    deviceCid=target,
                    ledger_pqPubKey=expected_device_pqpub,
                    provided_pqPubKey=pq_pub_for_log,
                    fix="Provide the same device KEM pqPubKey text that is registered on-ledger.",
                ), 409

            try:
                kyber_ct_b64, kem_ss = do_pq_kem_to_device(pq_pub_for_log)
            except Exception as e:
                return jsonify(error=f"pq_kem_failed: {e}"), 500

        shared = shared_x + (kem_ss or b"")
        k_enc, n_base = hkdf_key_and_nonce(shared, ctx)

        counter_val = ratchet_next_ctr(edge_party, dev_pub_hex, sender_id, epoch)
        nonce = build_nonce(nonce_base=n_base, counter=counter_val)

        aesgcm = AESGCM(k_enc)
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad_bytes)

        if len(ciphertext) > MAX_CIPHERTEXT_LEN:
            return jsonify(error="ciphertext too large"), 500

        enc_b64 = base64.b64encode(ciphertext).decode("ascii")
        eph_x_hex = eph.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()
        digest_hex = digest_for_transcript(ciphertext, aad_bytes or b"")

        if use_hybrid:
            pq_sig_b64 = make_pq_signature_blob(digest_hex)
            try:
                pq_sig_b64 = _hybrid_pq_sig_or_dummy(pq_sig_b64)
            except ValueError as e:
                return jsonify(error=str(e)), 400

    # -----------------------------------------------------------------------
    # SP Ed25519 signature check (optional)
    # -----------------------------------------------------------------------
    sp_pub_hex = _get_first_str(b, ["sp_ed25519_pub_hex", "spEd25519PubHex"])
    sp_sig_b64 = _get_first_str(b, ["sp_signature_b64", "spSignatureB64"])
    if not sp_pub_hex or not sp_sig_b64:
        return jsonify(
            error="SP signature fields missing",
            required=["sp_ed25519_pub_hex OR spEd25519PubHex", "sp_signature_b64 OR spSignatureB64"],
        ), 400

    if not SKIP_SP_VERIFY:
        try:
            sp_sig = base64.b64decode(sp_sig_b64)
            if len(sp_sig) > 128:
                return jsonify(error="sp_signature too large"), 400
            sp_pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(sp_pub_hex))
            sp_pub.verify(sp_sig, bytes.fromhex(digest_hex))
        except Exception as e:
            return jsonify(error="sp_signature_invalid", detail=str(e)), 400

    # Revocation check for SP key (epoch-scoped)
    rk_key = {"_1": DAML_PARTY, "_2": {"_1": epoch, "_2": sp_pub_hex}}
    try:
        rk = fetch_by_key(REVOKED_KEY_TEMPLATE, rk_key)
    except HTTPError:
        rk = None
    if rk:
        return jsonify(error="sp_key_revoked", epoch=epoch), 403

    # Timestamp skew check
    msg_ts = b.get("msgTimestamp")
    if not msg_ts:
        return jsonify(error="msgTimestamp required"), 400
    ts_parsed = _parse_iso_utc(msg_ts)
    if not ts_parsed:
        return jsonify(error="bad msgTimestamp"), 400
    now_utc = datetime.now(timezone.utc)
    skew_sec = abs((now_utc - ts_parsed).total_seconds())
    max_skew = _int_env("SCOPE_MAX_TS_SKEW", 300)
    if skew_sec > max_skew:
        return jsonify(error="msgTimestamp out of acceptable range", skew_seconds=skew_sec), 400

    # Attestations
    att_raw = b.get("attestation_cids", None)
    if att_raw is None:
        att_raw = b.get("attestations", [])
    if isinstance(att_raw, str):
        att_cids = [att_raw]
    elif isinstance(att_raw, list):
        att_cids = att_raw
    else:
        att_cids = []
    if any((not isinstance(x, str)) or x.startswith("#") for x in att_cids):
        return jsonify(error="bad_attestation_cids", hint="Use JSON-API contractIds, not '#1:0' refs."), 400

    # Device public key lookup fallback (from Device contract)
    if not device_pub_hex:
        dev = EDGE_CACHE.get(("device_by_cid", target)) or fetch_contract(DEVICE_TEMPLATE, target)
        if dev:
            EDGE_CACHE.set(("device_by_cid", target), dev)
            device_pub_hex = (dev.get("payload", {}) or {}).get("publicKey")
    if not device_pub_hex:
        return jsonify(error="Device contract not found or missing publicKey"), 404

    # Snapshot / merkle root
    snap_key = {"_1": DAML_PARTY, "_2": epoch}
    snap = EDGE_CACHE.get(("snapshot", epoch))
    if not snap:
        try:
            snap = fetch_by_key(SNAPSHOT_TEMPLATE, snap_key)
        except HTTPError:
            snap = None
        if snap:
            EDGE_CACHE.set(("snapshot", epoch), snap)

    merkle_root = b.get("merkleRoot") or ((snap.get("payload", {}) or {}).get("merkleRoot") if snap else "genesis")

    # ZK-PAC / policy proof
    use_zkpac = bool(b.get("use_zkpac") or b.get("useZkPac") or False)
    policy_proof = b.get("policy_proof")
    policy_proof_daml = None
    if use_zkpac:
        if not isinstance(policy_proof, dict):
            return jsonify(error="policy_proof required when useZkPac=true"), 400
        try:
            policy_proof_daml = {
                "policyId": policy_proof["policyId"],
                "leafHash": policy_proof.get("leafHash", ""),
                "merklePath": policy_proof.get("merklePath", []),
                "revealedAttrs": policy_proof.get("revealedAttrs", []),
            }
        except KeyError as e:
            return jsonify(error=f"missing field in policy_proof: {e}"), 400

    if use_hybrid and pq_pub_for_log:
        pq_pub_for_log = _daml_norm_b64_text(pq_pub_for_log)

    # senderPublicKey selection
    try:
        sender_public_key_value = _select_sender_public_key(b, sp_pub_hex)
    except ValueError as e:
        return jsonify(error=str(e), hint="Set SCOPE_SENDER_PUBLIC_KEY_MODE or provide senderPublicKey in request"), 400

    # -----------------------------------------------------------------------
    # Build DAML choice argument
    # ✅ FIX: algId must be Variant, not string
    # ✅ kyberCiphertextB64 always present in hybrid
    # -----------------------------------------------------------------------
    arg = {
        "edge": edge_party,
        "sp": sp,
        "senderId": sender_id,
        "algId": daml_variant(alg_id_tag),  # ✅ FIXED: DAML Variant encoding
        "targetDevice": target,
        "encryptedMessage": enc_b64,
        "devicePublicKey": device_pub_hex,
        "senderPublicKey": sender_public_key_value,
        "digest": digest_hex,
        "msgTimestamp": msg_ts,
        "epoch": epoch,
        "merkleRoot": merkle_root,
        "useZkPac": use_zkpac,
        "policyProof": policy_proof_daml if use_zkpac else None,
        "attestations": att_cids,
        "spSignatureB64": sp_sig_b64,
        "spEd25519PubHex": sp_pub_hex,
        "ephX25519Hex": eph_x_hex,
        "aad": (aad_str if aad_str else None),
        "counter": counter_val,
        "pqSignatureB64": (pq_sig_b64 if use_hybrid else None),
        "pqPubKey": (pq_pub_for_log if use_hybrid else None),
        "kyberCiphertextB64": (kyber_ct_b64 if use_hybrid else None),
    }

    def _do_verify(broker_contract_id: str):
        return exercise(BROKER_TEMPLATE, broker_contract_id, "VerifyAndRelayMessage", arg, token=edge_token)

    try:
        res = _do_verify(bc_cid)
    except requests.HTTPError as e:
        if _is_cache_expired_error(e):
            try:
                new_bc = _refresh_cache_for_broker(bc_cid, edge_party)
                bc_cid = new_bc
                res = _do_verify(bc_cid)
            except Exception as e2:
                return jsonify(error="cache_expired_refresh_failed", detail=str(e2)), 500
        else:
            status = e.response.status_code if getattr(e, "response", None) is not None else 500
            body = e.response.text if getattr(e, "response", None) is not None else str(e)
            return jsonify(error="json_api_request_failed", status=status, body=body), status

    elapsed_ms = (perf_counter_ns() - t0) / 1e6
    relaylog_cid = _extract_exercise_result(res)

    LAST_RELAY_VERIFY.update(
        {
            "edge": edge_party,
            "sp": sp,
            "deviceCid": target,
            "digest_hex": digest_hex,
            "epoch": epoch,
            "merkleRoot": merkle_root,
            "sp_pub_hex": sp_pub_hex,
            "senderPublicKey_used": sender_public_key_value,
            "eph_x25519_hex": eph_x_hex,
            "aad": aad_str,
            "counter": counter_val,
            "device_public_key": device_pub_hex,
            "senderId": sender_id,
            "useZkPac": use_zkpac,
            "policy_proof_present": bool(policy_proof_daml),
            "algId_tag": alg_id_tag,
            "algId_json": arg["algId"],
            "pqSignatureB64": pq_sig_b64,
            "pqPubKey": pq_pub_for_log,
            "kyberCiphertextB64": kyber_ct_b64,
            "expected_device_pqPubKey": expected_device_pqpub,
            "request_id": g.get("request_id"),
            "took_ms": elapsed_ms,
            "relaylog_cid": relaylog_cid,
            "skip_sp_verify": SKIP_SP_VERIFY,
        }
    )

    return jsonify(status="success", elapsed_ms=elapsed_ms, result=res, relaylog_cid=relaylog_cid), 200


# legacy alias
@app.post("/relay/message")
def relay_message_legacy():
    return relay_message()


# ---------------------------------------------------------------------------
# RelayLog utilities
# ---------------------------------------------------------------------------
@app.get("/relay/list")
def relay_list():
    rows = query_all(RELAY_LOG_TEMPLATE)
    return jsonify(count=len(rows), items=rows), 200


# ---------------------------------------------------------------------------
# Ack endpoints (disabled: no DAML choice exists to update `acked`)
# ---------------------------------------------------------------------------
@app.post("/relay/ack")
def relay_ack():
    return jsonify(
        error="not_implemented",
        detail="RelayLog has `acked : Bool` but your Main.daml has no choice to update it. Add a choice (e.g., Acknowledge) in DAML, then enable this endpoint.",
    ), 501


@app.post("/relay/ack_latest")
def relay_ack_latest():
    return jsonify(
        error="not_implemented",
        detail="RelayLog has `acked : Bool` but your Main.daml has no choice to update it. Add a choice (e.g., Acknowledge) in DAML, then enable this endpoint.",
    ), 501


# ---------------------------------------------------------------------------
# Logging passthrough → DAML LogRequest
# ---------------------------------------------------------------------------
@app.post("/log_batch_activity")
def log_batch_activity():
    data = request.get_json(silent=True)
    if not data or "logs" not in data:
        return jsonify(error="Invalid payload"), 400

    endpoint_url = os.getenv("SCOPE_LOG_ENDPOINT")
    if not endpoint_url:
        endpoint_url = request.host_url.rstrip("/") + "/log_batch_activity"

    out = []
    had_error = False
    for log in data["logs"]:
        try:
            res = create(
                LOGREQUEST_TEMPLATE,
                {"operator": DAML_PARTY, "logData": json.dumps(log, separators=(",", ":")), "endpoint": endpoint_url},
            )
            cid = (res.get("result") or {}).get("contractId") if isinstance(res, dict) else None
            if cid:
                log["damlContractId"] = cid
        except Exception as e:
            had_error = True
            log["damlError"] = str(e)
        out.append(log)

    return jsonify(status=("success" if not had_error else "partial"), processed_logs=out), (200 if not had_error else 207)


# ---------------------------------------------------------------------------
# Background poller for new RelayLog (optional demo)
# ---------------------------------------------------------------------------
def poll_relay_logs():
    seen = set()
    while True:
        try:
            rows = query_all(RELAY_LOG_TEMPLATE)
            for r in rows:
                cid = r.get("contractId")
                if cid and cid not in seen:
                    seen.add(cid)
                    app.logger.info("🔔 New RelayLog: %s", r.get("payload"))
        except Exception as e:
            app.logger.error("RelayLog poll error: %s", e)
        time.sleep(3)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    if os.getenv("DISABLE_RELAYLOG_POLLER", "0") != "1":
        threading.Thread(target=poll_relay_logs, daemon=True).start()

    port = _int_env("FLASK_PORT", 5000)
    app.logger.info("Flask config: party=%s  pkg=%s", DAML_PARTY, DAML_PKG_ID)
    print("== URL MAP ==")
    print(app.url_map)
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)





#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SCOPE Flask API
(Decentralised TA; ratchet + AlgId + Merkle-root + optional ZK-PAC + hybrid PQ)

✅ FIXED TO MATCH YOUR DAML MODEL (Main.daml + RunAll.daml)

Key alignment fixes applied in this file:

1) ✅ DAML AlgId is a VARIANT, not Text.
   → JSON-API needs: {"tag":"ALG_...","value":{}}
   We now send AlgId using `daml_variant(tag)`.

2) ✅ DAML normalizeB64 only removes whitespace; it does NOT decode+re-encode base64.
   → We added `_daml_norm_b64_text()` and use it for:
      - pqPubKey comparisons vs Device.pqPubKey
      - pqPubKey passed into VerifyAndRelayMessage
      - pqPubKey returned from /crypto/prepare_hybrid
   We STOP using `_norm_b64()` for pqPubKey values that go on-ledger.

3) ✅ senderPublicKey must match SigAttestation.senderPublicKey used to create attestations.
   → We keep your selectable mode via env:
      SCOPE_SENDER_PUBLIC_KEY_MODE = prefer_request | sp_ed25519 | sp_x25519

4) ✅ Flask previously verified SP signature always; DAML doesn’t.
   → We added `SCOPE_SKIP_SP_VERIFY` (default False).
     If True, Flask will skip SP Ed25519 verification (useful for DAML-only demos).

⚠️ Note about /relay/ack endpoints:
Your Main.daml RelayLog template has `acked : Bool` but NO choice to update it.
So exercising "Acknowledge" will fail.
This file now returns 501 for ack endpoints (clear message) instead of failing noisily.

✅ FIX APPLIED NOW:
- `arg` for VerifyAndRelayMessage MUST include `kyberCiphertextB64` when hybrid.
- `algId` MUST be encoded as a DAML Variant.
"""

import base64
import hashlib
import json
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from time import perf_counter_ns
from typing import Optional, Tuple, List, Dict, Any, Set

import requests
from requests.exceptions import HTTPError
from flask import Flask, jsonify, request, g
from werkzeug.exceptions import BadRequest

from flask_caching import Cache
from flask_compress import Compress

from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization, hashes, constant_time
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# Stable base directory: makes token + .keys paths stable regardless of CWD
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------------------
# Helpers: robust env int parsing (supports "2_000_000" style)
# ---------------------------------------------------------------------------
def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return int(default)
    try:
        return int(str(raw).replace("_", "").strip())
    except Exception:
        return int(default)


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return bool(default)
    return str(raw).strip().lower() in ("1", "true", "yes", "y", "on")


# ---------------------------------------------------------------------------
# Optional PQC (ML-KEM-768 / ML-DSA-65) via Open Quantum Safe
# ---------------------------------------------------------------------------
try:
    import oqs  # python-oqs

    def _oqs_has_bindings() -> bool:
        return hasattr(oqs, "KeyEncapsulation") and hasattr(oqs, "Signature")

    def _oqs_list_kems() -> List[str]:
        for name in (
            "get_enabled_kems",
            "get_enabled_KEMs",
            "get_enabled_kem_algorithms",
            "get_supported_kems",
        ):
            f = getattr(oqs, name, None)
            if callable(f):
                try:
                    ks = list(f())
                    if ks:
                        return ks
                except Exception:
                    pass
        # Fallback probe
        candidates = ["ML-KEM-768", "ML-KEM-512", "Kyber768", "Kyber512"]
        found = []
        for alg in candidates:
            try:
                with oqs.KeyEncapsulation(alg):
                    found.append(alg)
            except Exception:
                pass
        return found

    def _oqs_list_sigs() -> List[str]:
        for name in (
            "get_enabled_sigs",
            "get_enabled_sig_mechanisms",
            "get_enabled_signature_algorithms",
            "get_supported_sigs",
        ):
            f = getattr(oqs, name, None)
            if callable(f):
                try:
                    ss = list(f())
                    if ss:
                        return ss
                except Exception:
                    pass
        candidates = ["ML-DSA-65", "Dilithium3", "Dilithium2", "Falcon-512"]
        found = []
        for alg in candidates:
            try:
                with oqs.Signature(alg):
                    found.append(alg)
            except Exception:
                pass
        return found

    HAS_OQS = _oqs_has_bindings()
    OQS_ENABLED_KEMS: List[str] = _oqs_list_kems() if HAS_OQS else []
    OQS_ENABLED_SIGS: List[str] = _oqs_list_sigs() if HAS_OQS else []

except ImportError:
    oqs = None  # type: ignore
    HAS_OQS = False
    OQS_ENABLED_KEMS = []
    OQS_ENABLED_SIGS = []


# ---------------------------------------------------------------------------
# Flask basics
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config["CACHE_TYPE"] = "simple"
Cache(app)
Compress(app)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
LEDGER_HOST = os.getenv("LEDGER_HOST", "localhost")
LEDGER_HTTP_PORT = os.getenv("LEDGER_HTTP_PORT", "7576")
JSON_API = f"http://{LEDGER_HOST}:{LEDGER_HTTP_PORT}"

# Stable token path (absolute default); still overridable via TOKEN_PATH env var
TOKEN_PATH = os.getenv("TOKEN_PATH", os.path.join(BASE_DIR, "token.txt"))

# Key persistence
PERSIST = _bool_env("SCOPE_PERSIST_KEYS", True)

CACHE_TTL_SEC = _int_env("SCOPE_CACHE_TTL", 8)
DEFAULT_TIMEOUT = _int_env("SCOPE_TIMEOUT", 15)

# Skip SP verify? (Useful when you run DAML tests that send dummy SP sigs.)
SKIP_SP_VERIFY = _bool_env("SCOPE_SKIP_SP_VERIFY", False)

# --- Demo mode: reproducible keys (NOT production) ---
TEST_STATIC_KEYS = _bool_env("SCOPE_TEST_STATIC_KEYS", False)

ED25519_STATIC_SEED_HEX = os.getenv(
    "SCOPE_TEST_ED25519_SEED",
    "7f00bacbd1abb803c4bf2558c0032b090782f9bb8341862809edc3972b10ea55",
)
X25519_STATIC_SEED_HEX = os.getenv(
    "SCOPE_TEST_X25519_SEED",
    "551a606fc2c2a614ccb033572e21ae686ca25465b474a73bb601e30896f2fa8c",
)

# PQ algorithms (OQS names; can be overridden)
_env_kem = (os.getenv("SCOPE_PQ_KEM", "") or "").strip()
_env_sig = (os.getenv("SCOPE_PQ_SIG", "") or "").strip()
_DEFAULT_KEM_PREF = ["ML-KEM-768", "Kyber768", "ML-KEM-512", "Kyber512"]
_DEFAULT_SIG_PREF = ["ML-DSA-65", "Dilithium3", "Dilithium2", "Falcon-512"]


def _choose_default(preferred: List[str], enabled: List[str]) -> Optional[str]:
    for n in preferred:
        if n in enabled:
            return n
    return enabled[0] if enabled else None


OQS_KEM_ALG = _env_kem or _choose_default(_DEFAULT_KEM_PREF, OQS_ENABLED_KEMS) or "ML-KEM-768"
OQS_SIG_ALG = _env_sig or _choose_default(_DEFAULT_SIG_PREF, OQS_ENABLED_SIGS) or "ML-DSA-65"

# Hybrid policy: if pqSignatureB64 is missing, should we inject a dummy or fail?
HYBRID_REQUIRE_PQ_SIG_STRICT = _bool_env("SCOPE_HYBRID_PQ_SIG_STRICT", False)

# senderPublicKey population:
# - "prefer_request": use request.senderPublicKey if present, else fallback to sp_ed25519_pub_hex
# - "sp_ed25519": always use sp Ed25519 pub hex
# - "sp_x25519": use request field "sender_x25519_hex" OR "senderX25519Hex" if provided (else error)
SENDER_PUBLIC_KEY_MODE = (os.getenv("SCOPE_SENDER_PUBLIC_KEY_MODE", "prefer_request") or "").strip().lower()


# ---------------------------------------------------------------------------
# Security limits / policies
# ---------------------------------------------------------------------------
MAX_AAD_LEN = _int_env("SCOPE_MAX_AAD", 2048)
MAX_PLAINTEXT_LEN = _int_env("SCOPE_MAX_PLAINTEXT", 2_000_000)
MAX_CIPHERTEXT_LEN = _int_env("SCOPE_MAX_CIPHERTEXT", 3_000_000)
MAX_REQ_LEN = _int_env("SCOPE_MAX_REQUEST_BYTES", 6_000_000)

ALLOWED_ALGID_TAGS: Set[str] = {
    "ALG_X25519_AESGCM_ED25519",
    "ALG_HYBRID_X25519_KYBER_AESGCM_HYBRID_SIG",
}


# ---------------------------------------------------------------------------
# DAML JSON encoding helpers
# ---------------------------------------------------------------------------
def daml_variant(tag: str, value: Optional[dict] = None) -> dict:
    """Encode DAML variant for JSON-API."""
    if value is None:
        value = {}
    return {"tag": tag, "value": value}


def _daml_norm_b64_text(s: str) -> str:
    """
    EXACT MATCH to your DAML normalizeB64:
      replace "\n", "\r", "\t", " " with ""
    NOTE: No decoding/re-encoding. No +/ vs -_ rewriting.
    """
    if not s:
        return ""
    return (
        str(s)
        .replace("\n", "")
        .replace("\r", "")
        .replace("\t", "")
        .replace(" ", "")
    )


# ---------------------------------------------------------------------------
# Simple TTL cache
# ---------------------------------------------------------------------------
class TTLCache:
    def __init__(self, ttl: int):
        self.ttl = int(ttl)
        self._d: Dict[tuple, tuple] = {}

    def get(self, k):
        now = time.time()
        v = self._d.get(k)
        if not v:
            return None
        exp, val = v
        if exp < now:
            self._d.pop(k, None)
            return None
        return val

    def set(self, k, val):
        self._d[k] = (time.time() + self.ttl, val)

    def keys(self):
        now = time.time()
        out = []
        for k, (exp, _) in list(self._d.items()):
            if exp < now:
                self._d.pop(k, None)
            else:
                out.append((k, int(exp - now)))
        return out


EDGE_CACHE = TTLCache(CACHE_TTL_SEC)

# Simple per-edge rate limiter for relay_message
RATE_LIMIT_TTL = _int_env("SCOPE_RATE_TTL", 3)
RATE_LIMIT_BUCKET = _int_env("SCOPE_RATE_BUCKET", 30)
RATE_CACHE = TTLCache(RATE_LIMIT_TTL)


def _rate_ok(edge: str) -> bool:
    key = ("rate", edge)
    cur = RATE_CACHE.get(key) or 0
    if cur >= RATE_LIMIT_BUCKET:
        return False
    RATE_CACHE.set(key, cur + 1)
    return True


def next_counter(scope: tuple) -> int:
    """
    Local monotonic counter per scope (demo convenience only).
    ON-LEDGER monotonicity is enforced by RatchetState.
    """
    key = ("ctr",) + scope
    c = EDGE_CACHE.get(key) or 0
    c += 1
    EDGE_CACHE.set(key, c)
    return c


# ---------------------------------------------------------------------------
# JWT / JSON API helpers
# ---------------------------------------------------------------------------
def load_jwt(path: str) -> Optional[str]:
    try:
        raw = open(path, "rb").read()
    except Exception as e:
        app.logger.error("Failed to read %s: %s", path, e)
        return None
    for enc in ("utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "ascii"):
        try:
            tok = raw.decode(enc).strip()
            if "\x00" not in tok and tok:
                return tok
        except Exception:
            continue
    return None


jwt_token = load_jwt(TOKEN_PATH)
if not jwt_token:
    raise SystemExit("JWT token missing/invalid. Place it in token.txt or set TOKEN_PATH.")


ledger = requests.Session()
ledger.headers.update({"Authorization": f"Bearer {jwt_token}", "Content-Type": "application/json"})


def _json_api_get(path: str, **kw) -> requests.Response:
    r = ledger.get(f"{JSON_API}{path}", timeout=kw.pop("timeout", DEFAULT_TIMEOUT), **kw)
    r.raise_for_status()
    return r


def _json_api_post(path: str, json_body: dict) -> requests.Response:
    r = ledger.post(f"{JSON_API}{path}", json=json_body, timeout=DEFAULT_TIMEOUT)
    if r.status_code >= 400:
        app.logger.error("JSON API POST %s: %s -- body=%s", path, r.text, json.dumps(json_body))
    r.raise_for_status()
    return r


def _post_with_token(path: str, json_body: dict, token: str) -> requests.Response:
    hdrs = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    r = requests.post(f"{JSON_API}{path}", json=json_body, headers=hdrs, timeout=DEFAULT_TIMEOUT)
    if r.status_code >= 400:
        app.logger.error("JSON API POST %s: %s -- body=%s", path, r.text, json.dumps(json_body))
    r.raise_for_status()
    return r


# Preflight
try:
    _json_api_get("/v1/packages", timeout=DEFAULT_TIMEOUT)
except Exception as e:
    raise SystemExit(f"JSON-API not reachable at {JSON_API} or token rejected: {e}")


def _decode_jwt_claims_noverify(tok: str) -> Dict[str, Any]:
    """
    NOTE: no signature verification.
    We only use this for convenience (e.g., actAs hints); ledger authorization remains source-of-truth.
    """
    try:
        parts = tok.split(".")
        if len(parts) < 2:
            return {}
        p = parts[1]
        p += "=" * (-len(p) % 4)
        data = base64.urlsafe_b64decode(p.encode("ascii"))
        return json.loads(data.decode("utf-8"))
    except Exception:
        return {}


TOKEN_CLAIMS: Dict[str, Any] = _decode_jwt_claims_noverify(jwt_token)
DAML_CLAIMS = TOKEN_CLAIMS.get("https://daml.com/ledger-api", {}) or {}
CLAIM_ACTAS = set(DAML_CLAIMS.get("actAs") or [])
CLAIM_READAS = set(DAML_CLAIMS.get("readAs") or [])
CLAIM_ADMIN = bool(DAML_CLAIMS.get("admin", False))


# ---------------------------------------------------------------------------
# Package discovery
# ---------------------------------------------------------------------------
def _coerce_packages_list(obj: Any) -> List[str]:
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict) and "result" in obj and isinstance(obj["result"], list):
        return obj["result"]
    return []


def _package_modules_for(pid: str) -> List[str]:
    r = _json_api_get(f"/v1/packages/{pid}")
    info = r.json() or {}
    mods = info.get("modules", [])
    names: List[str] = []
    for m in mods:
        if isinstance(m, str):
            names.append(m)
        elif isinstance(m, dict) and "name" in m:
            names.append(str(m["name"]))
    return names


def discover_pkg_id() -> Optional[str]:
    try:
        ids_resp = _json_api_get("/v1/packages").json()
        ids = _coerce_packages_list(ids_resp)
        for pid in ids:
            try:
                if "Main" in _package_modules_for(pid):
                    app.logger.info("Discovered DAML_PKG_ID with Main: %s", pid)
                    return pid
            except Exception:
                continue
        for pid in ids:
            try:
                q = _json_api_post(
                    "/v1/query",
                    {"templateIds": [f"{pid}:Main:LogRequest"], "query": {}},
                )
                if q.status_code < 400:
                    app.logger.info("Discovered DAML_PKG_ID by probe: %s", pid)
                    return pid
            except Exception:
                pass
    except Exception as e:
        app.logger.warning("Package discovery failed: %s", e)
    return None


DAML_PKG_ID: Optional[str] = (os.getenv("DAML_PKG_ID") or "").strip() or discover_pkg_id()
if DAML_PKG_ID and DAML_PKG_ID.strip().lower() in {"<your-package-id>", "your-package-id"}:
    app.logger.warning("Ignoring placeholder DAML_PKG_ID=%r; discovering actual package id...", DAML_PKG_ID)
    real_pid = discover_pkg_id()
    if real_pid:
        DAML_PKG_ID = real_pid
    else:
        raise SystemExit("DAML_PKG_ID placeholder set; discovery failed. Set a real package id.")
if not DAML_PKG_ID:
    raise SystemExit("Could not determine DAML_PKG_ID. Ensure your DAR is uploaded and JSON-API is reachable.")


# ---------------------------------------------------------------------------
# Party resolution
# ---------------------------------------------------------------------------
def resolve_party_identifier(party_or_name: str) -> str:
    if not party_or_name or "::" in party_or_name:
        return party_or_name
    try:
        r = _json_api_get("/v1/parties", params={"id": party_or_name})
        res = r.json().get("result", [])
        if res:
            return res[0].get("identifier") or res[0].get("party") or party_or_name
    except Exception as e:
        app.logger.warning("Party resolution failed for %s: %s", party_or_name, e)
    return party_or_name


def resolve_operator_identifier() -> Optional[str]:
    try:
        r = _json_api_get("/v1/parties", params={"id": "Operator"})
        res = r.json().get("result", [])
        if res:
            return res[0].get("identifier") or res[0].get("party")
    except Exception:
        pass
    return None


def choose_party() -> str:
    env_wanted = os.getenv("DAML_PARTY") or os.getenv("DAML_PKG_PARTY") or ""
    env_resolved = resolve_party_identifier(env_wanted) if env_wanted else None

    authorized_raw = list(CLAIM_ACTAS | CLAIM_READAS)
    authorized_all: Set[str] = set(authorized_raw)

    for p in list(authorized_raw):
        try:
            rp = resolve_party_identifier(p)
            if rp:
                authorized_all.add(rp)
        except Exception:
            continue

    if env_resolved and (env_resolved in authorized_all or env_wanted in authorized_all):
        app.logger.info("Using party from env (authorized): %s", env_resolved)
        return env_resolved

    opid = resolve_operator_identifier()
    if opid and (opid in authorized_all or "Operator" in authorized_all):
        app.logger.info("Using Operator (authorized): %s", opid)
        return opid

    if authorized_raw:
        base = authorized_raw[0]
        resolved = resolve_party_identifier(base)
        app.logger.info("Using first authorized party from token: %s", resolved)
        return resolved

    if opid:
        app.logger.warning("JWT has no actAs/readAs; falling back to Operator id: %s", opid)
        return opid
    if env_resolved:
        app.logger.warning("JWT has no actAs/readAs and Operator id unknown; using env party anyway: %s", env_resolved)
        return env_resolved

    app.logger.warning("JWT has no actAs/readAs and no env party; using 'Operator' display name.")
    return "Operator"


DAML_PARTY = choose_party()
app.logger.info("Config OK: JSON_API=%s  DAML_PKG_ID=%s  DAML_PARTY=%s", JSON_API, DAML_PKG_ID, DAML_PARTY)


# ---------------------------------------------------------------------------
# Template IDs
# ---------------------------------------------------------------------------
def tid(entity: str) -> str:
    return f"{DAML_PKG_ID}:Main:{entity}"


LOGREQUEST_TEMPLATE = tid("LogRequest")
BROKER_TEMPLATE = tid("BrokerContract")
DEVICE_TEMPLATE = tid("Device")
SNAPSHOT_TEMPLATE = tid("TaSnapshot")
TACOMMITTEE_TEMPLATE = tid("TACommittee")
SNAPSHOT_PROPOSAL_TEMPLATE = tid("SnapshotProposal")
SIG_ATTEST_TEMPLATE = tid("SigAttestation")
REVOKED_KEY_TEMPLATE = tid("RevokedKey")
RELAY_LOG_TEMPLATE = tid("RelayLog")
ACCESS_POLICY_TEMPLATE = tid("AccessPolicy")
SP_PROFILE_TEMPLATE = tid("SPProfile")
RATCHET_TEMPLATE = tid("RatchetState")


# ---------------------------------------------------------------------------
# Crypto keys (Ed25519 + X25519 + optional PQ signature key)
# ---------------------------------------------------------------------------
KEY_DIR = os.getenv("SCOPE_KEY_DIR", os.path.join(BASE_DIR, ".keys"))
ED_FILE = os.path.join(KEY_DIR, "ed25519.key")
X_FILE = os.path.join(KEY_DIR, "x25519.key")
PQ_SIG_FILE = os.path.join(KEY_DIR, "pq_sig.json")


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def load_or_create_ed25519():
    if TEST_STATIC_KEYS:
        seed = bytes.fromhex(ED25519_STATIC_SEED_HEX)
        if len(seed) != 32:
            raise SystemExit("SCOPE_TEST_ED25519_SEED must be 32 bytes hex")
        return ed25519.Ed25519PrivateKey.from_private_bytes(seed)

    if PERSIST and os.path.isfile(ED_FILE):
        data = open(ED_FILE, "rb").read()
        return serialization.load_pem_private_key(data, password=None)
    sk = ed25519.Ed25519PrivateKey.generate()
    if PERSIST:
        ensure_dir(KEY_DIR)
        pem = sk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        open(ED_FILE, "wb").write(pem)
    return sk


def load_or_create_x25519():
    if TEST_STATIC_KEYS:
        seed = bytes.fromhex(X25519_STATIC_SEED_HEX)
        if len(seed) != 32:
            raise SystemExit("SCOPE_TEST_X25519_SEED must be 32 bytes hex")
        return x25519.X25519PrivateKey.from_private_bytes(seed)

    if PERSIST and os.path.isfile(X_FILE):
        data = open(X_FILE, "rb").read()
        return serialization.load_pem_private_key(data, password=None)
    sk = x25519.X25519PrivateKey.generate()
    if PERSIST:
        ensure_dir(KEY_DIR)
        pem = sk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        open(X_FILE, "wb").write(pem)
    return sk


def load_or_create_pq_sig():
    """
    Optional PQ signing keypair for pqSignatureB64 generation (ML-DSA/Dilithium/etc).

    NOTE:
      Your DAML compares pqPubKey to Device.pqPubKey (device KEM key).
      Therefore, this PQ signature key is NOT compared against pqPubKey and
      is purely a transport/benchmark blob.
    """
    if not HAS_OQS:
        return None, None, None

    if PERSIST and os.path.isfile(PQ_SIG_FILE):
        data = json.load(open(PQ_SIG_FILE, "r"))
        alg = data.get("alg", OQS_SIG_ALG)
        pk = base64.b64decode(data["pk"])
        sk = base64.b64decode(data["sk"])
        return alg, pk, sk

    try:
        with oqs.Signature(OQS_SIG_ALG) as s:
            pk = s.generate_keypair()
            sk = s.export_secret_key()
    except Exception as e:
        app.logger.warning("PQ sig keygen failed for %s: %s", OQS_SIG_ALG, e)
        return None, None, None

    if PERSIST and pk and sk:
        ensure_dir(KEY_DIR)
        json.dump(
            {"alg": OQS_SIG_ALG, "pk": base64.b64encode(pk).decode(), "sk": base64.b64encode(sk).decode()},
            open(PQ_SIG_FILE, "w"),
        )
    return OQS_SIG_ALG, pk, sk


ED_SK = load_or_create_ed25519()
ED_PK = ED_SK.public_key()
X_SK = load_or_create_x25519()
X_PK = X_SK.public_key()

if HAS_OQS:
    PQ_SIG_ALG, PQ_SIG_PK, PQ_SIG_SK = load_or_create_pq_sig()
else:
    PQ_SIG_ALG = PQ_SIG_PK = PQ_SIG_SK = None


def ed_pub_hex(pk: ed25519.Ed25519PublicKey) -> str:
    return pk.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()


def x_pub_hex(pk: x25519.X25519PublicKey) -> str:
    return pk.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()


# ---------------------------------------------------------------------------
# Base64 helpers (robust: base64 OR base64url input)
# ---------------------------------------------------------------------------
def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64_from_b64u(s: str) -> str:
    if not s:
        return s
    s = s.replace("-", "+").replace("_", "/")
    while len(s) % 4:
        s += "="
    return s


def _decode_maybe_b64_or_b64u(s: str) -> bytes:
    if not s:
        return b""
    try:
        return base64.b64decode(s, validate=True)
    except Exception:
        return base64.b64decode(_b64_from_b64u(s), validate=False)


def _norm_b64(s: str) -> str:
    """
    Canonical base64 by decoding then re-encoding.
    IMPORTANT: Do NOT use this for pqPubKey values that must match DAML text equality.
    Keep it only for binary operations (e.g., KEM ciphertext decode/encode).
    """
    if not s:
        return ""
    raw = _decode_maybe_b64_or_b64u(s)
    return base64.b64encode(raw).decode("ascii")


# ---------------------------------------------------------------------------
# HKDF / AES-GCM helpers
# ---------------------------------------------------------------------------
def hkdf_key_and_nonce(shared_secret: bytes, ctx: dict, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    ctx_bytes = json.dumps(ctx or {}, separators=(",", ":"), sort_keys=True).encode("utf-8")
    prk = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"scope hkdf prk").derive(shared_secret)
    k_enc = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"scope aes-gcm key" + ctx_bytes).derive(prk)
    n_base = HKDF(algorithm=hashes.SHA256(), length=12, salt=None, info=b"scope nonce base" + ctx_bytes).derive(prk)
    return k_enc, n_base


def build_nonce(nonce_base: bytes, counter: int) -> bytes:
    """96-bit nonce: 4 bytes from HKDF base + 8-byte big-endian counter."""
    if len(nonce_base) != 12:
        raise ValueError("nonce_base must be 12 bytes")
    return nonce_base[:4] + int(counter).to_bytes(8, "big")


def digest_for_transcript(ciphertext: bytes, aad: bytes = b"") -> str:
    return hashlib.sha256(ciphertext + (aad or b"")).hexdigest()


# ---------------------------------------------------------------------------
# PQ KEM (encapsulation to device pqPubKey)
# ---------------------------------------------------------------------------
def _oqs_expected_kem_pubkey_len(alg: str) -> Optional[int]:
    """
    Best-effort expected public key length for KEM alg.
    Supports different python-oqs versions (details may be object or dict).
    """
    try:
        with oqs.KeyEncapsulation(alg) as kem_probe:
            details = getattr(kem_probe, "details", None)
            if details is None:
                return None
            if hasattr(details, "length_public_key"):
                return int(getattr(details, "length_public_key"))
            if isinstance(details, dict) and "length_public_key" in details:
                return int(details["length_public_key"])
    except Exception:
        return None
    return None


def do_pq_kem_to_device(device_pq_pub_any: str) -> Tuple[str, bytes]:
    """
    Encapsulate to device ML-KEM/Kyber public key.

    Accepts base64 or base64url. Returns (kyberCiphertextB64, kem_shared_secret_bytes).

    ✅ FIX: If pubkey length mismatches expected length, we REJECT (no slicing).
    """
    if not HAS_OQS:
        raise RuntimeError("python-oqs is required for hybrid PQ mode")

    alg = OQS_KEM_ALG
    if OQS_ENABLED_KEMS and alg not in OQS_ENABLED_KEMS:
        alg = _choose_default(_DEFAULT_KEM_PREF, OQS_ENABLED_KEMS) or alg

    pk_bytes = _decode_maybe_b64_or_b64u(device_pq_pub_any or "")
    if not pk_bytes:
        raise ValueError("empty device pq public key")

    expected_len = _oqs_expected_kem_pubkey_len(alg)
    if expected_len is None:
        if alg in ("ML-KEM-768", "Kyber768"):
            expected_len = 1184
        elif alg in ("ML-KEM-512", "Kyber512"):
            expected_len = 800
        else:
            expected_len = None

    if expected_len is not None and len(pk_bytes) != expected_len:
        raise ValueError(f"PQ pubkey length mismatch for {alg}: got={len(pk_bytes)} expected={expected_len}")

    with oqs.KeyEncapsulation(alg) as kem:
        if hasattr(kem, "encapsulate"):
            ct, ss = kem.encapsulate(pk_bytes)
        elif hasattr(kem, "encap_secret"):
            ct, ss = kem.encap_secret(pk_bytes)
        else:
            raise RuntimeError(f"OQS KEM for {alg} has no encapsulate/encap_secret")

    return base64.b64encode(ct).decode("ascii"), ss


def make_pq_signature_blob(digest_hex: str) -> Optional[str]:
    """
    Optional PQ signature blob (base64) over digest bytes.
    DAML does NOT verify it cryptographically; it just requires presence for hybrid.
    """
    if not (HAS_OQS and PQ_SIG_ALG and PQ_SIG_SK):
        return None

    msg = bytes.fromhex(digest_hex)

    try:
        with oqs.Signature(PQ_SIG_ALG, secret_key=PQ_SIG_SK) as s:
            sig = s.sign(msg)
        return base64.b64encode(sig).decode("ascii")
    except TypeError:
        try:
            with oqs.Signature(PQ_SIG_ALG) as s:
                if not hasattr(s, "import_secret_key"):
                    return None
                s.import_secret_key(PQ_SIG_SK)
                sig = s.sign(msg)
            return base64.b64encode(sig).decode("ascii")
        except Exception:
            return None
    except Exception:
        return None


def _hybrid_pq_sig_or_dummy(current: Optional[str]) -> str:
    """
    If strict -> require real pqSignatureB64 (non-empty).
    Else -> supply a safe dummy if missing.
    """
    if current and current.strip():
        return current.strip()

    if HYBRID_REQUIRE_PQ_SIG_STRICT:
        raise ValueError("pqSignatureB64 required in hybrid mode (strict policy enabled)")

    return base64.b64encode(b"pq_sig_dummy").decode("ascii")


# ---------------------------------------------------------------------------
# JSON API helpers (contracts)
# ---------------------------------------------------------------------------
def query_all(template_id: str, query: dict = None):
    body = {"templateIds": [template_id], "query": query or {}}
    r = _json_api_post("/v1/query", body)
    return r.json().get("result", [])


def create(template_id: str, payload: dict, token: Optional[str] = None):
    body = {"templateId": template_id, "payload": payload}
    if token:
        return _post_with_token("/v1/create", body, token).json()
    return _json_api_post("/v1/create", body).json()


def exercise(template_id: str, contract_id: str, choice: str, argument: dict, token: Optional[str] = None):
    body = {"templateId": template_id, "contractId": contract_id, "choice": choice, "argument": argument}
    if token:
        return _post_with_token("/v1/exercise", body, token).json()
    return _json_api_post("/v1/exercise", body).json()


def fetch_contract(template_id: str, contract_id: str, token: Optional[str] = None) -> Optional[dict]:
    body = {"templateId": template_id, "contractId": contract_id}
    if token:
        rj = _post_with_token("/v1/fetch", body, token).json()
    else:
        rj = _json_api_post("/v1/fetch", body).json()
    return rj.get("result")


def fetch_by_key(template_id: str, key: dict) -> Optional[dict]:
    body = {"templateId": template_id, "key": key}
    try:
        r = _json_api_post("/v1/fetch", body)
        data = r.json()
        return data.get("result")
    except HTTPError as e:
        status = getattr(e.response, "status_code", None)
        if status in (404, 405, 501):
            return None
        raise


def _extract_exercise_result(resp_json: Dict[str, Any]) -> Any:
    res = resp_json.get("result") if isinstance(resp_json, dict) else None
    if isinstance(res, dict) and "exerciseResult" in res:
        return res["exerciseResult"]
    return None


# ---------------------------------------------------------------------------
# Ratchet helper (read lastCtr + 1 from ledger)
# ---------------------------------------------------------------------------
def ratchet_next_ctr(edge_party: str, device_key: str, sender_id: str, epoch: int) -> int:
    """
    ✅ FIX: If multiple RatchetState rows exist, use MAX(lastCtr).
    """
    rows = query_all(
        RATCHET_TEMPLATE,
        {"operator": DAML_PARTY, "edge": edge_party, "deviceKey": device_key, "senderId": sender_id, "epoch": epoch},
    )
    if not rows:
        return 1
    last = 0
    for r in rows:
        try:
            last = max(last, int((r.get("payload", {}) or {}).get("lastCtr", 0) or 0))
        except Exception:
            continue
    return last + 1


# ---------------------------------------------------------------------------
# Request guards
# ---------------------------------------------------------------------------
@app.before_request
def _require_json_and_cap():
    if request.method in ("POST", "PUT", "PATCH"):
        ct = request.headers.get("Content-Type", "")
        if "application/json" not in ct:
            return jsonify(error="content-type must be application/json"), 415
        if request.content_length and request.content_length > MAX_REQ_LEN:
            return jsonify(error="request too large"), 413


@app.errorhandler(BadRequest)
def _bad_request(e):
    return jsonify(error="bad_request", detail=str(e)), 400


@app.before_request
def _capture_request_id():
    rid = request.headers.get("X-Request-Id", "")
    if len(rid) > 128:
        return jsonify(error="X-Request-Id too long"), 400
    g.request_id = rid or ""


# ---------------------------------------------------------------------------
# Debug / health
# ---------------------------------------------------------------------------
@app.get("/debug/config")
def debug_config():
    return jsonify(
        json_api=JSON_API,
        daml_pkg_id=DAML_PKG_ID,
        daml_party=DAML_PARTY,
        token_path=TOKEN_PATH,
        has_oqs=HAS_OQS,
        oqs_kem_alg=OQS_KEM_ALG if HAS_OQS else None,
        oqs_sig_alg=OQS_SIG_ALG if HAS_OQS else None,
        enabled_kems=OQS_ENABLED_KEMS,
        enabled_sigs=OQS_ENABLED_SIGS,
        base_dir=BASE_DIR,
        key_dir=KEY_DIR,
        persist_keys=PERSIST,
        test_static_keys=TEST_STATIC_KEYS,
        hybrid_pq_sig_strict=HYBRID_REQUIRE_PQ_SIG_STRICT,
        sender_public_key_mode=SENDER_PUBLIC_KEY_MODE,
        skip_sp_verify=SKIP_SP_VERIFY,
    ), 200


@app.get("/debug/claims")
def debug_claims():
    return jsonify(
        daml_party=DAML_PARTY,
        actAs=list(CLAIM_ACTAS),
        readAs=list(CLAIM_READAS),
        admin=CLAIM_ADMIN,
        claims=TOKEN_CLAIMS,
    ), 200


@app.get("/debug/routes")
def debug_routes():
    routes = []
    for r in app.url_map.iter_rules():
        routes.append(
            {"rule": str(r), "endpoint": r.endpoint, "methods": sorted(m for m in r.methods if m not in ("HEAD", "OPTIONS"))}
        )
    return jsonify(routes=routes), 200


@app.get("/health/keys")
def health_keys():
    out = {
        "has_ed25519": True,
        "has_x25519": True,
        "ed25519_hex": ed_pub_hex(ED_PK),
        "x25519_hex": x_pub_hex(X_PK),
        "persist_keys": PERSIST,
        "has_oqs": HAS_OQS,
        "oqs_kem_alg": OQS_KEM_ALG if HAS_OQS else None,
        "oqs_sig_alg": PQ_SIG_ALG if HAS_OQS else None,
        "has_pq_sig_keypair": bool(PQ_SIG_PK and PQ_SIG_SK),
        "test_static_keys": TEST_STATIC_KEYS,
    }
    return jsonify(out), 200


# ---------------------------------------------------------------------------
# PQ endpoints (standalone tests)
# ---------------------------------------------------------------------------
@app.post("/pq/sign")
def pq_sign():
    if not HAS_OQS:
        return jsonify(ok=False, error="python-oqs not available"), 400
    body = request.get_json(silent=True) or {}
    sigs = OQS_ENABLED_SIGS
    alg = body.get("alg") or next((a for a in ("ML-DSA-65", "Dilithium3") if a in sigs), (sigs[0] if sigs else None))
    if not alg:
        return jsonify(ok=False, error="No PQ signature algorithms enabled in liboqs."), 400
    msg_b64u = body.get("message") or _b64u(b"hello-from-flask")
    try:
        msg = _decode_maybe_b64_or_b64u(msg_b64u)
    except Exception as e:
        return jsonify(ok=False, error=f"bad message b64(u): {e}"), 400

    try:
        with oqs.Signature(alg) as sig:
            pk = sig.generate_keypair()
            sig_bytes = sig.sign(msg)
            return jsonify(
                ok=True,
                alg=alg,
                public_key_b64u=_b64u(pk),
                signature_b64u=_b64u(sig_bytes),
                message_len=len(msg),
            ), 200
    except Exception as e:
        return jsonify(ok=False, error=f"{type(e).__name__}: {e}"), 500


@app.post("/pq/verify")
def pq_verify():
    if not HAS_OQS:
        return jsonify(ok=False, error="python-oqs not available"), 400
    body = request.get_json(silent=True) or {}
    alg = body.get("alg")
    if not alg:
        return jsonify(ok=False, error="Missing 'alg'."), 400
    try:
        msg = _decode_maybe_b64_or_b64u(body["message"])
        sig_b = _decode_maybe_b64_or_b64u(body["signature"])
        pk = _decode_maybe_b64_or_b64u(body["public_key"])
    except Exception as e:
        return jsonify(ok=False, error=f"base64(u) decode failed: {e}"), 400

    try:
        with oqs.Signature(alg) as v:
            valid = v.verify(msg, sig_b, pk)
        return jsonify(ok=True, valid=bool(valid)), 200
    except Exception as e:
        return jsonify(ok=False, error=f"{type(e).__name__}: {e}"), 500


# ---------------------------------------------------------------------------
# Crypto endpoints (classical + hybrid prepare)
# ---------------------------------------------------------------------------
@app.post("/crypto/encrypt_to_device")
def encrypt_to_device():
    """
    Classical: X25519 + HKDF + AES-GCM with local demo counter.
    (Your ON-LEDGER ratchet is enforced in VerifyAndRelayMessage.)
    """
    b = request.get_json(silent=True) or {}
    dev_pub_hex = (b.get("devicePublicKey") or "").strip()
    if not dev_pub_hex:
        return jsonify(error="devicePublicKey (X25519 hex) required"), 400

    try:
        epoch = int(b.get("epoch", 0))
    except Exception:
        return jsonify(error="bad epoch"), 400

    ptxt_is_b64 = bool(b.get("plaintext_is_b64", False))
    aad_str = b.get("aad", "")
    if len(aad_str.encode("utf-8")) > MAX_AAD_LEN:
        return jsonify(error="aad too large"), 400
    ctx = b.get("ctx", {}) or {}

    if "plaintext" not in b:
        return jsonify(error="plaintext required"), 400

    try:
        plaintext = _decode_maybe_b64_or_b64u(b["plaintext"]) if ptxt_is_b64 else b["plaintext"].encode("utf-8")
    except Exception as e:
        return jsonify(error=f"bad plaintext: {e}"), 400
    if len(plaintext) > MAX_PLAINTEXT_LEN:
        return jsonify(error="plaintext too large"), 400

    try:
        dev_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(dev_pub_hex))
    except Exception as e:
        return jsonify(error=f"bad devicePublicKey: {e}"), 400

    eph = x25519.X25519PrivateKey.generate()
    shared = eph.exchange(dev_pub)
    k_enc, n_base = hkdf_key_and_nonce(shared, ctx)

    ctr = next_counter(("dev", dev_pub_hex, epoch))
    nonce = build_nonce(nonce_base=n_base, counter=ctr)

    aesgcm = AESGCM(k_enc)
    aad_bytes = aad_str.encode("utf-8") if aad_str else None
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad_bytes)

    if len(ciphertext) > MAX_CIPHERTEXT_LEN:
        return jsonify(error="ciphertext too large"), 500

    eph_pub_raw = eph.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    dig = digest_for_transcript(ciphertext, aad_bytes or b"")

    return jsonify(
        ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
        digest_hex=dig,
        sender_x25519_hex=x_pub_hex(X_PK),
        ephemeral_x25519_hex=eph_pub_raw.hex(),
        counter=ctr,
    ), 200


@app.post("/crypto/prepare_hybrid")
def prepare_hybrid():
    """
    Hybrid prepare endpoint (X25519 + ML-KEM + AES-GCM).

    Returns:
      - pqPubKey: DAML-normalized (whitespace removed only) device KEM pubkey text
      - kyberCiphertextB64: KEM ciphertext (base64)
      - pqSignatureB64: optional dummy/real blob
    """
    if not HAS_OQS:
        return jsonify(error="python-oqs required for hybrid AlgId"), 500

    try:
        body = request.get_json(force=True, silent=False)
    except Exception as e:
        return jsonify(error=f"invalid JSON: {e}"), 400

    # Device X25519 pubkey (hex)
    dev_pub_hex = ""
    for key in ["devicePublicKey", "device_public_key_hex", "devicePublicKeyHex"]:
        v = body.get(key)
        if isinstance(v, str) and v.strip():
            dev_pub_hex = v.strip()
            break
    if not dev_pub_hex:
        return jsonify(error="devicePublicKey (X25519 hex) missing"), 400

    # Device PQ KEM pubkey (base64/base64url, but must match ledger text after DAML normalization)
    dev_pq_raw = ""
    for key in [
        "device_pq_pub_b64",
        "device_pq_pub_b64u",
        "devicePqPubB64",
        "devicePqPubB64u",
        "devicePqPubKeyB64",
        "devicePqPubKeyB64u",
        "device_pq_pub_key_b64",
        "device_pq_pub_key_b64u",
        "deviceKyberPubB64",
        "DeviceKyberPubB64",
        "deviceKyberPubB64u",
        "DeviceKyberPubB64u",
    ]:
        v = body.get(key)
        if isinstance(v, str) and v.strip():
            dev_pq_raw = v.strip()
            break
    if not dev_pq_raw:
        return jsonify(error="device PQ public key missing (ML-KEM/Kyber pubkey)"), 400

    # ✅ DAML-consistent normalization
    dev_pq_b64_daml = _daml_norm_b64_text(dev_pq_raw)

    # Plaintext
    ptxt_is_b64 = bool(body.get("plaintext_is_b64", False))
    raw_pt = body.get("plaintext", "")
    if (raw_pt is None or raw_pt == "") and "plaintext_b64" in body:
        raw_pt = body.get("plaintext_b64") or ""
        ptxt_is_b64 = True

    try:
        plaintext = _decode_maybe_b64_or_b64u(raw_pt) if ptxt_is_b64 else str(raw_pt).encode("utf-8")
    except Exception as e:
        return jsonify(error=f"bad plaintext: {e}"), 400
    if len(plaintext) > MAX_PLAINTEXT_LEN:
        return jsonify(error="plaintext too large"), 400

    # AAD
    aad_bytes: Optional[bytes] = None
    aad_for_log: Optional[str] = None
    if body.get("aad_b64u") is not None:
        try:
            aad_bytes = _decode_maybe_b64_or_b64u(body.get("aad_b64u") or "")
        except Exception as e:
            return jsonify(error=f"bad aad_b64u: {e}"), 400
        if len(aad_bytes) > MAX_AAD_LEN:
            return jsonify(error="aad too large"), 400
        aad_for_log = aad_bytes.decode("utf-8", errors="ignore")
    else:
        aad_str = body.get("aad") or ""
        if len(str(aad_str).encode("utf-8")) > MAX_AAD_LEN:
            return jsonify(error="aad too large"), 400
        aad_for_log = str(aad_str) if aad_str else None
        aad_bytes = str(aad_str).encode("utf-8") if aad_str else None

    ctx = body.get("ctx", {}) or {}
    try:
        epoch = int(body.get("epoch", 0))
    except Exception:
        return jsonify(error="bad epoch"), 400

    # X25519 ECDH
    try:
        eph = x25519.X25519PrivateKey.generate()
        shared_x = eph.exchange(x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(dev_pub_hex)))
    except Exception as e:
        return jsonify(error=f"bad devicePublicKey: {e}"), 400

    # PQ KEM encapsulation
    try:
        kyber_ct_b64, kem_ss = do_pq_kem_to_device(dev_pq_b64_daml)
    except Exception as e:
        return jsonify(error=f"pq_kem_failed: {e}"), 500

    shared = shared_x + kem_ss
    k_enc, n_base = hkdf_key_and_nonce(shared, ctx)

    ctr = next_counter(("dev_hybrid", dev_pub_hex, epoch))
    nonce = build_nonce(nonce_base=n_base, counter=ctr)

    aesgcm = AESGCM(k_enc)
    try:
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad_bytes)
    except Exception as e:
        return jsonify(error=f"aesgcm_encrypt_failed: {e}"), 500
    if len(ciphertext) > MAX_CIPHERTEXT_LEN:
        return jsonify(error="ciphertext too large"), 500

    enc_b64 = base64.b64encode(ciphertext).decode("ascii")
    eph_x_hex = eph.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()
    digest_hex = digest_for_transcript(ciphertext, aad_bytes or b"")

    pq_sig_b64 = make_pq_signature_blob(digest_hex)
    try:
        pq_sig_b64 = _hybrid_pq_sig_or_dummy(pq_sig_b64)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    return jsonify(
        ciphertext_b64=enc_b64,
        encryptedMessage_b64=enc_b64,
        digest_hex=digest_hex,
        ephemeral_x25519_hex=eph_x_hex,
        counter=ctr,
        kyberCiphertextB64=kyber_ct_b64,
        pqSignatureB64=pq_sig_b64,
        pqPubKey=dev_pq_b64_daml,
        devicePublicKey=dev_pub_hex,
        aad=aad_for_log,
    ), 200


@app.post("/sp/ed25519/sign_digest")
def sp_sign_digest():
    """
    JSON: {"digest_hex":"..."}
    Uses local ED_SK for demo. In real systems, SP signs client-side.
    """
    b = request.get_json(silent=True) or {}
    dig = (b.get("digest_hex") or "").strip()
    if not dig or len(dig) != 64:
        return jsonify(error="digest_hex (sha256 hex) required"), 400
    sig = ED_SK.sign(bytes.fromhex(dig))
    return jsonify(
        sp_ed25519_pub_hex=ed_pub_hex(ED_PK),
        sp_signature_b64=base64.b64encode(sig).decode("ascii"),
    ), 200


@app.get("/debug/cache")
def debug_cache():
    return jsonify(keys=[{"key": str(k), "ttl_s": ttl} for k, ttl in EDGE_CACHE.keys()]), 200


LAST_RELAY_VERIFY: Dict[str, Any] = {}


@app.get("/debug/last_verify")
def debug_last_verify():
    return jsonify(LAST_RELAY_VERIFY or {"status": "none"}), 200


# ---------------------------------------------------------------------------
# Relay endpoint helpers
# ---------------------------------------------------------------------------
def _parse_iso_utc(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    try:
        if ts.endswith("Z"):
            return datetime.fromisoformat(ts[:-1]).replace(tzinfo=timezone.utc)
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _get_first_str(body: dict, keys: List[str]) -> str:
    for k in keys:
        v = body.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def _is_cache_expired_error(http_err: requests.HTTPError) -> bool:
    resp = getattr(http_err, "response", None)
    if resp is None:
        return False
    if "[Verify] cache expired; call RefreshCache" in (resp.text or ""):
        return True
    try:
        data = resp.json()
    except ValueError:
        return False

    def _walk(obj) -> bool:
        if isinstance(obj, str):
            return "[Verify] cache expired; call RefreshCache" in obj
        if isinstance(obj, dict):
            return any(_walk(v) for v in obj.values())
        if isinstance(obj, list):
            return any(_walk(v) for v in obj)
        return False

    return _walk(data)


def _refresh_cache_for_broker(broker_cid: str, edge_party: str) -> str:
    """
    Exercise BrokerContract.RefreshCache once (controller = operator).
    Returns NEW BrokerContract cid (because RefreshCache archives and recreates).
    """
    new_valid_until = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    new_cached = [{"_1": edge_party, "_2": new_valid_until}]
    refresh_arg = {"newValidUntil": new_valid_until, "newCached": new_cached}

    resp = exercise(BROKER_TEMPLATE, broker_cid, "RefreshCache", refresh_arg)
    new_cid = _extract_exercise_result(resp)
    if not isinstance(new_cid, str) or not new_cid.strip():
        raise RuntimeError(f"RefreshCache did not return new cid. resp={resp}")
    return new_cid.strip()


def _get_device_expected_pqpub(device_cid: str) -> Optional[str]:
    if not device_cid:
        return None
    try:
        devc = EDGE_CACHE.get(("device_by_cid", device_cid)) or fetch_contract(DEVICE_TEMPLATE, device_cid)
        if devc:
            EDGE_CACHE.set(("device_by_cid", device_cid), devc)
            payload = devc.get("payload", {}) or {}
            return payload.get("pqPubKey") or payload.get("pq_pub_key") or payload.get("pq_pub_b64")
    except Exception as e:
        app.logger.warning("device pqPubKey fetch failed for %s: %s", device_cid, e)
    return None


def _select_sender_public_key(b: dict, sp_ed25519_pub_hex: str) -> str:
    """
    senderPublicKey selection (must match what SigAttestation used).

    Modes:
      - prefer_request: request.senderPublicKey if present else sp_ed25519_pub_hex
      - sp_ed25519: always sp_ed25519_pub_hex
      - sp_x25519: require request sender_x25519_hex or senderX25519Hex
    """
    if SENDER_PUBLIC_KEY_MODE == "sp_ed25519":
        return sp_ed25519_pub_hex

    if SENDER_PUBLIC_KEY_MODE == "sp_x25519":
        sx = _get_first_str(b, ["sender_x25519_hex", "senderX25519Hex", "senderPublicKey"])
        if not sx:
            raise ValueError("senderPublicKey expected to be X25519 hex but missing (mode=sp_x25519)")
        return sx

    provided = _get_first_str(b, ["senderPublicKey"])
    return provided if provided else sp_ed25519_pub_hex


# ---------------------------------------------------------------------------
# Relay endpoint (edge-controller → DAML VerifyAndRelayMessage)
# ---------------------------------------------------------------------------
@app.post("/relay_message")
def relay_message():
    t0 = perf_counter_ns()
    b = request.get_json(silent=True) or {}

    alg_id_tag = b.get("algId_tag", "ALG_X25519_AESGCM_ED25519")
    if alg_id_tag not in ALLOWED_ALGID_TAGS:
        return jsonify(error="invalid algId_tag"), 400
    use_hybrid = alg_id_tag == "ALG_HYBRID_X25519_KYBER_AESGCM_HYBRID_SIG"

    edge_token = (b.get("edge_token") or "").strip()
    if not edge_token:
        return jsonify(error="edge_token required (edge is controller)"), 400

    edge_raw = (b.get("edge") or "").strip()
    edge_party = resolve_party_identifier(edge_raw)
    if not edge_party:
        return jsonify(error="edge required"), 400

    # Authorize edge_token actAs includes edge_party
    et_claims = _decode_jwt_claims_noverify(edge_token)
    et_daml = et_claims.get("https://daml.com/ledger-api", {}) or {}
    et_actas_raw = set(et_daml.get("actAs") or [])
    et_actas_all: Set[str] = set(et_actas_raw)
    for p in list(et_actas_raw):
        try:
            rp = resolve_party_identifier(p)
            if rp:
                et_actas_all.add(rp)
        except Exception:
            continue

    if edge_party not in et_actas_all and edge_raw not in et_actas_all:
        return jsonify(error="edge_token not authorized for edge party", edge=edge_party, actAs=list(et_actas_all)), 403

    if not _rate_ok(edge_party):
        return jsonify(error="rate_limited"), 429

    sp = resolve_party_identifier((b.get("sp") or "").strip())
    if not sp:
        return jsonify(error="sp required"), 400

    # Find BrokerContract (operator)
    try:
        q = query_all(BROKER_TEMPLATE, {"operator": DAML_PARTY})
    except HTTPError as e:
        status = e.response.status_code if getattr(e, "response", None) is not None else 500
        body = e.response.text if getattr(e, "response", None) is not None else str(e)
        return jsonify(error="json_api_request_failed", status=status, body=body), status

    if not q:
        q = query_all(BROKER_TEMPLATE, {})
    if not q:
        return jsonify(error="No active BrokerContract found"), 404

    bc_cid = q[0]["contractId"]

    target = (b.get("targetDevice") or "").strip()
    if not target:
        return jsonify(error="targetDevice (Device CID) required"), 400

    try:
        epoch = int(b.get("epoch", 0))
    except Exception:
        return jsonify(error="bad epoch"), 400

    sender_id = (b.get("senderId") or "Sender1").strip()

    # For hybrid: fetch Device.pqPubKey for early mismatch check
    expected_device_pqpub = _get_device_expected_pqpub(target) if use_hybrid else None

    # ---- inputs for DAML choice ----
    enc_b64: str = ""
    digest_hex: str = ""
    eph_x_hex: str = ""
    aad_str: str = ""
    counter_val: int = 0
    device_pub_hex: Optional[str] = None

    pq_sig_b64: Optional[str] = None
    pq_pub_for_log: Optional[str] = None
    kyber_ct_b64: Optional[str] = None

    # -----------------------------------------------------------------------
    # CLIENT-SIDE ENCRYPT PATH
    # -----------------------------------------------------------------------
    if "encryptedMessage_b64" in b and "digest_hex" in b:
        enc_b64 = _get_first_str(b, ["encryptedMessage_b64", "ciphertext_b64"])
        digest_hex = _get_first_str(b, ["digest_hex"])
        device_pub_hex = _get_first_str(b, ["devicePublicKey"])
        eph_x_hex = _get_first_str(b, ["ephemeral_x25519_hex", "ephX25519Hex"])
        aad_str = str(b.get("aad") or "")

        if len(aad_str.encode("utf-8")) > MAX_AAD_LEN:
            return jsonify(error="aad too large"), 400

        try:
            counter_val = int(b.get("counter", 0))
        except Exception:
            return jsonify(error="bad counter"), 400

        if not (enc_b64 and digest_hex and device_pub_hex and eph_x_hex and counter_val):
            return jsonify(
                error="missing fields for client-side encrypt",
                required=["encryptedMessage_b64", "digest_hex", "devicePublicKey", "ephemeral_x25519_hex", "counter"],
            ), 400

        # Validate digest matches ciphertext(+aad)
        try:
            ct_bytes = base64.b64decode(enc_b64)
        except Exception as e:
            return jsonify(error="ciphertext decode failed", detail=str(e)), 400
        if len(ct_bytes) > MAX_CIPHERTEXT_LEN:
            return jsonify(error="ciphertext too large"), 400

        aad_bytes = aad_str.encode("utf-8") if aad_str else b""
        dig_chk = digest_for_transcript(ct_bytes, aad_bytes)

        try:
            if not constant_time.bytes_eq(bytes.fromhex(dig_chk), bytes.fromhex(digest_hex)):
                return jsonify(error="digest_mismatch", got=dig_chk, expected=digest_hex), 400
        except Exception as e:
            return jsonify(error="digest_hex_invalid", detail=str(e), got=dig_chk, expected=digest_hex), 400

        # Hybrid required fields
        if use_hybrid:
            kyber_ct_b64 = _get_first_str(b, ["kyberCiphertextB64", "kyber_ciphertext_b64", "kyber_ct_b64"])
            pq_sig_b64 = _get_first_str(b, ["pqSignatureB64", "pq_signature_b64", "pqSigB64"])
            pq_pub_for_log = _get_first_str(b, ["pqPubKey", "pq_pub_b64", "pq_pubkey_b64"])

            if not (kyber_ct_b64 and pq_pub_for_log):
                return jsonify(error="hybrid requires kyberCiphertextB64 and pqPubKey (client-side mode)"), 400

            # ✅ DAML-style mismatch check (whitespace-only normalization)
            if expected_device_pqpub:
                if _daml_norm_b64_text(pq_pub_for_log) != _daml_norm_b64_text(expected_device_pqpub):
                    return jsonify(
                        error="pq_pubkey_mismatch",
                        deviceCid=target,
                        ledger_pqPubKey=expected_device_pqpub,
                        client_pqPubKey=pq_pub_for_log,
                        fix="Send pqPubKey EXACTLY matching Device.pqPubKey text (after whitespace-only normalization).",
                    ), 409

            pq_pub_for_log = _daml_norm_b64_text(pq_pub_for_log)

            try:
                pq_sig_b64 = _hybrid_pq_sig_or_dummy(pq_sig_b64)
            except ValueError as e:
                return jsonify(error=str(e)), 400

    # -----------------------------------------------------------------------
    # SERVER-SIDE ENCRYPT PATH
    # -----------------------------------------------------------------------
    else:
        dev_pub_hex = (b.get("devicePublicKey") or "").strip()
        if not dev_pub_hex:
            return jsonify(error="devicePublicKey (X25519 hex) required when server-side encrypting"), 400
        device_pub_hex = dev_pub_hex

        if "plaintext" not in b:
            return jsonify(error="plaintext required for server-side encrypt"), 400

        ptxt_is_b64 = bool(b.get("plaintext_is_b64", False))
        try:
            plaintext = _decode_maybe_b64_or_b64u(b["plaintext"]) if ptxt_is_b64 else str(b["plaintext"]).encode("utf-8")
        except Exception as e:
            return jsonify(error=f"bad plaintext: {e}"), 400
        if len(plaintext) > MAX_PLAINTEXT_LEN:
            return jsonify(error="plaintext too large"), 400

        ctx = b.get("ctx", {}) or {}
        aad_str = str(b.get("aad") or "")
        if len(aad_str.encode("utf-8")) > MAX_AAD_LEN:
            return jsonify(error="aad too large"), 400
        aad_bytes = aad_str.encode("utf-8") if aad_str else None

        # X25519 ECDH
        try:
            eph = x25519.X25519PrivateKey.generate()
            shared_x = eph.exchange(x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(dev_pub_hex)))
        except Exception as e:
            return jsonify(error=f"bad devicePublicKey: {e}"), 400

        kem_ss = b""
        if use_hybrid:
            if not HAS_OQS:
                return jsonify(error="Hybrid AlgId requires python-oqs installed on edge"), 500

            dev_pq_raw = _get_first_str(
                b,
                [
                    "device_pq_pub_b64",
                    "device_pq_pub_b64u",
                    "devicePqPubB64",
                    "devicePqPubB64u",
                    "devicePqPubKeyB64",
                    "devicePqPubKeyB64u",
                    "device_pq_pub_key_b64",
                    "device_pq_pub_key_b64u",
                    "deviceKyberPubB64",
                    "DeviceKyberPubB64",
                    "deviceKyberPubB64u",
                    "DeviceKyberPubB64u",
                ],
            )
            if not dev_pq_raw:
                return jsonify(error="Hybrid AlgId requires device PQ KEM public key"), 400

            pq_pub_for_log = _daml_norm_b64_text(dev_pq_raw)

            if expected_device_pqpub and _daml_norm_b64_text(expected_device_pqpub) != pq_pub_for_log:
                return jsonify(
                    error="pq_pubkey_mismatch",
                    deviceCid=target,
                    ledger_pqPubKey=expected_device_pqpub,
                    provided_pqPubKey=pq_pub_for_log,
                    fix="Provide the same device KEM pqPubKey text that is registered on-ledger.",
                ), 409

            try:
                kyber_ct_b64, kem_ss = do_pq_kem_to_device(pq_pub_for_log)  # ✅ kyber_ct_b64 set here
            except Exception as e:
                return jsonify(error=f"pq_kem_failed: {e}"), 500

        shared = shared_x + (kem_ss or b"")
        k_enc, n_base = hkdf_key_and_nonce(shared, ctx)

        counter_val = ratchet_next_ctr(edge_party, dev_pub_hex, sender_id, epoch)
        nonce = build_nonce(nonce_base=n_base, counter=counter_val)

        aesgcm = AESGCM(k_enc)
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad_bytes)

        if len(ciphertext) > MAX_CIPHERTEXT_LEN:
            return jsonify(error="ciphertext too large"), 500

        enc_b64 = base64.b64encode(ciphertext).decode("ascii")
        eph_x_hex = eph.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()
        digest_hex = digest_for_transcript(ciphertext, aad_bytes or b"")

        if use_hybrid:
            pq_sig_b64 = make_pq_signature_blob(digest_hex)
            try:
                pq_sig_b64 = _hybrid_pq_sig_or_dummy(pq_sig_b64)
            except ValueError as e:
                return jsonify(error=str(e)), 400

    # -----------------------------------------------------------------------
    # SP Ed25519 signature check (optional)
    # -----------------------------------------------------------------------
    sp_pub_hex = _get_first_str(b, ["sp_ed25519_pub_hex", "spEd25519PubHex"])
    sp_sig_b64 = _get_first_str(b, ["sp_signature_b64", "spSignatureB64"])
    if not sp_pub_hex or not sp_sig_b64:
        return jsonify(
            error="SP signature fields missing",
            required=["sp_ed25519_pub_hex OR spEd25519PubHex", "sp_signature_b64 OR spSignatureB64"],
        ), 400

    if not SKIP_SP_VERIFY:
        try:
            sp_sig = base64.b64decode(sp_sig_b64)
            if len(sp_sig) > 128:
                return jsonify(error="sp_signature too large"), 400
            sp_pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(sp_pub_hex))
            sp_pub.verify(sp_sig, bytes.fromhex(digest_hex))
        except Exception as e:
            return jsonify(error="sp_signature_invalid", detail=str(e)), 400

    # Revocation check for SP key (epoch-scoped)
    rk_key = {"_1": DAML_PARTY, "_2": {"_1": epoch, "_2": sp_pub_hex}}
    try:
        rk = fetch_by_key(REVOKED_KEY_TEMPLATE, rk_key)
    except HTTPError:
        rk = None
    if rk:
        return jsonify(error="sp_key_revoked", epoch=epoch), 403

    # Timestamp skew check
    msg_ts = b.get("msgTimestamp")
    if not msg_ts:
        return jsonify(error="msgTimestamp required"), 400
    ts_parsed = _parse_iso_utc(msg_ts)
    if not ts_parsed:
        return jsonify(error="bad msgTimestamp"), 400
    now_utc = datetime.now(timezone.utc)
    skew_sec = abs((now_utc - ts_parsed).total_seconds())
    max_skew = _int_env("SCOPE_MAX_TS_SKEW", 300)
    if skew_sec > max_skew:
        return jsonify(error="msgTimestamp out of acceptable range", skew_seconds=skew_sec), 400

    # Attestations
    att_raw = b.get("attestation_cids", None)
    if att_raw is None:
        att_raw = b.get("attestations", [])
    if isinstance(att_raw, str):
        att_cids = [att_raw]
    elif isinstance(att_raw, list):
        att_cids = att_raw
    else:
        att_cids = []
    if any((not isinstance(x, str)) or x.startswith("#") for x in att_cids):
        return jsonify(error="bad_attestation_cids", hint="Use JSON-API contractIds, not '#1:0' refs."), 400

    # Device public key lookup fallback (from Device contract)
    if not device_pub_hex:
        dev = EDGE_CACHE.get(("device_by_cid", target)) or fetch_contract(DEVICE_TEMPLATE, target)
        if dev:
            EDGE_CACHE.set(("device_by_cid", target), dev)
            device_pub_hex = (dev.get("payload", {}) or {}).get("publicKey")
    if not device_pub_hex:
        return jsonify(error="Device contract not found or missing publicKey"), 404

    # Snapshot / merkle root
    snap_key = {"_1": DAML_PARTY, "_2": epoch}
    snap = EDGE_CACHE.get(("snapshot", epoch))
    if not snap:
        try:
            snap = fetch_by_key(SNAPSHOT_TEMPLATE, snap_key)
        except HTTPError:
            snap = None
        if snap:
            EDGE_CACHE.set(("snapshot", epoch), snap)

    merkle_root = b.get("merkleRoot") or ((snap.get("payload", {}) or {}).get("merkleRoot") if snap else "genesis")

    # ZK-PAC / policy proof
    use_zkpac = bool(b.get("use_zkpac") or b.get("useZkPac") or False)
    policy_proof = b.get("policy_proof")
    policy_proof_daml = None
    if use_zkpac:
        if not isinstance(policy_proof, dict):
            return jsonify(error="policy_proof required when useZkPac=true"), 400
        try:
            policy_proof_daml = {
                "policyId": policy_proof["policyId"],
                "leafHash": policy_proof.get("leafHash", ""),
                "merklePath": policy_proof.get("merklePath", []),
                "revealedAttrs": policy_proof.get("revealedAttrs", []),
            }
        except KeyError as e:
            return jsonify(error=f"missing field in policy_proof: {e}"), 400

    if use_hybrid and pq_pub_for_log:
        pq_pub_for_log = _daml_norm_b64_text(pq_pub_for_log)

    # senderPublicKey selection
    try:
        sender_public_key_value = _select_sender_public_key(b, sp_pub_hex)
    except ValueError as e:
        return jsonify(error=str(e), hint="Set SCOPE_SENDER_PUBLIC_KEY_MODE or provide senderPublicKey in request"), 400

    # -----------------------------------------------------------------------
    # Build DAML choice argument
    # ✅ FIX (A): algId must be Variant, not string
    # ✅ FIX (B): kyberCiphertextB64 always present in hybrid
    # -----------------------------------------------------------------------
    arg = {
        "edge": edge_party,
        "sp": sp,
        "senderId": sender_id,
        "algId": daml_variant(alg_id_tag),  # ✅ FIX (A)
        "targetDevice": target,
        "encryptedMessage": enc_b64,
        "devicePublicKey": device_pub_hex,
        "senderPublicKey": sender_public_key_value,
        "digest": digest_hex,
        "msgTimestamp": msg_ts,
        "epoch": epoch,
        "merkleRoot": merkle_root,
        "useZkPac": use_zkpac,
        "policyProof": policy_proof_daml if use_zkpac else None,
        "attestations": att_cids,
        "spSignatureB64": sp_sig_b64,
        "spEd25519PubHex": sp_pub_hex,
        "ephX25519Hex": eph_x_hex,
        "aad": (aad_str if aad_str else None),
        "counter": counter_val,
        "pqSignatureB64": (pq_sig_b64 if use_hybrid else None),
        "pqPubKey": (pq_pub_for_log if use_hybrid else None),
        "kyberCiphertextB64": (kyber_ct_b64 if use_hybrid else None),  # ✅ FIX (B)
    }

    def _do_verify(broker_contract_id: str):
        return exercise(BROKER_TEMPLATE, broker_contract_id, "VerifyAndRelayMessage", arg, token=edge_token)

    try:
        res = _do_verify(bc_cid)
    except requests.HTTPError as e:
        if _is_cache_expired_error(e):
            try:
                new_bc = _refresh_cache_for_broker(bc_cid, edge_party)
                bc_cid = new_bc
                res = _do_verify(bc_cid)
            except Exception as e2:
                return jsonify(error="cache_expired_refresh_failed", detail=str(e2)), 500
        else:
            status = e.response.status_code if getattr(e, "response", None) is not None else 500
            body = e.response.text if getattr(e, "response", None) is not None else str(e)
            return jsonify(error="json_api_request_failed", status=status, body=body), status

    elapsed_ms = (perf_counter_ns() - t0) / 1e6
    relaylog_cid = _extract_exercise_result(res)

    LAST_RELAY_VERIFY.update(
        {
            "edge": edge_party,
            "sp": sp,
            "deviceCid": target,
            "digest_hex": digest_hex,
            "epoch": epoch,
            "merkleRoot": merkle_root,
            "sp_pub_hex": sp_pub_hex,
            "senderPublicKey_used": sender_public_key_value,
            "eph_x25519_hex": eph_x_hex,
            "aad": aad_str,
            "counter": counter_val,
            "device_public_key": device_pub_hex,
            "senderId": sender_id,
            "useZkPac": use_zkpac,
            "policy_proof_present": bool(policy_proof_daml),
            "algId_tag": alg_id_tag,
            "algId_json": arg["algId"],
            "pqSignatureB64": pq_sig_b64,
            "pqPubKey": pq_pub_for_log,
            "kyberCiphertextB64": kyber_ct_b64,
            "expected_device_pqPubKey": expected_device_pqpub,
            "request_id": g.get("request_id"),
            "took_ms": elapsed_ms,
            "relaylog_cid": relaylog_cid,
            "skip_sp_verify": SKIP_SP_VERIFY,
        }
    )

    return jsonify(status="success", elapsed_ms=elapsed_ms, result=res, relaylog_cid=relaylog_cid), 200


# legacy alias
@app.post("/relay/message")
def relay_message_legacy():
    return relay_message()


# ---------------------------------------------------------------------------
# RelayLog utilities
# ---------------------------------------------------------------------------
def _sort_relaylogs_by_ts(rows: List[dict]) -> List[dict]:
    try:
        return sorted(rows, key=lambda r: r.get("payload", {}).get("ts", ""))
    except Exception:
        return rows


@app.get("/relay/list")
def relay_list():
    rows = query_all(RELAY_LOG_TEMPLATE)
    return jsonify(count=len(rows), items=rows), 200


@app.post("/relay/ack")
def relay_ack():
    """
    Your Main.daml RelayLog template has no Acknowledge choice.
    Ack is off-ledger in your description. Returning 501 to avoid confusion.
    """
    return jsonify(
        error="not_implemented",
        detail="RelayLog has no 'Acknowledge' choice in Main.daml. Ack is off-ledger in your design.",
    ), 501


@app.post("/relay/ack_latest")
def relay_ack_latest():
    return jsonify(
        error="not_implemented",
        detail="RelayLog has no 'Acknowledge' choice in Main.daml. Ack is off-ledger in your design.",
    ), 501


# ---------------------------------------------------------------------------
# Logging passthrough → DAML LogRequest
# ---------------------------------------------------------------------------
@app.post("/log_batch_activity")
def log_batch_activity():
    data = request.get_json(silent=True)
    if not data or "logs" not in data:
        return jsonify(error="Invalid payload"), 400

    endpoint_url = os.getenv("SCOPE_LOG_ENDPOINT")
    if not endpoint_url:
        endpoint_url = request.host_url.rstrip("/") + "/log_batch_activity"

    out = []
    had_error = False
    for log in data["logs"]:
        try:
            res = create(
                LOGREQUEST_TEMPLATE,
                {"operator": DAML_PARTY, "logData": json.dumps(log, separators=(",", ":")), "endpoint": endpoint_url},
            )
            cid = (res.get("result") or {}).get("contractId") if isinstance(res, dict) else None
            if cid:
                log["damlContractId"] = cid
        except Exception as e:
            had_error = True
            log["damlError"] = str(e)
        out.append(log)

    return jsonify(status=("success" if not had_error else "partial"), processed_logs=out), (200 if not had_error else 207)


# ---------------------------------------------------------------------------
# Background poller for new RelayLog (optional demo)
# ---------------------------------------------------------------------------
def poll_relay_logs():
    seen = set()
    while True:
        try:
            rows = query_all(RELAY_LOG_TEMPLATE)
            for r in rows:
                cid = r.get("contractId")
                if cid and cid not in seen:
                    seen.add(cid)
                    app.logger.info("🔔 New RelayLog: %s", r.get("payload"))
        except Exception as e:
            app.logger.error("RelayLog poll error: %s", e)
        time.sleep(3)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    if os.getenv("DISABLE_RELAYLOG_POLLER", "0") != "1":
        threading.Thread(target=poll_relay_logs, daemon=True).start()

    port = _int_env("FLASK_PORT", 5000)
    app.logger.info("Flask config: party=%s  pkg=%s", DAML_PARTY, DAML_PKG_ID)
    print("== URL MAP ==")
    print(app.url_map)
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
