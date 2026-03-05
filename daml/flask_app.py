#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SCOPE Flask API
(Decentralised TA; ratchet + AlgId + Merkle-root + optional ZK-PAC + hybrid PQ)


  - Hybrid PQ prepare + relay
  - Canonical digest TEXT (MATCHES Main.mkDigestText EXACTLY)
  - AlgId encoded as DAML Variant for JSON-API
  - pqPubKey whitespace-only normalization (MATCHES DAML normalizeB64)
  - Merkle path + ZK-PAC validation logic that mirrors Main.daml:
      * PolicyRoot check (policyId -> merkleRoot)
      * PolicyLeaf anchor check (policyId, leafHash)
      * AllowedVkId allowlist check
      * Merkle path step format "L:<sib>" / "R:<sib>" and derived root equals snapshot root
      * revealedAttrsHash check (computeRevealedAttrsHash = joinWith "|")
      * proofB64 sanity (base64-ish + non-empty)
      * Canonical ZK statement string mkZkStatement (same as DAML)
  - zkAttestations always included (even empty)
  - Optional endpoints to help build PolicyProof + statement off-ledger


Run:
  python3 flask_app.py
Env:
  LEDGER_HOST=localhost
  LEDGER_HTTP_PORT=7576
  TOKEN_PATH=/path/to/operator.jwt  (or token.txt)
"""

import base64
import hashlib
import json
import os
import re
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
from werkzeug.exceptions import NotFound
from werkzeug.exceptions import HTTPException

from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization, hashes, constant_time
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------------------------------------------------------
# Stable base directory: makes token + .keys paths stable regardless of CWD
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------------------
# Helpers: robust env parsing
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
# Optional PQC via Open Quantum Safe (python-oqs)
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
# Flask
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config["CACHE_TYPE"] = "simple"
Cache(app)
Compress(app)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
# Prefer explicit JSON_API env (needed for WSL -> Windows host routing)
JSON_API = (os.getenv("JSON_API") or "").strip()
if not JSON_API:
    LEDGER_HOST = os.getenv("LEDGER_HOST", "localhost")
    LEDGER_HTTP_PORT = os.getenv("LEDGER_HTTP_PORT", "7576")
    JSON_API = f"http://{LEDGER_HOST}:{LEDGER_HTTP_PORT}"

TOKEN_PATH = os.getenv("TOKEN_PATH", os.path.join(BASE_DIR, "token.txt"))

PERSIST = _bool_env("SCOPE_PERSIST_KEYS", True)
CACHE_TTL_SEC = _int_env("SCOPE_CACHE_TTL", 8)
DEFAULT_TIMEOUT = _int_env("SCOPE_TIMEOUT", 15)

SKIP_SP_VERIFY = _bool_env("SCOPE_SKIP_SP_VERIFY", False)

TEST_STATIC_KEYS = _bool_env("SCOPE_TEST_STATIC_KEYS", False)
ED25519_STATIC_SEED_HEX = os.getenv(
    "SCOPE_TEST_ED25519_SEED",
    "7f00bacbd1abb803c4bf2558c0032b090782f9bb8341862809edc3972b10ea55",
)
X25519_STATIC_SEED_HEX = os.getenv(
    "SCOPE_TEST_X25519_SEED",
    "551a606fc2c2a614ccb033572e21ae686ca25465b474a73bb601e30896f2fa8c",
)

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

HYBRID_REQUIRE_PQ_SIG_STRICT = _bool_env("SCOPE_HYBRID_PQ_SIG_STRICT", False)

SENDER_PUBLIC_KEY_MODE = (os.getenv("SCOPE_SENDER_PUBLIC_KEY_MODE", "prefer_request") or "").strip().lower()

# ---------------------------------------------------------------------------
# Limits
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
# DAML JSON helpers
# ---------------------------------------------------------------------------
def daml_variant(tag: str, value: Optional[dict] = None) -> dict:
    if value is None:
        value = {}
    return {"tag": tag, "value": value}


def _daml_norm_b64_text(s: str) -> str:
    # EXACT MATCH to DAML normalizeB64: remove whitespace only
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
# Canonical digest TEXT (MUST match Main.mkDigestText)
# ---------------------------------------------------------------------------
def mk_digest_text(
    ciphertext_b64: str,
    eph_x25519_hex: str,
    aad_opt: Optional[str],
    sp_ed25519_pub_hex: str,
    device_pk_hex: str,
    sender_pk: str,
    msg_ts_iso: str,
    epoch: int,
    counter: int,
    alg_id_tag: str,
) -> str:
    aad_s = aad_opt if (aad_opt is not None) else ""
    return (
        "ct=" + str(ciphertext_b64)
        + "|eph=" + str(eph_x25519_hex)
        + "|aad=" + str(aad_s)
        + "|sp=" + str(sp_ed25519_pub_hex)
        + "|dev=" + str(device_pk_hex)
        + "|sender=" + str(sender_pk)
        + "|ts=" + str(msg_ts_iso)
        + "|epoch=" + str(int(epoch))
        + "|ctr=" + str(int(counter))
        + "|alg=" + str(alg_id_tag)
    )


# ---------------------------------------------------------------------------
# ZK-PAC mirror logic (matches Main.daml behavior)
# ---------------------------------------------------------------------------
_ALLOWED_B64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")


def _first_bad_b64_char(s: str) -> Optional[str]:
    for ch in s:
        if ch not in _ALLOWED_B64_CHARS:
            return ch
    return None


def _is_base64ish_text(s: str) -> bool:
    s2 = _daml_norm_b64_text(s)
    if s2 == "":
        return False
    bad = _first_bad_b64_char(s2)
    return bad is None


def compute_revealed_attrs_hash(attrs: List[str]) -> str:
    # DAML: joinWith "|" attrs
    return "|".join([str(a) for a in attrs])


def _is_prefix(pref: str, s: str) -> bool:
    return s.startswith(pref)


def _drop_prefix_unsafe(pref: str, s: str) -> str:
    return s[len(pref):]


def merkle_combine(direction: str, cur: str, sib: str) -> str:
    # DAML: "H(" <> dir <> ":" <> cur <> ":" <> sib <> ")"
    return f"H({direction}:{cur}:{sib})"


def apply_merkle_step(cur: str, step: str) -> str:
    if _is_prefix("L:", step):
        sib = _drop_prefix_unsafe("L:", step)
        return merkle_combine("L", cur, sib)
    if _is_prefix("R:", step):
        sib = _drop_prefix_unsafe("R:", step)
        return merkle_combine("R", cur, sib)
    return "INVALID_STEP"


def merkle_root_from_leaf(leaf_hash: str, merkle_path: List[str]) -> str:
    cur = leaf_hash
    for step in merkle_path:
        cur = apply_merkle_step(cur, str(step))
    return cur


def mk_zk_statement(
    operator_party_text: str,
    epoch: int,
    merkle_root: str,
    counter: int,
    device_pk: str,
    sp_party_text: str,
    policy_id: str,
    leaf_hash: str,
    revealed_attrs_hash: str,
    digest_text: str,
    alg_id_tag: str,
    vk_id: str,
) -> str:
    # Mirrors DAML mkZkStatement (partyToTextClean already done on ledger; here we pass identifiers)
    return (
        "op=" + operator_party_text
        + "|epoch=" + str(int(epoch))
        + "|mr=" + str(merkle_root)
        + "|ctr=" + str(int(counter))
        + "|dev=" + str(device_pk)
        + "|sp=" + sp_party_text
        + "|policyId=" + str(policy_id)
        + "|leafHash=" + str(leaf_hash)
        + "|rah=" + str(revealed_attrs_hash)
        + "|digest=" + str(digest_text)
        + "|alg=" + str(alg_id_tag)
        + "|vkId=" + str(vk_id)
        + "|res=OK"
    )


def _subset(req: List[str], have: List[str]) -> bool:
    have_set = set(have)
    for x in req:
        if x not in have_set:
            return False
    return True


# ---------------------------------------------------------------------------
# TTL cache
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
    key = ("ctr",) + scope
    c = EDGE_CACHE.get(key) or 0
    c += 1
    EDGE_CACHE.set(key, c)
    return c


# ---------------------------------------------------------------------------
# JWT / JSON-API helpers
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


def _packages_list() -> List[str]:
    ids_resp = _json_api_get("/v1/packages").json()
    ids = _coerce_packages_list(ids_resp)
    return [str(x).strip() for x in ids if isinstance(x, str) and str(x).strip()]


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


def _sanitize_pkg_id(pid: Optional[str]) -> Optional[str]:
    if not pid:
        return None
    pid = str(pid).strip()
    while pid.startswith("="):
        pid = pid[1:].strip()
    pid = re.sub(r"[^0-9a-fA-F]", "", pid).lower()
    if len(pid) != 64 or not re.fullmatch(r"[0-9a-f]{64}", pid):
        return None
    return pid


def _template_resolves(pid: str, module: str, entity: str) -> bool:
    try:
        _json_api_post("/v1/query", {"templateIds": [f"{pid}:{module}:{entity}"], "query": {}})
        return True
    except Exception:
        return False


def choose_pkg_id() -> str:
    env_pid = _sanitize_pkg_id(os.getenv("DAML_PKG_ID") or os.getenv("PKG") or os.getenv("PACKAGE_ID") or "")
    if env_pid:
        pkgs = set(_packages_list())
        if env_pid in pkgs and _template_resolves(env_pid, "Main", "Device"):
            app.logger.info("Using DAML_PKG_ID from env: %s", env_pid)
            return env_pid
        app.logger.warning("Env DAML_PKG_ID invalid or not resolvable: %s", env_pid)

    pkgs = _packages_list()
    for pid in reversed(pkgs):
        pid2 = _sanitize_pkg_id(pid)
        if not pid2:
            continue
        try:
            if "Main" not in _package_modules_for(pid2):
                continue
        except Exception:
            continue
        if _template_resolves(pid2, "Main", "Device"):
            app.logger.info("Auto-selected DAML_PKG_ID: %s", pid2)
            return pid2

    raise SystemExit("Could not determine resolvable DAML_PKG_ID for Main:Device. Check DAR upload / JSON-API.")


DAML_PKG_ID: str = choose_pkg_id()


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
    # Strong overrides first
    env_operator = (os.getenv("OPERATOR") or "").strip()
    env_party = (os.getenv("DAML_PARTY") or os.getenv("DAML_PKG_PARTY") or "").strip()

    # Token authorized set
    authorized_raw = list(CLAIM_ACTAS | CLAIM_READAS)
    authorized_all: Set[str] = set(authorized_raw)
    for p in list(authorized_raw):
        try:
            rp = resolve_party_identifier(p)
            if rp:
                authorized_all.add(rp)
        except Exception:
            continue

    # 1) OPERATOR env (most explicit)
    if env_operator:
        env_op_res = resolve_party_identifier(env_operator)
        return env_op_res

    # 2) DAML_PARTY env
    if env_party:
        env_resolved = resolve_party_identifier(env_party)
        return env_resolved

    # 3) Prefer first actAs from token (most reliable)
    if authorized_raw:
        return resolve_party_identifier(authorized_raw[0])

    # 4) Only then try resolving display "Operator"
    opid = resolve_operator_identifier()
    if opid:
        return opid

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
SIG_ATTEST_TEMPLATE = tid("SigAttestation")
ZK_ATTEST_TEMPLATE = tid("ZkVerifyAttestation")
REVOKED_KEY_TEMPLATE = tid("RevokedKey")
RELAY_LOG_TEMPLATE = tid("RelayLog")
ACCESS_POLICY_TEMPLATE = tid("AccessPolicy")
SP_PROFILE_TEMPLATE = tid("SPProfile")
RATCHET_TEMPLATE = tid("RatchetState")
POLICY_ROOT_TEMPLATE = tid("PolicyRoot")
POLICY_LEAF_TEMPLATE = tid("PolicyLeaf")
ALLOWED_VKID_TEMPLATE = tid("AllowedVkId")


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
# Base64 helpers
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
    if not s:
        return ""
    raw = _decode_maybe_b64_or_b64u(s)
    return base64.b64encode(raw).decode("ascii")


# ---------------------------------------------------------------------------
# HKDF / AES-GCM
# ---------------------------------------------------------------------------
def hkdf_key_and_nonce(shared_secret: bytes, ctx: dict, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    ctx_bytes = json.dumps(ctx or {}, separators=(",", ":"), sort_keys=True).encode("utf-8")
    prk = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"scope hkdf prk").derive(shared_secret)
    k_enc = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"scope aes-gcm key" + ctx_bytes).derive(prk)
    n_base = HKDF(algorithm=hashes.SHA256(), length=12, salt=None, info=b"scope nonce base" + ctx_bytes).derive(prk)
    return k_enc, n_base


def build_nonce(nonce_base: bytes, counter: int) -> bytes:
    if len(nonce_base) != 12:
        raise ValueError("nonce_base must be 12 bytes")
    return nonce_base[:4] + int(counter).to_bytes(8, "big")


def digest_sha256_hex(ciphertext: bytes, aad: bytes = b"") -> str:
    return hashlib.sha256(ciphertext + (aad or b"")).hexdigest()


# ---------------------------------------------------------------------------
# PQ KEM
# ---------------------------------------------------------------------------
def _oqs_expected_kem_pubkey_len(alg: str) -> Optional[int]:
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
    if not HAS_OQS:
        raise RuntimeError("python-oqs is required for hybrid PQ mode")

    alg = OQS_KEM_ALG
    if OQS_ENABLED_KEMS and alg not in OQS_ENABLED_KEMS:
        alg = _choose_default(_DEFAULT_KEM_PREF, OQS_ENABLED_KEMS) or alg

    # ✅ CRITICAL: match DAML normalizeB64 BEFORE decoding
    device_pq_pub_any = _daml_norm_b64_text(device_pq_pub_any or "")

    pk_bytes = _decode_maybe_b64_or_b64u(device_pq_pub_any)
    if not pk_bytes:
        raise ValueError("empty device pq public key")

    expected_len = _oqs_expected_kem_pubkey_len(alg)
    if expected_len is None:
        if alg in ("ML-KEM-768", "Kyber768"):
            expected_len = 1184
        elif alg in ("ML-KEM-512", "Kyber512"):
            expected_len = 800

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


def make_pq_signature_blob(message_bytes: bytes) -> Optional[str]:
    if not (HAS_OQS and PQ_SIG_ALG and PQ_SIG_SK):
        return None
    try:
        with oqs.Signature(PQ_SIG_ALG, secret_key=PQ_SIG_SK) as s:
            sig = s.sign(message_bytes)
        return base64.b64encode(sig).decode("ascii")
    except TypeError:
        try:
            with oqs.Signature(PQ_SIG_ALG) as s:
                if not hasattr(s, "import_secret_key"):
                    return None
                s.import_secret_key(PQ_SIG_SK)
                sig = s.sign(message_bytes)
            return base64.b64encode(sig).decode("ascii")
        except Exception:
            return None
    except Exception:
        return None


def _hybrid_pq_sig_or_dummy(current: Optional[str]) -> str:
    if current and current.strip():
        return current.strip()
    if HYBRID_REQUIRE_PQ_SIG_STRICT:
        raise ValueError("pqSignatureB64 required in hybrid mode (strict enabled)")
    return base64.b64encode(b"pq_sig_dummy").decode("ascii")


# ---------------------------------------------------------------------------
# JSON-API contract helpers
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
# Ratchet helper (read lastCtr+1)
# ---------------------------------------------------------------------------
def ratchet_next_ctr(edge_party: str, device_key: str, sender_id: str, epoch: int) -> int:
    q_base = {"edge": edge_party, "deviceKey": device_key, "senderId": sender_id, "epoch": int(epoch)}

    rows: List[dict] = []
    try:
        rows = query_all(RATCHET_TEMPLATE, {"operator": DAML_PARTY, **q_base})
    except Exception:
        rows = []

    if not rows:
        try:
            rows = query_all(RATCHET_TEMPLATE, {"op": DAML_PARTY, **q_base})
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

@app.get("/relay/list")
def relay_list():
    # simple helper: list most recent RelayLog contracts
    rows = query_all(RELAY_LOG_TEMPLATE, {})
    # newest first by ts, then counter
    def keyfun(r):
        p = (r.get("payload", {}) or {})
        return (str(p.get("ts", "")), int(p.get("counter", 0) or 0))
    rows_sorted = sorted(rows, key=keyfun, reverse=True)
    return jsonify(items=rows_sorted[:50], count=len(rows_sorted)), 200


@app.get("/debug/cache")
def debug_cache():
    return jsonify(
        edge_cache_keys=EDGE_CACHE.keys(),
        rate_cache_keys=RATE_CACHE.keys(),
        cache_ttl_sec=CACHE_TTL_SEC,
        rate_ttl_sec=RATE_LIMIT_TTL,
        rate_bucket=RATE_LIMIT_BUCKET,
    ), 200


# ---------------------------------------------------------------------------
# Debug: JWT / DAML claims
# ---------------------------------------------------------------------------
@app.get("/debug/claims")
def debug_claims():
    # Do not leak the raw JWT; return decoded claims only.
    return jsonify(
        token_path=TOKEN_PATH,
        daml_party=DAML_PARTY,
        claim_actAs=sorted(list(CLAIM_ACTAS)),
        claim_readAs=sorted(list(CLAIM_READAS)),
        claim_admin=bool(CLAIM_ADMIN),
        daml_claims=DAML_CLAIMS,
        token_claims=TOKEN_CLAIMS,
    ), 200


@app.errorhandler(HTTPException)
def _http_exc(e):
    return jsonify(error=e.name, detail=str(e)), e.code
@app.errorhandler(Exception)
def _any_exception(e):
    app.logger.exception("Unhandled exception")
    return jsonify(error="internal_error", detail=str(e)), 500
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
# Small getters
# ---------------------------------------------------------------------------
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


def _bearer_token_from_header() -> str:
    auth = (request.headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return ""


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


def _parse_alg_id_tag(b: dict) -> str:
    t = _get_first_str(b, ["algId_tag", "algIdTag"])
    if t:
        return t
    alg = b.get("algId")
    if isinstance(alg, str) and alg.strip():
        return alg.strip()
    if isinstance(alg, dict) and isinstance(alg.get("tag"), str) and alg["tag"].strip():
        return alg["tag"].strip()
    return "ALG_X25519_AESGCM_ED25519"


def _select_sender_public_key(b: dict, sp_ed25519_pub_hex: str) -> str:
    if SENDER_PUBLIC_KEY_MODE == "sp_ed25519":
        return sp_ed25519_pub_hex
    if SENDER_PUBLIC_KEY_MODE == "sp_x25519":
        sx = _get_first_str(b, ["sender_x25519_hex", "senderX25519Hex", "senderPublicKey"])
        if not sx:
            raise ValueError("senderPublicKey expected X25519 hex but missing (mode=sp_x25519)")
        return sx
    provided = _get_first_str(b, ["senderPublicKey"])
    return provided if provided else sp_ed25519_pub_hex


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
        oqs_kem_alg=(OQS_KEM_ALG if HAS_OQS else None),
        oqs_sig_alg=(OQS_SIG_ALG if HAS_OQS else None),
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


@app.get("/debug/routes")
def debug_routes():
    routes = []
    for r in app.url_map.iter_rules():
        routes.append({"rule": str(r), "endpoint": r.endpoint, "methods": sorted(m for m in r.methods if m not in ("HEAD", "OPTIONS"))})
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
# ZK helper endpoints (optional)
# ---------------------------------------------------------------------------
@app.post("/zk/compute_revealed_attrs_hash")
def zk_compute_revealed_attrs_hash():
    b = request.get_json(silent=True) or {}
    attrs = b.get("revealedAttrs", [])
    if not isinstance(attrs, list):
        return jsonify(error="revealedAttrs must be list"), 400
    return jsonify(revealedAttrsHash=compute_revealed_attrs_hash([str(x) for x in attrs])), 200


@app.post("/zk/derive_merkle_root")
def zk_derive_merkle_root():
    b = request.get_json(silent=True) or {}
    leaf = str(b.get("leafHash") or "")
    path = b.get("merklePath", [])
    if not leaf:
        return jsonify(error="leafHash required"), 400
    if not isinstance(path, list):
        return jsonify(error="merklePath must be list"), 400
    root = merkle_root_from_leaf(leaf, [str(x) for x in path])
    ok_steps = (root != "INVALID_STEP")
    return jsonify(derivedRoot=root, okSteps=ok_steps), (200 if ok_steps else 400)


@app.post("/zk/build_statement")
def zk_build_statement():
    b = request.get_json(silent=True) or {}
    required = ["epoch", "merkleRoot", "counter", "devicePublicKey", "sp", "policyId", "leafHash", "revealedAttrsHash", "digest", "algId_tag", "vkId"]
    missing = [k for k in required if k not in b]
    if missing:
        return jsonify(error="missing_fields", missing=missing), 400
    stmt = mk_zk_statement(
        operator_party_text=str(DAML_PARTY),
        epoch=int(b["epoch"]),
        merkle_root=str(b["merkleRoot"]),
        counter=int(b["counter"]),
        device_pk=str(b["devicePublicKey"]),
        sp_party_text=str(resolve_party_identifier(str(b["sp"]))),
        policy_id=str(b["policyId"]),
        leaf_hash=str(b["leafHash"]),
        revealed_attrs_hash=str(b["revealedAttrsHash"]),
        digest_text=str(b["digest"]),
        alg_id_tag=str(b["algId_tag"]),
        vk_id=str(b["vkId"]),
    )
    return jsonify(statement=stmt), 200


# ---------------------------------------------------------------------------
# Crypto endpoints
# ---------------------------------------------------------------------------
@app.post("/crypto/encrypt_to_device")
def encrypt_to_device():
    b = request.get_json(silent=True) or {}

    dev_pub_hex = (b.get("devicePublicKey") or "").strip()
    if not dev_pub_hex:
        return jsonify(error="devicePublicKey (X25519 hex) required"), 400

    try:
        epoch = int(b.get("epoch", 0))
    except Exception:
        return jsonify(error="bad epoch"), 400

    ptxt_is_b64 = bool(b.get("plaintext_is_b64", False))
    aad_str = str(b.get("aad", "") or "")
    if len(aad_str.encode("utf-8")) > MAX_AAD_LEN:
        return jsonify(error="aad too large"), 400
    ctx = b.get("ctx", {}) or {}

    if "plaintext" not in b:
        return jsonify(error="plaintext required"), 400

    try:
        plaintext = _decode_maybe_b64_or_b64u(b["plaintext"]) if ptxt_is_b64 else str(b["plaintext"]).encode("utf-8")
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

    enc_b64 = base64.b64encode(ciphertext).decode("ascii")
    eph_hex = eph.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()

    sp_ed25519_pub_hex = _get_first_str(b, ["spEd25519PubHex", "sp_ed25519_pub_hex"]) or ed_pub_hex(ED_PK)
    sender_pk = _get_first_str(b, ["senderPublicKey"]) or sp_ed25519_pub_hex
    msg_ts = _get_first_str(b, ["msgTimestamp"]) or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    alg_id_tag = _get_first_str(b, ["algId_tag", "algIdTag", "algId"]) or "ALG_X25519_AESGCM_ED25519"

    digest_text = mk_digest_text(
        ciphertext_b64=enc_b64,
        eph_x25519_hex=eph_hex,
        aad_opt=(aad_str if aad_str else None),
        sp_ed25519_pub_hex=sp_ed25519_pub_hex,
        device_pk_hex=dev_pub_hex,
        sender_pk=sender_pk,
        msg_ts_iso=msg_ts,
        epoch=epoch,
        counter=ctr,
        alg_id_tag=alg_id_tag,
    )

    return jsonify(
        ciphertext_b64=enc_b64,
        encryptedMessage_b64=enc_b64,
        digest=digest_text,
        digest_hex=digest_text,
        digest_sha256_hex=digest_sha256_hex(ciphertext, (aad_bytes or b"")),
        sender_x25519_hex=x_pub_hex(X_PK),
        ephemeral_x25519_hex=eph_hex,
        counter=ctr,
        msgTimestamp=msg_ts,
        epoch=epoch,
        aad=(aad_str if aad_str else None),
    ), 200


@app.post("/crypto/prepare_hybrid")
def prepare_hybrid():
    if not HAS_OQS:
        return jsonify(error="python-oqs required for hybrid AlgId"), 500

    try:
        body = request.get_json(force=True, silent=False)
    except Exception as e:
        return jsonify(error=f"invalid JSON: {e}"), 400

    dev_pub_hex = _get_first_str(body, ["devicePublicKey", "device_public_key_hex", "devicePublicKeyHex"])
    if not dev_pub_hex:
        return jsonify(error="devicePublicKey (X25519 hex) missing"), 400

    dev_pq_raw = _get_first_str(
        body,
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
        return jsonify(error="device PQ public key missing (ML-KEM/Kyber pubkey)"), 400

    # MUST match on-ledger text equality after normalizeB64 (whitespace-only).
    dev_pq_b64_daml = _daml_norm_b64_text(dev_pq_raw)

    # plaintext optional (so your "minimal payload" quick test works)
    ptxt_is_b64 = bool(body.get("plaintext_is_b64", False))
    raw_pt = body.get("plaintext", None)
    if raw_pt is None:
        # default: empty plaintext is valid for AES-GCM
        plaintext = b""
    else:
        try:
            plaintext = _decode_maybe_b64_or_b64u(raw_pt) if ptxt_is_b64 else str(raw_pt).encode("utf-8")
        except Exception as e:
            return jsonify(error=f"bad plaintext: {e}"), 400

    if len(plaintext) > MAX_PLAINTEXT_LEN:
        return jsonify(error="plaintext too large"), 400

    aad_str = str(body.get("aad") or "")
    if len(aad_str.encode("utf-8")) > MAX_AAD_LEN:
        return jsonify(error="aad too large"), 400
    aad_bytes = aad_str.encode("utf-8") if aad_str else None
    aad_for_log = aad_str if aad_str else None

    ctx = body.get("ctx", {}) or {}
    try:
        epoch = int(body.get("epoch", 0))
    except Exception:
        return jsonify(error="bad epoch"), 400

    sender_id = _get_first_str(body, ["senderId", "sender_id"]) or "Sender1"

    try:
        eph = x25519.X25519PrivateKey.generate()
        shared_x = eph.exchange(x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(dev_pub_hex)))
    except Exception as e:
        return jsonify(error=f"bad devicePublicKey: {e}"), 400

    try:
        kyber_ct_b64, kem_ss = do_pq_kem_to_device(dev_pq_b64_daml)
    except Exception as e:
        return jsonify(error=f"pq_kem_failed: {e}"), 500

    shared = shared_x + kem_ss
    k_enc, n_base = hkdf_key_and_nonce(shared, ctx)

    forced_ctr = _get_first_int(body, ["counter", "ctr", "nextCtr", "ratchetCtr", "ratchetCounter"])
    if forced_ctr is not None:
        if forced_ctr <= 0:
            return jsonify(error="counter must be >= 1"), 400
        ctr = int(forced_ctr)
    else:
        use_ledger_ctr = bool(body.get("useLedgerCounter") or body.get("use_ledger_counter") or False)
        if use_ledger_ctr:
            edge_party = resolve_party_identifier(_get_first_str(body, ["edge", "edgeParty", "edge_party"]))
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
    eph_x_hex = eph.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()

    msg_ts = _get_first_str(body, ["msgTimestamp"]) or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    sp_ed_pub_hex = _get_first_str(body, ["spEd25519PubHex", "sp_ed25519_pub_hex"]) or ed_pub_hex(ED_PK)
    sender_public_key = _get_first_str(body, ["senderPublicKey"]) or sp_ed_pub_hex
    alg_id_tag = _get_first_str(body, ["algId_tag", "algIdTag", "algId"]) or "ALG_HYBRID_X25519_KYBER_AESGCM_HYBRID_SIG"

    digest_text = mk_digest_text(
        ciphertext_b64=enc_b64,
        eph_x25519_hex=eph_x_hex,
        aad_opt=(aad_for_log if aad_for_log else None),
        sp_ed25519_pub_hex=sp_ed_pub_hex,
        device_pk_hex=dev_pub_hex,
        sender_pk=sender_public_key,
        msg_ts_iso=msg_ts,
        epoch=epoch,
        counter=ctr,
        alg_id_tag=alg_id_tag,
    )

    pq_sig_b64 = make_pq_signature_blob(digest_text.encode("utf-8"))
    try:
        pq_sig_b64 = _hybrid_pq_sig_or_dummy(pq_sig_b64)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    return jsonify(
        ciphertext_b64=enc_b64,
        encryptedMessage_b64=enc_b64,
        digest=digest_text,
        digest_hex=digest_text,
        digest_sha256_hex=digest_sha256_hex(ciphertext, aad_bytes or b""),
        ephemeral_x25519_hex=eph_x_hex,
        counter=ctr,
        kyberCiphertextB64=kyber_ct_b64,
        pqSignatureB64=pq_sig_b64,
        pqPubKey=dev_pq_b64_daml,
        devicePublicKey=dev_pub_hex,
        aad=aad_for_log,
        msgTimestamp=msg_ts,
        epoch=epoch,
        senderId=sender_id,
        spEd25519PubHex=sp_ed_pub_hex,
        senderPublicKey=sender_public_key,
        algId_tag=alg_id_tag,
    ), 200


@app.post("/sp/ed25519/sign_digest")
def sp_sign_digest():
    b = request.get_json(silent=True) or {}
    dig = (b.get("digest") or "").strip()
    dig_hex = (b.get("digest_hex") or "").strip()

    to_sign: Optional[bytes] = None
    mode = "text"

    if dig:
        to_sign = dig.encode("utf-8")
        mode = "text"
    elif dig_hex:
        if re.fullmatch(r"[0-9a-fA-F]{64}", dig_hex):
            to_sign = bytes.fromhex(dig_hex.lower())
            mode = "hex"
        else:
            to_sign = dig_hex.encode("utf-8")
            mode = "text"
    else:
        return jsonify(error="digest or digest_hex required"), 400

    sig = ED_SK.sign(to_sign)
    return jsonify(
        sp_ed25519_pub_hex=ed_pub_hex(ED_PK),
        sp_signature_b64=base64.b64encode(sig).decode("ascii"),
        signed_over=mode,
    ), 200


# ---------------------------------------------------------------------------
# Relay endpoint
# ---------------------------------------------------------------------------
LAST_RELAY_VERIFY: Dict[str, Any] = {}


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
            return payload.get("pqPubKey")
    except Exception as e:
        app.logger.warning("device pqPubKey fetch failed for %s: %s", device_cid, e)
    return None


def _fetch_snapshot_merkle_root(epoch: int) -> str:
    snap_key = {"_1": DAML_PARTY, "_2": int(epoch)}
    snap = EDGE_CACHE.get(("snapshot", epoch))
    if not snap:
        try:
            snap = fetch_by_key(SNAPSHOT_TEMPLATE, snap_key)
        except HTTPError:
            snap = None
        if snap:
            EDGE_CACHE.set(("snapshot", epoch), snap)
    if snap:
        return (snap.get("payload", {}) or {}).get("merkleRoot") or "genesis"
    return "genesis"


def _zk_validate_against_ledger(
    *,
    operator_party: str,
    epoch: int,
    merkle_root: str,
    counter: int,
    device_pk: str,
    sp_party: str,
    digest_text: str,
    alg_id_tag: str,
    policy_proof: Dict[str, Any],
) -> Tuple[Dict[str, Any], str]:
    """
    Mirrors Main.daml checks for policyProof block.
    Returns (policy_proof_daml_payload, expected_statement)
    """
    # Required fields
    required = ["policyId", "leafHash", "merklePath", "revealedAttrs", "revealedAttrsHash", "vkId", "proofB64"]
    missing = [k for k in required if k not in policy_proof]
    if missing:
        raise ValueError(f"policyProof missing fields: {missing}")

    policy_id = str(policy_proof["policyId"])
    leaf_hash = str(policy_proof["leafHash"])
    merkle_path = policy_proof.get("merklePath", [])
    revealed_attrs = policy_proof.get("revealedAttrs", [])
    revealed_attrs_hash = str(policy_proof["revealedAttrsHash"])
    vk_id = str(policy_proof["vkId"])
    proof_b64 = str(policy_proof["proofB64"])

    if policy_id == "" or leaf_hash == "" or vk_id == "" or revealed_attrs_hash == "":
        raise ValueError("policyProof fields must be non-empty: policyId/leafHash/vkId/revealedAttrsHash")

    if not isinstance(merkle_path, list):
        raise ValueError("policyProof.merklePath must be a list")
    if not isinstance(revealed_attrs, list):
        raise ValueError("policyProof.revealedAttrs must be a list")

    # proofB64 sanity (base64-ish + non-empty)
    if not _is_base64ish_text(proof_b64):
        bad = _first_bad_b64_char(_daml_norm_b64_text(proof_b64)) or "?"
        raise ValueError(f"proofB64 invalid base64-ish char: {bad}")

    # AllowedVkId exists on-ledger
    vk_key = {"_1": operator_party, "_2": str(vk_id)}
    vk = fetch_by_key(ALLOWED_VKID_TEMPLATE, vk_key)
    if not vk:
        raise ValueError("vkId not allowed (no AllowedVkId record)")

    # PolicyRoot exists and matches merkleRoot
    pr_key = {"_1": operator_party, "_2": str(policy_id)}
    pr = fetch_by_key(POLICY_ROOT_TEMPLATE, pr_key)
    if not pr:
        raise ValueError("PolicyRoot missing for policyId")
    pr_root = (pr.get("payload", {}) or {}).get("merkleRoot")
    if str(pr_root) != str(merkle_root):
        raise ValueError("Merkle root mismatch with PolicyRoot")

    # Merkle path derives expected root (same deterministic function as DAML)
    derived = merkle_root_from_leaf(leaf_hash, [str(x) for x in merkle_path])
    if derived == "INVALID_STEP":
        raise ValueError("merklePath step encoding invalid (expected L:/R:)")
    if str(merkle_root) != "genesis" and str(derived) != str(merkle_root):
         raise ValueError("merklePath does not derive expected snapshot Merkle root")

    # PolicyLeaf anchor exists and allowedAttrs covers revealedAttrs
    pl_key = {"_1": operator_party, "_2": {"_1": str(policy_id), "_2": str(leaf_hash)}}
    pl = fetch_by_key(POLICY_LEAF_TEMPLATE, pl_key)
    if not pl:
        raise ValueError("No PolicyLeaf anchor for (policyId, leafHash)")
    allowed_attrs = (pl.get("payload", {}) or {}).get("allowedAttrs") or []
    allowed_attrs = [str(x) for x in allowed_attrs] if isinstance(allowed_attrs, list) else []
    revealed_attrs_s = [str(x) for x in revealed_attrs]
    if not _subset(revealed_attrs_s, allowed_attrs):
        raise ValueError("revealedAttrs not allowed by leaf")

    # revealedAttrsHash must equal computeRevealedAttrsHash(revealedAttrs)
    expected_rah = compute_revealed_attrs_hash(revealed_attrs_s)
    if str(revealed_attrs_hash) != str(expected_rah):
        raise ValueError("revealedAttrsHash mismatch (must equal computeRevealedAttrsHash(revealedAttrs))")

    expected_stmt = mk_zk_statement(
        operator_party_text=str(operator_party),
        epoch=int(epoch),
        merkle_root=str(merkle_root),
        counter=int(counter),
        device_pk=str(device_pk),
        sp_party_text=str(sp_party),
        policy_id=str(policy_id),
        leaf_hash=str(leaf_hash),
        revealed_attrs_hash=str(revealed_attrs_hash),
        digest_text=str(digest_text),
        alg_id_tag=str(alg_id_tag),
        vk_id=str(vk_id),
    )

    policy_proof_daml = {
        "policyId": policy_id,
        "leafHash": leaf_hash,
        "merklePath": [str(x) for x in merkle_path],
        "revealedAttrs": revealed_attrs_s,
        "revealedAttrsHash": revealed_attrs_hash,
        "vkId": vk_id,
        "proofB64": proof_b64,
    }
    return policy_proof_daml, expected_stmt


@app.post("/relay_message")
def relay_message():
    t0 = perf_counter_ns()
    b = request.get_json(silent=True) or {}

    alg_id_tag = _parse_alg_id_tag(b)
    if alg_id_tag not in ALLOWED_ALGID_TAGS:
        return jsonify(error="invalid_algId", got=alg_id_tag, allowed=sorted(list(ALLOWED_ALGID_TAGS))), 400
    use_hybrid = (alg_id_tag == "ALG_HYBRID_X25519_KYBER_AESGCM_HYBRID_SIG")

    edge_token = _get_first_str(b, ["edge_token", "edgeToken", "edge_jwt", "edgeJwt"]) or _bearer_token_from_header()
    if not edge_token:
        return jsonify(error="edge_token_missing", fix="Provide edge JWT in JSON edge_token or Authorization header"), 400

    edge_raw = (b.get("edge") or "").strip()
    edge_party = resolve_party_identifier(edge_raw)
    if not edge_party:
        return jsonify(error="edge required"), 400
    if not _rate_ok(edge_party):
        return jsonify(error="rate_limited"), 429

    sp = resolve_party_identifier((b.get("sp") or "").strip())
    if not sp:
        return jsonify(error="sp required"), 400

    # Find BrokerContract
    q = query_all(BROKER_TEMPLATE, {"operator": DAML_PARTY})
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

    enc_b64 = _get_first_str(b, ["encryptedMessage_b64", "encryptedMessage", "ciphertext_b64", "ciphertextB64", "ciphertext_b64u"])
    if not enc_b64:
        return jsonify(error="encryptedMessage_b64 required"), 400

    device_pub_hex = _get_first_str(b, ["devicePublicKey", "device_public_key_hex"])
    if not device_pub_hex:
        dev = EDGE_CACHE.get(("device_by_cid", target)) or fetch_contract(DEVICE_TEMPLATE, target)
        if dev:
            EDGE_CACHE.set(("device_by_cid", target), dev)
            device_pub_hex = (dev.get("payload", {}) or {}).get("publicKey")
    if not device_pub_hex:
        return jsonify(error="devicePublicKey missing and Device contract not found"), 404

    eph_x_hex = _get_first_str(b, ["ephemeral_x25519_hex", "ephX25519Hex", "eph_x25519_hex"])
    if not eph_x_hex:
        return jsonify(error="ephemeral_x25519_hex required"), 400

    aad_str = str(b.get("aad") or "")
    if len(aad_str.encode("utf-8")) > MAX_AAD_LEN:
        return jsonify(error="aad too large"), 400

    try:
        counter_val = int(b.get("counter", 0))
    except Exception:
        return jsonify(error="bad counter"), 400
    if counter_val <= 0:
        return jsonify(error="counter must be >= 1"), 400

    sp_pub_hex = _get_first_str(b, ["sp_ed25519_pub_hex", "spEd25519PubHex"])
    sp_sig_b64 = _get_first_str(b, ["sp_signature_b64", "spSignatureB64"])
    if not sp_pub_hex or not sp_sig_b64:
        return jsonify(error="SP signature fields missing",
                       required=["sp_ed25519_pub_hex/spEd25519PubHex", "sp_signature_b64/spSignatureB64"]), 400

    try:
        sender_public_key_value = _select_sender_public_key(b, sp_pub_hex)
    except ValueError as e:
        return jsonify(error=str(e)), 400

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
        return jsonify(error="msgTimestamp out of range", skew_seconds=skew_sec), 400

    # Canonical ledger digest TEXT (mkDigestText)
    aad_opt = aad_str if aad_str else None
    digest_text = mk_digest_text(
        ciphertext_b64=enc_b64,
        eph_x25519_hex=eph_x_hex,
        aad_opt=aad_opt,
        sp_ed25519_pub_hex=sp_pub_hex,
        device_pk_hex=device_pub_hex,
        sender_pk=sender_public_key_value,
        msg_ts_iso=msg_ts,
        epoch=epoch,
        counter=counter_val,
        alg_id_tag=alg_id_tag,
    )

    # Optional SP verify (Flask-only)
    if not SKIP_SP_VERIFY:
        try:
            sp_sig = base64.b64decode(sp_sig_b64)
            sp_pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(sp_pub_hex))
            # verify over digest_text bytes (paper-aligned; DAML doesn't verify)
            sp_pub.verify(sp_sig, digest_text.encode("utf-8"))
        except Exception as e:
            return jsonify(error="sp_signature_invalid", detail=str(e)), 400

    # Revocation check (epoch scoped)
    rk_key = {"_1": DAML_PARTY, "_2": {"_1": epoch, "_2": sp_pub_hex}}
    rk = fetch_by_key(REVOKED_KEY_TEMPLATE, rk_key)
    if rk:
        return jsonify(error="sp_key_revoked", epoch=epoch), 403

    # Hybrid fields
    pq_sig_b64: Optional[str] = None
    pq_pub_for_log: Optional[str] = None
    kyber_ct_b64: Optional[str] = None
    if use_hybrid:
        kyber_ct_b64 = _get_first_str(b, ["kyberCiphertextB64", "kyber_ciphertext_b64", "kyber_ct_b64"])
        pq_sig_b64 = _get_first_str(b, ["pqSignatureB64", "pq_signature_b64", "pqSigB64"])
        pq_pub_for_log = _get_first_str(b, ["pqPubKey", "pq_pub_b64", "pq_pubkey_b64", "device_pq_pub_b64", "device_pq_pub_b64u"])
        if not (kyber_ct_b64 and pq_pub_for_log):
            return jsonify(error="hybrid requires kyberCiphertextB64 and pqPubKey"), 400

        expected_device_pqpub = _get_device_expected_pqpub(target)
        if expected_device_pqpub:
            if _daml_norm_b64_text(pq_pub_for_log) != _daml_norm_b64_text(expected_device_pqpub):
                return jsonify(error="pq_pubkey_mismatch", ledger_pqPubKey=expected_device_pqpub, client_pqPubKey=pq_pub_for_log), 409

        pq_pub_for_log = _daml_norm_b64_text(pq_pub_for_log)
        try:
            pq_sig_b64 = _hybrid_pq_sig_or_dummy(pq_sig_b64)
        except ValueError as e:
            return jsonify(error=str(e)), 400

    # Snapshot merkleRoot (must match TaSnapshot on-ledger)
    merkle_root = str(b.get("merkleRoot") or _fetch_snapshot_merkle_root(epoch))

    # ZK-PAC
    use_zkpac = bool(b.get("use_zkpac") or b.get("useZkPac") or False)

    policy_proof_in = None
    if isinstance(b.get("policyProof"), dict):
        policy_proof_in = b.get("policyProof")
    elif isinstance(b.get("policy_proof"), dict):
        policy_proof_in = b.get("policy_proof")

    policy_proof_daml = None
    expected_stmt = None
    if use_zkpac:
        if not isinstance(policy_proof_in, dict):
            return jsonify(error="policyProof required when useZkPac=true"), 400
        try:
            policy_proof_daml, expected_stmt = _zk_validate_against_ledger(
                operator_party=str(DAML_PARTY),
                epoch=epoch,
                merkle_root=merkle_root,
                counter=counter_val,
                device_pk=device_pub_hex,
                sp_party=str(sp),
                digest_text=digest_text,
                alg_id_tag=alg_id_tag,
                policy_proof=policy_proof_in,
            )
        except Exception as e:
            app.logger.error("ZK-PAC validation failed: %s", str(e))
            app.logger.error(
                "policyProof_in=%s",
                json.dumps(policy_proof_in, separators=(",", ":"), ensure_ascii=False),
            )
            return jsonify(
                error="zkpac_validation_failed",
                detail=str(e),
                got_policyId=str((policy_proof_in or {}).get("policyId")),
                got_vkId=str((policy_proof_in or {}).get("vkId")),
                got_leafHash=str((policy_proof_in or {}).get("leafHash")),
                got_revealedAttrsHash=str((policy_proof_in or {}).get("revealedAttrsHash")),
                got_revealedAttrs=(policy_proof_in or {}).get("revealedAttrs"),
                got_merklePath_len=len((policy_proof_in or {}).get("merklePath") or []),
            ), 400
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

    zk_att_raw = b.get("zkAttestation_cids", None)
    if zk_att_raw is None:
        zk_att_raw = b.get("zkAttestations", [])
    if isinstance(zk_att_raw, str):
        zk_att_cids = [zk_att_raw]
    elif isinstance(zk_att_raw, list):
        zk_att_cids = zk_att_raw
    else:
        zk_att_cids = []

    # Build DAML choice argument (MATCH Main.VerifyAndRelayMessage)
    arg = {
        "edge": edge_party,
        "sp": sp,
        "senderId": sender_id,
        "algId": alg_id_tag,  # ✅ VARIANT
        "targetDevice": target,
        "encryptedMessage": enc_b64,
        "devicePublicKey": device_pub_hex,
        "senderPublicKey": sender_public_key_value,
        "digest": digest_text,  # ✅ mkDigestText
        "msgTimestamp": msg_ts,
        "epoch": epoch,
        "merkleRoot": merkle_root,
        "useZkPac": use_zkpac,
        "policyProof": policy_proof_daml if use_zkpac else None,
        "attestations": att_cids,
        "zkAttestations": zk_att_cids,  # ✅ REQUIRED ALWAYS
        "spSignatureB64": sp_sig_b64,
        "spEd25519PubHex": sp_pub_hex,
        "ephX25519Hex": eph_x_hex,
        "aad": (aad_opt if aad_opt is not None else None),
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
                bc_cid2 = _refresh_cache_for_broker(bc_cid, edge_party)
                res = _do_verify(bc_cid2)
                bc_cid = bc_cid2
            except Exception as e2:
                return jsonify(error="cache_refresh_failed", detail=str(e2)), 500
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
            "digest": digest_text,
            "epoch": epoch,
            "merkleRoot": merkle_root,
            "counter": counter_val,
            "algId_tag": alg_id_tag,
            "useZkPac": use_zkpac,
            "expectedZkStatement": expected_stmt,
            "relaylog_cid": relaylog_cid,
            "took_ms": elapsed_ms,
        }
    )

    return jsonify(status="success", elapsed_ms=elapsed_ms, relaylog_cid=relaylog_cid, digest=digest_text, result=res), 200


@app.post("/relay/message")
def relay_message_legacy():
    return relay_message()


@app.get("/debug/last_verify")
def debug_last_verify():
    return jsonify(LAST_RELAY_VERIFY or {"status": "none"}), 200


# ---------------------------------------------------------------------------
# Relay ACK
# ---------------------------------------------------------------------------
@app.post("/relay/ack")
def relay_ack():
    b = request.get_json(silent=True) or {}
    cid = _get_first_str(b, ["relayLogCid", "contractId", "cid"])
    if not cid:
        return jsonify(error="relayLogCid required", example={"relayLogCid": "<contractId>"}), 400

    token = _bearer_token_from_header() or jwt_token
    try:
        res = exercise(RELAY_LOG_TEMPLATE, cid, "Acknowledge", {}, token=token)
    except requests.HTTPError as e:
        status = e.response.status_code if getattr(e, "response", None) is not None else 500
        body = e.response.text if getattr(e, "response", None) is not None else str(e)
        return jsonify(error="ack_failed", status=status, body=body), status

    new_cid = _extract_exercise_result(res)
    return jsonify(ok=True, old_cid=cid, new_cid=new_cid, result=res), 200


@app.post("/relay/ack_latest")
def relay_ack_latest():
    b = request.get_json(silent=True) or {}
    epoch = b.get("epoch", None)
    device_key = _get_first_str(b, ["deviceKey", "devicePublicKey"])
    sender_id = _get_first_str(b, ["senderId"])

    q = {}
    if epoch is not None:
        try:
            q["epoch"] = int(epoch)
        except Exception:
            return jsonify(error="bad epoch"), 400
    if device_key:
        q["deviceKey"] = device_key
    if sender_id:
        q["senderId"] = sender_id

    rows = query_all(RELAY_LOG_TEMPLATE, q if q else None)

    unacked = []
    for r in rows:
        payload = r.get("payload", {}) or {}
        if not bool(payload.get("acked", False)):
            unacked.append(r)

    if not unacked:
        return jsonify(ok=True, detail="no unacked RelayLog found", filters=q), 200

    unacked = sorted(
        unacked,
        key=lambda r: (
            (r.get("payload", {}) or {}).get("ts", ""),
            int((r.get("payload", {}) or {}).get("counter", 0) or 0),
        ),
    )
    latest = unacked[-1]
    cid = latest.get("contractId")

    token = _bearer_token_from_header() or jwt_token
    try:
        res = exercise(RELAY_LOG_TEMPLATE, cid, "Acknowledge", {}, token=token)
    except requests.HTTPError as e:
        status = e.response.status_code if getattr(e, "response", None) is not None else 500
        body = e.response.text if getattr(e, "response", None) is not None else str(e)
        return jsonify(error="ack_latest_failed", status=status, body=body), status

    new_cid = _extract_exercise_result(res)
    return jsonify(ok=True, old_cid=cid, new_cid=new_cid, picked=latest.get("payload"), result=res), 200


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
            res = create(LOGREQUEST_TEMPLATE, {"operator": DAML_PARTY, "logData": json.dumps(log, separators=(",", ":")), "endpoint": endpoint_url})
            cid = (res.get("result") or {}).get("contractId") if isinstance(res, dict) else None
            if cid:
                log["damlContractId"] = cid
        except Exception as e:
            had_error = True
            log["damlError"] = str(e)
        out.append(log)

    return jsonify(status=("success" if not had_error else "partial"), processed_logs=out), (200 if not had_error else 207)


# ---------------------------------------------------------------------------
# Background poller (optional)
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
    print("== URL MAP ==")
    print(app.url_map)
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)