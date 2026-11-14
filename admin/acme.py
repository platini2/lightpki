# LightPKI ACME server
# Copyright (C) 2026 Patricio S. Latini
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""A small ACME (RFC 8555) server in front of the intermediate CA.

Lets certbot, acme.sh, lego, Caddy, Traefik, cert-manager... obtain and
renew certificates automatically, the way they would from Let's Encrypt.

Scope, on purpose:
  * http-01 validation only (no dns-01 / tls-alpn-01, so no wildcards).
  * DNS names only, and only under ACME_ALLOWED_DOMAINS.
  * Accounts identified by their key; no external account binding.
  * Signing goes through the sign_acme_csr script, so the CA lock, the
    database and the OCSP/CRL URLs are exactly the same as for every
    other certificate.

Run it under gunicorn with ONE worker process (threads are fine): nonces
and the state lock live in that process. State is kept as JSON files in
$INTERMEDIATECA_DIRECTORY/acme, so it survives restarts.
"""

import base64
import hashlib
import json
import os
import re
import secrets
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509.oid import ExtensionOID, NameOID
from flask import Flask, Response, request

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INTERMEDIATE_DIR = os.environ.get("INTERMEDIATECA_DIRECTORY", "")
STATE_DIR = os.path.join(INTERMEDIATE_DIR, "acme")
DOMAIN = os.environ.get("DOMAIN", "")
ALLOWED_DOMAINS = [
    d.strip().lower().strip(".")
    for d in (os.environ.get("ACME_ALLOWED_DOMAINS") or DOMAIN).split(",")
    if d.strip()
]
CERT_DAYS = int(os.environ.get("ACME_CERT_DAYS", "90"))
MAX_NAMES = 100
ORDER_LIFETIME = timedelta(days=7)
NONCE_LIFETIME = 3600  # seconds
VALIDATION_TIMEOUT = 10  # seconds per http-01 fetch

LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")

app = Flask(__name__)
_state_lock = threading.Lock()
_nonce_lock = threading.Lock()
_nonces = {}


# --- helpers ---------------------------------------------------------------


def b64u_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text):
    if not isinstance(text, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", text):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def now():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def new_id():
    return secrets.token_urlsafe(16)


class AcmeError(Exception):
    def __init__(self, kind, detail, status=400):
        super().__init__(detail)
        self.kind = kind
        self.detail = detail
        self.status = status


def url_for_path(path):
    return request.url_root.rstrip("/") + path


def new_nonce():
    nonce = b64u_encode(secrets.token_bytes(16))
    cutoff = time.time() - NONCE_LIFETIME
    with _nonce_lock:
        for key in [k for k, t in _nonces.items() if t < cutoff]:
            del _nonces[key]
        _nonces[nonce] = time.time()
    return nonce


def use_nonce(nonce):
    with _nonce_lock:
        issued = _nonces.pop(nonce, None)
    return issued is not None and issued >= time.time() - NONCE_LIFETIME


@app.after_request
def add_acme_headers(resp):
    resp.headers["Replay-Nonce"] = new_nonce()
    resp.headers["Cache-Control"] = "no-store"
    resp.headers.add("Link", f'<{url_for_path("/acme/directory")}>;rel="index"')
    return resp


@app.errorhandler(AcmeError)
def acme_error(err):
    body = {"type": f"urn:ietf:params:acme:error:{err.kind}", "detail": err.detail, "status": err.status}
    return Response(json.dumps(body), err.status, content_type="application/problem+json")


@app.errorhandler(404)
def not_found(_err):
    return acme_error(AcmeError("malformed", "Not found", 404))


@app.errorhandler(405)
def not_allowed(_err):
    return acme_error(AcmeError("malformed", "Method not allowed", 405))


def json_response(obj, status=200, location=None):
    resp = Response(json.dumps(obj), status, content_type="application/json")
    if location:
        resp.headers["Location"] = location
    return resp


# --- state (one JSON file per object, under the CA volume) -----------------


def _path(kind, obj_id):
    if not ID_RE.match(obj_id):
        raise AcmeError("malformed", "Bad identifier", 404)
    return os.path.join(STATE_DIR, kind, obj_id + ".json")


def load(kind, obj_id):
    try:
        with open(_path(kind, obj_id)) as fh:
            return json.load(fh)
    except FileNotFoundError:
        raise AcmeError("malformed", f"No such {kind[:-1]}", 404)


def save(kind, obj):
    path = _path(kind, obj["id"])
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path))
    with os.fdopen(fd, "w") as fh:
        json.dump(obj, fh)
    os.replace(tmp, path)


def account_by_thumbprint(thumb):
    index = os.path.join(STATE_DIR, "keys", thumb + ".json")
    try:
        with open(index) as fh:
            return load("accounts", json.load(fh)["account"])
    except FileNotFoundError:
        return None


# --- JWS ------------------------------------------------------------------


def jwk_public_key(jwk):
    kty = jwk.get("kty")
    if kty == "RSA":
        n = int.from_bytes(b64u_decode(jwk["n"]), "big")
        e = int.from_bytes(b64u_decode(jwk["e"]), "big")
        key = rsa.RSAPublicNumbers(e, n).public_key()
        if key.key_size < 2048:
            raise AcmeError("badPublicKey", "RSA account keys must be at least 2048 bits")
        return key
    if kty == "EC":
        curves = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1()}
        curve = curves.get(jwk.get("crv"))
        if curve is None:
            raise AcmeError("badPublicKey", "Unsupported EC curve")
        x = int.from_bytes(b64u_decode(jwk["x"]), "big")
        y = int.from_bytes(b64u_decode(jwk["y"]), "big")
        return ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
    raise AcmeError("badPublicKey", "Unsupported key type")


def jwk_thumbprint(jwk):
    if jwk.get("kty") == "RSA":
        members = {k: jwk[k] for k in ("e", "kty", "n")}
    else:
        members = {k: jwk[k] for k in ("crv", "kty", "x", "y")}
    canonical = json.dumps(members, sort_keys=True, separators=(",", ":"))
    return b64u_encode(hashlib.sha256(canonical.encode()).digest())


def verify_signature(key, alg, signing_input, signature):
    try:
        if alg == "RS256" and isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
            return
        sizes = {"ES256": (32, hashes.SHA256(), "secp256r1"), "ES384": (48, hashes.SHA384(), "secp384r1")}
        if alg in sizes and isinstance(key, ec.EllipticCurvePublicKey):
            size, digest, curve = sizes[alg]
            if key.curve.name != curve or len(signature) != 2 * size:
                raise AcmeError("badSignatureAlgorithm", "Algorithm does not match key")
            r = int.from_bytes(signature[:size], "big")
            s = int.from_bytes(signature[size:], "big")
            key.verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(digest))
            return
    except InvalidSignature:
        raise AcmeError("unauthorized", "JWS signature is invalid", 403)
    raise AcmeError("badSignatureAlgorithm", "Supported: RS256, ES256, ES384")


def parse_jws(allow_jwk=False):
    """Verify the request's JWS; return (payload, account or None, jwk)."""
    if request.mimetype != "application/jose+json":
        raise AcmeError("malformed", "Content-Type must be application/jose+json", 415)
    try:
        body = json.loads(request.get_data(as_text=True))
        protected = json.loads(b64u_decode(body["protected"]))
        payload_b64 = body["payload"]
        signature = b64u_decode(body["signature"])
    except (ValueError, KeyError, TypeError):
        raise AcmeError("malformed", "Request is not a flattened JWS")

    if protected.get("url") != request.url:
        raise AcmeError("unauthorized", "JWS url does not match request URL", 401)
    if not use_nonce(protected.get("nonce", "")):
        raise AcmeError("badNonce", "Invalid or expired nonce")

    alg = protected.get("alg")
    account = None
    if "jwk" in protected and "kid" not in protected:
        if not allow_jwk:
            raise AcmeError("malformed", "This request must use a kid, not a jwk")
        jwk = protected["jwk"]
        key = jwk_public_key(jwk)
    elif "kid" in protected and "jwk" not in protected:
        prefix = url_for_path("/acme/acct/")
        kid = protected["kid"]
        if not isinstance(kid, str) or not kid.startswith(prefix):
            raise AcmeError("accountDoesNotExist", "Unknown kid", 400)
        account = load("accounts", kid[len(prefix):])
        if account["status"] != "valid":
            raise AcmeError("unauthorized", "Account is not valid", 403)
        jwk = account["jwk"]
        key = jwk_public_key(jwk)
    else:
        raise AcmeError("malformed", "Exactly one of jwk and kid is required")

    signing_input = f"{body['protected']}.{payload_b64}".encode()
    verify_signature(key, alg, signing_input, signature)

    if payload_b64 == "":
        payload = None  # POST-as-GET
    else:
        try:
            payload = json.loads(b64u_decode(payload_b64))
        except ValueError:
            raise AcmeError("malformed", "Payload is not JSON")
    return payload, account, jwk


# --- domain policy ---------------------------------------------------------


def check_identifier(ident):
    if not isinstance(ident, dict) or ident.get("type") != "dns":
        raise AcmeError("unsupportedIdentifier", "Only dns identifiers are supported")
    name = str(ident.get("value", "")).lower().rstrip(".")
    if name.startswith("*."):
        raise AcmeError("rejectedIdentifier", f"{name}: wildcards need dns-01, which is not supported")
    labels = name.split(".")
    if len(name) > 253 or len(labels) < 2 or not all(LABEL_RE.match(label) for label in labels):
        raise AcmeError("rejectedIdentifier", f"{name!r} is not a valid DNS name")
    if not any(name == d or name.endswith("." + d) for d in ALLOWED_DOMAINS):
        raise AcmeError(
            "rejectedIdentifier",
            f"{name} is outside the allowed domains ({', '.join(ALLOWED_DOMAINS)})",
            403,
        )
    return name


# --- object views ------------------------------------------------------------


def account_view(acct):
    return {
        "status": acct["status"],
        "contact": acct.get("contact", []),
        "orders": url_for_path(f"/acme/acct/{acct['id']}/orders"),
    }


def refresh_order(order):
    """Bring an order's status up to date with its authorizations."""
    if order["status"] in ("pending", "ready") and now() > datetime.fromisoformat(order["expires"]):
        order["status"] = "invalid"
    if order["status"] == "pending":
        statuses = [load("authz", a)["status"] for a in order["authzs"]]
        if any(s != "pending" and s != "valid" for s in statuses):
            order["status"] = "invalid"
        elif all(s == "valid" for s in statuses):
            order["status"] = "ready"
    return order


def order_view(order):
    view = {
        "status": order["status"],
        "expires": iso(datetime.fromisoformat(order["expires"])),
        "identifiers": [{"type": "dns", "value": n} for n in order["names"]],
        "authorizations": [url_for_path(f"/acme/authz/{a}") for a in order["authzs"]],
        "finalize": url_for_path(f"/acme/order/{order['id']}/finalize"),
    }
    if order.get("cert"):
        view["certificate"] = url_for_path(f"/acme/cert/{order['cert']}")
    if order.get("error"):
        view["error"] = order["error"]
    return view


def challenge_view(authz):
    chall = {
        "type": "http-01",
        "url": url_for_path(f"/acme/chall/{authz['id']}"),
        "status": authz["chall_status"],
        "token": authz["token"],
    }
    if authz.get("validated"):
        chall["validated"] = authz["validated"]
    if authz.get("error"):
        chall["error"] = authz["error"]
    return chall


def authz_view(authz):
    status = authz["status"]
    if status == "pending" and now() > datetime.fromisoformat(authz["expires"]):
        status = "expired"
    return {
        "status": status,
        "expires": iso(datetime.fromisoformat(authz["expires"])),
        "identifier": {"type": "dns", "value": authz["name"]},
        "challenges": [challenge_view(authz)],
    }


def owned(obj, account):
    if obj["account"] != account["id"]:
        raise AcmeError("unauthorized", "Not owned by this account", 403)
    return obj


# --- endpoints ---------------------------------------------------------------


@app.route("/acme/directory")
def directory():
    return json_response(
        {
            "newNonce": url_for_path("/acme/new-nonce"),
            "newAccount": url_for_path("/acme/new-account"),
            "newOrder": url_for_path("/acme/new-order"),
            "revokeCert": url_for_path("/acme/revoke-cert"),
            "meta": {"externalAccountRequired": False},
        }
    )


@app.route("/acme/new-nonce", methods=["HEAD", "GET"])
def nonce():
    return Response(status=200 if request.method == "HEAD" else 204)


@app.route("/acme/new-account", methods=["POST"])
def new_account():
    payload, _, jwk = parse_jws(allow_jwk=True)
    payload = payload or {}
    thumb = jwk_thumbprint(jwk)
    with _state_lock:
        existing = account_by_thumbprint(thumb)
        if existing:
            return json_response(account_view(existing), 200, url_for_path(f"/acme/acct/{existing['id']}"))
        if payload.get("onlyReturnExisting"):
            raise AcmeError("accountDoesNotExist", "No account for this key")
        contact = payload.get("contact", [])
        if not isinstance(contact, list) or not all(
            isinstance(c, str) and c.startswith("mailto:") and len(c) < 256 for c in contact
        ):
            raise AcmeError("invalidContact", "Contacts must be mailto: URLs")
        acct = {"id": new_id(), "status": "valid", "jwk": jwk, "contact": contact, "created": iso(now())}
        save("accounts", acct)
        save("keys", {"id": thumb, "account": acct["id"]})
    return json_response(account_view(acct), 201, url_for_path(f"/acme/acct/{acct['id']}"))


@app.route("/acme/acct/<acct_id>", methods=["POST"])
def account(acct_id):
    payload, acct, _ = parse_jws()
    if acct["id"] != acct_id:
        raise AcmeError("unauthorized", "Not your account", 403)
    if payload and payload.get("status") == "deactivated":
        with _state_lock:
            acct["status"] = "deactivated"
            save("accounts", acct)
    elif payload and "contact" in payload:
        with _state_lock:
            acct["contact"] = [c for c in payload["contact"] if isinstance(c, str)]
            save("accounts", acct)
    return json_response(account_view(acct))


@app.route("/acme/acct/<acct_id>/orders", methods=["POST"])
def account_orders(acct_id):
    _, acct, _ = parse_jws()
    if acct["id"] != acct_id:
        raise AcmeError("unauthorized", "Not your account", 403)
    return json_response({"orders": [url_for_path(f"/acme/order/{o}") for o in acct.get("orders", [])]})


@app.route("/acme/new-order", methods=["POST"])
def new_order():
    payload, acct, _ = parse_jws()
    idents = (payload or {}).get("identifiers")
    if not isinstance(idents, list) or not idents:
        raise AcmeError("malformed", "identifiers is required")
    if len(idents) > MAX_NAMES:
        raise AcmeError("rejectedIdentifier", f"At most {MAX_NAMES} names per order")
    names = sorted({check_identifier(i) for i in idents})
    expires = now() + ORDER_LIFETIME
    with _state_lock:
        authz_ids = []
        for name in names:
            authz = {
                "id": new_id(),
                "account": acct["id"],
                "name": name,
                "status": "pending",
                "chall_status": "pending",
                "token": b64u_encode(secrets.token_bytes(32)),
                "expires": expires.isoformat(),
            }
            save("authz", authz)
            authz_ids.append(authz["id"])
        order = {
            "id": new_id(),
            "account": acct["id"],
            "status": "pending",
            "names": names,
            "authzs": authz_ids,
            "expires": expires.isoformat(),
        }
        save("orders", order)
        acct.setdefault("orders", []).append(order["id"])
        acct["orders"] = acct["orders"][-100:]
        save("accounts", acct)
    return json_response(order_view(order), 201, url_for_path(f"/acme/order/{order['id']}"))


@app.route("/acme/order/<order_id>", methods=["POST"])
def get_order(order_id):
    _, acct, _ = parse_jws()
    with _state_lock:
        order = refresh_order(owned(load("orders", order_id), acct))
        save("orders", order)
    return json_response(order_view(order))


@app.route("/acme/authz/<authz_id>", methods=["POST"])
def get_authz(authz_id):
    _, acct, _ = parse_jws()
    authz = owned(load("authz", authz_id), acct)
    return json_response(authz_view(authz))


def validate_http01(name, token, expected):
    """Fetch the token over HTTP; return None on success or an error string."""
    url = f"http://{name}/.well-known/acme-challenge/{token}"
    req = urllib.request.Request(url, headers={"User-Agent": "LightPKI-ACME"})
    try:
        with urllib.request.urlopen(req, timeout=VALIDATION_TIMEOUT) as resp:
            body = resp.read(4096).decode("utf-8", "replace").strip()
    except urllib.error.HTTPError as exc:
        return f"{url} returned HTTP {exc.code}"
    except (urllib.error.URLError, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        return f"Could not fetch {url}: {reason}"
    if body != expected:
        return f"{url} did not return the expected key authorization"
    return None


@app.route("/acme/chall/<authz_id>", methods=["POST"])
def challenge(authz_id):
    _, acct, jwk = parse_jws()
    with _state_lock:
        authz = owned(load("authz", authz_id), acct)
        start = authz["chall_status"] == "pending" and authz["status"] == "pending"
        if start:
            authz["chall_status"] = "processing"
            save("authz", authz)
    if start:
        # Validated inline (a few seconds at most); clients poll either way.
        key_auth = f"{authz['token']}.{jwk_thumbprint(jwk)}"
        error = validate_http01(authz["name"], authz["token"], key_auth)
        with _state_lock:
            authz = load("authz", authz_id)
            if error is None:
                authz.update(status="valid", chall_status="valid", validated=iso(now()))
            else:
                authz.update(
                    status="invalid",
                    chall_status="invalid",
                    error={"type": "urn:ietf:params:acme:error:unauthorized", "detail": error, "status": 403},
                )
            save("authz", authz)
    resp = json_response(challenge_view(authz))
    resp.headers.add("Link", f'<{url_for_path("/acme/authz/" + authz_id)}>;rel="up"')
    return resp


def csr_names(csr):
    names = set()
    try:
        san = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    except x509.ExtensionNotFound:
        san = None
    if san is not None:
        if any(not isinstance(g, x509.DNSName) for g in san):
            raise AcmeError("badCSR", "Only DNS names are allowed in the CSR")
        names.update(n.lower().rstrip(".") for n in san.get_values_for_type(x509.DNSName))
    cns = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    for attr in cns:
        names.add(str(attr.value).lower().rstrip("."))
    return names


def check_csr_key(csr):
    key = csr.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        if key.key_size < 2048:
            raise AcmeError("badCSR", "RSA keys must be at least 2048 bits")
    elif isinstance(key, ec.EllipticCurvePublicKey):
        if key.curve.name not in ("secp256r1", "secp384r1"):
            raise AcmeError("badCSR", "EC keys must use P-256 or P-384")
    else:
        raise AcmeError("badCSR", "Key must be RSA or ECDSA")


@app.route("/acme/order/<order_id>/finalize", methods=["POST"])
def finalize(order_id):
    payload, acct, _ = parse_jws()
    with _state_lock:
        order = refresh_order(owned(load("orders", order_id), acct))
        if order["status"] != "ready":
            save("orders", order)
            raise AcmeError("orderNotReady", f"Order is {order['status']}, not ready", 403)
        order["status"] = "processing"
        save("orders", order)

    try:
        der = b64u_decode((payload or {}).get("csr", ""))
        csr = x509.load_der_x509_csr(der)
    except ValueError:
        fail_order(order_id, "badCSR", "CSR is not a valid DER-encoded request")
    if not csr.is_signature_valid:
        fail_order(order_id, "badCSR", "CSR signature is invalid")
    try:
        check_csr_key(csr)
        names = csr_names(csr)
    except AcmeError as err:
        fail_order(order_id, err.kind, err.detail)
    if names != set(order["names"]):
        fail_order(order_id, "badCSR", "CSR names do not match the order's validated names")

    cn = next((n for n in order["names"] if len(n) <= 64), None)
    if cn is None:
        fail_order(order_id, "badCSR", "No name short enough (64 chars) for the subject CN")
    san_list = ",".join(f"DNS:{n}" for n in order["names"])
    cert_id = new_id()
    cert_dir = os.path.join(STATE_DIR, "certs")
    os.makedirs(cert_dir, mode=0o700, exist_ok=True)
    cert_path = os.path.join(cert_dir, cert_id + ".pem")
    with tempfile.NamedTemporaryFile("wb", suffix=".csr", dir=cert_dir, delete=False) as fh:
        fh.write(csr.public_bytes(serialization.Encoding.PEM))
        csr_path = fh.name
    try:
        proc = subprocess.run(
            [os.path.join(REPO_ROOT, "sign_acme_csr"), csr_path, cert_path, cn, san_list, str(CERT_DAYS)],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )
    finally:
        os.unlink(csr_path)
    if proc.returncode != 0:
        app.logger.error("sign_acme_csr failed: %s %s", proc.stdout, proc.stderr)
        fail_order(order_id, "serverInternal", "Signing failed; see the LightPKI logs", 500)

    with open(cert_path, "rb") as fh:
        cert = x509.load_pem_x509_certificate(fh.read())
    with _state_lock:
        order = load("orders", order_id)
        order.update(status="valid", cert=cert_id)
        save("orders", order)
        save("certinfo", {"id": cert_id, "account": acct["id"], "serial": format(cert.serial_number, "X")})
    app.logger.info("Issued %s for %s (serial %X)", cert_id, ",".join(order["names"]), cert.serial_number)
    return json_response(order_view(order), 200, url_for_path(f"/acme/order/{order_id}"))


def fail_order(order_id, kind, detail, status=400):
    with _state_lock:
        order = load("orders", order_id)
        order["status"] = "invalid"
        order["error"] = {"type": f"urn:ietf:params:acme:error:{kind}", "detail": detail, "status": status}
        save("orders", order)
    raise AcmeError(kind, detail, status)


@app.route("/acme/cert/<cert_id>", methods=["POST"])
def certificate(cert_id):
    _, acct, _ = parse_jws()
    owned(load("certinfo", cert_id), acct)
    with open(os.path.join(STATE_DIR, "certs", cert_id + ".pem")) as fh:
        leaf = fh.read()
    with open(os.path.join(INTERMEDIATE_DIR, "certs", "intermediate.cert.pem")) as fh:
        intermediate = fh.read()
    return Response(leaf.strip() + "\n" + intermediate.strip() + "\n", content_type="application/pem-certificate-chain")


REVOCATION_REASONS = {
    0: "unspecified",
    1: "keyCompromise",
    3: "affiliationChanged",
    4: "superseded",
    5: "cessationOfOperation",
}


@app.route("/acme/revoke-cert", methods=["POST"])
def revoke_cert():
    payload, acct, _ = parse_jws()
    try:
        cert = x509.load_der_x509_certificate(b64u_decode((payload or {}).get("certificate", "")))
    except ValueError:
        raise AcmeError("malformed", "certificate is not valid DER")
    reason = REVOCATION_REASONS.get((payload or {}).get("reason", 0))
    if reason is None:
        raise AcmeError("badRevocationReason", "Unsupported revocation reason")
    serial = format(cert.serial_number, "X")
    # Only the account that obtained the certificate may revoke it.
    issued_here = False
    certinfo_dir = os.path.join(STATE_DIR, "certinfo")
    for fname in os.listdir(certinfo_dir) if os.path.isdir(certinfo_dir) else []:
        with open(os.path.join(certinfo_dir, fname)) as fh:
            info = json.load(fh)
        if info["serial"] == serial:
            issued_here = True
            if info["account"] != acct["id"]:
                raise AcmeError("unauthorized", "Certificate was issued to another account", 403)
    if not issued_here:
        raise AcmeError("unauthorized", "Certificate was not issued over ACME", 403)
    for script, args in (("revoke_serial", [serial, reason]), ("generate_crl", [])):
        proc = subprocess.run(
            [os.path.join(REPO_ROOT, script), *args], cwd=REPO_ROOT, capture_output=True, text=True, timeout=120
        )
        if proc.returncode != 0:
            if "Already revoked" in proc.stdout + proc.stderr:
                raise AcmeError("alreadyRevoked", "Certificate is already revoked")
            app.logger.error("%s failed: %s %s", script, proc.stdout, proc.stderr)
            raise AcmeError("serverInternal", "Revocation failed; see the LightPKI logs", 500)
    return Response(status=200)
