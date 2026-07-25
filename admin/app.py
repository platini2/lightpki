import hmac
import ipaddress
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime, timezone

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
    Response,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
if not ADMIN_PASSWORD:
    raise SystemExit(
        "ADMIN_PASSWORD is not set or empty; refusing to start an unauthenticated admin UI"
    )

CN_RE = re.compile(r"^(\*\.)?[A-Za-z0-9._-]+$")
OU_RE = re.compile(r"^[A-Za-z0-9 ._-]+$")
SERIAL_RE = re.compile(r"^[0-9A-Fa-f]+$")
BUNDLE_RE = re.compile(r"^[A-Za-z0-9._*-]+\.zip$")
EXTENSIONS = ("server_cert", "usr_cert", "ocsp")
KEY_SPECS = {
    "2048": "RSA 2048",
    "4096": "RSA 4096",
    "prime256v1": "ECDSA P-256 (prime256v1)",
    "secp384r1": "ECDSA P-384 (secp384r1)",
    "secp521r1": "ECDSA P-521 (secp521r1)",
}

EXPIRY_WARNING_DAYS = int(os.environ.get("EXPIRY_WARNING_DAYS", "30"))
EXPIRY_WEBHOOK_URL = os.environ.get("EXPIRY_WEBHOOK_URL", "")
EXPIRY_CHECK_INTERVAL_HOURS = float(os.environ.get("EXPIRY_CHECK_INTERVAL_HOURS", "24"))


def parse_san_entries(raw):
    """Turn a user-supplied comma-separated list of hostnames/IPs into
    the DNS:/IP:-tagged entries issue_key_cert's SAN_LIST expects,
    classifying each one automatically."""
    entries = []
    errors = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            ipaddress.ip_address(part)
            entries.append(f"IP:{part}")
            continue
        except ValueError:
            pass
        if CN_RE.match(part):
            entries.append(f"DNS:{part}")
        else:
            errors.append(f"'{part}' is not a valid hostname or IP address.")
    return entries, errors


app = Flask(__name__)
app.secret_key = os.environ.get("ADMIN_SECRET_KEY") or secrets.token_hex(32)


# --- Auth -------------------------------------------------------------


@app.before_request
def require_basic_auth():
    auth = request.authorization
    valid = (
        auth is not None
        and hmac.compare_digest(auth.username or "", ADMIN_USERNAME)
        and hmac.compare_digest(auth.password or "", ADMIN_PASSWORD)
    )
    if not valid:
        return Response(
            "Authentication required",
            401,
            {"WWW-Authenticate": 'Basic realm="LightPKI Admin"'},
        )


def csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_hex(16)
        session["csrf_token"] = token
    return token


def check_csrf():
    token = session.get("csrf_token")
    submitted = request.form.get("csrf_token")
    if not token or not submitted or not hmac.compare_digest(token, submitted):
        abort(400)


app.jinja_env.globals["csrf_token"] = csrf_token


# --- Script execution ---------------------------------------------------
# Every privileged operation (issuing/revoking a cert, regenerating the
# CRL) is delegated to the existing shell scripts rather than reimplemented
# here, so their CN validation / permission handling stays the single
# source of truth.


class ScriptResult:
    def __init__(self, returncode, stdout, stderr):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def run_script(name, args, timeout=120):
    path = os.path.join(REPO_ROOT, name)
    try:
        proc = subprocess.run(
            [path, *args],
            cwd=REPO_ROOT,
            env=os.environ.copy(),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return ScriptResult(proc.returncode, proc.stdout, proc.stderr)
    except subprocess.TimeoutExpired as exc:
        return ScriptResult(1, exc.stdout or "", f"Timed out after {timeout}s")
    except OSError as exc:
        return ScriptResult(1, "", str(exc))


# --- CA / certificate state ----------------------------------------------


def ca_info(cert_path):
    if not os.path.isfile(cert_path):
        return None
    proc = subprocess.run(
        ["openssl", "x509", "-noout", "-subject", "-enddate", "-in", cert_path],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return None
    subject = None
    enddate = None
    for line in proc.stdout.splitlines():
        if line.startswith("subject="):
            subject = line[len("subject=") :].strip()
        elif line.startswith("notAfter="):
            enddate = line[len("notAfter=") :].strip()
    return {"subject": subject, "enddate": enddate}


def ca_summary():
    root_cert = os.path.join(
        os.environ.get("ROOTCA_DIRECTORY", ""), "certs", "ca.cert.pem"
    )
    intermediate_cert = os.path.join(
        os.environ.get("INTERMEDIATECA_DIRECTORY", ""),
        "certs",
        "intermediate.cert.pem",
    )
    return {"root": ca_info(root_cert), "intermediate": ca_info(intermediate_cert)}


def inspect_cert(cert_path, cn):
    """Read back the extension type / key spec / extra SAN entries of an
    existing cert, so a renewal can reissue with the same shape without
    the caller having to remember or re-supply them."""
    if not os.path.isfile(cert_path):
        return None
    proc = subprocess.run(
        ["openssl", "x509", "-in", cert_path, "-noout", "-text"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return None
    text = proc.stdout

    if "OCSP Signing" in text:
        extension = "ocsp"
    elif "TLS Web Server Authentication" in text:
        extension = "server_cert"
    elif "TLS Web Client Authentication" in text or "E-mail Protection" in text:
        extension = "usr_cert"
    else:
        extension = None

    key_spec = None
    m = re.search(r"ASN1 OID:\s*(\S+)", text)
    if m and m.group(1) in KEY_SPECS:
        key_spec = m.group(1)
    if key_spec is None:
        m = re.search(r"Public-Key:\s*\((\d+)\s*bit\)", text)
        if m and m.group(1) in KEY_SPECS:
            key_spec = m.group(1)

    extra_sans = []
    m = re.search(r"X509v3 Subject Alternative Name:\s*\n\s*(.+)", text)
    if m:
        for part in m.group(1).split(","):
            part = part.strip()
            if part.startswith("IP Address:"):
                entry = "IP:" + part[len("IP Address:") :]
            elif part.startswith("DNS:"):
                entry = part
            else:
                continue
            if entry != f"DNS:{cn}":
                extra_sans.append(entry)

    return {"extension": extension, "key_spec": key_spec, "extra_sans": extra_sans}


def _openssl_query(cert_path, *args):
    proc = subprocess.run(
        ["openssl", "x509", "-in", cert_path, "-noout", *args],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return None
    output = proc.stdout.strip()
    return output.split("=", 1)[1] if "=" in output else output


def describe_cert(cert_path):
    """Build a human-friendly decode of a certificate for the View page."""
    if not os.path.isfile(cert_path):
        return None

    proc = subprocess.run(
        ["openssl", "x509", "-in", cert_path, "-noout", "-text"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return None
    text = proc.stdout

    key_algo = None
    if "id-ecPublicKey" in text:
        m = re.search(r"ASN1 OID:\s*(\S+)", text)
        key_algo = f"ECDSA ({m.group(1)})" if m else "ECDSA"
    elif "rsaEncryption" in text:
        m = re.search(r"Public-Key:\s*\((\d+)\s*bit\)", text)
        key_algo = f"RSA {m.group(1)}-bit" if m else "RSA"

    def extension_line(label):
        m = re.search(rf"{label}:.*?\n\s*(.+)", text)
        return m.group(1).strip() if m else None

    sans = []
    san_line = extension_line("X509v3 Subject Alternative Name")
    if san_line:
        for part in san_line.split(","):
            part = part.strip()
            if part:
                sans.append(part.replace("IP Address:", "IP:"))

    return {
        "subject": _openssl_query(cert_path, "-subject"),
        "issuer": _openssl_query(cert_path, "-issuer"),
        "serial": _openssl_query(cert_path, "-serial"),
        "not_before": _openssl_query(cert_path, "-startdate"),
        "not_after": _openssl_query(cert_path, "-enddate"),
        "fingerprint_sha256": _openssl_query(cert_path, "-fingerprint", "-sha256"),
        "key_algo": key_algo,
        "sig_algo": re.search(r"Signature Algorithm:\s*(\S+)", text).group(1)
        if re.search(r"Signature Algorithm:\s*(\S+)", text)
        else None,
        "sans": sans,
        "key_usage": extension_line("X509v3 Key Usage"),
        "ext_key_usage": extension_line("X509v3 Extended Key Usage"),
        "aia": extension_line("Authority Information Access"),
        "raw_text": text,
    }


def _expiry_notified_path():
    return os.path.join(os.environ.get("INTERMEDIATECA_DIRECTORY", ""), ".expiry_notified")


def _load_notified_serials():
    path = _expiry_notified_path()
    if not os.path.isfile(path):
        return set()
    with open(path) as f:
        return {line.strip() for line in f if line.strip()}


def _mark_notified(serial):
    with open(_expiry_notified_path(), "a") as f:
        f.write(serial + "\n")


def _send_expiry_webhook(entry):
    payload = json.dumps(
        {
            "cn": entry["cn"],
            "ou": entry["ou"],
            "serial": entry["serial"],
            "expiry": entry["expiry"],
            "days_remaining": entry["days_remaining"],
            "message": (
                f"LightPKI: certificate for {entry['cn']} expires in "
                f"{entry['days_remaining']} day(s) ({entry['expiry']})."
            ),
        }
    ).encode()
    req = urllib.request.Request(
        EXPIRY_WEBHOOK_URL, data=payload, headers={"Content-Type": "application/json"}
    )
    urllib.request.urlopen(req, timeout=10)


def check_expiring_certificates():
    if not EXPIRY_WEBHOOK_URL:
        return
    notified = _load_notified_serials()
    for entry in load_certificates():
        if entry["status"] != "Expiring Soon":
            continue
        if entry["serial"] in notified:
            continue
        try:
            _send_expiry_webhook(entry)
            _mark_notified(entry["serial"])
        except Exception as exc:
            print(f"lightpki admin: expiry webhook failed for {entry['cn']}: {exc}", file=sys.stderr)


def _expiry_alert_loop():
    while True:
        try:
            check_expiring_certificates()
        except Exception as exc:
            print(f"lightpki admin: expiry check failed: {exc}", file=sys.stderr)
        time.sleep(EXPIRY_CHECK_INTERVAL_HOURS * 3600)


def start_expiry_alert_thread():
    if EXPIRY_WEBHOOK_URL:
        threading.Thread(target=_expiry_alert_loop, daemon=True).start()


def parse_dn(dn):
    fields = {}
    for part in dn.split("/"):
        if "=" in part:
            key, _, value = part.partition("=")
            fields[key] = value
    return fields


def parse_asn1_time(raw):
    return datetime.strptime(raw.rstrip("Z"), "%y%m%d%H%M%S").replace(
        tzinfo=timezone.utc
    )


def load_certificates():
    intermediate_dir = os.environ.get("INTERMEDIATECA_DIRECTORY", "")
    index_path = os.path.join(intermediate_dir, "index.txt")
    entries = []
    if not os.path.isfile(index_path):
        return entries

    now = datetime.now(timezone.utc)
    output_dir = os.environ.get("OUTPUT_DIRECTORY", "")

    with open(index_path) as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 6:
                continue
            status_flag, expiry_raw, revoke_raw, serial, _filename, subject = parts[:6]
            dn = parse_dn(subject)

            try:
                expiry = parse_asn1_time(expiry_raw)
            except ValueError:
                expiry = None

            days_remaining = (expiry - now).days if expiry is not None else None

            if status_flag == "R":
                status = "Revoked"
            elif expiry is None:
                status = "Valid"
            elif expiry < now:
                status = "Expired"
            elif days_remaining is not None and days_remaining <= EXPIRY_WARNING_DAYS:
                status = "Expiring Soon"
            else:
                status = "Valid"

            cn = dn.get("CN", "")
            bundle = None
            if cn:
                candidate = os.path.join(output_dir, f"{cn}.zip")
                if os.path.isfile(candidate):
                    bundle = f"{cn}.zip"

            entries.append(
                {
                    "serial": serial,
                    "cn": cn,
                    "ou": dn.get("OU", ""),
                    "status": status,
                    "expiry": expiry.strftime("%Y-%m-%d %H:%M UTC")
                    if expiry
                    else expiry_raw,
                    "expiry_dt": expiry,
                    "days_remaining": days_remaining,
                    "revoked_at": revoke_raw or None,
                    "bundle": bundle,
                }
            )

    entries.sort(key=lambda e: e["serial"])
    return entries


# --- Routes ---------------------------------------------------------------


@app.route("/")
def dashboard():
    return render_template("dashboard.html", ca=ca_summary(), certs=load_certificates())


@app.route("/cert/<serial>")
def view_cert(serial):
    if not SERIAL_RE.match(serial):
        abort(400)

    entries = load_certificates()
    match = next((e for e in entries if e["serial"] == serial), None)
    if match is None:
        abort(404)

    intermediate_dir = os.environ.get("INTERMEDIATECA_DIRECTORY", "")
    cert_path = os.path.join(intermediate_dir, "certs", f"{match['cn']}.cert.pem")
    details = describe_cert(cert_path)
    if details is None:
        flash(f"Could not read the certificate file for {match['cn']}.", "error")
        return redirect(url_for("dashboard"))

    return render_template("cert_view.html", entry=match, details=details)


@app.route("/issue", methods=["GET", "POST"])
def issue():
    if request.method == "GET":
        return render_template("issue.html", extensions=EXTENSIONS, key_specs=KEY_SPECS)

    check_csrf()

    cn = request.form.get("cn", "").strip()
    ou = request.form.get("ou", "").strip()
    extension = request.form.get("extension", "")
    key_spec = request.form.get("key_spec", "")
    sans = request.form.get("sans", "").strip()

    form_state = dict(cn=cn, ou=ou, extension=extension, key_spec=key_spec, sans=sans)

    errors = []
    if not CN_RE.match(cn):
        errors.append(
            'CN must contain only letters, digits, ".", "_", "-", '
            'optionally prefixed with a single "*." wildcard label.'
        )
    if not OU_RE.match(ou):
        errors.append('OU must contain only letters, digits, spaces, ".", "_", "-".')
    if extension not in EXTENSIONS:
        errors.append("Invalid certificate type.")
    if key_spec not in KEY_SPECS:
        errors.append("Invalid key type.")
    san_entries, san_errors = parse_san_entries(sans)
    errors.extend(san_errors)

    if errors:
        for e in errors:
            flash(e, "error")
        return render_template(
            "issue.html", extensions=EXTENSIONS, key_specs=KEY_SPECS, **form_state
        )

    args = [cn, ou, extension, key_spec]
    if san_entries:
        args.append(",".join(san_entries))

    result = run_script("issue_key_cert", args)
    if result.returncode != 0:
        flash(f"issue_key_cert failed:\n{result.stdout}\n{result.stderr}", "error")
        return render_template(
            "issue.html", extensions=EXTENSIONS, key_specs=KEY_SPECS, **form_state
        )

    flash(f"Certificate issued for {cn}.", "success")
    return redirect(url_for("dashboard"))


@app.route("/revoke/<serial>", methods=["POST"])
def revoke(serial):
    check_csrf()

    if not SERIAL_RE.match(serial):
        abort(400)

    entries = load_certificates()
    match = next((e for e in entries if e["serial"] == serial), None)
    if match is None:
        abort(404)
    if match["status"] == "Revoked":
        flash(f"{match['cn']} is already revoked.", "error")
        return redirect(url_for("dashboard"))

    cn = match["cn"]
    if not CN_RE.match(cn):
        abort(400)

    result = run_script("revoke_cert", [cn])
    if result.returncode != 0:
        flash(f"revoke_cert failed:\n{result.stdout}\n{result.stderr}", "error")
        return redirect(url_for("dashboard"))

    crl_result = run_script("generate_crl", [])
    if crl_result.returncode != 0:
        flash(
            f"Certificate revoked, but CRL regeneration failed:\n"
            f"{crl_result.stdout}\n{crl_result.stderr}",
            "error",
        )
        return redirect(url_for("dashboard"))

    flash(f"Certificate for {cn} revoked and CRL regenerated.", "success")
    return redirect(url_for("dashboard"))


@app.route("/renew/<serial>", methods=["POST"])
def renew(serial):
    check_csrf()

    if not SERIAL_RE.match(serial):
        abort(400)

    entries = load_certificates()
    match = next((e for e in entries if e["serial"] == serial), None)
    if match is None:
        abort(404)
    if match["status"] == "Revoked":
        flash(f"{match['cn']} is revoked; issue a new certificate instead of renewing.", "error")
        return redirect(url_for("dashboard"))

    cn = match["cn"]
    ou = match["ou"]
    if not CN_RE.match(cn) or not OU_RE.match(ou):
        abort(400)

    intermediate_dir = os.environ.get("INTERMEDIATECA_DIRECTORY", "")
    cert_path = os.path.join(intermediate_dir, "certs", f"{cn}.cert.pem")
    info = inspect_cert(cert_path, cn)
    if info is None or info["extension"] is None or info["key_spec"] is None:
        flash(
            f"Could not determine the certificate type/key of the existing certificate "
            f"for {cn}; issue a new certificate manually instead.",
            "error",
        )
        return redirect(url_for("dashboard"))

    revoke_result = run_script("revoke_cert", [cn])
    if revoke_result.returncode != 0:
        flash(
            f"Renewal failed while revoking the existing certificate for {cn}:\n"
            f"{revoke_result.stdout}\n{revoke_result.stderr}",
            "error",
        )
        return redirect(url_for("dashboard"))

    crl_result = run_script("generate_crl", [])
    if crl_result.returncode != 0:
        flash(
            f"Existing certificate for {cn} revoked, but CRL regeneration failed:\n"
            f"{crl_result.stdout}\n{crl_result.stderr}",
            "error",
        )
        return redirect(url_for("dashboard"))

    # The old key/cert are chmod 400/444 (read-only); issue_key_cert can't
    # overwrite them via genrsa/openssl ca's -out, so remove them now that
    # they're revoked and no longer needed.
    key_path = os.path.join(intermediate_dir, "private", f"{cn}.key.pem")
    try:
        if os.path.isfile(cert_path):
            os.remove(cert_path)
        if os.path.isfile(key_path):
            os.remove(key_path)
    except OSError as exc:
        flash(
            f"Existing certificate for {cn} was revoked, but the old key/cert files "
            f"could not be removed before reissuing: {exc}",
            "error",
        )
        return redirect(url_for("dashboard"))

    issue_args = [cn, ou, info["extension"], info["key_spec"]]
    if info["extra_sans"]:
        issue_args.append(",".join(info["extra_sans"]))

    issue_result = run_script("issue_key_cert", issue_args)
    if issue_result.returncode != 0:
        flash(
            f"The existing certificate for {cn} was revoked, but reissuing a new one "
            f"failed:\n{issue_result.stdout}\n{issue_result.stderr}\n"
            "Issue a new certificate manually via the Issue Certificate form.",
            "error",
        )
        return redirect(url_for("dashboard"))

    flash(f"Renewed {cn}: new certificate issued, previous one revoked and added to the CRL.", "success")
    return redirect(url_for("dashboard"))


@app.route("/crl")
def crl():
    intermediate_dir = os.environ.get("INTERMEDIATECA_DIRECTORY", "")
    crl_path = os.path.join(intermediate_dir, "crl", "intermediate.crl.pem")
    crl_exists = os.path.isfile(crl_path)
    crl_text = None
    if crl_exists:
        proc = subprocess.run(
            ["openssl", "crl", "-in", crl_path, "-noout", "-text"],
            capture_output=True,
            text=True,
        )
        if proc.returncode == 0:
            crl_text = proc.stdout
    return render_template("crl.html", crl_exists=crl_exists, crl_text=crl_text)


@app.route("/crl/download")
def crl_download():
    intermediate_dir = os.environ.get("INTERMEDIATECA_DIRECTORY", "")
    crl_dir = os.path.join(intermediate_dir, "crl")
    if not os.path.isfile(os.path.join(crl_dir, "intermediate.crl.pem")):
        abort(404)
    return send_from_directory(crl_dir, "intermediate.crl.pem", as_attachment=True)


@app.route("/download/<filename>")
def download(filename):
    if not BUNDLE_RE.match(filename):
        abort(400)
    output_dir = os.environ.get("OUTPUT_DIRECTORY", "")
    if not os.path.isfile(os.path.join(output_dir, filename)):
        abort(404)
    return send_from_directory(output_dir, filename, as_attachment=True)


def main():
    port = int(os.environ.get("ADMIN_PORT", "8080"))
    start_expiry_alert_thread()
    from waitress import serve

    serve(app, host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
