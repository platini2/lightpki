import hmac
import ipaddress
import os
import re
import secrets
import subprocess
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

CN_RE = re.compile(r"^[A-Za-z0-9._-]+$")
OU_RE = re.compile(r"^[A-Za-z0-9 ._-]+$")
SERIAL_RE = re.compile(r"^[0-9A-Fa-f]+$")
BUNDLE_RE = re.compile(r"^[A-Za-z0-9._-]+\.zip$")
EXTENSIONS = ("server_cert", "usr_cert", "ocsp")
KEY_SPECS = {
    "2048": "RSA 2048",
    "4096": "RSA 4096",
    "prime256v1": "ECDSA P-256 (prime256v1)",
    "secp384r1": "ECDSA P-384 (secp384r1)",
    "secp521r1": "ECDSA P-521 (secp521r1)",
}

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

            if status_flag == "R":
                status = "Revoked"
            elif expiry is not None and expiry < now:
                status = "Expired"
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


@app.route("/issue", methods=["GET", "POST"])
def issue():
    if request.method == "GET":
        return render_template("issue.html", extensions=EXTENSIONS, key_specs=KEY_SPECS)

    check_csrf()

    cn = request.form.get("cn", "").strip()
    ou = request.form.get("ou", "").strip()
    extension = request.form.get("extension", "")
    key_spec = request.form.get("key_spec", "")
    san_ip = request.form.get("san_ip", "").strip()

    form_state = dict(cn=cn, ou=ou, extension=extension, key_spec=key_spec, san_ip=san_ip)

    errors = []
    if not CN_RE.match(cn):
        errors.append('CN must contain only letters, digits, ".", "_", "-".')
    if not OU_RE.match(ou):
        errors.append('OU must contain only letters, digits, spaces, ".", "_", "-".')
    if extension not in EXTENSIONS:
        errors.append("Invalid certificate type.")
    if key_spec not in KEY_SPECS:
        errors.append("Invalid key type.")
    if san_ip:
        try:
            ipaddress.ip_address(san_ip)
        except ValueError:
            errors.append("SAN IP is not a valid IPv4/IPv6 address.")

    if errors:
        for e in errors:
            flash(e, "error")
        return render_template(
            "issue.html", extensions=EXTENSIONS, key_specs=KEY_SPECS, **form_state
        )

    args = [cn, ou, extension, key_spec]
    if san_ip:
        args.append(san_ip)

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
    from waitress import serve

    serve(app, host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
