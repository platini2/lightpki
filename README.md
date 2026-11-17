# lightpki

A lightweight, self-hosted two-tier Certificate Authority (root + intermediate)
built on plain OpenSSL shell scripts, with certificate issuance, revocation,
CRL, an OCSP responder, and an optional web admin UI. Runs standalone or in
Docker, with all state (keys, certs, CA database) kept in a few plain
directories you control.

## Features

- Root CA + intermediate CA, standard X.509v3 extensions (`basicConstraints`,
  `keyUsage`, `extendedKeyUsage`).
- Issue server, client, and OCSP-signing certificates (`server_cert`,
  `usr_cert`, `ocsp`).
- RSA (any length) or ECDSA (`prime256v1`, `secp384r1`, `secp521r1`) keys,
  your choice independently for the root CA, the intermediate CA, and each
  issued certificate.
- Wildcard CNs (`*.example.com`).
- Multiple Subject Alternative Names per certificate — any mix of DNS names
  (including wildcards) and IPv4/IPv6 addresses; the CN is always included
  as a SAN automatically.
- Sign externally-generated CSRs — the requester's private key never has
  to touch this CA.
- Revocation with automatic CRL regeneration, and a built-in OCSP responder.
- The CRL and CA certificates served over HTTP at the CRL Distribution
  Point URL embedded in issued certificates.
- Optional ACME server (RFC 8555, http-01): certbot, acme.sh, lego, Caddy,
  Traefik or cert-manager get and renew certificates automatically, the way
  they would from Let's Encrypt.
- Optional web admin UI: dashboard, issue/revoke/renew certificates, view and
  download the CRL, expiry alerting via webhook — all without `docker exec`.
- Runs standalone (any POSIX `/bin/sh`) or in Docker (Alpine-based image).

## Quick start (Docker, with permanent storage)

Certs/keys are stored in host-mounted volumes so they survive container
rebuilds and restarts. The container runs as an unprivileged user
(uid/gid `10001`), so the host directories must be owned by it. This also
applies when upgrading from an older version that ran as root:

```
sudo mkdir -p /var/docker/lightpki/root /var/docker/lightpki/intermediate /var/docker/lightpki/out
sudo chown -R 10001:10001 /var/docker/lightpki
```

```
sudo docker run -d --name=lightpki \
  -p 2560:2560 \
  -p 127.0.0.1:8080:8080 \
  -p 8081:8081 \
  -p 8443:8443 \
  -v /var/docker/lightpki/root:/opt/pki/root:rw \
  -v /var/docker/lightpki/intermediate:/opt/pki/intermediate:rw \
  -v /var/docker/lightpki/out:/opt/pki/out:rw \
  -e PKI_HOME=/opt/pki \
  -e DOMAIN=example.com \
  -e OCSP=true \
  -e CRL=true \
  -e ACME=true \
  -e ACME_ALLOWED_DOMAINS=example.com \
  -e OCSP_PORT=2560 \
  -e OCSP_SERVER=true \
  -e ROOTCA_DIRECTORY=/opt/pki/root \
  -e ROOTCA_PASSPHRASE=TESTING123 \
  -e INTERMEDIATECA_DIRECTORY=/opt/pki/intermediate \
  -e INTERMEDIATECA_PASSPHRASE=TESTING123 \
  -e OUTPUT_DIRECTORY=/opt/pki/out \
  -e C=US \
  -e ST=New York \
  -e L=New York \
  -e O=Example \
  -e OU=Example Certificate Authority \
  -e ROOTCN=Example Root CA \
  -e INTERMEDIATECN=Example Intermediate CA \
  -e MAIL=admin@example.com \
  -e ADMIN_UI=true \
  -e ADMIN_PORT=8080 \
  -e ADMIN_USERNAME=admin \
  -e ADMIN_PASSWORD=CHANGE_ME \
  -e EXPIRY_WARNING_DAYS=30 \
  -e EXPIRY_WEBHOOK_URL=https://your-webhook-endpoint \
  -e EXPIRY_CHECK_INTERVAL_HOURS=24 \
  -e CRL_REGEN_INTERVAL_HOURS=24 \
  --restart=unless-stopped \
  lightpki
```

`ROOTCA_PASSPHRASE`, `INTERMEDIATECA_PASSPHRASE`, and `ADMIN_PASSWORD` **must**
be changed to real secrets before any non-test use — `TESTING123`/
`CHANGE_ME` are placeholders only.

On first run this creates the root CA, intermediate CA, an OCSP-signing
certificate (if `OCSP=true`), and a `www.$DOMAIN` server certificate, then
starts the OCSP responder and/or admin UI depending on the flags below.
Subsequent restarts skip CA creation (guarded by a `.initialized` marker in
the persisted `root/` volume) but still re-apply the OCSP/CRL URI
configuration on every start, so those stay correct even across image
rebuilds.

The admin UI is published on `127.0.0.1` only. Reach it over an SSH tunnel
or a TLS-terminating reverse proxy on the same host; don't publish port
8080 directly, since Basic Auth over plain HTTP sends the password readable.
The OCSP responder (port 2560) is meant to be reachable by clients and only
serves signed, public revocation status.

The OCSP responder is restarted automatically if it exits, and the image
has a `HEALTHCHECK` (`./healthcheck`) that fails when the admin UI or OCSP
port stops accepting connections, so `docker ps` shows `unhealthy`.

### Taking the root CA offline

The root CA is only used once, on first start, to sign the intermediate.
After that the running services never need it, and `start_pki` drops
`ROOTCA_PASSPHRASE` before starting them. Leaving the root key on the same
server as the web UI means a compromise of the UI is a compromise of the
whole PKI, so once the first start has finished:

1. Copy `/var/docker/lightpki/root/private/ca.key.pem` to offline storage
   (encrypted USB drive, password manager attachment, HSM...).
2. Delete it from the server: `sudo shred -u /var/docker/lightpki/root/private/ca.key.pem`.
3. Recreate the container without `-e ROOTCA_PASSPHRASE=...` (the value is
   otherwise visible to anyone who can run `docker inspect`).

Keep `root/certs/ca.cert.pem` and the `.initialized` marker in place. Until
the key is removed, `start_pki` prints a warning on every start. To sign a
new intermediate later, restore the key temporarily and run `sign_root_ca`.

Once running:

```
docker exec -it lightpki ./issue_key_cert ftp.example.com "FTP Server" server_cert 2048
docker exec -it lightpki ./revoke_cert ftp.example.com
```

## Quick start (standalone)

Any POSIX shell (`dash`, `bash`, Alpine's `ash`) — no bash-only syntax is
used.

```
git clone <repo> && cd lightpki
cp .env.example .env
# edit .env: set real passphrases/admin password, your domain, etc.
# .env is git-ignored; never commit it.
set -a; source .env; set +a
./start_pki
./issue_key_cert ftp.example.com "FTP Server" server_cert 2048
```

## Issuing certificates

```
issue_key_cert <CN> <OU> <extension> <key_spec> [SAN_LIST]
```

| Argument | Meaning |
|---|---|
| `CN` | Common Name / hostname. Letters, digits, `.`, `_`, `-`, or a single leading `*.` wildcard label (e.g. `*.example.com`). |
| `OU` | Organizational Unit, free text (quote it if it has spaces). |
| `extension` | `server_cert` (TLS server), `usr_cert` (TLS client), or `ocsp` (OCSP responder signing cert). |
| `key_spec` | RSA key length (`2048`, `4096`) or an EC curve name (`prime256v1`, `secp384r1`, `secp521r1`). |
| `SAN_LIST` (optional) | Comma-separated extra SAN entries as `DNS:name` or `IP:address`. The CN is always included as a SAN automatically, even if this is omitted. |

Examples:

```
issue_key_cert ftp.example.com "FTP Server" server_cert 2048
issue_key_cert ftp.example.com "FTP Server" server_cert prime256v1
issue_key_cert "*.example.com" "Web Service" server_cert 2048
issue_key_cert www.example.com "Web Service" server_cert 2048 "DNS:example.com,IP:10.0.0.5"
```

Each issuance produces `certs/<CN>.cert.pem`, `private/<CN>.key.pem` (mode
400), and a zip bundle (`<CN>.zip`, containing the cert, key, and CA chain)
in `OUTPUT_DIRECTORY`.

Certificate validity defaults to 3650 days; override with the `CERT_DAYS`
environment variable.

## Signing an externally-generated CSR

If the requester generates their own key and CSR (so the private key never
touches this CA), sign it directly instead:

```
sign_csr <CSR_FILE> <extension>
```

Only the CN is trusted from the submitted CSR — every other DN field
(organization, etc.) is replaced with this CA's own values, and
`basicConstraints`/`keyUsage`/`extendedKeyUsage` always come from the
`extension` type regardless of what the CSR requests (a CSR asking for
`CA:TRUE` or `keyCertSign` is signed anyway, just with those requests
silently ignored). SAN entries the CSR itself requests **are** copied
into the issued certificate as-is — review them before signing.

The admin UI's **Sign CSR** page does this review for you: paste a CSR,
and it shows the extracted CN, requested SAN entries, key type, and any
suspicious requested extensions before you confirm and sign.

No private key is generated or stored by this CA for CSR-signed
certificates, so their zip bundle contains only the cert and chain.

## Revoking certificates

```
revoke_cert ftp.example.com
revoke_serial 100A [reason]
```

`revoke_cert` revokes the latest certificate issued for a name;
`revoke_serial` revokes exactly one certificate by serial number (shown in
the admin UI), which is what you want when several certificates share a
name, e.g. after ACME renewals. The admin UI always revokes by serial.
Either marks the certificate revoked in the CA database. Regenerate the CRL
afterwards with `./generate_crl` (the admin UI's Revoke button does this
automatically). The admin UI also regenerates the CRL periodically on its
own (see `CRL_REGEN_INTERVAL_HOURS` below) since it has its own validity
window and goes stale if nothing ever refreshes it. With the admin UI off
but `OCSP_SERVER=true`, `start_pki` does the same refresh itself. With both
off, schedule `./generate_crl` yourself (e.g. via cron).

All scripts that change the CA database (`issue_key_cert`, `sign_csr`,
`sign_acme_csr`, `revoke_cert`, `revoke_serial`, `generate_crl`) take an exclusive lock on
`$INTERMEDIATECA_DIRECTORY/.ca.lock`, so running them at the same time (from
the admin UI, `docker exec`, or cron) is safe. They need `flock`, which
Alpine's BusyBox and util-linux provide; on macOS install it with
`brew install flock`.

## Serving the CRL over HTTP

With `CRL=true`, issued server certificates carry a CRL Distribution Point
of `http://crl.$DOMAIN:$CRL_PORT/intermediate.crl` (no port when
`CRL_PORT=80`), and `start_pki` runs a small read-only HTTP server on
`CRL_PORT` (default 8081) that answers it. Point `crl.$DOMAIN` at the
LightPKI host in your DNS. It serves:

| Path | Content |
|---|---|
| `/intermediate.crl` | The CRL, DER-encoded (what clients fetch) |
| `/intermediate.crl.pem` | The same CRL, PEM |
| `/ca-chain.pem` | Intermediate + root certificates, PEM |
| `/root.crt` | Root CA certificate, DER (to install in trust stores) |
| `/intermediate.crt` | Intermediate CA certificate, DER |

It is plain HTTP on purpose: clients fetch CRLs while checking a TLS
connection, so serving them over TLS would be circular, and everything
here is public and signed. The CRL is regenerated on every start, after
every revocation, and every `CRL_REGEN_INTERVAL_HOURS`.

Certificates issued before `CRL=true` (or before this version, which used
a `.crl.pem` URL on port 80) keep their old URL until they are renewed.

## ACME (automatic issuance and renewal)

With `ACME=true`, `start_pki` runs an ACME server (RFC 8555) on `ACME_PORT`
(default 8443, HTTPS). On first start it issues itself a certificate for
`acme.$DOMAIN`; point that name at the LightPKI host in your DNS. The
directory URL is:

```
https://acme.example.com:8443/acme/directory
```

Clients must trust the LightPKI root first, since the ACME server's own
certificate comes from it (see "Trusting the LightPKI root" below). Then,
for example with the distribution's certbot package:

```
certbot certonly --standalone \
  --server https://acme.example.com:8443/acme/directory \
  -d app.example.com -d www.app.example.com
certbot renew        # from cron/systemd timer, as usual
```

Debian/Ubuntu and RHEL-family certbot packages use the system trust store.
The certbot snap doesn't: run it with
`REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt`, including from its
renewal timer.

How it works and what it allows:

- **Validation:** `http-01` only. LightPKI fetches
  `http://<name>/.well-known/acme-challenge/<token>` on port 80, so each
  name must resolve, from the LightPKI host, to the machine running the
  client. No `dns-01`, so no wildcard certificates over ACME.
- **Allowed names:** DNS names equal to or under one of
  `ACME_ALLOWED_DOMAINS` (comma-separated, default `$DOMAIN`). Anything
  else is refused. No IP addresses.
- **Certificates:** `ACME_CERT_DAYS` (default 90) days, server-auth only,
  with the same OCSP/CRL URLs as other server certificates, subject
  `OU=ACME`. Only the validated names are included; anything else the CSR
  asks for (extra names, `CA:TRUE`, other extensions) is ignored. RSA
  (2048+) or ECDSA P-256/P-384 keys.
- **Accounts:** any key can register; there is no external account binding,
  so anyone who can reach the ACME port and control a name under the
  allowed domains can get a certificate for it. Keep the port on your
  internal network.
- **Revocation:** `certbot revoke` works for certificates the same account
  obtained. ACME certificates show in the admin UI with `OU=ACME`; you can
  view and revoke them there, but not renew them (their client does that).
- State (accounts, orders, issued certificates) lives in
  `intermediate/acme/` on the persistent volume.

## Trusting the LightPKI root

Machines only accept LightPKI certificates (including the admin UI's and the
ACME server's) once the LightPKI root is installed in their trust store. The
CRL server publishes it at `http://crl.example.com:8081/root.crt` (DER). It
is downloaded over plain HTTP, so compare its SHA-256 fingerprint with the
one in the admin UI (Dashboard → Root CA → View) before trusting it:

```
openssl x509 -inform DER -in root.crt -noout -fingerprint -sha256
```

Debian/Ubuntu (`update-ca-certificates` needs PEM, so convert while saving):

```
curl -s http://crl.example.com:8081/root.crt | sudo openssl x509 -inform DER -out /usr/local/share/ca-certificates/lightpki-root.crt
sudo update-ca-certificates
```

RHEL/Rocky/Alma/Fedora (accepts DER as is):

```
sudo curl -s -o /etc/pki/ca-trust/source/anchors/lightpki-root.crt http://crl.example.com:8081/root.crt
sudo update-ca-trust
```

macOS (Safari, Chrome and the system):

```
curl -s -o /tmp/lightpki-root.crt http://crl.example.com:8081/root.crt
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain /tmp/lightpki-root.crt
```

Windows (administrator PowerShell):

```
Invoke-WebRequest http://crl.example.com:8081/root.crt -OutFile lightpki-root.crt
Import-Certificate -FilePath lightpki-root.crt -CertStoreLocation Cert:\LocalMachine\Root
```

Firefox uses its own store unless `security.enterprise_roots.enabled` is
on (the default on Windows and macOS); otherwise import the file under
Settings → Privacy & Security → Certificates.

## Checking OCSP status

```
./ocsp_check_cert /path/to/some.cert.pem
```

Queries the running OCSP responder for that certificate's status
(`good`/`revoked`).

## Admin UI

Set `ADMIN_UI=true` to serve a web UI on `ADMIN_PORT` (default 8080),
protected by HTTP Basic Auth (`ADMIN_USERNAME` / `ADMIN_PASSWORD` — the app
refuses to start if the password is empty). It lets you do everything below
without `docker exec`:

- **Dashboard** — root/intermediate CA subject and expiry, and a table of
  every issued certificate with its status (Valid / Expiring Soon / Expired /
  Revoked), serial, expiry, and a download link for its zip bundle.
- **View** — a View button on every issued certificate (or click its CN)
  and on the root/intermediate CA rows opens a friendly decoded page:
  subject, issuer, validity dates, key algorithm/size, signature
  algorithm, SHA-256 fingerprint, key usage/extended key usage,
  Authority Info Access, and the full SAN list — plus the raw
  `openssl x509 -text` output in a collapsible section for anyone who
  wants it.
- **Issue** — a form for CN (including wildcards), OU, certificate type, key
  type (RSA or ECDSA), additional SAN entries (comma-separated
  hostnames/IPs, auto-classified), and a validity period (days, defaults
  to `CERT_DAYS`/3650, overridable per certificate).
- **Sign CSR** — paste an externally-generated CSR; shows the extracted CN,
  requested SAN entries, key type, and any suspicious requested extensions
  (`CA:TRUE`, `keyCertSign` — always ignored regardless) for review before
  you confirm and sign. No private key ever touches this CA for these.
- **Revoke** — one click; automatically regenerates the CRL afterwards.
- **Renew** — one click on any non-revoked certificate: reads the *existing*
  certificate's extension type, key algorithm/size, and SAN entries back out
  of the cert itself, revokes it, regenerates the CRL, and reissues a fresh
  certificate with the same identity — no need to remember what you
  originally issued it with.
- **CRL** — view the parsed CRL and download the raw file. It's also
  regenerated automatically on startup and every `CRL_REGEN_INTERVAL_HOURS`
  (default 24), independent of whether anything's actually been revoked —
  the CRL has its own validity window (`default_crl_days = 30`) and goes
  stale on its own if nothing ever regenerates it.
- **Expiry alerting** — if `EXPIRY_WEBHOOK_URL` is set, certificates *and
  the root/intermediate CA certificates themselves* within
  `EXPIRY_WARNING_DAYS` (default 30) of expiring show as "Expiring Soon," and
  a background check (on startup, then every `EXPIRY_CHECK_INTERVAL_HOURS`,
  default 24) POSTs a JSON payload
  (`{cn, ou, serial, expiry, days_remaining, message}`) to that URL once per
  certificate the first time it crosses the threshold. A CA cert lapsing is
  far more serious than any single leaf cert — every certificate it signed
  stops verifying — so it's watched the same way.

### HTTPS for the admin UI

Set `ADMIN_TLS=true` to serve the admin UI over HTTPS on the same
`ADMIN_PORT`, instead of plain HTTP. On first start LightPKI issues itself a
certificate for `admin.$DOMAIN`, plus `localhost` and `127.0.0.1` so it also
works over an SSH tunnel (`ADMIN_TLS_SANS` changes those extra names). Point
`admin.$DOMAIN` at the LightPKI host and open
`https://admin.example.com:8080`; browsers trust it once the LightPKI root
is installed (see "Trusting the LightPKI root" under ACME).

To use a certificate from another CA instead, such as a Let's Encrypt
certificate from certbot, see "Using a certbot certificate" below.

With HTTPS on, the session cookie is marked `Secure`, so the login and the
CSRF token only travel encrypted.

Certificates for LightPKI's own services (the admin UI and the ACME server)
are valid for 397 days, renewed automatically 30 days before they expire
(checked at start and hourly), and picked up without a restart. 397 days
because Apple platforms (Safari, and Chrome on macOS) reject TLS server
certificates valid for more than 825 days, even from a private CA. A 10-year
ACME server certificate from LightPKI 1.4 is replaced on the first start.
To change the admin certificate's names, delete
`intermediate/certs/admin.<domain>.cert.pem` and restart.

### Using a certbot certificate

If certbot already manages a certificate for the admin UI's name (for
example a Let's Encrypt one, trusted by every browser without installing the
LightPKI root), mount certbot's folder read-only and point LightPKI at the
files:

```yaml
  lightpki:
    image: platini2/lightpki:1.5
    environment:
      ADMIN_UI: "true"
      ADMIN_TLS: "true"
      ADMIN_TLS_CERT: /certs/live/admin.example.com/fullchain.pem
      ADMIN_TLS_KEY: /certs/live/admin.example.com/privkey.pem
    volumes:
      - /var/docker/certbot/certs:/certs:ro
```

- **Mount the whole certbot config folder** (what certbot calls
  `/etc/letsencrypt`), not just `live/<name>`: the files in `live/` are
  symlinks into `archive/`, which must be inside the mount too.
- **Use `fullchain.pem`**, not `cert.pem`, so browsers get the intermediate.
- **Renewals are picked up automatically.** LightPKI checks hourly whether
  the certificate changed and reloads the admin UI without a restart, once
  the new certificate and key match.
- **The key must be readable by LightPKI.** The container runs as uid/gid
  `10001`, and certbot keeps `privkey.pem` and the `live/` and `archive/`
  folders root-only. LightPKI refuses to start with a message saying so.
  Grant group `10001` read access to just this certificate with a certbot
  deploy hook, which also re-applies it after every renewal. Save it as
  `renewal-hooks/deploy/lightpki.sh` inside the certbot folder
  (`/var/docker/certbot/certs/renewal-hooks/deploy/lightpki.sh`), make it
  executable, and run it once by hand:

  ```sh
  #!/bin/sh
  # Let LightPKI (gid 10001) read the admin UI certificate and key.
  NAME=admin.example.com
  LE=$(cd "$(dirname "$0")/../.." && pwd)   # certbot's config folder
  for d in "$LE/live" "$LE/archive" "$LE/live/$NAME" "$LE/archive/$NAME"; do
      chgrp 10001 "$d" && chmod g+rx "$d"
  done
  chgrp 10001 "$LE/archive/$NAME"/privkey*.pem
  chmod g+r "$LE/archive/$NAME"/privkey*.pem
  ```

  Other certificates' keys stay root-only.

LightPKI never writes to the mounted folder and doesn't issue or renew this
certificate; certbot does.

All state-changing actions (issue/revoke/renew) are CSRF-protected and
delegate to the same shell scripts described above — the admin UI never
reimplements certificate logic itself. Without `ADMIN_TLS=true`, keep it
on localhost or behind a TLS-terminating reverse proxy.

## Environment variables

The same `.env` file works with `set -a; source .env` and with
`docker run --env-file .env` / Compose `env_file:`. Docker keeps quotes
literally, so the scripts strip one pair of surrounding quotes from the
name settings (`C`, `ST`, `L`, `O`, `OU`, `ROOTCN`, `INTERMEDIATECN`,
`MAIL`, `DOMAIN`); otherwise they would end up inside every certificate
name, which LibreSSL-based clients reject.

| Variable | Default | Purpose |
|---|---|---|
| `PKI_HOME` | — | Base directory; must be the parent of `ROOTCA_DIRECTORY`/`INTERMEDIATECA_DIRECTORY` and match the `openssl.cnf` files' expectations. |
| `DOMAIN` | — | Base domain used to derive `www.$DOMAIN`, `ocsp.$DOMAIN`, `crl.$DOMAIN`. |
| `OCSP` | `false` | Whether to configure/issue an OCSP-signing certificate and AIA extension. |
| `OCSP_PORT` | — | Port the OCSP responder listens on. |
| `OCSP_SERVER` | `false` | Whether `start_pki` launches the OCSP responder. |
| `CRL` | `false` | Set a CRL Distribution Point URI in issued server certs and serve it over HTTP. |
| `CRL_PORT` | `8081` | Port of the CRL / CA certificate HTTP server; part of the CRL URL unless `80`. |
| `ACME` | `false` | Run the ACME server. |
| `ACME_PORT` | `8443` | HTTPS port of the ACME server. |
| `ACME_ALLOWED_DOMAINS` | `$DOMAIN` | Comma-separated domains ACME may issue for (the domain itself and anything under it). |
| `ACME_CERT_DAYS` | `90` | Validity of certificates issued over ACME. |
| `ROOTCA_DIRECTORY` / `INTERMEDIATECA_DIRECTORY` | — | Where each CA's keys/certs/database live. |
| `ROOTCA_PASSPHRASE` / `INTERMEDIATECA_PASSPHRASE` | — | Passphrases encrypting each CA's private key. Required (non-empty) or the corresponding `create_*_ca` script refuses to run. |
| `ROOTCA_KEY_SPEC` / `INTERMEDIATECA_KEY_SPEC` | `4096` | RSA key length or EC curve name (`prime256v1`, `secp384r1`, `secp521r1`) for each CA's own key. Independent per CA -- an EC root can sign an RSA intermediate and vice versa. |
| `ROOTCA_DAYS` / `INTERMEDIATECA_DAYS` | `3650` | Validity period (days) for the root/intermediate CA certs themselves. |
| `OUTPUT_DIRECTORY` | — | Where issued cert/key/chain zip bundles are written. |
| `C`, `ST`, `L`, `O`, `OU`, `MAIL` | — | Distinguished Name fields shared by both CAs. |
| `ROOTCN` / `INTERMEDIATECN` | — | Common Names for the root/intermediate CA certs. |
| `CERT_DAYS` | `3650` | Validity period (days) for issued leaf certificates. |
| `ADMIN_UI` | `false` | Enable the web admin UI. |
| `ADMIN_PORT` | `8080` | Admin UI listen port. |
| `ADMIN_TLS` | `false` | Serve the admin UI over HTTPS (see "HTTPS for the admin UI"). |
| `ADMIN_TLS_SANS` | `DNS:localhost,IP:127.0.0.1` | Extra names in the admin UI certificate, besides `admin.$DOMAIN`. |
| `ADMIN_TLS_CERT` / `ADMIN_TLS_KEY` | — | Use this PEM certificate (chain) and key for the admin UI instead of issuing one, e.g. from a mounted certbot folder; reloaded when they change. |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | `admin` / — | Admin UI Basic Auth credentials; password is required. |
| `ADMIN_SECRET_KEY` | random | Signs the admin UI's session cookie (CSRF tokens). Set explicitly to keep sessions valid across restarts; otherwise a new random key is generated each start. |
| `EXPIRY_WARNING_DAYS` | `30` | Days-to-expiry threshold for the "Expiring Soon" status/alerting. |
| `EXPIRY_WEBHOOK_URL` | — | If set, enables expiry alerting to this URL. |
| `EXPIRY_CHECK_INTERVAL_HOURS` | `24` | How often the background expiry check runs (plus once at startup). |
| `CRL_REGEN_INTERVAL_HOURS` | `24` | How often the CRL is automatically regenerated (plus once at startup), independent of revocations, so it never goes stale from inactivity. Active when `ADMIN_UI=true` or `OCSP_SERVER=true`. |

## Cleanup

```
./cleanup_pki
```

Wipes `root/`, `intermediate/`, and `out/` — irreversible, only for
resetting a test instance.

## Security notes

- This is a **private** CA. Browsers/clients only trust certificates it
  issues once you've explicitly imported `ca-chain.cert.pem`'s root into
  their trust store — it does not (and cannot) get you a publicly-trusted
  certificate the way Let's Encrypt/a commercial CA would.
- Change every placeholder credential (`ROOTCA_PASSPHRASE`,
  `INTERMEDIATECA_PASSPHRASE`, `ADMIN_PASSWORD`) before any real deployment.
- The admin UI uses plain HTTP unless `ADMIN_TLS=true`. The Quick start
  publishes it on `127.0.0.1` only; with HTTPS on you can publish it on
  your network, but it still guards the whole CA behind one password.
- The ACME server issues to anyone who can reach it and pass http-01 for a
  name under `ACME_ALLOWED_DOMAINS`; keep port 8443 internal and the
  allowed domains narrow.
- Take the root CA key offline after first start (see
  "Taking the root CA offline").
- The container runs as uid `10001`, not root.
- `.env` is git-ignored and excluded from the Docker build context
  (`.dockerignore`); copy `.env.example` to start. Prefer passing secrets
  via `-e`/orchestrator secrets at runtime.

## License

LightPKI is Copyright (C) 2026 Patricio S. Latini.

This program is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option)
any later version. It is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
[LICENSE](LICENSE) file for the full text.

The current version is in the [VERSION](VERSION) file and is shown at the
bottom of every admin UI page.
