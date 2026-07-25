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
- Optional web admin UI: dashboard, issue/revoke/renew certificates, view and
  download the CRL, expiry alerting via webhook — all without `docker exec`.
- Runs standalone (any POSIX `/bin/sh`) or in Docker (Alpine-based image).

## Quick start (Docker, with permanent storage)

Certs/keys are stored in host-mounted volumes so they survive container
rebuilds and restarts.

```
sudo docker run -d --name=lightpki \
  -p 2560:2560 \
  -p 8080:8080 \
  -v /var/docker/lightpki/root:/opt/pki/root:rw \
  -v /var/docker/lightpki/intermediate:/opt/pki/intermediate:rw \
  -v /var/docker/lightpki/out:/opt/pki/out:rw \
  -e PKI_HOME=/opt/pki \
  -e DOMAIN=example.com \
  -e OCSP=true \
  -e OCSP_PORT=2560 \
  -e OCSP_SERVER=true \
  -e CRL=false \
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
# edit .env: set real passphrases/admin password, your domain, etc.
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
```

Marks the certificate revoked in the CA database. Regenerate the CRL
afterwards with `./generate_crl` (the admin UI's Revoke button does this
automatically). The admin UI also regenerates the CRL periodically on its
own (see `CRL_REGEN_INTERVAL_HOURS` below) since it has its own validity
window and goes stale if nothing ever refreshes it — without the admin UI,
schedule `./generate_crl` yourself (e.g. via cron) if you go a long time
between revocations.

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
  type (RSA or ECDSA), and additional SAN entries (comma-separated
  hostnames/IPs, auto-classified).
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

All state-changing actions (issue/revoke/renew) are CSRF-protected and
delegate to the same shell scripts described above — the admin UI never
reimplements certificate logic itself. Put it behind a TLS-terminating
reverse proxy for anything beyond local/trusted-network use.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `PKI_HOME` | — | Base directory; must be the parent of `ROOTCA_DIRECTORY`/`INTERMEDIATECA_DIRECTORY` and match the `openssl.cnf` files' expectations. |
| `DOMAIN` | — | Base domain used to derive `www.$DOMAIN`, `ocsp.$DOMAIN`, `crl.$DOMAIN`. |
| `OCSP` | `false` | Whether to configure/issue an OCSP-signing certificate and AIA extension. |
| `OCSP_PORT` | — | Port the OCSP responder listens on. |
| `OCSP_SERVER` | `false` | Whether `start_pki` launches the OCSP responder. |
| `CRL` | `false` | Whether to set a CRL Distribution Point URI in issued certs. |
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
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | `admin` / — | Admin UI Basic Auth credentials; password is required. |
| `ADMIN_SECRET_KEY` | random | Signs the admin UI's session cookie (CSRF tokens). Set explicitly to keep sessions valid across restarts; otherwise a new random key is generated each start. |
| `EXPIRY_WARNING_DAYS` | `30` | Days-to-expiry threshold for the "Expiring Soon" status/alerting. |
| `EXPIRY_WEBHOOK_URL` | — | If set, enables expiry alerting to this URL. |
| `EXPIRY_CHECK_INTERVAL_HOURS` | `24` | How often the background expiry check runs (plus once at startup). |
| `CRL_REGEN_INTERVAL_HOURS` | `24` | How often the CRL is automatically regenerated (plus once at startup), independent of revocations, so it never goes stale from inactivity. Always active when `ADMIN_UI=true`. |

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
- The admin UI has no built-in TLS — put it behind a reverse proxy if it's
  reachable beyond a trusted local network.
- `.env` is excluded from the Docker build context (`.dockerignore`) so
  passphrases aren't baked into the image layer if you edit it in place —
  prefer passing secrets via `-e`/orchestrator secrets at runtime instead.
