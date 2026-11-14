# LightPKI CRL / CA certificate HTTP server
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

"""Serve the CRL and the public CA certificates over plain HTTP.

This is what the crlDistributionPoints URL in issued certificates points
at. It is deliberately plain HTTP: clients fetch CRLs while validating a
TLS connection, so serving them over TLS would be circular. Everything
served here is public and signed, so there is nothing to protect.

Read-only, no authentication, a fixed list of files, nothing else.
"""

import base64
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

INTERMEDIATE_DIR = os.environ.get("INTERMEDIATECA_DIRECTORY", "")
ROOT_DIR = os.environ.get("ROOTCA_DIRECTORY", "")
PORT = int(os.environ.get("CRL_PORT", "8081"))


def _pem_to_der(path):
    with open(path) as fh:
        text = fh.read()
    match = re.search(
        r"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", text, re.S
    )
    if not match:
        raise ValueError(f"no certificate in {path}")
    return base64.b64decode("".join(match.group(1).split()))


def _read(path):
    with open(path, "rb") as fh:
        return fh.read()


# URL path -> (content type, loader). Files are read on every request so a
# regenerated CRL is served immediately; they are all small.
ROUTES = {
    "/intermediate.crl": (
        "application/pkix-crl",
        lambda: _read(os.path.join(INTERMEDIATE_DIR, "crl", "intermediate.crl")),
    ),
    "/intermediate.crl.pem": (
        "application/x-pem-file",
        lambda: _read(os.path.join(INTERMEDIATE_DIR, "crl", "intermediate.crl.pem")),
    ),
    "/ca-chain.pem": (
        "application/pem-certificate-chain",
        lambda: _read(os.path.join(INTERMEDIATE_DIR, "certs", "ca-chain.cert.pem")),
    ),
    "/root.crt": (
        "application/pkix-cert",
        lambda: _pem_to_der(os.path.join(ROOT_DIR, "certs", "ca.cert.pem")),
    ),
    "/intermediate.crt": (
        "application/pkix-cert",
        lambda: _pem_to_der(os.path.join(INTERMEDIATE_DIR, "certs", "intermediate.cert.pem")),
    ),
}


class Handler(BaseHTTPRequestHandler):
    server_version = "LightPKI-CRL"
    sys_version = ""
    # Drop clients that connect and then send nothing.
    timeout = 10

    def _respond(self, send_body):
        route = ROUTES.get(self.path.split("?", 1)[0])
        if route is None:
            self.send_error(404)
            return
        content_type, loader = route
        try:
            body = loader()
        except (OSError, ValueError):
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # Clients cache CRLs until nextUpdate on their own; keep proxies honest.
        self.send_header("Cache-Control", "max-age=300")
        self.end_headers()
        if send_body:
            self.wfile.write(body)

    def do_GET(self):
        self._respond(True)

    def do_HEAD(self):
        self._respond(False)

    def log_message(self, fmt, *args):
        sys.stderr.write("crl-server: %s - %s\n" % (self.address_string(), fmt % args))


def main():
    server = ThreadingHTTPServer(("", PORT), Handler)
    server.daemon_threads = True
    print(f"CRL server listening on port {PORT}", file=sys.stderr)
    server.serve_forever()


if __name__ == "__main__":
    main()
