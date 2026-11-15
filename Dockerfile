# Alpine 3.24 ships OpenSSL 3.5 (LTS, supported until 2030).
FROM alpine:3.24
RUN apk add --no-cache openssl zip python3 py3-pip tini \
 && addgroup -S -g 10001 pki \
 && adduser -S -D -H -u 10001 -G pki -h /opt/pki pki
WORKDIR /opt/pki
# Owned by the runtime user: start_pki rewrites intermediate-openssl.cnf in
# place on every start.
COPY --chown=pki:pki . /opt/pki/
# The directory itself must be writable too: `sed -i` creates its temp file
# next to the config. Pre-creating the volume mount points owned by pki also
# makes fresh named Docker volumes start out owned by pki instead of root.
RUN mkdir -p root intermediate out \
 && chown pki:pki /opt/pki root intermediate out \
 && chmod +x create_root_ca create_intermediate_ca sign_root_ca generate_crl \
             issue_key_cert revoke_cert sign_csr ocsp_check_cert start_ocsp_server \
             start_pki cleanup_pki healthcheck sign_acme_csr revoke_serial
RUN pip3 install --no-cache-dir --break-system-packages -r admin/requirements.txt
# Host volumes for root/, intermediate/ and out/ must be owned by this uid:
#   sudo chown -R 10001:10001 /var/docker/lightpki
USER pki
# OCSP, admin UI, CRL/CA certificates (HTTP), ACME (HTTPS)
EXPOSE 2560 8080 8081 8443
HEALTHCHECK --interval=30s --timeout=30s --start-period=180s --retries=3 CMD ["./healthcheck"]
# tini as PID 1 reaps orphaned processes. Without it PID 1 is start_pki or
# the admin UI, which never reap them: BusyBox `timeout` (used by the OCSP
# health check, every ~15s) leaves its watcher process behind, and those
# piled up as thousands of zombies. -s also makes it work when Docker's own
# init (`--init`, compose `init: true`) is PID 1 instead. -e 143: exiting
# because of `docker stop` (SIGTERM) counts as a clean exit.
ENTRYPOINT ["/sbin/tini", "-s", "-e", "143", "--"]
CMD ["./start_pki"]
