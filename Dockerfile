FROM alpine:3.19
RUN apk add --no-cache openssl zip python3 py3-pip \
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
             start_pki cleanup_pki healthcheck
RUN pip3 install --no-cache-dir --break-system-packages -r admin/requirements.txt
# Host volumes for root/, intermediate/ and out/ must be owned by this uid:
#   sudo chown -R 10001:10001 /var/docker/lightpki
USER pki
EXPOSE 2560
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=180s --retries=3 CMD ["./healthcheck"]
CMD ["./start_pki"]
