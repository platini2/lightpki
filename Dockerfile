FROM alpine:3.19
RUN apk add --no-cache openssl zip python3 py3-pip
WORKDIR /opt/pki
COPY . /opt/pki/
RUN chmod +x create_root_ca create_intermediate_ca sign_root_ca generate_crl \
             issue_key_cert revoke_cert ocsp_check_cert start_ocsp_server \
             start_pki cleanup_pki
RUN pip3 install --no-cache-dir --break-system-packages -r admin/requirements.txt
EXPOSE 2560
EXPOSE 8080
CMD ["./start_pki"]
