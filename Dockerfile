FROM alpine:3.19
RUN apk add --no-cache openssl zip
WORKDIR /opt/pki
COPY . /opt/pki/
RUN chmod +x create_root_ca create_intermediate_ca sign_root_ca generate_crl \
             issue_key_cert revoke_cert ocsp_check_cert start_ocsp_server \
             start_pki cleanup_pki
EXPOSE 2560
CMD ["./start_pki"]
