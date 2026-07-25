# lightpki

Running from Docker with Permanent Storage of Certs
output certs are stored in volume out on host.

To start the container

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
--restart=unless-stopped \
lightpki

To issue a certificate  
docker exec -it lightpki ./issue_key_cert ftp.example.com "FTP Server" server_cert 2048

The 4th argument accepts an RSA key length (2048, 4096) or an EC curve
name (prime256v1, secp384r1, secp521r1), e.g.
docker exec -it lightpki ./issue_key_cert ftp.example.com "FTP Server" server_cert prime256v1

To revoke a certificate 
docker exec -it lightpki ./revoke_cert ftp.example.com

Admin UI
When ADMIN_UI=true, a web UI is served on ADMIN_PORT (default 8080) at
http://<host>:8080/ protected by HTTP Basic Auth (ADMIN_USERNAME /
ADMIN_PASSWORD). It lets you view CA and certificate status, issue and
revoke certificates, and view/download the CRL, without needing
docker exec. Always set ADMIN_PASSWORD to something other than the
default before exposing this port. Put it behind a TLS-terminating
reverse proxy for anything beyond local/trusted-network use.

Running standalone
Edit .env for proper configuration
Run initially to set enviroment variable 
source .env

To initialize the PKI
./start_pki

then 

./issue_key_cert ftp.example.com "FTP Server" server_cert 2048
