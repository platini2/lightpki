# lightpki

Running from Docker with Permanent Storage of Certs
output certs are stored in volume out on host.

To start the container

sudo docker run -d --name=lightpki \
  -p 2560:2560 \
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
  -e ST="New York" \
  -e L="New York" \
  -e O="Example" \
  -e OU="Example Certificate Authority" \
  -e ROOTCN="Example Root CA" \
  -e INTERMEDIATECN="Example Intermediate CA" \
  -e MAIL="admin@example.com" \
--restart=unless-stopped \
lightpki

To issue a certificate  
docker exec -it lightpki ./issue_key_cert ftp.example.com "FTP Server" server_cert 2048

To revoke a certificate 
docker exec -it lightpki ./revoke_cert ftp.example.com

Running standalone
Edit .env for proper configuration
Run initially to set enviroment variable 
source .env

To initialize the PKI
./startup_pki

then 

./issue_key_cert ftp.example.com "FTP Server" server_cert 2048
