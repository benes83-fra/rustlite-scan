
set OPENSSL_CONF=C:\%OPENSSL_DIR\bin\cnf\openssl.cnf

openssl genrsa -out ca.key 4096

openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
  -out ca.crt -subj "/CN=Test Root CA"
openssl genrsa -out server.key 2048

openssl req -new -key server.key -out server.csr -subj "/CN=localhost"

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 365 -sha256

