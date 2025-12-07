docker build -t local-snmpd .

docker run --rm --name snmpd -p 161:161/udp local-snmpd

