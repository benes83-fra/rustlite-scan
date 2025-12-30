docker run -d --name freeradius -p 1812:1812/udp -p 1813:1813/udp -v .\clients.conf:/etc/freeradius/3.2/clients.conf freeradius/freeradius-server:latest-3.2-alpine -X
