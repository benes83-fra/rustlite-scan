
#!/usr/bin/env python3
#!/usr/bin/env python3
# responder.py
# Advertise a simple _http._tcp.local service with a TXT record.

import time
from zeroconf import ServiceInfo, Zeroconf

service_type = "_http._tcp.local."
service_name = "rustlite-test._http._tcp.local."
service_port = 8080
properties = {"path": "/test", "version": "0.1"}

info = ServiceInfo(
    type_=service_type,
    name=service_name,
    addresses=[b"\x7f\x00\x00\x01"],  # 127.0.0.1 (loopback) as bytes
    port=service_port,
    properties=properties,
    server="rustlite-test.local.",
)

zc = Zeroconf()
print("Registering service:", service_name)
zc.register_service(info,allow_name_change=True)

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    pass
finally:
    print("Unregistering service")
    zc.unregister_service(info)
    zc.close()
# responder.py
# Advertise a simple _http._tcp.local service with a TXT record.

import time
from zeroconf import ServiceInfo, Zeroconf

service_type = "_http._tcp.local."
service_name = "rustlite-test._http._tcp.local."
service_port = 8080
properties = {"path": "/test", "version": "0.1"}

info = ServiceInfo(
    type_=service_type,
    name=service_name,
    addresses=[b"\x7f\x00\x00\x01"],  # 127.0.0.1 (loopback) as bytes
    port=service_port,
    properties=properties,
    server="rustlite-test.local.",
)

zc = Zeroconf()
print("Registering service:", service_name)
zc.register_service(info)

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    pass
finally:
    print("Unregistering service")
    zc.unregister_service(info)
    zc.close()
