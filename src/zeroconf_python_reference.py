#!/usr/bin/env python3

from zeroconf import ServiceBrowser, ServiceListener, Zeroconf
import zeroconf

class MyListener(ServiceListener):

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        print(f"Service {name} updated")

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        print(f"Service {name} removed")

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        info = zc.get_service_info(type_, name)
        print(f"Service {name} added, service info: {info}")

zc = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zc, [
    "_googlecast._tcp.local.",
    "_http._tcp.local.",
    "_smb._tcp.local."
], listener)

a = bytes.fromhex("0000000000010000000000000b5f676f6f676c6563617374045f746370056c6f63616c00000c8001")
b = bytes.fromhex("0000840000000001000000030b5f676f6f676c6563617374045f746370056c6f63616c00000c000100000078002e2b4d6954562d41464d55302d3837613135373131326236656438313765663565316636343833666136613135c00cc02e001080010000119400be2369643d38376131353731313262366564383137656635653166363438336661366131352363643d37374639434637423034373041453635304633463941423135373041343733440777703d3830313003726d3d0576653d30350d6d643d4d6954562d41464d55301269633d2f73657475702f69636f6e2e706e6710666e3d5869616f6d6920545620426f780963613d3236363735370473743d300f62733d464138464444394334384433046e663d330963743d4542354343320372733dc02e0021800100000078002d000000001f492438376131353731312d326236652d643831372d656635652d316636343833666136613135c01dc13800018001000000780004c0a884d9")
c = zeroconf._protocol.incoming.DNSIncoming(a)
d = zeroconf._protocol.incoming.DNSIncoming(b)
print(c)
print(d)
print(d.answers()[0])

try:
    input("Press enter to exit...\n\n")
finally:
    zc.close()
