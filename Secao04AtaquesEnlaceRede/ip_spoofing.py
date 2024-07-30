import random

from scapy.all import IP


def generate_binary_str(length: int) -> str:
    binary_str = ""

    for _ in range(length):
        binary_str += str(random.randint(0, 1))

    return binary_str


def complete_byte(value: str) -> str:
    length = len(value)

    if length >= 8:
        return value

    missing = 8 - length

    return "0" * missing + value


def generate_ip(net: str, net_mask: str) -> str:
    net = net.split(".")

    net_integer = [int(ip_part) for ip_part in net]

    net_binary = [bin(ip_part).removeprefix("0b") for ip_part in net_integer]
    net_binary = [complete_byte(ip_part) for ip_part in net_binary]

    ip = "".join(net_binary)

    net_mask = net_mask.removeprefix("/")
    net_mask = int(net_mask)

    net_id = ip[:net_mask]
    new_host_id = generate_binary_str(32 - net_mask)

    new_ip = net_id + new_host_id

    new1 = int(new_ip[:8], base=2)
    new2 = int(new_ip[8:16], base=2)
    new3 = int(new_ip[16:24], base=2)
    new4 = int(new_ip[24:], base=2)

    new_ip = f"{new1}.{new2}.{new3}.{new4}"

    return new_ip

def ip_spoofing(victim_ip: str, attacker_ip: str) -> IP:
    ip = IP()

    ip.src = attacker_ip
    ip.dst = victim_ip

    return ip

victim_ip = "192.168.56.103"
attacker_ip = generate_ip("192.168.56.0", "/24")

ip = ip_spoofing(victim_ip, attacker_ip)
ip.show()
