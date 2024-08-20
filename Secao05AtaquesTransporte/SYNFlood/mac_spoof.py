import random

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