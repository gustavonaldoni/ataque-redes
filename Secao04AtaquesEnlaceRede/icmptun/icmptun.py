from scapy.all import ICMP, IP, send

import aes
import argparse
import sys
import textwrap
import threading
import time

MAX_DATA_SIZE = 512  # 512 bytes
SLEEP_SECONDS = 0.1


def print_line():
    print("-" * 40)


def ReLU(number: int) -> int:
    return max(0, number)


def calculate_packet_size(is_the_last: bool, buffer_size: int) -> int:
    ETHERNET_HEADER_SIZE = 14
    IPV4_HEADER_SIZE = 20
    ICMP_HEADER_SIZE = 8

    headers_size = ICMP_HEADER_SIZE + IPV4_HEADER_SIZE + ETHERNET_HEADER_SIZE
    data_size = MAX_DATA_SIZE

    if is_the_last:
        data_size = buffer_size % MAX_DATA_SIZE

    return data_size + headers_size


class ICMPTunClient:
    def __init__(self, args) -> None:
        self.args = args

    def main_menu(self):
        with open("./interface/main_menu.txt", "r") as main_menu_file:
            print(main_menu_file.read())

    def send(self):
        ip = IP(dst=self.args.target)
        icmp = ICMP(type=8, code=0)

        buffer = b""

        if self.args.file:
            with open(self.args.file, "rb") as file:
                file_data = file.read()
                file_size = len(file_data)

                if self.args.encrypted == "yes":
                    aes_return = aes.aes_encrypt(file_data)
                    buffer = aes_return.pack_bytes()

                elif self.args.encrypted == "no":
                    buffer = file_data

                buffer_size = len(buffer)

                last_block_data_size = buffer_size % MAX_DATA_SIZE

                packet_counter = 1

                print(f"[*] Initialing:")
                print(f"    - Source IP:            {ip.src}")
                print(f"    - Destination IP:       {ip.dst}")
                print(f"    - Data block size:      {MAX_DATA_SIZE} bytes")
                print(f"    - Last block data size: {last_block_data_size} bytes")

                if self.args.encrypted == "yes":
                    print(f"    - Encryption:           AES-{aes.AES_KEY_SIZE* 8} EAX")

                print_line()

                print(f"[*] Buffer size:            {buffer_size} bytes")

                if self.args.encrypted == "yes":
                    print(f"    - Key size:             {aes.AES_KEY_SIZE} bytes")
                    print(f"    - Nonce size:           {aes.AES_NONCE_SIZE} bytes")
                    print(f"    - MAC Tag size:         {aes.AES_MAC_TAG_SIZE} bytes")

                print(f"    - File size:            {file_size} bytes")
                print_line()

                packets_to_send = (buffer_size // MAX_DATA_SIZE) + 1
                packets_size = calculate_packet_size(False, buffer_size)
                last_packet_size = calculate_packet_size(True, buffer_size)
                time_to_send = SLEEP_SECONDS * packets_to_send

                print(f"[*] Packets to send:        {packets_to_send}")
                print(f"    - Packets size:         {packets_size} bytes")
                print(f"    - Last packet size:     {last_packet_size} bytes")
                print(f"    - Time to send:         {time_to_send} s")
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

    def run(self):
        self.main_menu()
        print_line()

        self.send_thread = threading.Thread(target=self.send)
        self.send_thread.start()


class ICMPTunServer:
    def __init__(self, args) -> None:
        self.args = args

    def receive(self):
        pass

    def run(self):
        pass


def main():
    epilog = ""

    with open("./interface/epilog.txt", "r") as epilog_file:
        epilog = epilog_file.read()

    parser = argparse.ArgumentParser(
        description="ICMP Tunneler by Gustavo Naldoni",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(epilog),
    )

    parser.add_argument("-t", "--target", required=True, help="specified IP")
    parser.add_argument("-f", "--file", required=True, help="file to send")
    parser.add_argument(
        "-e",
        "--encrypted",
        required=False,
        default="yes",
        help="use encryption (AES EAX)",
    )

    args = parser.parse_args()

    icmptun = ICMPTunClient(args)
    icmptun.run()


if __name__ == "__main__":
    main()
