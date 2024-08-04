from Crypto.Cipher import AES
from dataclasses import dataclass

import secrets

AES_KEY_SIZE = 32  # 32 bytes * 8 = 256 bits
AES_NONCE_SIZE = 16
AES_MAC_TAG_SIZE = 16


@dataclass
class AESReturnEAXMode:
    key: bytes
    nonce: bytes
    mac_tag: bytes
    ciphertext: bytes

    def format_into_bytes(self) -> bytes:
        return self.key + self.nonce + self.mac_tag + self.ciphertext


def aes_encrypt(data: bytes) -> AESReturnEAXMode:
    key = secrets.token_bytes(AES_KEY_SIZE)
    nonce = secrets.token_bytes(AES_NONCE_SIZE)

    encrypt_cipher = AES.new(key, AES.MODE_EAX, nonce=nonce, mac_len=AES_MAC_TAG_SIZE)
    ciphertext, mac_tag = encrypt_cipher.encrypt_and_digest(data)

    return AESReturnEAXMode(ciphertext, key, nonce, mac_tag)


def aes_decrypt(aes_return: AESReturnEAXMode) -> bytes:
    decrypt_cipher = AES.new(aes_return.key, AES.MODE_EAX, aes_return.nonce)
    plaintext = decrypt_cipher.decrypt_and_verify(
        aes_return.ciphertext, aes_return.mac_tag
    )

    return plaintext
