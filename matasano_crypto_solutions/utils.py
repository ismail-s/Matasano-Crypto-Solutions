from base64 import b64encode, b64decode
from binascii import hexlify
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from typing import Sequence
import os


current_dir = str(Path(__file__).parent)
hex_to_bytes = bytes.fromhex


def bytes_to_hex(x: bytes) -> str:
    return hexlify(x).decode('ascii')


base64_to_bytes = b64decode
bytes_to_base64 = b64encode


def text_to_bytes(text: str) -> bytes:
    return bytes(text, 'ascii')


def get_file(relative_path: str):
    return open(os.path.join(current_dir, relative_path), 'r').read()


def aes_ecb_decode(ciphertext: bytes, password: bytes) -> bytes:
    backend = default_backend()
    cipher = Cipher(algorithms.AES(password), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    res = decryptor.update(ciphertext) + decryptor.finalize()
    return res


def aes_ecb_encode(plaintext: bytes, password: bytes) -> bytes:
    backend = default_backend()
    cipher = Cipher(algorithms.AES(password), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    res = encryptor.update(plaintext) + encryptor.finalize()
    return res


def xor(x: bytes, y: bytes) -> bytes:
    return bytes((a ^ b for a, b in zip(x, y)))


def split_into_groups(string: Sequence, size: int):
    return [string[i:i + size] for i in range(0, len(string), size)]
