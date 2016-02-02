from base64 import b64encode, b64decode
from binascii import hexlify
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
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


def decode_aes_ecb(ciphertext, password):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(password), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    res = decryptor.update(ciphertext) + decryptor.finalize()
    return res.decode('ascii')


def xor(x: bytes, y: bytes) -> bytes:
    return bytes((a ^ b for a, b in zip(x, y)))
