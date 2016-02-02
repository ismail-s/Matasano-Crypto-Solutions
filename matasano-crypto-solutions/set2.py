from utils import (
    base64_to_bytes,
    aes_ecb_decode,
    aes_ecb_encode,
    get_file,
    split_into_groups,
    xor)


def pad_with_pkcs7(message: bytes, block_length: int) -> bytes:
    if len(message) >= block_length:
        amount_to_pad = len(message) % block_length
    else:
        amount_to_pad = block_length - len(message)
    res = message + (bytes([amount_to_pad]) * amount_to_pad)
    return res


def aes_cbc_decode(ciphertext: bytes, password: bytes, iv: bytes) -> bytes:
    blocks = split_into_groups(ciphertext, 16)
    res = []
    # Sort out the first block on its own, as it requires iv
    res.append(xor(aes_ecb_decode(blocks[0], password), iv))
    # Sort out all other blocks
    for i, block in enumerate(blocks[1:], 1):
        res.append(xor(aes_ecb_decode(block, password), blocks[i - 1]))
    return b''.join(res)


def aes_cbc_encode(plaintext: bytes, password: bytes, iv: bytes) -> bytes:
    blocks = split_into_groups(plaintext, 16)
    res = []
    prev_block = iv
    for block in blocks:
        prev_block = aes_ecb_encode(xor(prev_block, block), password)
        res.append(prev_block)
    return b''.join(res)


print('Set 2')
print('Challenge 9')
res9 = pad_with_pkcs7(b'YELLOW SUBMARINE', 20)
assert res9 == b'YELLOW SUBMARINE\x04\x04\x04\x04'
print(res9)

print('Challenge 10')
ciphertext10 = base64_to_bytes(get_file('10.txt'))
password10 = b'YELLOW SUBMARINE'
iv = b'\x00' * 16
res10 = aes_cbc_decode(ciphertext10, password10, iv).decode('ascii')
assert res10.startswith("I'm back and I'm ringin' the bell")
print(res10)
# Check that encrypting is the opposite of decrypting
test_ciphertext10 = aes_cbc_encode(res10.encode('ascii'), password10, iv)
assert test_ciphertext10 == ciphertext10
