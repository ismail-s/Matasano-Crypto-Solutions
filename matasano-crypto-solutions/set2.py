def pad_with_pkcs7(message: bytes, block_length: int) -> bytes:
    if len(message) >= block_length:
        amount_to_pad = len(message) % block_length
    else:
        amount_to_pad = block_length - len(message)
    res = message + (bytes([amount_to_pad]) * amount_to_pad)
    return res


print('Set 2')
print('Challenge 9')
res9 = pad_with_pkcs7(b'YELLOW SUBMARINE', 20)
assert res9 == b'YELLOW SUBMARINE\x04\x04\x04\x04'
print(res9)
