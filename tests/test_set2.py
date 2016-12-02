from matasano_crypto_solutions.set2 import *

def test_task_9():
    res9 = pad_with_pkcs7(b'YELLOW SUBMARINE', 20)
    assert res9 == b'YELLOW SUBMARINE\x04\x04\x04\x04'

def test_task_10():
    ciphertext10 = base64_to_bytes(get_file('10.txt'))
    password10 = b'YELLOW SUBMARINE'
    iv = b'\x00' * 16
    res10 = aes_cbc_decode(ciphertext10, password10, iv).decode('ascii')
    assert res10.startswith("I'm back and I'm ringin' the bell")

    # Check that encrypting is the opposite of decrypting
    test_ciphertext10 = aes_cbc_encode(res10.encode('ascii'), password10, iv)
    assert test_ciphertext10 == ciphertext10
    
def test_task_11():
    some_ciphertext = base64_to_bytes(get_file('10.txt'))
    password, iv = b'YELLOW SUBMARINE', b'\x00' * 16
    some_text = aes_cbc_decode(some_ciphertext, password, iv).decode('ascii')
    plaintext = text_to_bytes(some_text)
    ciphertext, actual_answer = encryption_oracle(plaintext)
    res = check_if_ecb_or_cbc(ciphertext)
    assert res == actual_answer
