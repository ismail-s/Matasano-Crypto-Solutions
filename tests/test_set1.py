from matasano_crypto_solutions.set1 import *  # noqa: F403


def test_task_1():
    res1 = hex_to_base64(
        '49276d206b696c6c696e6720796f757220627261696e206c6'
        '96b65206120706f69736f6e6f7573206d757368726f6f6d')
    assert res1 == (b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc'
                    b'29ub3VzIG11c2hyb29t')


def test_task_2():
    x = hex_to_bytes('1c0111001f010100061a024b53535009181c')
    y = hex_to_bytes('686974207468652062756c6c277320657965')
    res2 = bytes_to_hex(xor(x, y))
    assert res2 == '746865206b696420646f6e277420706c6179'


def test_task_3():
    ciphertext = hex_to_bytes('1b37373331363f78151b7f2b783431333d78397828372d'
                              '363c78373e783a393b3736')
    res3 = decode_1_byte_xor(ciphertext)
    assert res3[1] == "Cooking MC's like a pound of bacon"


def test_task_4():
    ciphertexts = get_file('4.txt').split('\n')
    res4 = find_and_decrypt_ciphertexts(ciphertexts)
    assert res4[1] == 'Now that the party is jumping\n'


def test_task_5():
    plaintext5 = ("Burning 'em, if you ain't quick and nimble\n"
                  "I go crazy when I hear a cymbal""")
    key = "ICE"
    correct_answer = ("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343"
                      "c2a26226324272765272a282b2f20430a652e2c652a3124333a653e"
                      "2b2027630c692b20283165286326302e27282f")
    res5 = bytes_to_hex(repeating_key_xor(text_to_bytes(plaintext5),
                                          text_to_bytes(key)))
    assert res5 == correct_answer


def test_task_6():
    string1 = b'this is a test'
    string2 = b'wokka wokka!!!'
    assert hamming_distance(string1, string2) == 37

    ciphertext6 = get_file('6.txt')
    ciphertext6 = base64_to_bytes(ciphertext6)
    res6 = decode_repeating_byte_xor(ciphertext6)
    assert res6[0] == 'Terminator X: Bring the noise'


def test_task_7():
    ciphertext7 = get_file('7.txt')
    ciphertext7 = base64_to_bytes(ciphertext7)
    password = b"YELLOW SUBMARINE"
    res7 = aes_ecb_decode(ciphertext7, password).decode('ascii')
    assert res7.startswith("I'm back and I'm ringin' the bell ")


def test_task_8():
    ciphertexts8 = get_file('8.txt').split('\n')
    ciphertexts8 = [bytes.fromhex(x) for x in ciphertexts8 if x]
    res8 = detect_aes_ecb_encrypted_texts(ciphertexts8)
    assert len(res8[1]) == 1
    most_likely_string = bytes_to_hex(res8[1][0])
    assert most_likely_string == (
        'd880619740a8a19b7840a8a31c810a3d08649af' +
        '70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af7' +
        '0dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70' +
        'dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70d' +
        'c06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f' +
        '2c123c58386b06fba186a')
    # Max no. of repeats of a 16 byte chunk found
    assert res8[0] == 4
