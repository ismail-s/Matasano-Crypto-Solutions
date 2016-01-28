from base64 import b64encode, b64decode
from binascii import hexlify, unhexlify
from collections import Counter, defaultdict
from string import ascii_letters
from typing import Dict, Iterable, List
from pathlib import Path
import os
import itertools
from functools import reduce
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

current_dir = str(Path(__file__).parent)


def get_file(relative_path: str):
    return open(os.path.join(current_dir, relative_path), 'r').read()


def get_most_common_from_counter(counter: Counter, n: int):
    """Like counter.most_common(n), but includes elements with
    equal counts, which means the returned
    list may be longer than n. Elements with the same count are ordered in
    reverse alphabetical order (easier to code), but all elements with a
    given count will be returned if one is returned.

    >>> get_most_common_from_counter(Counter('test'), 1)
    [('t', 2)]
    >>> get_most_common_from_counter(Counter('test'), 2)
    [('t', 2), ('s', 1), ('e', 1)]
    >>> get_most_common_from_counter(Counter('test'), 1)
    [('t', 2)]
    >>> get_most_common_from_counter(Counter('teest'), 1)
    [('t', 2), ('e', 2)]
    >>> get_most_common_from_counter(Counter('teest'), 9)
    [('t', 2), ('e', 2), ('s', 1)]"""
    if n < 0:
        return []
    elems = counter.most_common()
    # nums holds all the nums we have seen so far, including duplicates
    last_num = elems[0][1]
    total_nums_so_far = i = 1
    for elem, num in elems[1:]:
        if total_nums_so_far >= n and num < last_num:
            break
        # we either haven't got enough nums or we haven't finished collecting
        # elems with the same count
        last_num = num
        total_nums_so_far += 1
        i += 1
    return sorted(elems[:i], key=lambda tup: str(
        tup[1]) + tup[0], reverse=True)


def hex_to_base64(bstr: str):
    return b64encode(bytes.fromhex(bstr))


def xor(x: str, y: str):
    x = bytes.fromhex(x)
    y = bytes.fromhex(y)
    return hexlify(bytes((a ^ b for a, b in zip(x, y))))


def repeating_key_xor(string: bytes, key: bytes) -> str:
    res = bytearray()
    repeating_key = itertools.cycle(key)
    for a, b in zip(string, repeating_key):
        res.append(a ^ b)
    return hexlify(res).decode('ascii')


def find_english_text(texts: Iterable):
    scores = defaultdict(list)
    for text in texts:
        score = 0
        count = Counter(text.lower())
        most_common = {x for x, _ in get_most_common_from_counter(count, 5)}
        least_common = {x for x, _ in count.most_common()[:-5 - 1:-1]}
        for e in ['e', 't', 'a', 'o']:
            if e in most_common:
                score += 1
        for e in ['z', 'q', 'x']:
            if e in least_common or e not in count:
                score += 1
        for e in text:
            if e not in ascii_letters:
                score -= 1
        if count[' '] < 2:
            score -= 2
        scores[score].append(text)
    max_score = max(scores.keys())
    res = scores[max_score]
    choice = 0
    if len(res) > 1:
        if max_score < 0:
            return ''
        choice = int(input('Select one of these: '))
        if not 0 <= choice < len(res):
            return ''
    return res[choice]


def decode_1_byte_xor(x: bytes):
    strings = {}  # type: Dict[bytes, str]
    for e in range(256):
        try:
            y = bytes((a ^ e for a in x)).decode('ascii')
        except UnicodeDecodeError:
            continue
        strings[y] = chr(e)
    if not strings:
        return '', ''
    res = find_english_text(strings.keys())
    if not res:
        return '', ''
    return strings[res], res


def find_and_decrypt_ciphertexts(ciphertexts: list):
    plaintexts = {}
    for c in ciphertexts:
        key, string = decode_1_byte_xor(bytes.fromhex(c))
        if not key or not string:
            continue
        plaintexts[string] = key
    res = find_english_text(plaintexts.keys())
    return plaintexts[res], res


def hamming_distance(string1: bytes, string2: bytes):
    res = 0
    for a, b in zip(string1, string2):
        # '07b' means add zero padding, make the number be in binary and be
        # 8 digits long.
        a, b = map(lambda x: format(x, '08b'), (a, b))
        assert len(a) == len(b)
        for A, B in zip(a, b):
            res += int(A) ^ int(B)
    return res


def normalised_hamming_distance(string1: bytes, string2: bytes):
    assert len(string1) == len(string2)
    return hamming_distance(string1, string2) / len(string1)


def split_into_groups(string: Iterable, size: int):
    return [string[i:i + size] for i in range(0, len(string), size)]


def decode_repeating_byte_xor(ciphertext: bytes):
    c = ciphertext
    edit_distances = defaultdict(list)
    for keysize in range(2, 41):
        k, e = keysize, []
        e.append(normalised_hamming_distance(c[:k], c[k:k * 2]))
        e.append(normalised_hamming_distance(c[k * 2:k * 3], c[k * 3:k * 4]))
        e.append(normalised_hamming_distance(c[k * 3:k * 4], c[k * 4:k * 5]))
        e.append(normalised_hamming_distance(c[k * 4:k * 5], c[k * 5:k * 6]))
        edit_distances[sum(e) / 4].append(keysize)
    likely_keysizes = sorted(edit_distances.items())[:5]

    def reducing_func(x, y):
        return x + y[1]
    possible_keysizes = reduce(reducing_func, likely_keysizes, [])
    keys = []
    for keysize in possible_keysizes:
        blocks = split_into_groups(ciphertext, keysize)
        if len(blocks[-1]) != keysize:
            del blocks[-1]
        transposed_blocks = zip(*blocks)
        key = []
        for block in transposed_blocks:
            char, _ = decode_1_byte_xor(block)
            key.append(char)
        keys.append(''.join(key))
    keys = [x for x in keys if x]
    plaintexts = {}
    for key in keys:
        plaintexts[
            unhexlify(
                repeating_key_xor(
                    ciphertext,
                    bytes(
                        key,
                        'ascii'))).decode('ascii')] = key
    plaintext = find_english_text(plaintexts.keys())
    return plaintexts[plaintext], plaintext


def decode_aes_ecb(ciphertext, password):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(password), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    res = decryptor.update(ciphertext) + decryptor.finalize()
    return res.decode('ascii')


def detect_aes_ecb_encrypted_texts(ciphertexts: List[bytes]):
    max_repeats = defaultdict(list)
    for text in ciphertexts:
        counts = Counter(split_into_groups(text, 16))
        most_no_of_repeats = counts.most_common(1)[0][1]
        max_repeats[most_no_of_repeats].append(text)
    most_repeats = max(max_repeats.keys())
    return most_repeats, max_repeats[most_repeats]


def main():
    res1 = hex_to_base64(
        '49276d206b696c6c696e6720796f757220627261696e206c6'
        '96b65206120706f69736f6e6f7573206d757368726f6f6d')
    print('Task 1')
    print(res1)
    assert res1 == (b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc'
                    b'29ub3VzIG11c2hyb29t')

    print('Task 2')
    x = '1c0111001f010100061a024b53535009181c'
    y = '686974207468652062756c6c277320657965'
    res2 = xor(x, y)
    print(res2)
    assert res2 == b'746865206b696420646f6e277420706c6179'

    print('Task 3')
    ciphertext = ('1b37373331363f78151b7f2b783431333d78397828372d'
                  '363c78373e783a393b3736')
    res3 = decode_1_byte_xor(bytes.fromhex(ciphertext))
    print(res3[1])
    assert res3[1] == "Cooking MC's like a pound of bacon"

    print('Task 4')
    ciphertexts = get_file('4.txt').split('\n')
    res4 = find_and_decrypt_ciphertexts(ciphertexts)
    print('Key: {0}\nPlaintext: {1}'.format(*res4))
    assert res4[1] == 'Now that the party is jumping\n'

    print('Task 5')
    plaintext = """Burning 'em, if you ain't quick and nimble
    I go crazy when I hear a cymbal"""
    key = "ICE"
    correct_answer = ("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343"
                      "c2a26226324272765272a282b2f20430a652e2c652a3124333a653e"
                      "2b2027630c692b20283165286326302e27282f")
    res5 = repeating_key_xor(bytes(plaintext, 'ascii'), bytes(key, 'ascii'))
    print(res5)
    assert res5 == correct_answer

    print('Task 6')
    string1 = b'this is a test'
    string2 = b'wokka wokka!!!'
    print('Hamming Distance Check:', hamming_distance(string1, string2))
    ciphertext6 = get_file('6.txt')
    ciphertext6 = b64decode(ciphertext6)
    res6 = decode_repeating_byte_xor(ciphertext6)
    assert res6[0] == 'Terminator X: Bring the noise'
    print('Key:', res6[0])
    print('Plaintext:')
    print(res6[1])

    print('Task 7')
    ciphertext7 = get_file('7.txt')
    ciphertext7 = b64decode(ciphertext7)
    password = b"YELLOW SUBMARINE"
    res7 = decode_aes_ecb(ciphertext7, password)
    assert res7.startswith("I'm back and I'm ringin' the bell ")
    print(res7)

    print('Task 8')
    ciphertexts8 = get_file('8.txt').split('\n')
    ciphertexts8 = [bytes.fromhex(x) for x in ciphertexts8 if x]
    res8 = detect_aes_ecb_encrypted_texts(ciphertexts8)
    assert len(res8[1]) == 1
    print('Most likely string:', hexlify(res8[1][0]).decode('ascii'))
    print('Max no. of repeats of a 16byte chunk found:', res8[0])


if __name__ == '__main__':
    main()
