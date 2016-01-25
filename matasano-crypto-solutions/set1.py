from base64 import b64encode
from binascii import hexlify
from collections import Counter, defaultdict
from string import ascii_letters
from typing import Dict
from pathlib import Path
import os

current_dir = str(Path(__file__).parent)


def get_most_common_from_counter(counter: Counter, n: int):
    """Like counter.most_common(n), but includes elements with
    equal counts, which means the returned
    list may be longer than n."""
    elems = counter.most_common()
    count = 1
    i = 1
    last_seen_elem, last_num = elems[0]
    for elem, num in elems[1:]:
        if last_num > num:
            count += 1
        last_seen_elem = elem
        last_num = num
        i += 1
        if count == n:
            break
    return elems[:i]


def hex_to_base64(bstr: str):
    return b64encode(bytes.fromhex(bstr))


def xor(x: str, y: str):
    x = bytes.fromhex(x)
    y = bytes.fromhex(y)
    return hexlify(bytes((a ^ b for a, b in zip(x, y))))


def find_english_text(texts: list):
    scores = defaultdict(list)
    for text in texts:
        score = 0
        count = Counter(text.lower())
        most_common = {x for x, _ in count.most_common(5)}
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


def decode_1_byte_xor(bstr: str):
    x = bytes.fromhex(bstr)
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
        key, string = decode_1_byte_xor(c)
        if not key or not string:
            continue
        plaintexts[string] = key
    res = find_english_text(plaintexts.keys())
    return plaintexts[res], res

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
res3 = decode_1_byte_xor(ciphertext)
print(res3[1])
assert res3[1] == "Cooking MC's like a pound of bacon"

print('Task 4')
ciphertexts = open(os.path.join(current_dir, '4.txt'), 'r').read().split('\n')
res4 = find_and_decrypt_ciphertexts(ciphertexts)
print('Key: {0}\nPlaintext: {1}'.format(*res4))
assert res4[1] == 'Now that the party is jumping\n'