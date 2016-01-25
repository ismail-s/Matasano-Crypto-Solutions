from base64 import b64encode
from binascii import hexlify
from collections import Counter, defaultdict
from string import ascii_letters
from typing import Dict, Iterable
from pathlib import Path
import os
import itertools

current_dir = str(Path(__file__).parent)


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


def repeating_key_xor(string: str, key: str) -> str:
    res = bytearray()
    repeating_key = itertools.cycle(bytes(key, 'ascii'))
    for a, b in zip(bytes(string, 'ascii'), repeating_key):
        res.append(a^b)
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

print('Task 5')
plaintext = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
key = "ICE"
correct_answer = ("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c"
"2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b20276"
"30c692b20283165286326302e27282f")
res5 = repeating_key_xor(plaintext, key)
print(res5)
assert res5 == correct_answer
