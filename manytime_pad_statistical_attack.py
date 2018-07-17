#!/usr/bin/env python

"""
Break repeating-key XOR
https://cryptopals.com/sets/1/challenges/6
"""

import binascii
import string

from base64 import b64decode
from lantern.fitness import ChiSquared
from lantern.analysis import frequency
from lantern.structures import Decryption
from lantern.util import group, split_columns, combine_columns, remove


ciphertext = binascii.unhexlify("49c04f833bb9716b464288a599a693fcf75729348ac18ae40eca274eef8172c643d07db2777b465888f1cdbd93b9f503353ed88488e80ed43c41efc47ec748966eae7160080c8fb499b79fedba167d37cbd683e241cf3c4aeb8157dd55843bbc6c2f12448ea299b899f4ff19297bebc88de4049f334ae49049c043d076b46b6a144d85bddcf5bef8ee0338298ac096e811cf304ba88c79c7519e3bb2762f094282f1d2bb93fcba3e307bcb8494e80ecd7542e98a44c753d076bc612f0143c7a2d8bc92b9ee1f387be1cd8ae041de3b4ba89049c043d075b8607b465b8ea5d7b085eaba003c288ad08ce241fb204ce08175cd54d073bc766b464d89b599a19efcba073834dac881a70fda345da89049c043d050b47668464088bed2b092b9fb192532c5d197eb189f345ba89044c753823b907965035f93a899b883eaee573e29c5d797e219de3846e6814acd4a9c3bb47e2f2f0c8aa4caa1d6d0ba1a2828de8490ef049f1e46e6835bc754d068b2756a46418ebfcca193eaba03353e8ad38ce80dda754ce79175c942d068b86c7b0a4983f1ddba81f7ba163a3ac3cac4f309da754ce78b53cd509569fd75660848c7a2d8bc92b9ee1f387be1cd8ae041dc3443e4c45cc44f937efd6f6e124f8fb4ddf582f1ff570a33c3d081a733de374de1906edd548069b46b6a465b8fb4d7f59efcba05383ace848bf2159f345ba89055cd54953bbe6a660348c790d5bc95fcba24353e8ace91ea11da310ffd9469c043d071a86a7604439ff1cca585fcee033435cd8485eb0d9f2147edc452c006b93bbf7d68465588a4cbf586f8e81332358ad78ce241da2d4ce48549c043d06faf716e0a0c84b0d7bb99edba072f34c9c181e341cc3446ecc47fc9459b3bb4762f124482b8cbf586ebf50738298ad488e602da264ee4884ac047843bb9772f1f4392f1d2bb99eeba163f34dfd0c4f309d6260fea9149c043d050b4766846588fb4d7f584fcfb137d3dd8cb89a709d6260fea8b69c0479e3bbc38620f4082f1d1bc91f1ba03327bc6c185f1049f2147edc453cd478277a4387b1143c7bcd0b993eaba1f343cc28497e608db755be0814acd4a9c3b94387c0e4d89a599b299b9fb037d3ac4ddc4f500cb300ffb8549c043d050b47668465892a3d7b092b9ea16313e8ac58ae341cc3d5afcc46bcd549472be6c2f0e49c7a2d8bc92b9ee187d2fc2c1c4ed14cd2c0fe18a49c043827eae3862095e82f1dca39ffdff193e3e8ad08ba702d0384aa89d4fc9449272a93865134197b8d7b2d6ecea5734358ac5c4e013da345ba88c68d806b96ffd6b6a034194f1cdbad6fbff573c7bc6c190f304cd7558fa8d68c6409f77b97d6b46588fb499a597e9ff057d3ad9848ce241cc2540e3814dc4439168b83856095995f1f4b49cfce903247bd9c58de341cb3d4aa8af7ec948843bad6a601049c7a5d1b482b9d3573932ce8490ef04cd305ca88a44c753d076a86b7b464486a7dcf59bfcfb19297bd9cb89e241d23c5ceb8c73c94b953bb17164030c86bf99bd99f7ff04297bc7c58aa712de3c4ba8904fcd47943ba9706a0b0c8fb499b492fdff137d2fdfd68aee0fd8755be7c449c043827efd6f6e150c83b4d8b1d6eaf31b3835c9c1c4ee0f9f2147edc449c0478468fd6c67030c8abecaa1d6f0f7073229dec58af341cf3c4aeb815488429f75a9386d03408eb4cfb0d6edf2122f3ed98485e941de2140e5c454ce068473b86a6a150c89be99b893f8f41e333c8acd8aa708cb755ce98d69da498579b17d2f1f4392f1d2bb99eeba162e7bddc1c4e904da3141fcc453c7069e74fd6b6e0f48c7a5d1b0d6c8ef1238358af781e915da3b4cedc44edc53967dfd7961020c89bed7a693f7e9127d28cbcd80a720d33c4cedc455c74a943ba4777a140c93bed7b283fcba043c32ce8490ef049f045aed8152ce40d06cb46c67464482a399bd93f8fe572933cf84b5f204da3b0ffb8c4ac049d078bc6a6a150c81becbf58ff6ef572e3ac3c0c4c60dd6364aa89769c04f833ba97162030cbebecca793b9f4182933c3ca83a703ca210fe9c46ecd45827ea9222f024389a5e6b684f6e904022fc2c1bbf415cd304ee597")
ciphertext = bytearray(ciphertext)

def xor(a, b):
    """XOR two equal buffers (longest truncated)"""
    return bytearray([c ^ d for c, d in zip(a, b)])


def str_to_bits(s):
    """Convert a string to its bit string representation"""
    return ''.join(format(ord(i), 'b').zfill(8) for i in s)


def bytearray_to_bits(array):
    return ''.join(format(i, 'b').zfill(8) for i in array)


def hamming_distance(a, b):
    """Calculate the binary hamming distance between two strings"""
    assert len(a) == len(b)
    return sum(c1 != c2 for c1, c2 in zip(a, b))

assert hamming_distance(str_to_bits("this is a test"), str_to_bits("wokka wokka!!!")) == 37


# ciphertext = b64decode(ciphertext)
# decryptions = []

# # Determine the keysize by brute forcing key sizes and checking the edit distance between byte groups
# # If we have chosen the correct keysize then we compute dist(a XOR b) which will roughly 2-3 bits different in each byte
# # However if we have chosen incorrectly then we compute dist(x XOR y) where x and y are effecitvely 'random' bytestrings
# # which we expect to share approximately 4 bits due to probabilily. Because the correct key will show a lower edit distance
# # we can keep track of the lowest edit distance through comparisons and then use that as an indicator of the correct key size
# for keysize in range(2, 40):
#     blocks = group(ciphertext, keysize)

#     # 10 blocks is enough of an average to make the correct keysize appear on top
#     NUM_BLOCKS = 10
#     edit_distance = sum(hamming_distance(bytearray_to_bits(blocks[i]), bytearray_to_bits(blocks[i + 1])) for i in range(NUM_BLOCKS))
#     edit_distance /= (NUM_BLOCKS * keysize)

#     decryption = Decryption(key=keysize, plaintext='', score=edit_distance)
#     decryptions.append(decryption)

# decryptions = sorted(decryptions)
# keysize = decryptions[0].key

# for d in decryptions:
#     print("{}: {}".format(d.key, d.score))


def is_printable(s):
    return all(c in string.printable for c in s)


def modified_xor_brute(ciphertext):
    """
    Bruteforce XOR keys to decrypt ciphertext
    We assume the plaintext is english text
    """
    MAX_BYTE = 2**8 - 1
    decryptions = []

    for key in range(MAX_BYTE):
        key_extended = bytearray([key] * len(ciphertext))

        try:
            plaintext = xor(ciphertext, key_extended).decode('utf-8')
        except UnicodeDecodeError:
            continue
        else:
            if not is_printable(plaintext):
                continue

            if remove(plaintext, string.whitespace + string.punctuation + string.digits) == "":
                continue

            # Due to the limitations of ChiSquared we need to make the plaintext uppercase and without whitespace + punctuation
            score = ChiSquared(frequency.english.unigrams)(remove(plaintext, string.whitespace + string.punctuation + string.digits).upper())
            decryption = Decryption(plaintext, key, score)

            # This is a (flaw?) in lantern that punct + whitespace is removed when scoring, however because the score
            # calculation is based on length, this means that incorrect strings full of punctuation can out score
            # correct decryptions with mostly letters. Therefore, we modify the score by how many characters were
            # removed during scoring. I should probably fix this in latern
            decryption.score /= len(remove(plaintext, string.whitespace + string.punctuation + string.digits)) / len(plaintext)
            decryptions.append(decryption)

    return sorted(decryptions, reverse=True) if decryptions else [None]

# Given the keysize, we can reduce repeated xor to N instances of single byte xor where N is the length of the key
# The text when decrypted will not be adjacent, therefore another statistical model will be used in order to score it

keysize = 30
columns = split_columns(ciphertext, keysize)

#print(column[0] ^ )

bests_columns = [modified_xor_brute(column)[0].plaintext for column in columns]
print(combine_columns(bests_columns))
