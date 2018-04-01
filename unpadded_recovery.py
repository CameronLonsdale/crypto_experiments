#!/usr/bin/python3

from Crypto.PublicKey import RSA
from random import randint


# function that implements Extended euclidean
# algorithm
def extended_euclidean(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_euclidean(b % a, a)
        return (g, x - (b // a) * y, y)


# modular inverse driver function
def modinv(a, m):
    g, x, y = extended_euclidean(a, m)
    return x % m


key1 = RSA.importKey(b"""-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAOkUiQbhnp4G8ndornW7fHaG5rROA1DQrLpPHggLdWWQVd6S4T3x
lnTKY2ITwJdHDYmqJED5zSdZ95kerrAtT3sCAQMCQQCbYwYElmm+r0xPmx75J6hP
BJnNiVeLNch8NL6wB6OZCZ3f3P8C/EKb9RqQ/ZXFjXluceennnK7/iTCurCAAG6L
AiEA/78MlF2oKi9zGpmYkg859gv9uNQ0U1XW5QmTTtiYZ+kCIQDpT7rOW88IW2eg
7v7N37jhWAGP8VfNt4Xba3NXF5RBwwIhAKp/Xbg+cBwfohG7uwwKJqQH/ns4IuI5
Oe4GYjSQZZqbAiEAm4p8iZKKBZJFFfSp3pUl65ABCqDlM8+ukkeiOg+4K9cCIExE
wR1jvOV+WxZ1FS7jez+Y2c2PsVfXf8YSrcio1Nsk
-----END RSA PRIVATE KEY-----""")


banned_message = b"You can't sign this message"
banned_signature = key1.sign(banned_message, None)[0]
print("Banned message: {}".format(banned_message))
print("Signature we want: {}".format(banned_signature))


def challenge_sign_message(m):
    """Sign all messages using private key, except the banned message"""
    if m != banned_message:
        return key1.sign(m, None)[0]

    return (None, None)


public_N = key1.n
public_e = key1.e

different_message = "A different message"

# M' = ((S**E mod N) M) mod N
fudge_factor = randint(1, public_N)
print("Fudge factor we chose: {}".format(fudge_factor))

malicious_message = (((fudge_factor**public_e) % public_N) * int.from_bytes(banned_message, byteorder='big')) % public_N
print("Malicious message: {}".format(malicious_message))

malicious_signature = challenge_sign_message(malicious_message.to_bytes((malicious_message.bit_length() + 7) // 8, 'big'))
print("Malicious signature: {}".format(malicious_signature))


unfudged_signature = (malicious_signature * modinv(fudge_factor, public_N)) % public_N
print("Final signature {}".format(unfudged_signature))

assert unfudged_signature == banned_signature
