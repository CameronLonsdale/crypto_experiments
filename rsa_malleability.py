#!/usr/bin/python3

from Crypto.PublicKey import RSA
import struct


key1 = RSA.importKey(b"""-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAOkUiQbhnp4G8ndornW7fHaG5rROA1DQrLpPHggLdWWQVd6S4T3x
lnTKY2ITwJdHDYmqJED5zSdZ95kerrAtT3sCAQMCQQCbYwYElmm+r0xPmx75J6hP
BJnNiVeLNch8NL6wB6OZCZ3f3P8C/EKb9RqQ/ZXFjXluceennnK7/iTCurCAAG6L
AiEA/78MlF2oKi9zGpmYkg859gv9uNQ0U1XW5QmTTtiYZ+kCIQDpT7rOW88IW2eg
7v7N37jhWAGP8VfNt4Xba3NXF5RBwwIhAKp/Xbg+cBwfohG7uwwKJqQH/ns4IuI5
Oe4GYjSQZZqbAiEAm4p8iZKKBZJFFfSp3pUl65ABCqDlM8+ukkeiOg+4K9cCIExE
wR1jvOV+WxZ1FS7jez+Y2c2PsVfXf8YSrcio1Nsk
-----END RSA PRIVATE KEY-----""")

plaintext = b"\xC8"
print("Plaintext: {}".format(int.from_bytes(plaintext, byteorder='big')))

c1 = int.from_bytes(key1.encrypt(plaintext, None)[0], byteorder='big')
print("Ciphertext: {}".format(c1))

modified_amount = c1 * (2 ** key1.e)
print("Doubled ciphertext: {}".format(modified_amount))

modified_amount = struct.pack(">I", modified_amount)
print("Decrypted message: {}".format(int.from_bytes(key1.decrypt(modified_amount), byteorder='big')))
