#!/usr/bin/env python3

from Crypto.PublicKey import RSA
from decimal import Decimal, getcontext


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


# function implementing Chinese remainder theorem
# list m contains all the modulii
# list x contains the remainders of the equations
def crt(m, x):
    # We run this loop while the list of
    # remainders has length greater than 1
    while True:
        # temp1 will contain the new value
        # of A. which is calculated according
        # to the equation m1' * m1 * x0 + m0'
        # * m0 * x1
        temp1 = modinv(m[1], m[0]) * x[0] * m[1] + modinv(m[0], m[1]) * x[1] * m[0]

        # temp2 contains the value of the modulus
        # in the new equation, which will be the
        # product of the modulii of the two
        # equations that we are combining
        temp2 = m[0] * m[1]

        # we then remove the first two elements
        # from the list of remainders, and replace
        # it with the remainder value, which will
        # be temp1 % temp2
        x.remove(x[0])
        x.remove(x[0])
        x = [temp1 % temp2] + x

        # we then remove the first two values from
        # the list of modulii as we no longer require
        # them and simply replace them with the new
        # modulii that  we calculated
        m.remove(m[0])
        m.remove(m[0])
        m = [temp2] + m

        # once the list has only one element left,
        # we can break as it will only  contain
        # the value of our final remainder
        if len(x) == 1:
            break

    # returns the remainder of the final equation
    return x[0]


# Precision will increase depending ont he length of the message. Hopefully is a good enough default
def nthroot(n, A, precision=1000):
    """Find nth root of A"""
    getcontext().prec = precision

    n = Decimal(n)
    x_0 = A / n  # Step 1: make a while guess.
    x_1 = 1      # Need it to exist before step 2
    while True:
        # Step 2:
        x_0, x_1 = x_1, (1 / n) * ((n - 1) * x_0 + (A / (x_0 ** (n - 1))))
        if x_0 == x_1:
            return x_1


key1 = RSA.importKey(b"""-----BEGIN PUBLIC KEY-----
MFowDQYJKoZIhvcNAQEBBQADSQAwRgJBAOkUiQbhnp4G8ndornW7fHaG5rROA1DQ
rLpPHggLdWWQVd6S4T3xlnTKY2ITwJdHDYmqJED5zSdZ95kerrAtT3sCAQM=
-----END PUBLIC KEY-----""")


key2 = RSA.importKey(b"""-----BEGIN PUBLIC KEY-----
MFowDQYJKoZIhvcNAQEBBQADSQAwRgJBANw80JNrNThoKs9QDbOKEQxiX1vXexOa
jZL1wznI9zIRtlCl/ERI0v7UyKJyrIIJT6/Tqp+mbcyfcBJj9g6rJe8CAQM=
-----END PUBLIC KEY-----""")

key3 = RSA.importKey(b"""-----BEGIN PUBLIC KEY-----
MFowDQYJKoZIhvcNAQEBBQADSQAwRgJBAMXjTfYFvsF7a8B4AHF1bNFbG97mOCC3
pBJ4ChAJfOQcMm/YWD7TdZAEap2rmMfwlfp3s9EhkW0vq1DH2K3jRHMCAQM=
-----END PUBLIC KEY-----""")

plaintext = b"Super secret message wow omg its getting longer"
print("Plaintext: {0} : {1}".format(plaintext, int.from_bytes(plaintext, byteorder='big')))

c1 = int.from_bytes(key1.encrypt(plaintext, None)[0], byteorder='big')
c2 = int.from_bytes(key2.encrypt(plaintext, None)[0], byteorder='big')
c3 = int.from_bytes(key3.encrypt(plaintext, None)[0], byteorder='big')

print("Exponent: {}".format(key1.e))
assert key1.e == key2.e == key3.e

moduli = [key1.n, key2.n, key3.n]
enc_values = [c1, c2, c3]
combined_encryption = crt(moduli, enc_values)

print("CRT encrypt value: {}".format(combined_encryption))

decrypted_message = round(nthroot(key1.e, combined_encryption))
print("Decrypted message: {0} : {1}".format(decrypted_message.to_bytes((decrypted_message.bit_length() + 7) // 8, 'big'), decrypted_message))
