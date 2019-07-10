#!/usr/env python3

"""
Brute force search through the parameters which created the seed for a PRNG.
With low entropy, this is achievable.

Based on https://people.eecs.berkeley.edu/~daw/papers/ddj-netscape.html
"""

import os
import hashlib
from datetime import datetime

from functools import partial
import concurrent.futures

import multiprocessing


def mklcpr(x):
    return (0xDEECE66D * x + 0x2BBB62DC) >> 1


def create_seed() -> int:
    """Generate the seed used for an PRNG"""
    dt = datetime.now()
    print(dt.second)
    print(dt.microsecond)
    print(os.getpid())
    print(os.getppid())
    a: int = mklcpr(dt.microsecond)
    b: int = mklcpr(os.getpid() + dt.second + os.getppid() << 12)
    hashed = hashlib.new('md5')
    hashed.update(a.to_bytes((a.bit_length() + 7) // 8, byteorder='little'))
    hashed.update(b.to_bytes((b.bit_length() + 7) // 8, byteorder='little'))
    return int(hashed.hexdigest(), base=16)


GLOBAL_SEED: int = create_seed()

#print(f"Seed: {GLOBAL_SEED}")


def generate_random_bytes():
    global GLOBAL_SEED
    stream = hashlib.md5(GLOBAL_SEED.to_bytes(((GLOBAL_SEED.bit_length() + 7) // 8), byteorder='little')).hexdigest()
    GLOBAL_SEED += 1
    return stream


def estimate_microseconds(stream_sample, seconds, pid, ppid, chunk_size, start):
    for microsecond in range(start, start + chunk_size + 1):
        a: int = mklcpr(microsecond)
        b: int = mklcpr(pid + seconds + ppid << 12)
        hashed = hashlib.new('md5')
        hashed.update(a.to_bytes((a.bit_length() + 7) // 8, byteorder='little'))
        hashed.update(b.to_bytes((b.bit_length() + 7) // 8, byteorder='little'))
        seed = int(hashed.hexdigest(), base=16)

        hash = hashlib.md5(seed.to_bytes(((seed.bit_length() + 7) // 8), byteorder='little')).hexdigest()
        if hash == stream_sample:
            print(start)
            print(chunk_size)
            print(microsecond)
            print(f"Seed: {seed}")


def attack(stream_sample):
    MAX_SECONDS = 30
    MAX_MICROSECONDS = 1_000_000
    MAX_PID = 100_000

    seconds = 8
    pid = 97004
    ppid = 373

    pool_size = multiprocessing.cpu_count()
    chunksize = MAX_MICROSECONDS // pool_size
    iterable = [chunksize * i for i in range(0, pool_size)]

    estimator = partial(estimate_microseconds, stream_sample, seconds, pid, ppid, chunksize)
    with concurrent.futures.ProcessPoolExecutor() as executor:
        executor.map(estimator, iterable, chunksize=1)

# random_bytes = generate_random_bytes()
# print(f"Random bytes 1: {random_bytes}")


attack("30a93ae3b547cf8c853b52ce44124cc6")


# print(f"Random bytes 2: {generate_random_bytes()}")
# print(f"Random bytes 3: {generate_random_bytes()}")
