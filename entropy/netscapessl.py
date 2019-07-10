#!/usr/bin/env python3

"""
Netscape 1.1 Secure Socket Layer PRNG Implementation
"""

import os
import hashlib

from datetime import datetime


def mklcpr(x: int) -> int:
    """Scrambler"""
    return (0xDEECE66D * x + 0x2BBB62DC) >> 1


def create_seed() -> int:
    """Generate a seed for use in a PRNG"""
    dt = datetime.now()
    pid = os.getpid()
    ppid = os.getppid()
    print(f"Second: {dt.second}, Microsecond: {dt.microsecond}, pid: {pid}, ppid: {ppid}")

    # Use time and pids to create seed
    a: int = mklcpr(dt.microsecond)
    b: int = mklcpr(pid + dt.second + ppid << 12)
    hashed = hashlib.new('md5')
    hashed.update(a.to_bytes((a.bit_length() + 7) // 8, byteorder='little'))
    hashed.update(b.to_bytes((b.bit_length() + 7) // 8, byteorder='little'))
    return int(hashed.hexdigest(), base=16)


GLOBAL_SEED: int = create_seed()


def generate_random_bytes() -> str:
    """Use the seed as input to a hash function to create a stream of bytes
    seed incremented with each use
    """
    global GLOBAL_SEED
    stream = hashlib.md5(GLOBAL_SEED.to_bytes(((GLOBAL_SEED.bit_length() + 7) // 8), byteorder='little')).hexdigest()
    GLOBAL_SEED += 1
    return stream


print(generate_random_bytes())
