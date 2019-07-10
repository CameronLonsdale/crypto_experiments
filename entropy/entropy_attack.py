#!/usr/bin/env python3

import hashlib

from functools import partial
import concurrent.futures

import multiprocessing


def mklcpr(x: int) -> int:
    """Scrambler"""
    return (0xDEECE66D * x + 0x2BBB62DC) >> 1


def create_seed(second, microsecond, pid, ppid) -> int:
    a: int = mklcpr(microsecond)
    b: int = mklcpr(pid + second + ppid << 12)
    hashed = hashlib.new('md5')
    hashed.update(a.to_bytes((a.bit_length() + 7) // 8, byteorder='little'))
    hashed.update(b.to_bytes((b.bit_length() + 7) // 8, byteorder='little'))
    return int(hashed.hexdigest(), base=16)


def crack_microseconds(stream_sample, second, pid, ppid, chunk_size, start):
    """Brute force through microseconds and calculate the seed to try and
    recalculate the stream sample
    """
    for microsecond in range(start, start + chunk_size + 1):
        seed = create_seed(second, microsecond, pid, ppid)

        stream = hashlib.md5(seed.to_bytes(((seed.bit_length() + 7) // 8), byteorder='little')).hexdigest()
        if stream == stream_sample:
            print(f"Microsecond: {microsecond}, Seed: {seed}")
            return seed


def compute_seed() -> str:
    """Compute the seed for a weak Netscape 1.1 seed"""

    # Target stream: 0a8c7d96c32671a29ce6e3b64885221a
    # Timestamp of use: 2019-07-10T14:24:49+00:00
    # Use number: 1
    # Process ID: Unknown
    # Microsecond: Unknown
    # Parent Process ID: 1

    MAX_MICROSECONDS = 1_000_000
    MAX_PID = 255  # Smaller Range for quicker estimating

    target_stream = "0a8c7d96c32671a29ce6e3b64885221a"
    second = 49
    ppid = 1

    # Solution: Microsecond: 978317, Pid: 32
    # Seed is 69299815854415606899619666958297726510

    pool_size = multiprocessing.cpu_count()
    chunksize = MAX_MICROSECONDS // pool_size
    microsecond_start_points = [chunksize * i for i in range(0, pool_size)]

    # Multiprocessing on the microseconds as we want to get through the list of pids as quick as possible
    # While weighting the earlier pids higher as they're more likely to be correct
    for pid in range(2, MAX_PID + 1):
        print(f"Trying pid: {pid}")
        cracker = partial(crack_microseconds, target_stream, second, pid, ppid, chunksize)
        with concurrent.futures.ProcessPoolExecutor() as executor:
            potential_seeds = executor.map(cracker, microsecond_start_points, chunksize=1)
            if any(potential_seeds):
                return next(seed for seed in potential_seeds if seed is not None)


print(f"Seed: {compute_seed()}")
