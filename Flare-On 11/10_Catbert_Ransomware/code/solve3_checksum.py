# flareon11 challenge 10
# catmeme3 vm
#

from itertools import product
from string import ascii_letters, digits
from time import time
from zlib import adler32


class Checksum1:
    # formula for first 4 chars is a checksum
    # - checksum seed value 0x1505
    # - for each char index 0..3
    #   - checksum = checksum << 5 + checksum + char
    # - then checksum = checksum & 0xffffffff
    # - then compare to 0x7c8df4cb
    def __init__(self, seed=0x1505):
        self.seed = seed
        self.checksum = seed

    def update(self, value):
        # value is supposed to be a 32 bit input = 4 ASCII bytes
        for byte in value:
            self.checksum = (self.checksum << 5) + self.checksum + byte
        self.checksum = self.checksum & 0xFFFFFFFF
        return self.checksum

    def reset(self):
        self.checksum = self.seed


class Checksum2:
    # checksum 2 for second dword is based on ror32 by d bits + add
    def __init__(self, seed=0x0):
        self.seed = seed
        self.checksum = seed

    def update(self, value):
        # value is supposed to be a 32 bit input = 4 ASCII bytes
        for byte in value:
            self.checksum = ror(self.checksum, 0xD, 32) + byte
        self.checksum = self.checksum & 0xFFFFFFFF
        return self.checksum

    def reset(self):
        self.checksum = self.seed


class Checksum3:
    # checksum 3 for remaining second half - last 8 chars
    # Adler32 implementation
    def __init__(self, seed=0x1):
        self.seed = seed
        self.m11 = seed
        self.m12 = 0

    def update(self, value):
        # value is supposed to be a 64 bit input = 8 ASCII bytes
        for byte in value:
            self.m11 = (self.m11 + byte) % 0xFFF1
            self.m12 = (self.m12 + self.m11) % 0xFFF1
        result = ((self.m12 << 0x10) | self.m11) & 0xFFFFFFFF
        return result

    def reset(self):
        self.m11 = self.seed
        self.m12 = 0


def ror(n, c, bits=32):
    mask = (1 << bits) - 1
    return ((n >> c) | (n << (bits - c))) & mask


if __name__ == "__main__":
    # init
    check1 = Checksum1()
    # test checksum 1 class
    test = b"0123"
    sum = check1.update(test)
    assert sum == 0x7C7838CB  # value from vm trace
    # test checksum 2 class
    check2 = Checksum2()
    test = b"4567"
    sum = check2.update(test)
    assert sum == 0x69B00D77  # value from vm trace
    # test checksum 3 against zlib.adler32
    test = b"89ABCDEF"
    sum = adler32(test)
    assert sum == 0x8CF0207

    # crack adler32 target hash 0x0f910374
    # either online or via a dictionary
    # while the algorithm is quite fast, bruteforcing over 8 chars
    # could be rough
    # it can be guessed as password based on the first 8 known chars
    # or by doing an adler32 hash lookup https://md5hashing.net/hash/adler32/0f910374

    # find second input dword with checksum 0x8b681d82
    target = 0x8B681D82
    sum = 0
    start = time()
    p = product(ascii_letters + digits + "_@", repeat=4)
    i = 0
    while sum != target:
        candidate = bytes("".join(next(p)), "UTF-8")
        check2.reset()
        sum = check2.update(candidate)
        # i += 1
        # if i % 1000 == 0:
        #     print(f"i {i} candidate {candidate} sum {sum:x}")
    end = time()
    print(
        f"[*] candidate2 {candidate} has checksum {sum:x} with target {target:x} after {end - start} seconds"
    )

    # now we need to find an input that yields the checksum 0x7c8df4cb
    target = 0x7C8DF4CB
    sum = 0
    start = time()
    p = product(ascii_letters + digits + "_@", repeat=4)
    i = 0
    while True:
        candidate = bytes("".join(next(p)), "UTF-8")
        check1.reset()
        sum = check1.update(candidate)
        if sum == target:
            print(f"[*] candidate1 {candidate} found with target sum {sum:x}")
            i += 1
            if i == 2:
                break
    end = time()
    print(
        f"[*] {i} candidates for checksum1 found after {end - start} seconds"
    )
    # [*] candidate b'Veqz' has checksum 7c8df4cb with target 7c8df4cb
