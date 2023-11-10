# Flare-On 10, Challenge 06, FlareSay
#
# Re-implementation of relevant 16-Bit code in Python
# For a static solution
#

from binascii import hexlify
from subprocess import run


def rol(value, bits, size=32):
    mask = 0xFFFFFFFF
    # if size != 32:
    #    mask = 2 ** size - 1
    # if bits > size:
    #    bits = bits % size
    return (value << bits) & mask | (value >> (size - bits)) & mask


def ror(value, bits, size=32):
    # if bits > size:
    #    bits = bits % size
    return (value >> bits) | (value << (size - bits))


def rol7XorAdd(bstring):
    assert len(bstring) == 16
    ecx = 0
    i = 0
    while i < 4:
        ecx = ecx ^ rol(ecx, 7) + bstring[0 + 4 * i]
        ecx = ecx ^ rol(ecx, 7) + bstring[1 + 4 * i]
        ecx = ecx ^ rol(ecx, 7) + bstring[2 + 4 * i]
        ecx = ecx ^ rol(ecx, 7) + bstring[3 + 4 * i]
        i = i + 1
    return ecx


# the remains of past pain, before realizing the polyglotness of flaresay...
# 0000000000408E85 53 69 6D 6F 6E 20 53 61 79 73 20 4F 70 65 6E 21 Simon Says Open!
# yields rcx = 00000000F9B4EA84 / ecx = F9B4EA84
# assert(rol7XorAdd(b"Simon Says Open!") == 0xF9B4EA84)


class PRNG:
    seed_98 = 0

    # constructor expects the key scancode string, see sub 8c3
    def __init__(self, scancode):
        hash = 0
        for i in range(5):
            # not sure if this could be a bug. was expecting every scancode to be used
            # # for calc'ing the seed. but its only offsets 01, 12, 23, 34 and 45
            bx = int.from_bytes(scancode[i : i + 2], "little")
            bx = bx >> 5
            hash = (hash + bx) & 0xFFFF
        self.seed_98 = hash
        # assertion check for correct scancode
        assert self.seed_98 == 0x0C0A

    def LCG_b1(self):
        self.seed_98 = (self.seed_98 * 0x5A7F + 0x3079) & 0xFFFF
        yield (self.seed_98)

    def random_9a(self, start, stop):
        range = stop - start
        r = next(self.LCG_b1()) * (range + 1)
        result = ((r >> 16) & 0xFFFF) + start
        return result


# Main
if __name__ == "__main__":
    # sub 8c3 calcs seed based on RTC clock unless konami code is entered
    # retrieve konamicode @ 0x9dd size 0xA
    flaresay_file = "../challenge_files/flaresay.exe"
    with open(flaresay_file, "rb") as f:
        flaresay_content = bytearray(f.read())
        f.seek(0x9DD)
        konami_scancode_sequence_95d = f.read(0xA)
    f.close()
    assert konami_scancode_sequence_95d == b"HHPPKMKMBA"

    # Instantiate PRNG with konami code, calcs initial seed from it
    rng = PRNG(konami_scancode_sequence_95d)

    key_scan_codes = b"HPKM"
    sum_scancodes_63f = 0
    bignum_96f = 0
    # do the sub 17e calculations for each level
    for level in range(0x80):
        # key scancode for this level
        current_level_scancode = key_scan_codes[rng.random_9a(0, 3)]
        # sum up the scancodes
        sum_scancodes_63f = (sum_scancodes_63f + current_level_scancode) & 0xFFFF
        # do the sub 17e bignum calculations
        bignum_96f = (
            (bignum_96f * 64) + (bignum_96f * 65536) + sum_scancodes_63f - bignum_96f
        ) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        # debug output
        print(
            f"Level = {level + 1}, Scancode = {hex(current_level_scancode)} ({chr(current_level_scancode)}), bignum_96f = {hex(bignum_96f)}"
        )

    # the bignum value is saved in a weird fashion @ 97f
    # it consists of 8 words, the words are stored "big endian", i.e. most significant word first
    # but each word is stored "little endian"
    a = bignum_96f.to_bytes(16, "big")
    memory_96f = bytearray(16)
    # swap intra word endianness
    for w in range(8):
        memory_96f[w * 2] = a[w * 2 + 1]
        memory_96f[w * 2 + 1] = a[w * 2]

    # See flaresay.exe PE view @ 0x408fa6
    # rol7XorAdd value of 16 bytes @ 0x408e87 has to be 0x31D9F5FF
    assert rol7XorAdd(memory_96f) == 0x31D9F5FF
    print(
        f"The final memory value for bignum @ 96f is: {hexlify(memory_96f)} with rol7XorAdd value of 0x31D9F5FF"
    )

    patched_flaresay = flaresay_file[:-3] + "_patched.exe"
    # sub 51a patches flaresay.exe
    # searches for 16 * 0xCC, lseeks + 5 -> 0x8e85
    flaresay_content[0x8E85 : 0x8E85 + 16] = memory_96f
    print(f"Writing {patched_flaresay}")
    with open(patched_flaresay, "wb") as f:
        f.write(flaresay_content)
    f.close()

    # Executing patched flaresay
    print("Running patched flaresay")
    run([patched_flaresay])
