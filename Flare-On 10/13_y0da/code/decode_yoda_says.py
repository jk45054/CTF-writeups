# Flare-On 10, Challenge 13, y0da
#
# Recover flag from text output "M4st3r Y0d4 says"
# How to get it?
# - run y0da.exe
# - connect to its listening port on 1337/tcp
# - enter command: gimmie_s3cr3t
# - enter pasword: patience_y0u_must_h4v3
# - yields: M4st3r Y0d4 says OIZC4eMC/UnTPfDDMMaHeQXUHMPZy4LfSgg/HnB5SXVOIyKOBIHMe45B2KBCe5T/HRfRHZ4SKJe3eLJHeMe5IM5QQJ======
#
# String is base32 encoded with a custom alphabet
# Decoded bytes are encrypted with random values from
# MT19937 PRNG with static seed 0x5d1ff27d
# Decryption based on analysis of the ROP chain code
#

from base64 import b32decode
from binascii import unhexlify


# python implementation of MT19937 by Tom Liston
# https://github.com/tliston/mt19937
class mt19937:
    u, d = 11, 0xFFFFFFFF
    s, b = 7, 0x9D2C5680
    t, c = 15, 0xEFC60000
    l = 18
    n = 624

    def my_int32(self, x):
        return x & 0xFFFFFFFF

    def __init__(self, seed):
        w = 32
        r = 31
        f = 1812433253
        self.m = 397
        self.a = 0x9908B0DF
        self.MT = [0] * self.n
        self.index = self.n + 1
        self.lower_mask = (1 << r) - 1
        self.upper_mask = self.my_int32(~self.lower_mask)
        self.MT[0] = self.my_int32(seed)
        for i in range(1, self.n):
            self.MT[i] = self.my_int32(
                (f * (self.MT[i - 1] ^ (self.MT[i - 1] >> (w - 2))) + i)
            )

    def extract_number(self):
        if self.index >= self.n:
            self.twist()
            self.index = 0
        y = self.MT[self.index]
        # this implements the so-called "tempering matrix"
        # this, functionally, should alter the output to
        # provide a better, higher-dimensional distribution
        # of the most significant bits in the numbers extracted
        y = y ^ ((y >> self.u) & self.d)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        y = y ^ (y >> self.l)
        self.index += 1
        return self.my_int32(y)

    def twist(self):
        for i in range(0, self.n):
            x = (self.MT[i] & self.upper_mask) + (
                self.MT[(i + 1) % self.n] & self.lower_mask
            )
            xA = x >> 1
            if (x % 2) != 0:
                xA = xA ^ self.a
            self.MT[i] = self.MT[(i + self.m) % self.n] ^ xA


# this is how master yoda tells us the flag
yoda_says_custom_b32_alpha = "OIZC4eMC/UnTPfDDMMaHeQXUHMPZy4LfSgg/HnB5SXVOIyKOBIHMe45B2KBCe5T/HRfRHZ4SKJe3eLJHeMe5IM5QQJ======"

# encrypted flag bytes from the decrypted resource jpg
jpg_flag_bytes = unhexlify(
    "7F 2B D8 F5 C3 44 6D B7 75 95 89 A7 B9 C3 2C 3F 9E 91 B8 DC 6E 55 A7 51 E6 2C 59 BC 9C 12 98 06 8B A0 50 79 18 AA 29 4E 84 96 5F A6 37 9F ED 9A 33 3C ED 34 2D 63 7F 6C 5A".replace(
        " ", ""
    )
)

# hex values we know from debugging
dbg_yoda_says_bytes = unhexlify(
    "73 F7 C0 FE DC EA 92 26 C3 39 B5 8A CF 83 4A 65 9B B8 85 10 32 D7 D6 26 77 36 AA E7 C6 4E 9B D9 6F 86 F3 1C A7 CF DC 5D 67 A1 E6 6C 26 95 3E 4F A2 8C FD BF 77 DA E0 05".replace(
        " ", ""
    )
)
dbg_mt_rands = unhexlify(
    "9D B5 DF 75 92 C8 67 0B 50 60 0F B3 4E EB D6 67 08 EB 59 E9 CF 7F F5 39 A4 07 CB A2 D3 16 C6 93 18 4B 01 04 64 A5 4D A8 42 7D 24 D0 A8 2B FB AF A1 7D 24 5D 35 EB 3B DE 4D 64 69 A4".replace(
        " ", ""
    )
)

# the prng ist MT19937
# init function @ 0x38e4a called @ 0x5721 with seed 0x5d1ff27d (the overwritten yoda's tip number in shared buf)
# generate the rands like y0da does
prng = mt19937(0x5D1FF27D)
mt_rands = bytearray(0x3C)
for i in range(0, len(mt_rands), 4):
    mt_rands[i : i + 4] = int.to_bytes(prng.extract_number(), 4, "big")
mt_rands = bytes(mt_rands)
assert mt_rands == dbg_mt_rands

# the encrypted flag is base32 encoded @ 5e3cc with a call to sub 2bddf
# Which applies custom base32 alphabet Q4T23aSwLnUgHPOIfyKBJVM5+DXZC/Re=
# translate base32 string from custom alphabet to standard alphabet A-Z2-7= (RFC4648)
yoda_says_b32 = yoda_says_custom_b32_alpha.translate(
    str.maketrans(
        "Q4T23aSwLnUgHPOIfyKBJVM5+DXZC/Re=", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567="
    )
)
# now we can base32 decode it
yoda_says_bytes = b32decode(yoda_says_b32)
assert yoda_says_bytes == dbg_yoda_says_bytes

# each character of the jpg_flag_bytes was decrypted to a plaintext char by the ROP chain created in sub 1d361
# and saved to [rbp + 20h]
# at the end of the ROP chain, each plaintext char is then encrypted again using the MT19937 rand bytes
# yoda_says_bytes[j] = flag[j] ^ mt_rands[j] ^ ((mt_rands[j] << 1 & 0xff) & (mt_rands[j] >> 1 & 0xff)) ^ (mt_rands[j] << 2 & 0xff)
flag = bytearray(len(yoda_says_bytes))
for j in range(len(yoda_says_bytes)):
    flag[j] = (
        yoda_says_bytes[j]
        ^ mt_rands[j]
        ^ ((mt_rands[j + 1] << 1 & 0xFF) & (mt_rands[j + 2] >> 1 & 0xFF))
        ^ (mt_rands[j + 3] << 2 & 0xFF)
    )

print(flag.decode("UTF-8"))
