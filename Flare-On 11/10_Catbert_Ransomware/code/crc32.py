# crc32a/b derived from https://github.com/Michaelangel007/crc32
#
# crc32a <-> ITU I.363.5 (Bzip2)
# crc32b <-> ITU V.42 (Pkzip)
#
# Teststring b"123456789" -> crc32a = 0xFC891918, crc32b = 0xCBF43926
#
# Polynomial  Shift  Reverse Data  Reverse CRC  Checksum    Name     Function
# 0x04C11DB7  Left   No            No           0xFC891918  crc32a   crc32a_forward_leftshift
# 0x04C11DB7  Left   Yes           Yes          0xCBF43926  crc32b   crc32b_forward_leftshift
# 0xEDB88320  Right  No            No           0xCBF43926  crc32b   crc32b_reverse_rightshift
# 0xEDB88320  Right  Yes           Yes          0xFC891918  crc32a   crc32a_reverse_rightshift
#

import binascii
from array import array
import sys
import zlib

# function to reverse bits of a value
# true story: it's really awesome to not skip leading zeros on binary values
def reflect(num, bits):
    result = 0
    mask = num
    for i in range(bits):
        result = result << 1
        if ((mask & 1) == 1):
            result = result | 1
        mask = mask >> 1
    return(result)

# forward poly
f_poly = 0x04c11db7

# generate forward lookup table
f_table = array('L')
for byte in range(256):
    curByte = (byte << 24) & 0xffffffff
    for bit in range(8):
        if ((curByte & 0x80000000) != 0):
            curByte = curByte << 1
            curByte = curByte ^ f_poly
        else:
            curByte = curByte << 1
    f_table.append(curByte & 0xffffffff)

print("generated forward table with poly {}: t0 = {}, t1 = {}, t8 = {}, t16 = {}, t128 = {}".format(hex(f_poly), hex(f_table[0]), hex(f_table[1]), hex(f_table[8]), hex(f_table[16]), hex(f_table[128])))

# reverse/reflective poly
r_poly = 0xedb88320

# generate reverse/reflective lookup table
r_table = array('L')
for byte in range(256):
    curByte = byte & 0xffffffff
    for bit in range(8):
        if ((curByte & 0x1)):
            curByte = curByte >> 1
            curByte = curByte ^ r_poly
        else:
            curByte = curByte >> 1
    r_table.append(curByte & 0xffffffff)

print("generated reverse/reflective table with poly {}: t0 = {}, t1 = {}, t8 = {}, t16 = {}, t128 = {}".format(hex(r_poly), hex(r_table[0]), hex(r_table[1]), hex(r_table[8]), hex(r_table[16]), hex(r_table[128])))

# crc32a, ITU I.363.5 (Bzip2) - correct
def crc32a_forward_leftshift(data):
    crc = 0xffffffff
    for byte in data:
#        pos = (((byte << 24) ^ crc) >> 24) & 0xff
        pos = (byte ^ (crc >> 24)) & 0xff
        crc = ((crc << 8) ^ f_table[pos]) & 0xffffffff
    return (~crc)

# crc32a, ITU I.363.5 (Bzip2) - correct
def crc32a_forward_leftshift_noFinalNot(data):
    crc = 0xffffffff
    for byte in data:
#        pos = (((byte << 24) ^ crc) >> 24) & 0xff
        pos = (byte ^ (crc >> 24)) & 0xff
        crc = ((crc << 8) ^ f_table[pos]) & 0xffffffff
    return (crc)

# crc32a, ITU I.363.5 (Bzip2) - correct
def crc32a_reverse_rightshift(data):
    crc = 0xffffffff
    for byte in data:
        pos = (crc ^ reflect(byte, 8)) & 0xff
        crc = (r_table[pos] ^ (crc >> 8)) & 0xffffffff
#        crc = r_table[(crc ^ byte) &0xff] ^ (crc >> 8)
    return (reflect(~crc, 32))

# crc32b, ITU V.42 (Pkzip) - correct
def crc32b_reverse_rightshift(data):
    crc = 0xffffffff
    for byte in data:
        pos = (crc ^ byte) & 0xff
        crc = (r_table[pos] ^ (crc >> 8)) & 0xffffffff
#        crc = r_table[(crc ^ byte) &0xff] ^ (crc >> 8)
    return (~crc)

# crc32b, ITU V.42 (Pkzip) - correct
def crc32b_forward_leftshift(data):
    crc = 0xffffffff
    for byte in data:
#        pos = (((byte << 24) ^ crc) >> 24) & 0xff
#        pos = (reverse_bit(byte) ^ (crc >> 24)) & 0xff
#        crc = ((crc << 8) ^ f_table[pos]) & 0xffffffff
        crc = (f_table[(reflect(byte, 8) ^ (crc >> 24)) & 0xff] ^ (crc << 8)) & 0xffffffff
    return (reflect(~crc, 32))
	
# test, str = "123456789"
s = "123456789"
print("\ntest str = '123456789', expected crc32 = 0xcbf43926, logic error crc32 (mismatched table/calc) = 0xfc4f2be9")
a = binascii.crc32(s.encode('utf-8'))
print("binascii.crc32 = {}".format(hex(a & 0xffffffff)))
a = zlib.crc32(s.encode('utf-8'))
print("zlib.crc32 = {}".format(hex(a & 0xffffffff)))

# calc crc32a, ITU I.363.5 (Bzip2)
b = crc32a_forward_leftshift(s.encode('utf-8'))
print("crc32a_forward_leftshift [ITU I.363.5, used in bzip2] = {}".format(hex(b & 0xffffffff)))
b = crc32a_reverse_rightshift(s.encode('utf-8'))
print("crc32a_reverse_rightshift [ITU I.363.5, used in bzip2] = {}".format(hex(b & 0xffffffff)))

# calc crc32b, ITU V.42 (Pkzip)
c = crc32b_reverse_rightshift(s.encode('utf-8'))
print("crc32b_reverse_rightshift [ITU V.42, used in pkzip] = {}".format(hex(c & 0xffffffff)))
c = crc32b_forward_leftshift(s.encode('utf-8'))
print("crc32b_forward_leftshift [ITU V.42, used in pkzip] = {}".format(hex(c & 0xffffffff)))


# if you read this, you are dumbo!
#with open(sys.argv[1], "rb") as f:
#	dat = f.read()

# dat = b"G3tDaJ0bD0neM4te"
dat = b"DaCubicleLife101"
print(f"\nchecksums for {dat} ({dat.hex()})")

a = binascii.crc32(dat)
print("binascii.crc32 = {}".format(hex(a & 0xffffffff)))
a = zlib.crc32(dat)
print("zlib.crc32 = {}".format(hex(a & 0xffffffff)))

# calc crc32a, ITU I.363.5 (Bzip2)
b = crc32a_forward_leftshift(dat)
print("crc32a_forward_leftshift [ITU I.363.5, used in bzip2] = {}".format(hex(b & 0xffffffff)))
b = crc32a_forward_leftshift_noFinalNot(dat)
print("crc32a_forward_leftshift_noFinalNot [ITU I.363.5, used in bzip2] = {}".format(hex(b & 0xffffffff)))
b = crc32a_reverse_rightshift(dat)
print("crc32a_reverse_rightshift [ITU I.363.5, used in bzip2] = {}".format(hex(b & 0xffffffff)))

# calc crc32b, ITU V.42 (Pkzip)
c = crc32b_reverse_rightshift(dat)
print("crc32b_reverse_rightshift [ITU V.42, used in pkzip] = {}".format(hex(c & 0xffffffff)))
c = crc32b_forward_leftshift(dat)
print("crc32b_forward_leftshift [ITU V.42, used in pkzip] = {}".format(hex(c & 0xffffffff)))


