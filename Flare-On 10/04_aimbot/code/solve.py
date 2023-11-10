# Flare-On 10, Challenge 4, aimbot
#
# Calculate flag based on fifth stage shellcode in aimbot.dll
#

from binascii import crc32
from string import printable
from itertools import product

flag_base = 25 * b"\x20" + b"flare-on.com"
flag = bytearray(flag_base)

with open("../files/spcr2.cfg", "rb") as f:
    # if ( wrap_ReadFile_737(hFile, &dd_file_offset_4, 4i64) != 4 )
    dd_file_offset_4 = int.from_bytes(f.read(4), "little")
    # wrap_SetFilePointer_6A4(hFile, 81i64, 0);
    f.seek(81)
    # if ( wrap_ReadFile_737(hFile, flag, 8i64) != 8 )
    flag[0:8] = f.read(8)
f.close()

# flag[8] = *(_BYTE *)(hMod + 0x30EE);          // byte @ sauerbraten mapped 0x30ee
# has to be bruted or guessed. from guessing, this should be an underline
flag[8] = ord("_")

# dd_file_offset_4_xor_0x4203120c = dd_file_offset_4 ^ 0x4203120C;
dd_file_offset_4_xor_0x4203120c = dd_file_offset_4 ^ 0x4203120C
# flag[9] = dd_file_offset_4 ^ 0xC;
flag[9] = (dd_file_offset_4 ^ 0xC) & 0xFF
# flag[10] = (unsigned __int16)((dd_file_offset_4 ^ 0x120C) & 0xFF00) >> 8;
flag[10] = ((dd_file_offset_4 ^ 0x120C) & 0xFF00) >> 8
# flag[11] = ((dd_file_offset_4 ^ 0x4203120C) & 0xFF0000u) >> 16;
flag[11] = ((dd_file_offset_4 ^ 0x4203120C) & 0xFF0000) >> 16
# flag[12] = ((dd_file_offset_4 ^ 0x4203120C) & 0xFF000000) >> 24;
flag[12] = ((dd_file_offset_4 ^ 0x4203120C) & 0xFF000000) >> 24

# dd_file_offset_4_xor_0x4203120c = dd_file_offset_4 ^ 0x1715151E;
dd_file_offset_4_xor_0x4203120c = dd_file_offset_4 ^ 0x1715151E

# qmemcpy(&flag[13], &dd_file_offset_4_xor_0x4203120c, 4ui64);
flag[13:17] = dd_file_offset_4_xor_0x4203120c.to_bytes(4, "little")

# dd_file_offset_4_xor_0x4203120c = dd_file_offset_4 ^ 0x15040232;
dd_file_offset_4_xor_0x4203120c = dd_file_offset_4 ^ 0x15040232

# qmemcpy(&flag[17], &dd_file_offset_4_xor_0x4203120c, 4ui64);###
flag[17:21] = dd_file_offset_4_xor_0x4203120c.to_bytes(4, "little")

# v12 = *(_DWORD *)(hMod + 0x229450) ^ 0x32061E1A;// winning condition / game state check
# solving this challenge without running the game makes this tough
# we know flag[24] = "@"
flag[24] = ord("@")

# we have to bruteforce 3 chars here
for i in product(printable, repeat=3):
    flag[21] = ord(i[0])
    flag[22] = ord(i[1])
    flag[23] = ord(i[2])
    if crc32(flag[0:25]) == 0xA5561586:
        print(f"Flag is: {str(flag, 'UTF-8')}")
        exit()

print("Failed bruting the CRC32 check!")
