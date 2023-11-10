# Flare-On 10, Challenge 3, mypassion
#
# Script used to re-implement the data file dropped
# And manipulated based on System.wDay value
#

from binascii import crc32

# buf size 174.080 bytes @ file offset 0x1c3f0
# this gets xmm add with 0x1F + System.wDay (1 = 1st October, 30 = 30th September)
# starts with E5 46 61 7B 4C 33 2A 47 EF CD D6 50 06 26 92 8F
buf_start = 0x1C3F0
buf_len = 2720 * 16 * 4

# possibly something important buf2 size 55 bytes @ 0x46be0
# also gets the same value added as above
# starts with 12 F3 CA 3D 78 5C 21 3F 39 5C 81 78 A5 43 C4 F6
buf2_start = 0x46BE0
buf2_len = 55

with open("../challenge_files/mypassion.exe", "rb") as f:
    f.seek(buf_start)
    buf_content = f.read(buf_len)
    f.seek(buf2_start)
    buf2_content = f.read(buf2_len)
f.close()

# write first and second buf
with open("../files/buf_0x1c3f0_size_174080.bin", "wb") as f:
    f.write(buf_content)
f.close()
with open("../files/buf_0x46be0_size_55.bin", "wb") as f:
    f.write(buf2_content)
f.close()

# concantenate the contents of both bufs
buf_complete = buf_content + buf2_content

# calculate crc32 value
buf_crc32 = crc32(buf_complete)
print(f"original buffer content size {len(buf_complete)} has crc32 of {hex(buf_crc32)}")

# write combined bufs
with open("../files/buf_size_174135.bin", "wb") as f:
    f.write(buf_complete)
f.close()
