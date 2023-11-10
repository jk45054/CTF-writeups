# Flare-On 10, Challenge 13, y0da
#
# Decrypt flag from decrypted resource jpg (marker 1, len 0x39)
# Decryption takes place in the ROP chain code (552 gadgets)
# Performing 150 calculations for each flag byte
#

from binascii import unhexlify
from Crypto.Cipher import ARC4


def ROPchain(eax: bytes) -> bytes:
    eax = (eax >> 3) | (eax << 5) & 0xFF
    eax = (eax + 0xAC) & 0xFF
    eax = eax ^ j
    eax = (eax - 4) & 0xFF
    eax = eax ^ j
    eax = ~eax & 0xFF
    eax = (eax - j) & 0xFF
    eax = (eax >> 3) | (eax << 5) & 0xFF
    eax = (eax + j) & 0xFF
    eax = (eax >> 2) | (eax << 6) & 0xFF
    eax = ~eax & 0xFF
    eax = (eax >> 6) | (eax << 2) & 0xFF
    eax = (eax + j) & 0xFF
    eax = ~eax & 0xFF
    eax = eax ^ 0xD
    eax = -eax & 0xFF  # neg
    eax = (eax + 0x7B) & 0xFF
    eax = eax ^ 0xBF
    eax = (eax - 0xC3) & 0xFF
    eax = eax ^ j
    eax = (eax + 0x60) & 0xFF
    eax = (eax >> 5) | (eax << 3) & 0xFF
    eax = (eax + j) & 0xFF
    eax = ~eax & 0xFF
    eax = (eax - 0x18) & 0xFF
    eax = eax ^ j
    eax = (eax - j) & 0xFF
    eax = eax ^ j
    eax = (eax - 0xF3) & 0xFF
    eax = eax ^ j
    eax = (eax >> 2) | (eax << 6) & 0xFF
    eax = eax ^ j
    eax = -eax & 0xFF  # neg
    eax = (eax - 0xC5) & 0xFF
    eax = ~eax & 0xFF
    eax = (eax >> 7) | (eax << 1) & 0xFF
    eax = (eax - 0xFF) & 0xFF
    eax = (eax >> 7) | (eax << 1) & 0xFF
    eax = (eax - j) & 0xFF
    eax = eax ^ 0x8F
    eax = (eax + 0x70) & 0xFF
    eax = ~eax & 0xFF
    eax = (eax - 0x36) & 0xFF
    eax = (eax >> 2) | (eax << 6) & 0xFF
    eax = ~eax & 0xFF
    eax = (eax + 0xE8) & 0xFF
    eax = -eax & 0xFF  # neg
    eax = (eax - 0x56) & 0xFF
    eax = eax ^ j
    eax = (eax >> 6) | (eax << 2) & 0xFF
    eax = eax ^ j
    eax = (eax + j) & 0xFF
    eax = ~eax & 0xFF
    eax = (eax >> 5) | (eax << 3) & 0xFF
    eax = eax ^ 0x40
    eax = (eax - 0x9A) & 0xFF
    eax = ~eax & 0xFF
    eax = (eax + j) & 0xFF
    eax = eax ^ 0x16
    eax = (eax - 0x81) & 0xFF
    eax = ~eax & 0xFF
    eax = eax ^ j
    eax = (eax - 0xB2) & 0xFF
    eax = (eax >> 2) | (eax << 6) & 0xFF
    eax = -eax & 0xFF  # neg
    eax = (eax - 0x90) & 0xFF
    eax = ~eax & 0xFF
    eax = (eax - 0x28) & 0xFF
    eax = -eax & 0xFF  # neg
    eax = (eax - j) & 0xFF
    eax = -eax & 0xFF  # neg
    eax = (eax >> 2) | (eax << 6) & 0xFF
    eax = (eax - 0xDC) & 0xFF
    eax = (eax >> 7) | (eax << 1) & 0xFF
    eax = eax ^ 0x7C
    eax = (eax >> 2) | (eax << 6) & 0xFF
    eax = -eax & 0xFF  # neg
    eax = (eax + 0x96) & 0xFF
    eax = eax ^ 0xA3
    eax = ~eax & 0xFF
    eax = (eax - j) & 0xFF
    eax = (eax >> 6) | (eax << 2) & 0xFF
    eax = eax ^ 0xCB
    eax = ~eax & 0xFF
    eax = (eax - 0x1A) & 0xFF
    eax = eax ^ 0xB6
    eax = ~eax & 0xFF
    eax = -eax & 0xFF  # neg
    eax = (eax - 0xB1) & 0xFF
    eax = ~eax & 0xFF
    eax = -eax & 0xFF  # neg
    eax = ~eax & 0xFF
    eax = -eax & 0xFF  # neg
    eax = eax ^ 0xE1
    eax = (eax + 0x8F) & 0xFF
    eax = (eax >> 1) | (eax << 7) & 0xFF
    eax = (eax + 0x5A) & 0xFF
    eax = -eax & 0xFF  # neg
    eax = (eax + j) & 0xFF
    eax = eax ^ 0x78
    eax = -eax & 0xFF  # neg
    eax = eax ^ 0xEB
    eax = ~eax & 0xFF
    eax = eax ^ j
    eax = (eax + j) & 0xFF
    eax = eax ^ j
    eax = -eax & 0xFF  # neg
    eax = eax ^ 0x25
    eax = (eax >> 7) | (eax << 1) & 0xFF
    eax = (eax + j) & 0xFF
    eax = eax ^ 0xC9
    eax = (eax - j) & 0xFF
    eax = eax ^ j
    eax = (eax + j) & 0xFF
    eax = (eax >> 3) | (eax << 5) & 0xFF
    eax = -eax & 0xFF  # neg
    eax = eax ^ j
    eax = (eax - 0x49) & 0xFF
    eax = ~eax & 0xFF
    eax = (eax - 0x1E) & 0xFF
    eax = eax ^ j
    eax = -eax & 0xFF  # neg
    eax = (eax + j) & 0xFF
    eax = (eax >> 5) | (eax << 3) & 0xFF
    eax = eax ^ 0x20
    eax = (eax - j) & 0xFF
    eax = eax ^ 0x22
    eax = (eax - 0x58) & 0xFF
    eax = -eax & 0xFF  # neg
    eax = eax ^ j
    eax = (eax - j) & 0xFF
    eax = (eax >> 6) | (eax << 2) & 0xFF
    eax = -eax & 0xFF  # neg
    eax = (eax - j) & 0xFF
    eax = ~eax & 0xFF
    eax = (eax + 0xE4) & 0xFF
    eax = ~eax & 0xFF
    eax = eax ^ j
    eax = (eax - j) & 0xFF
    eax = ~eax & 0xFF
    eax = (eax + j) & 0xFF
    eax = eax ^ j
    eax = ~eax & 0xFF
    eax = eax ^ 0xC2
    eax = (eax - j) & 0xFF
    eax = ~eax & 0xFF
    eax = (eax + j) & 0xFF
    eax = ~eax & 0xFF
    eax = -eax & 0xFF  # neg
    eax = (eax >> 7) | (eax << 1) & 0xFF
    return eax


# Main #
if __name__ == "__main__":
    # the flag bytes from the decrypted resouce logged during debugging
    dbg_jpg_flag_bytes = unhexlify(
        "7F 2B D8 F5 C3 44 6D B7 75 95 89 A7 B9 C3 2C 3F 9E 91 B8 DC 6E 55 A7 51 E6 2C 59 BC 9C 12 98 06 8B A0 50 79 18 AA 29 4E 84 96 5F A6 37 9F ED 9A 33 3C ED 34 2D 63 7F 6C 5A".replace(
            " ", ""
        )
    )
    # read encrypted resource: file offset 0x8d604, size 0x1b2f5
    with open("../challenge_files/y0da.exe", "rb") as f:
        f.seek(0x8D604)
        encrypted_jpg = f.read(0x1B2F5)
    f.close()

    # decrypt resource with rc4 key patience_y0u_must_h4v3
    cipher = ARC4.new(b"patience_y0u_must_h4v3")
    decrypted_jpg = cipher.decrypt(encrypted_jpg)
    assert decrypted_jpg[0:4] == b"\xff\xd8\xff\xe0"

    # the encrypted flag is located behind a magic marker dword in the jpg overlay at the end
    # flag magic marker FF E1 AA 3B
    # flag size 0x39
    jpg_flag_bytes = decrypted_jpg[0x1B0F5 : 0x1B0F5 + 0x39]
    assert jpg_flag_bytes == dbg_jpg_flag_bytes

    # decrypt each flag character like the ROP chain would
    flag = bytearray(len(jpg_flag_bytes))
    for j in range(len(jpg_flag_bytes)):
        flag[j] = ROPchain(jpg_flag_bytes[j])
    print(flag.decode("UTF-8"))
