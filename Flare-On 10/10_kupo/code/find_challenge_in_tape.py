# Flare-On 10, Challenge 10, kupo
#
# Try to find the challenge file inside the tape file
#

from binascii import hexlify

with open("../files/c10.Z", "rb") as f:
    c10z = f.read()
f.close()

with open("../challenge_files/forth.tap", "rb") as g:
    forthtap = g.read()
g.close()

i = 0  # index into forth.tap
j = 0  # index into c10.Z
k = 0  # index of gap
found_c10 = False
newgap = False
gap = bytearray()
for i in range(len(forthtap)):
    if forthtap[i] != c10z[j]:
        if not newgap:
            newgap = True
            k += 1
        # print(f"[-] Mismatch at forth.tap file offset {hex(i)} = {hex(forthtap[i])}")
        gap.append(forthtap[i])
        i = i + 1
        continue
    if newgap:
        if k == 1:
            print(
                f"[*] Stuff before c10.Z in forth.tap with len = {hex(len(gap))}, content = {hexlify(gap)}"
            )
        else:
            print(
                f"[*] Gap #{k-1} at forth.tap offset {hex(i)}, total mismatched bytes: {hex(len(gap))}, content: {hexlify(gap)}"
            )
        gap = bytearray()
        newgap = False
    if not found_c10:
        found_c10 = True
        print("[+] Found start")

    i += 1
    j += 1
    if j == len(c10z):
        print(
            f"[*] Reached end of c10.Z, footer bytes remaining in forth.tap: {hex(len(forthtap)-i)}, footer = {hexlify(forthtap[i:])}"
        )
        break
    # print(f"[+] Match: forth.tap index {hex(i)} matches c10.Z index {hex(j)}")
