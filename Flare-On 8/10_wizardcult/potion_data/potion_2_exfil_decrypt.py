spells = dict()
with open("dumped_spelltable.txt", "r") as f:
    for spell in f:
        index, name = spell.split('=')
        spells[name.rstrip()] = int(index, 16)
f.close()

exfil = bytearray()
with open("potion_2_exfil.txt", "r") as g:
    for line in g:
        try:
            prefix, castText = line.rstrip().split("cast ")
            #print(castText)
            spellName, damageText = castText.split(" on ")
            exfil.append(spells[spellName])
            #print(spellName, spells[spellName])
            #print(damageText)
            try:
                first, last = damageText.split("d", 1)
                crap, crap, crap, damage1txt = first.split(" ")
                damage2txt, crap = last.split(" ", 1)
                exfil.append(int(damage1txt))
                exfil.append(int(damage2txt))
                #print(damage1)
                #print(damage2)
            except:
                pass
        except:
            pass
g.close()

with open("potion_2_exfil_bytes.bin", "wb") as f:
    f.write(exfil)
f.close()

# mock3 was generated with crypt period (24) of each byte value 0-255
# \x00 * 24, \x01 * 24, ..., \xff * 24 (total len 24 * 256 = 6144)
# the generated file was placed as /mage_tower/cool_wizard_meme.png and exfiltrated by
# replaying the potion (vm) recipe from pcap file
# spell casting was decoded into binary with potion_2_exfil_mock3_decrypt.py

with open("potion_2_exfil_mock3_bytes.bin", "rb") as f:
    lookup = f.read()

# approach:
# take crypted byte at offset i, loop with index j through mock3 starting at i % 24 step 24
# find crypted byte after j steps -> then j is the plaintext value

exfil_decrypted = bytearray()
for i in range(len(exfil)):
    for j in range(i % 24, len(lookup), 24):
        if (exfil[i] == lookup[j]):
            # found lookup byte
            exfil_decrypted.append(j // 24)
            break

with open("potion_2_exfil_bytes_decrypted.png", "wb") as f:
    f.write(exfil_decrypted)
f.close()
