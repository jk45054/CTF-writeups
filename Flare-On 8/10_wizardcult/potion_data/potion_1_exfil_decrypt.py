spells = dict()
with open("dumped_spelltable.txt", "r") as f:
    for spell in f:
        index, name = spell.split('=')
        spells[name.rstrip()] = int(index, 16)
f.close()

exfil = bytearray()
with open("potion_1_exfil.txt", "r") as g:
    for line in g:
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
g.close()

with open("potion_1_exfil_bytes.bin", "wb") as f:
    f.write(exfil)
f.close()

# decrypt / vm program 1 -> guesstimates XOR 0xa2
exfil_decrypted = bytes(a ^ 0xA2 for a in exfil)

with open("potion_1_exfil_bytes_decrypted.bin", "wb") as f:
    f.write(exfil_decrypted)
f.close()

#print(exfil_decrypted)
