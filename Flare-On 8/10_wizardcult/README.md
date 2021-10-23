# Flare-On 8, Challenge 10, wizardcult

## Task

We have one final task for you. We captured some traffic of a malicious cyber-space computer hacker interacting with our web server. Honestly, I padded my resume a bunch to get this job and don't even know what a pcap file does, maybe you can figure out what's going on.

## Files

Filename | Size | SHA256
--- | --- | ---
wizardcult.pcap | 11,843,056 bytes | ffba10439fc6435f314ec3a317cebe3f4f7d8a89bd01132e58970689eaaca62d

## High Level Summary

- The network traffic recorded in `wizardcult.pcap` consists of packets exchanged between the assumed attacking client (172.16.30.249, dubbed *Attacker*) and the targeted webserver (172.16.30.245, dubbed *Target*)
- The Attacker used the attack techniques Authentication Bypass (via SQLi) and Command Injection to make the Target download & execute a malicious 64 Bit Linux Go Binary called *induct*.
- induct uses the Internet Relay Chat (IRC) protocol to connect back to the Attacker for Command & Control (C2) purposes.
- The C2 commands are encoded in a role playing game style of textual chat messages.
  - Dungeon Descriptions are encoded Shell Commands to be executed on the Target.
  - Potion Ingredients define a custom Virtual Machine (VM) Configuration to be applied to the output of the Shell Commands.
  - Spell Casting messages are used to exfiltrate the VM-transformed output back to the Attacker.
- The recorded IRC traffic contains two executed Shell Commands and their encrypted output.
  - The dungeon *Graf's Infernal Disco* executes `ls /mages_tower` on the Target.
    - The VM defined by the *Potion of Acid Resistance* encrypts each byte of the output with a single byte XOR cipher (value 0xA2).
    - The output yields the filenames `cool_wizard_meme.png` and `induct`
  - The dungeon *The Sunken Crypt* executes `/mages_tower/cool_wizard_meme.png` on the Target.
    - The VM defined by the *Potion of Water Breathing* applies a polyalphabetic cipher with 24 substitution alphabets on the output.
    - The output yields a PNG file containing the flag `wh0_n33ds_sw0rds_wh3n_you_h4ve_m4ge_h4nd@flare-on.com`

![cool_wizard_meme.png](pics/flag.png)

## Technical Details

### PCAP

### induct

#### Static Analysis

#### Dynamic Analysis

#### Data Structures, Code Tables

#### Advanced Analysis, Replaying IRC Traffic from PCAP

#### Decoding Dungeon 1

#### Decoding Dungeon 2

I guess I took the cheesy road on this one, picking a chosen plaintext attack. Putting selectively crafted files named `cool_wizard_meme.png` into the directory `/mages_tower`, one can replay *The Sunken Crypt* dungeon to induct. It will then encrypt the contents and exfiltrate that through spell casting. Decoding the spellcasts, one can deduce characteristics about the (unknown) applied crypto cipher.

I began with 128 null bytes that - after decoding the [spell casting](potion_data/potion_2_exfil_mock_128_nullbytes.txt) - [yielded](potion_data/potion_2_exfil_mock_bytes.bin):

```txt
Offset(h) 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
00000000  58 DA C5 91 28 75 76 03 F8 68 C5 D3 C8 91 83 61  XÚÅ‘(uv.øhÅÓÈ‘ƒa
00000010  5D 0D 76 CB 40 E0 85 EA 58 DA C5 91 28 75 76 03  ].vË@à…êXÚÅ‘(uv.
00000020  F8 68 C5 D3 C8 91 83 61 5D 0D 76 CB 40 E0 85 EA  øhÅÓÈ‘ƒa].vË@à…ê
00000030  58 DA C5 91 28 75 76 03 F8 68 C5 D3 C8 91 83 61  XÚÅ‘(uv.øhÅÓÈ‘ƒa
00000040  5D 0D 76 CB 40 E0 85 EA 58 DA C5 91 28 75 76 03  ].vË@à…êXÚÅ‘(uv.
00000050  F8 68 C5 D3 C8 91 83 61 5D 0D 76 CB 40 E0 85 EA  øhÅÓÈ‘ƒa].vË@à…ê
00000060  58 DA C5 91 28 75 76 03 F8 68 C5 D3 C8 91 83 61  XÚÅ‘(uv.øhÅÓÈ‘ƒa
00000070  5D 0D 76 CB 40 E0 85 EA 58 DA C5 91 28 75 76 03  ].vË@à…êXÚÅ‘(uv.
```

One can easily identify a repeating pattern with a period of 0x18.

Next, I crafted a payload of 0x18 times each byte value from 0x00 to 0xff, generating a mock file of 6,144 bytes. Decoding the spell casting again yields the [data](potion_data/potion_2_exfil_mock3_bytes.bin) needed to create a lookup mechanism for the polyalphabetic substition cipher.

Using this lookup mechanism, it is possible to decrypt the originally exfiltrated file without having to understand the custom vm code:

```python
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
```
