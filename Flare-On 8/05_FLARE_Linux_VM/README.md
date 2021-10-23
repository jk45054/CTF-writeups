# Flare-On 8, Challenge 5, FLARE Linux VM

## Task

Because of your superior performance throughout the FLARE-ON 8 Challenge, the FLARE team has invited you to their office to hand you a special prize! Ooh – a special prize from FLARE ? What could it be? You are led by a strong bald man with a strange sense of humor into a very nice conference room with very thick LED dimming glass. As you overhear him mumbling about a party and its shopping list you notice a sleek surveillance camera. The door locks shut!

Excited, you are now waiting in a conference room with an old and odd looking computer on the table. The door is closed with a digital lock with a full keyboard on it.

Now you realise… The prize was a trap! They love escape rooms and have locked you up in the office to make you test out their latest and greatest escape room technology. The only way out is the door – but it locked and it appears you have to enter a special code to get out. You notice the glyph for U+2691 on it. You turn you attention to the Linux computer - it seems to have been infected by some sort of malware that has encrypted everything in the documents directory, including any potential clues.

Escape the FLARE Linux VM to get the flag - hopefully it will be enough to find your way out.

Hints:

You can import "FLARE Linux VM.ovf" with both VMWare and VirtualBox.
Log in as 'root' using the password 'flare'
If you use VirtualBox and want to use ssh, you may need to enable port forwarding. The following link explains how to do it: <https://nsrc.org/workshops/2014/btnog/raw-attachment/wiki/Track2Agenda/ex-virtualbox-portforward-ssh.htm>

## Files

Filename | Size | SHA256
--- | --- | ---
FLARE Linux VM.mf | 193 bytes | 4aaf3404fdd70b9b68155610268d88c0c78f51d11e33b5722a470a1d3281bf5f
FLARE Linux VM.ovf | 7,692 bytes | fda88adc8256070e21aa34e2ad5cfe30bca1276fd8bba42c53ff0868e1a0ad6f
FLARE_Linux_VM-disk1.vmdk | 349,718,528 bytes | 01f13de25ce4bf28efb7a8e6b109d8999dc3e73544c0dda248222b179c9aab81
intro.txt | 1,593 bytes | 7c48019aff73f3aff7d2112c5a4f33ed178b8be82bfd469d94bee81303237fbc

## High Level Summary

- The provided Linux VM has a suspicious crontab entry periodically executing the program `/usr/bin/zyppe` (hinted to by `~/.viminfo`).
- `zyppe` is a 64 Bit ELF Linux binary that checks the directory **$HOME/Documents/** for new files.
- It encrypts the first 1,024 byte using a modified RC4 cipher and the key `A secret is no longer a secret once someone knows it`, saves them to **filename.broken** and deletes the original file.
  - The RC4 cipher is modified in the way that each (normal RC4) cipher byte is additionally XOR'd with the previous keystream byte.
- Decrypting all previously encrypted files in **$HOME/Documents/** yields a bunch of text files that have to be processed in a certain order.
  - The only fully readable files at the start are the ones beginning with the character u.
    - udon_noodles.txt gives the hint, that all files beginning with the same character have something in common -> The way to decode them is the same.
  - Each set of text files yields characters for a password and the algorithm to decode the next set of files.
  - The order of the text file processing is given through **shopping_list.txt** (**/USR/BIN/DOT**), which also hints at a second suspicious binary.
  - The algorithms to apply are ROR 7, Base64, XOR, SUB 4, RC4, Bifid Cipher, Vignere Cipher and AES-CBC-256.
- With the recovered password of ```E4Q5d6f`s4lD5I``` **/usr/bin/dot** yields the flag **H4Ck3r_e5c4P3D@flare-on.com**

## Details

- The algorithms used are
  - s* -> Rotate right 7 (hint from ugali.txt)
  - r* -> Base64 (hint from strawberries.txt)
  - b* -> XOR with `Reese's` (hint from reeses.txt)
  - i* -> SUB 4 (hint from banana_chips.txt)
  - n* -> RC4 with key `493513` (hint from iced_coffee.txt)
  - d* -> Bifid cipher with keywords `eggs` (hint from natillas.txt)
  - o* -> Vignere cipher with keyword `microwave` (hint from donuts.txt)
  - t* -> AES-CBC-256 with key `Sheep should sleep in a shed15.2` and IV `PIZZA00000000000000000000000000`
