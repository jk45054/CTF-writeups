# Crowdstrike Adversary Quest 2022 / Protective Penguin / #3 Lights Out

## Challenge Description

Unfortunately, the incident response team informed us about further unknown activity another gapped device. They found mysterious files on the host, but they were unable to analyze the samples. We need you to find out what they were used for.

## TL;DR Summary

TL;DR

## Pre-Requisites

Installation of tools needed for cross-platform debugging and emulation.

```console
$ sudo apt install libc6-armhf-cross
$ sudo apt install gdb-multiarch
$ sudo apt install qemu-user
$ sudo apt install qemu-user-binfmt
$ sudo apt install 'binfmt*'
```

## Analysis

Inspect the files

```console
$ file *
Font-Unix: data
i:         ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-armhf.so.3, missing section headers
lds:       ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-armhf.so.3, BuildID[sha1]=149cba1150c097a6784e9f32bf7954f9109d75ba, for GNU/Linux 3.2.0, not stripped
```

Font-Unix - could be crypted data, maybe the flag, we don't know yet.

```txt
Offset(h) 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
00000000  F2 6B F6 A7 8D 18 C2 2C 33 12 19 D6 4C D2 18 C4  òkö§..Â,3..ÖLÒ.Ä
00000010  1A D7 34 18                                      .×4.
```

Interesting strings in file **i**

```txt
/mnt/git-infrastructure/network-services.password
/usr/bin/lds
/tmp/.Font-Unix
```

Emulate arm elf32 binary with Qiling:

```console
$ mkdir rootfs
$ cp -a /usr/arm-linux-gnueabihf/lib/ ./rootfs/
$ qltool run -f ./lds --rootfs ./rootfs/ -v debug
Usage: ./lds <path>
```

```console
$ qltool run -f ./lds --rootfs ./rootfs/ --args ./Font-Unix
[*] Sending ./Font-Unix
[!] opening handler failed
```

Seems to be missing something, could be exfiltration tool for bridging the air gap.

Interesting part seems to be binary i, which seems to have corrupted ELF headers... IDA pro complains, qiling doesnt load it either

Possible fix (untested/TODO): https://reverseengineering.stackexchange.com/questions/12316/fixing-corrupt-elf-header-field-e-shnum-for-use-in-gdb

Run `i` with gdb. Attach with gdb-multiarch

```console
$ qemu-arm -g 12345 -L /usr/arm-linux-gnueabihf/ ./i
$ gdb-multiarch ./i
(gdb) set arch mips
(gdb) set endian little
(gdb) target remote localhost:12345
Remote debugging using localhost:12345
```

This errors though in gdb and IDA ends somewhere in the unknowns...

Let's create this mysterious file `/mnt/git-infrastructure/network-services.password` and put a fake flag string in it.

```console
$ cat network-services.password 
CS{could_be_a_flag}
```

```txt
$ qemu-arm -strace -L /usr/arm-linux-gnueabihf/ ./i
[...]
16903 open("/mnt/git-infrastructure/network-services.password",O_RDONLY) = 3
16903 read(3,0x21034,1024) = 20
16903 close(3) = 0
16903 open("/tmp/.Font-Unix",O_RDWR|O_CREAT,0700) = 3
16903 write(3,0x21034,1) = 1
16903 write(3,0x21035,1) = 1
16903 write(3,0x21036,1) = 1
16903 write(3,0x21037,1) = 1
16903 write(3,0x21038,1) = 1
16903 write(3,0x21039,1) = 1
16903 write(3,0x2103a,1) = 1
16903 write(3,0x2103b,1) = 1
16903 write(3,0x2103c,1) = 1
16903 write(3,0x2103d,1) = 1
16903 write(3,0x2103e,1) = 1
16903 write(3,0x2103f,1) = 1
16903 write(3,0x21040,1) = 1
16903 write(3,0x21041,1) = 1
16903 write(3,0x21042,1) = 1
16903 write(3,0x21043,1) = 1
16903 write(3,0x21044,1) = 1
16903 write(3,0x21045,1) = 1
16903 write(3,0x21046,1) = 1
16903 write(3,0x21047,1) = 1
16903 execve("/usr/bin/lds",{"/usr/bin/lds","/tmp/.Font-Unix",NULL}) = -1 errno=2 (No such file or directory)
```

Yields the following `/tmp/.Font-Unix` content

```txt
$ xxd /tmp/.Font-Unix 
00000000: f26b f6a7 d641 ffd1 5824 5bfa 118c a4c2  .k...A..X$[.....
00000010: 1d88 4b9f                                ..K.
```

First 4 hex bytes seem to match the first 4 bytes from the challenge Font-Unix file. Interesting!

Try remote debugging with IDA to `qemu-arm -g`

```console
$ qemu-arm -g 12345 -L /usr/arm-linux-gnueabihf/ ./i
```

Set breakpoint in main, step through the code.

The interesting code starts after a dynamically calculated jump to `0x103EC` (could be just a jump back to PC after call to 0x10484 from 0x103E8).

Code to read in plaintext, open destination file for writing and generating the initial XOR value in R6

```nasm
LOAD:000103EC MOV             R0, R8                  ; filename = /mnt/git-infrastructure/network-services.password
LOAD:000103EE MOVS            R1, #0
LOAD:000103F0 MOVS            R7, #5
LOAD:000103F2 SVC             5                       ; open
LOAD:000103F4 MOV             R5, R0
LOAD:000103F6 MOV.W           R10, #0x210
LOAD:000103FA MOV.W           R10, R10,LSL#8
LOAD:000103FE ADD.W           R10, R10, #0x34 ; '4'
LOAD:00010402 MOV             R1, R10                 ; buf
LOAD:00010404 MOV.W           R2, #0x400              ; count
LOAD:00010408 MOVS            R7, #3
LOAD:0001040A SVC             3                       ; read
LOAD:0001040C MOV             R4, R0
LOAD:0001040E MOV             R0, R5                  ; fd
LOAD:00010410 MOVS            R7, #6
LOAD:00010412 SVC             6                       ; close
LOAD:00010414 MOVS            R0, #0x10608            ; filename = /tmp/.Font-Unix
LOAD:0001041E MOVS            R1, #0x42 ; 'B'
LOAD:00010420 MOV.W           R2, #0x1C0
LOAD:00010424 MOVS            R7, #5
LOAD:00010426 SVC             5                       ; open
LOAD:00010428 MOV             R5, R0
LOAD:0001042A EORS            R6, R6                  ; empty initial XOR value
LOAD:0001042C ADDS            R6, #0xA5               ; add 0xA5
LOAD:0001042E EORS            R6, R4                  ; XOR with R4 (amount of bytes read @ 0x1040A)
LOAD:00010430 MOV             R9, PC
LOAD:00010432 MOV             R0, R0
```

Initial XOR value is `0xA5 ^ len(data)`. For len=20 (0x14), `R6 = 0xB1`

Crypto loop follows:

```nasm
LOAD:00010434 crypt_loop                              ; CODE XREF: LOAD:00010464↓j
LOAD:00010434 MOV             R0, R0
LOAD:00010436 MOV             R0, R5                  ; fd for syscall write
LOAD:00010438 MOV             R1, R10                 ; buf for syscall write
LOAD:0001043A LDRB.W          R11, [R10]              ; get next char
LOAD:0001043E EOR.W           R11, R11, R6            ; XOR with R6
LOAD:00010442 STRB.W          R11, [R10]              ; write back XOR'd char
LOAD:00010446 LSLS            R6, R6, #2              ; R6 << 2
LOAD:00010448 EOR.W           R6, R6, R11             ; R6 = R6 ^ written char
LOAD:0001044C ADDS            R6, R6, #2              ; R6 += 2
LOAD:0001044E AND.W           R6, R6, #0xFF           ; R6 &= 0xFF
LOAD:00010452 MOVS            R2, #1                  ; count for syscall write
LOAD:00010454 MOVS            R7, #4                  ; syscall number
LOAD:00010456 SVC             4                       ; write single char to file
LOAD:00010458 ADD.W           R10, R10, #1            ; move buffer pointer += 1
LOAD:0001045C ADD.W           R4, R4, #0xFFFFFFFF     ; R4 -= 1
LOAD:00010460 CMP             R4, #0                  ; done yet?
LOAD:00010462 IT HI
```

Execve'ing lds to exfiltrate the data via led0/led1

```nasm
LOAD:00010466 MOVS            R0, #0x105F8            ; filename = /usr/bin/lds
LOAD:00010470 MOVS            R1, #0x21024            ; argv = ['/usr/bin/lds', '/tmp/.Font-Unix']
LOAD:0001047A EORS            R2, R2                  ; envp = NULL
LOAD:0001047C MOVS            R7, #0xB                ; syscall number
LOAD:0001047E SVC             0xB                     ; execve
```

syscall table: https://syscalls.w3challs.com/?arch=arm_strong

### Write a Decryptor

Decryptor for Font-Unix

```python
import sys

with open(sys.argv[1], "rb") as f:
    crypted_flag = f.read()

decrypted_flag = bytearray(len(crypted_flag))

# set initial XOR value
XOR_value = 0xA5 ^ len(crypted_flag)

for i in range(len(crypted_flag)):
    decrypted_flag[i] = crypted_flag[i] ^ XOR_value
    XOR_value <<= 2
    XOR_value ^= crypted_flag[i]
    XOR_value += 2
    XOR_value &= 0xFF

print(decrypted_flag)
```

## Now it's Flag Time!

```console
$ ./decrypt.py Font-Unix 
bytearray(b'CS{c4st0m_1mpl4nts}\n')
```

Flag: **CS{c4st0m_1mpl4nts}**
