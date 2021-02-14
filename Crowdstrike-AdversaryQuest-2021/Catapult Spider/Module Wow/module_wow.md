# Crowdstrike Adversary Quest 2021 / Catapult Spider / #3 Module Wow

## Challenge Description
Diving deeper into CATAPULT SPIDER's malware, we found that it also supports handing off tasks to external modules. We identified one such module that looks like it might be used to validate a key or password of some sorts, but we're really not sure.
Can you validate our assumption, and, if possible, extract the key?

## Approach

### First Info about Evidence File
```
file module.wow 
module.wow: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=0e5d6a93a2dc3a28eace2b7179e81ce32b968e34, for GNU/Linux 3.2.0, not stripped
```

Checksec
```
checksec module.wow
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Rabin2 for entrypoints and strings (output edited slightly for readability)
```
rabin2 -e -ee -z module.wow 
[Entrypoints]
vaddr=0x000010e0 paddr=0x000010e0 haddr=0x00000018 hvaddr=0x00000018 type=program

[Constructors]
vaddr=0x000011d0 paddr=0x000011d0 hvaddr=0x00003de8 hpaddr=0x00002de8 type=init
vaddr=0x00001180 paddr=0x00001180 hvaddr=0x00003df0 hpaddr=0x00002df0 type=fini

[Main]
vaddr=0x000012fa paddr=0x000012fa

[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00002008 0x00002008 30  31   .rodata ascii oops. something went wrong! :(
1   0x00002027 0x00002027 17  18   .rodata ascii [!] mmap() failed
2   0x00002039 0x00002039 19  20   .rodata ascii Usage: %s <string>\n
3   0x00002050 0x00002050 36  37   .rodata ascii [!] setup handler for SIGSEGV failed
4   0x00002078 0x00002078 34  35   .rodata ascii [!] setup handlerfor SIGBUS failed
5   0x000020a0 0x000020a0 35  36   .rodata ascii [!] setup handler for SIGFPE failed
6   0x000020c8 0x000020c8 35  36   .rodata ascii [!] setup handler for SIGILL failed
0   0x000030b4 0x000040b4 4   5    .data   ascii C_c0
1   0x000030bb 0x000040bb 6   7    .data   ascii CS{c'1
2   0x000030d5 0x000040d5 6   7    .data   ascii ACS{lw
3   0x000030f4 0x000040f4 5   6    .data   ascii cryp<
4   0x00003121 0x00004121 4   5    .data   ascii ^c0d
5   0x00003154 0x00004154 6   7    .data   ascii ^0n_l5
```



