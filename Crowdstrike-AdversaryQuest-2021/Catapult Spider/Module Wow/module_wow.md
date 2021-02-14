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

