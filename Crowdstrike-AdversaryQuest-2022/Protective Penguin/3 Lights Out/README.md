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
$ sudo pip3 install qiling
```

## Basic Preliminary Analysis

Let's take a first look at the three provided files.

```console
$ ls -la
-rwxr-xr-x 1 501 dialout     20 Jul 13 08:53 Font-Unix
-rwxr-xr-x 1 501 dialout   5564 Jul 13 08:53 i
-rwxr-xr-x 1 501 dialout   8772 Jul 13 08:53 lds
```

```console
$ file *
Font-Unix: data
i:         ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-armhf.so.3, missing section headers
lds:       ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-armhf.so.3, BuildID[sha1]=149cba1150c097a6784e9f32bf7954f9109d75ba, for GNU/Linux 3.2.0, not stripped
```

### File *Font-Unix*

Since **Font-Unix** is only 20 bytes in size, let's inspect that closer first.

```hexdump
Offset(h) 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
00000000  F2 6B F6 A7 8D 18 C2 2C 33 12 19 D6 4C D2 18 C4  òkö§..Â,3..ÖLÒ.Ä
00000010  1A D7 34 18                                      .×4.
```

At this step of the analysis, we can only guess the meaning. A CTF-ish guess could be, that we are looking at the encrypted flag - or anything else, really.

### File *i*

The file command's output above reads, that *i* is a 32 Bit ARM ELF executable with *missing section headers*. That doesn't sound too good.

It's also dynamically linked to `/lib/ld-linux-armhf.so.3` for ARM CPUs, so straight out execution on a vanilla x86 linux system won't work.

Some interesting strings found are

```console
$ strings i
/mnt/git-infrastructure/network-services.password
/usr/bin/lds
/tmp/.Font-Unix
```

While we don't know their meaning or usage context yet, */usr/bin/lds* and */tmp/.Font-Unix* could have some relationship with the provided files *lds* and *Font-Unix*.

If we try to run *i* with emulation software like [Qiling](https://docs.qiling.io/en/latest/), we get ELF parsing errors.

```console
$ mkdir rootfs
$ cp -a /usr/arm-linux-gnueabihf/lib/ ./rootfs/
$ qltool run -f ./lds --rootfs ./rootfs/ -v debug
[+]	Profile: Default
[+]	Set init_kernel_get_tls
Traceback (most recent call last):
[...]
elftools.construct.core.FieldError: expected 4, found 0
[...]
elftools.common.exceptions.ELFParseError: expected 4, found 0
```

An initial QEMU run will raise a Segmentation Fault.

```console
$ qemu-arm -L /usr/arm-linux-gnueabihf/ ./i
qemu: uncaught target signal 11 (Segmentation fault) - core dumped
Segmentation fault (core dumped)
```

### File *lds*

The file command's output above reads, that *lds* is also a 32 Bit ARM ELF executable dynamically linked to `/lib/ld-linux-armhf.so.3` for ARM CPUs.

Some interesting strings that stand out are

```console
$ strings lds
[...]
[!] opening handler failed
[!] writing payload to handler failed
/sys/class/leds/led0/brightness
/sys/class/leds/led1/brightness
/sys/class/leds/led0/trigger
[!] error initializing led0
/sys/class/leds/led1/trigger
error initializing led1
Usage: %s <path>
[*] Sending %s
raspi_led_sender.c
transmission_send_data
transmission_send_file
channel_initialize
transmission_send_end
channel_set_state
transmission_send_error
channel_api_write_value
transmission_send_start
```

Looks like *lds* might be used to somehow transmit data/files. It also seems to access two LEDs (trigger, brightness). Quite interesting.

We can emulate running it with Qiling:

```console
$ qltool run -f ./lds --rootfs ./rootfs/ -v debug
Usage: ./lds <path>
```

So it needs a path name as a command line argument. Why not pass it *Font-Unix* for fun and giggles. After all, *lds* might be the exfiltration compontent out of the provided challenges files.

```console
$ qltool run -f ./lds --rootfs ./rootfs/ --args ./Font-Unix
[*] Sending ./Font-Unix
[!] opening handler failed
```

Seems to be missing a *handler*, whatever that may be. This concludes what we can get out of basic preliminary analysis steps.

## Advanced Analysis

Let's recap what we know/assume so far

- *Font-Unix* contains 20 bytes, which is likely encrypted/encoded data.
- A path string to `/tmp/.Font-Unix` is found in binary *i*.
- Binary *i* also contains the path string `/usr/bin/lds`, which may be a reference to the provided file *lds*
- *i* also contains the path string `/mnt/git-infrastructure/network-services.password`.

It seems to be a good idea to dive deeper into binary *i* and find out what it is doing precisely.

### File *i*

Loading the file *i* as it is into [Cutter](https://cutter.re) at least for version 2.0.3 based on Rizin version 0.3.0 crashes it completely. Great start. ;-)

We could try to fix the (maybe deliberately corrupted) ELF headers ([Link](https://reverseengineering.stackexchange.com/questions/12316/fixing-corrupt-elf-header-field-e-shnum-for-use-in-gdb)). We don't have to though.

Trying to open it in IDA Pro yields the warning message *SHT table size or offset is invalid*. We can still stare at some ARM assembly, but static analysis shows some weird looking code beginning @ `0x103EC`.

```nasm
LOAD:000103D0 main                                    ; DATA XREF: start+20↑o
LOAD:000103D0                 PUSH            {R11}
LOAD:000103D4                 ADD             R11, SP, #0
LOAD:000103D8                 SUB             SP, SP, #0xC
LOAD:000103DC                 STR             R0, [R11,#var_8]
LOAD:000103E0                 STR             R1, [R11,#var_C]
LOAD:000103E4                 MOV             R7, PC
LOAD:000103E8                 BL              sub_10484
LOAD:000103EC                 TSTCS           R0, R0,ASR#12
LOAD:000103F0                 SVCLE           0x52705
LOAD:000103F4                 VST1.8          {D20-D22}, [PC],R5
LOAD:000103F8                 B               0x13EEC10
LOAD:000103F8 ; End of function main
LOAD:000103F8 ; ---------------------------------------------------------------------------
LOAD:000103FC                 DCD 0xF10A2A0A, 0x46510A34, 0x6280F44F, 0xDF032703, 0x46284604
LOAD:000103FC                 DCD 0xDF062706, 0x2002001, 0x2001D80, 0x21423008, 0x72E0F44F
LOAD:000103FC                 DCD 0xDF052705, 0x40764605, 0x406636A5, 0x460046F9, 0x46284600
LOAD:000103FC                 DCD 0xF89A4651, 0xEA8BB000, 0xF88A0B06, 0xB6B000, 0x60BEA86
LOAD:000103FC                 DCD 0xF0061CB6, 0x220106FF, 0xDF042704, 0xA01F10A, 0x34FFF104
LOAD:000103FC                 DCD 0xBF882C00, 0x200146CF, 0x1D400200, 0x30F80200, 0x2092102
LOAD:000103FC                 DCD 0x2093110, 0x40523124, 0xDF0B270B, 0
LOAD:00010484 ; =============== S U B R O U T I N E =======================================
LOAD:00010484 sub_10484                               ; CODE XREF: main+18↑p
LOAD:00010484                 MOV             R5, R1,LSL R8
LOAD:00010488                 EOR             R5, R5, R2
LOAD:0001048C                 ADD             R5, R5, #0xF9
LOAD:00010490                 AND             R5, R5, #0xFF
LOAD:00010494                 ADD             R7, R7, R5
LOAD:00010498                 MOV             R8, PC
LOAD:0001049C                 BX              R7
LOAD:0001049C ; End of function sub_10484
LOAD:0001049C ; ---------------------------------------------------------------------------
LOAD:000104A0 aMntGitInfrastr DCB "/mnt/git-infrastructure/network-services.password",0
LOAD:000104D2                 DCW 0xE1A0
LOAD:000104D4                 DCD 0xE1A00000, 0xE1A00000, 0xE1A00000, 0xE1A00000
LOAD:000104E4 ; ---------------------------------------------------------------------------
LOAD:000104E4                 MOV             R3, #0
LOAD:000104E8                 MOV             R0, R3
LOAD:000104EC                 MOV             SP, R11
LOAD:000104F0                 POP             {R11}
LOAD:000104F4                 BX              LR
```

We can definitely recognize the suspicious string `/mnt/git-infrastructure/network-services.password` here.

Let's run it again, this time with qemu's option `-strace` to log system calls.

```console
$ qemu-arm -strace -L /usr/arm-linux-gnueabihf/ ./i
[..]
23483 open("/mnt/git-infrastructure/network-services.password",O_RDONLY) = -1 errno=2 (No such file or directory)
23483 read(-2,0x21034,1024) = -1 errno=9 (Bad file descriptor)
23483 close(-2) = -1 errno=9 (Bad file descriptor)
23483 open("/tmp/.Font-Unix",O_RDWR|O_CREAT,0700) = 3
[...]
```

So binary *i* is - not unexpectedly - trying to read from file `/mnt/git-infrastructure/network-services.password`. Afterwards it is opening file `/tmp/.Font-Unix` for reading and writing.

Let's supply *i* with a fake flag...

```console
$ sudo mkdir /mnt/git-infrastructure/
$ sudo sh -c 'echo "CS{could_be_a_flag}" > /mnt/git-infrastructure/network-services.password'
```

... and run it again.

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

Very interesting. *i* seems to read from our fake flag file, write to `/tmp/.Font-Unix` and then execute *lds* with `/tmp/.Font-Unix` as its `path` argument.

What did *i* write to `/tmp/.Font-Unix`?

```console
$ xxd /tmp/.Font-Unix 
00000000: f26b f6a7 d641 ffd1 5824 5bfa 118c a4c2  .k...A..X$[.....
00000010: 1d88 4b9f                                ..K.
```

The first four hex bytes match the first four bytes from the challenge file *Font-Unix*. Very interesting, we're onto something!

Let's do some (remote IDA) debugging on *i*!

```console
$ qemu-arm -g 12345 -L /usr/arm-linux-gnueabihf/ ./i
```

Connect IDA to the remote gdb debugger and set breakpoint in function **main()**. Start stepping through the code especially of function **sub_10484()**.

```nasm
LOAD:00010484 sub_10484                               ; CODE XREF: main+18↑p
LOAD:00010484 MOV             R5, R1,LSL R8           ; R8 = 0 => R5 = R1 = argv
LOAD:00010488 EOR             R5, R5, R2              ; R5 ^= R2 (argv ^ envp) = 0x08
LOAD:0001048C ADD             R5, R5, #0xF9           ; R5 += 0xF9 = 0x101
LOAD:00010490 AND             R5, R5, #0xFF           ; R5 &= 0xFF = 0x01
LOAD:00010494 ADD             R7, R7, R5              ; R7 += R5 => 0x103EC + 1
LOAD:00010494                                         ; (activates Thumb mode)
LOAD:00010498 MOV             R8, PC                  ; R8 = ptr to string @ 0x104A0
LOAD:0001049C BX              R7                      ; branch back to 0x103EC in Thumb mode
```

All that function **sub_10484()** does is

- Load address of string @ `0x104A0` into register R8 (`/mnt/git-infrastructure/network-services.password`)
- Branch back to address `0x103EC` in [Thumb mode](https://developer.arm.com/documentation/dui0473/m/overview-of-the-arm-architecture/changing-between-arm--thumb--and-thumbee-state) (lowest Bit = 1)

So beginning @ address `0x103EC`, we have to analyze the code as `CODE16` instead of `CODE32`.

We can force IDA to interprete the bytes as CODE16 with hotkey `ALT + G` and set the value for `T()` to 1. This will not be needed during remote debugging though, as IDA will realize the mode switch then automatically.

Step-by-step instructions:

- Highlight (misinterpreted) Code from adresses `0x103EC` to `0x103FB` and undefine it (hotkey `u`)
- Highlight addresses `0x103EC` to `0x10484` and mark it as Thumb Code (hotkey `ALT + g`, set value T to 0x1)
- Highlight addresses `0x103EC` to `0x10484` again and force IDA to analyze it as code (hotkey `c`, option *Force* when prompted)

To make sense of the syscalls, refer to an [ARM syscall table](https://syscalls.w3challs.com/?arch=arm_strong).

The following Thumb code will read the contents of `/mnt/git-infrastructure/network-services.password`, open the destination file `/tmp/.Font-Unix` for writing and calculate the initial XOR value in register R6 based on amounts of (password) bytes read.

```nasm
LOAD:000103EC                 CODE16
LOAD:000103EC                 MOV             R0, R8  ; filename = /mnt/git-infrastructure/network-services.password
LOAD:000103EE                 MOVS            R1, #0
LOAD:000103F0                 MOVS            R7, #5  ; syscall number
LOAD:000103F2                 SVC             5       ; syscall open
LOAD:000103F4                 MOV             R5, R0  ; fd returned by open
LOAD:000103F6                 MOV.W           R10, #0x210
LOAD:000103FA                 MOV.W           R10, R10,LSL#8
LOAD:000103FE                 ADD.W           R10, R10, #0x34 ; '4'
LOAD:00010402                 MOV             R1, R10 ; buf
LOAD:00010404                 MOV.W           R2, #0x400 ; count
LOAD:00010408                 MOVS            R7, #3  ; syscall number
LOAD:0001040A                 SVC             3       ; syscall read
LOAD:0001040C                 MOV             R4, R0  ; save bytes read in R4
LOAD:0001040E                 MOV             R0, R5  ; fd
LOAD:00010410                 MOVS            R7, #6  ; syscall number
LOAD:00010412                 SVC             6       ; syscall close
LOAD:00010414                 MOVS            R0, #0x10608 ; filename = /tmp/.Font-Unix
LOAD:0001041E                 MOVS            R1, #0x42 ; 'B'
LOAD:00010420                 MOV.W           R2, #0x1C0
LOAD:00010424                 MOVS            R7, #5  ; syscall number
LOAD:00010426                 SVC             5       ; syscall open
LOAD:00010428                 MOV             R5, R0
LOAD:0001042A                 EORS            R6, R6  ; empty initial XOR value
LOAD:0001042C                 ADDS            R6, #0xA5 ; add 0xA5
LOAD:0001042E                 EORS            R6, R4  ; R6 = 0xA5 XOR R4 (amount of bytes read @ 0x1040A)
LOAD:00010430                 MOV             R9, PC
LOAD:00010432                 MOV             R0, R0
```

Initial XOR value is `0xA5 ^ len(data)`. For the size of the provided file *Font-Unix*, the value of R6 would be `R6 = 0xA5 ^ 0x14 = 0xB1`.

Then follows the crypto loop to encrypt the data read and to write it byte-by-byte to the destination file `/tmp/.Font-Unix`.

```nasm
LOAD:00010434 crypt_loop                              ; CODE XREF: LOAD:00010464↓j
LOAD:00010434                 MOV             R0, R0
LOAD:00010436                 MOV             R0, R5  ; fd for syscall write
LOAD:00010438                 MOV             R1, R10 ; buf for syscall write
LOAD:0001043A                 LDRB.W          R11, [R10] ; get next char
LOAD:0001043E                 EOR.W           R11, R11, R6 ; XOR with R6
LOAD:00010442                 STRB.W          R11, [R10] ; write back XOR'd char
LOAD:00010446                 LSLS            R6, R6, #2 ; R6 << 2
LOAD:00010448                 EOR.W           R6, R6, R11 ; R6 = R6 ^ written char
LOAD:0001044C                 ADDS            R6, R6, #2 ; R6 += 2
LOAD:0001044E                 AND.W           R6, R6, #0xFF ; R6 &= 0xFF
LOAD:00010452                 MOVS            R2, #1  ; count for syscall write
LOAD:00010454                 MOVS            R7, #4  ; syscall number
LOAD:00010456                 SVC             4       ; syscall write (single char to file)
LOAD:00010458                 ADD.W           R10, R10, #1 ; move buffer pointer += 1
LOAD:0001045C                 ADD.W           R4, R4, #0xFFFFFFFF ; R4 -= 1
LOAD:00010460                 CMP             R4, #0  ; done yet?
LOAD:00010462                 IT HI
LOAD:00010464                 MOVHI           PC, R9
```

Once that is finished, execute `/usr/bin/lds` with argument `/tmp/.Font-Unix`, likely for exfiltration/transmission purposes.

```nasm
LOAD:00010466                 MOVS            R0, #0x105F8 ; filename = /usr/bin/lds
LOAD:00010470                 MOVS            R1, #0x21024 ; argv = ['/usr/bin/lds', '/tmp/.Font-Unix']
LOAD:0001047A                 EORS            R2, R2  ; envp = NULL
LOAD:0001047C                 MOVS            R7, #0xB ; syscall number
LOAD:0001047E                 SVC             0xB     ; syscall execve
```

### What will *lds* do with the contents of */tmp/.Font-Unix* though?

Firing up Cutter for a quick decompilation view of *lds*, we can see that *lds* will try to transmit the (already encrypted) contents of the file given as the command line argument.

```cpp
undefined4 main(int argc, char **argv)
{
[...]    
    if (argc == 2) {
        printf(*(undefined4 *)0x10b4c, argv[1]);
        uVar1 = transmission_send_file(argv[1]);
    } else {
        printf(*(undefined4 *)0x10b48, *argv);
        uVar1 = 0xffffffff;
    }
    return uVar1;
}
```

```cpp
undefined4 transmission_send_file(char *arg1)
{
[...]
    transmission_send_start();
    var_ch = fopen(arg1, *(undefined4 *)0x10acc);
    if (var_ch == 0) {
        uVar2 = 0xffffffff;
    } else {
        while( true ) {
            iStack16 = fread(&filename, 1, 0x80, var_ch);
            if (iStack16 == 0) break;
            iVar1 = transmission_send_data((int32_t)&filename, iStack16);
            if (iVar1 == -1) {
                transmission_send_error();
            }
        }
        transmission_send_end();
    }
    return uVar2;
}
```

While it may be interesting to analyze it all, it does not seem to be needed to solve this challenge.

### Decrypting *Font-Unix*

With the knowledge gained from analyzing binary *i*, we can write a [decryption program](./decrypt.py) to recover the original content of `/mnt/git-infrastructure/network-services.password` that corresponds to the supplied and encrypted file *Font-Unix*. Just re-implement the crypto loop.

```python
decrypted_flag = bytearray(len(crypted_flag))

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
