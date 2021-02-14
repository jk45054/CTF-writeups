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
rabin2 -e -ee -M -z module.wow 
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

### Execution in a Sandbox
```
./module.wow 
Usage: ./module.wow <string>
```

```
./module.wow test
oops. something went wrong! :(
```

### Disassembly of Function main()
Use radare2 to disassemble function *main* of module.wow (output is additionally commented with ;;)
```assembly
r2 -q -c "aaa; pd 76 @ main" module.wow 
Warning: run r2 with -e io.cache=true to fix relocations in disassembly
            ; DATA XREF from entry0 @ 0x1101
┌ 358: int main (uint32_t argc, char **argv);
│           ; var char **var_b0h @ rbp-0xb0
│           ; var uint32_t var_a4h @ rbp-0xa4
│           ; var struct sigaction *act @ rbp-0xa0
│           ; var int64_t var_18h @ rbp-0x18
│           ; var int64_t canary @ rbp-0x8
│           ; arg uint32_t argc @ rdi
│           ; arg char **argv @ rsi
│           0x000012fa      55             push rbp
│           0x000012fb      4889e5         mov rbp, rsp
│           0x000012fe      4881ecb00000.  sub rsp, 0xb0
│           0x00001305      89bd5cffffff   mov dword [var_a4h], edi    ; argc
│           0x0000130b      4889b550ffff.  mov qword [var_b0h], rsi    ; argv
│           0x00001312      64488b042528.  mov rax, qword fs:[0x28]
│           0x0000131b      488945f8       mov qword [canary], rax
│           0x0000131f      31c0           xor eax, eax
│           0x00001321      83bd5cffffff.  cmp dword [var_a4h], 2
│       ┌─< 0x00001328      7428           je 0x1352
│       │   0x0000132a      488b8550ffff.  mov rax, qword [var_b0h]
│       │   0x00001331      488b00         mov rax, qword [rax]
│       │   0x00001334      4889c6         mov rsi, rax
│       │   0x00001337      488d3dfb0c00.  lea rdi, str.Usage:__s__string__n ; 0x2039 ; "Usage: %s <string>\n" ; const char *format
│       │   0x0000133e      b800000000     mov eax, 0
│       │   0x00001343      e848fdffff     call sym.imp.printf         ; int printf(const char *format)
│       │   0x00001348      b8ffffffff     mov eax, 0xffffffff         ; -1
│      ┌──< 0x0000134d      e9f8000000     jmp 0x144a
│      ││   ; CODE XREF from main @ 0x1328
│      │└─> 0x00001352      488d8560ffff.  lea rax, [act]
│      │    0x00001359      4883c008       add rax, 8
│      │    0x0000135d      4889c7         mov rdi, rax
│      │    0x00001360      e83bfdffff     call sym.imp.sigemptyset
│      │    0x00001365      488d056dfeff.  lea rax, [sym.sighandler]   ; 0x11d9
│      │    0x0000136c      48898560ffff.  mov qword [act], rax
│      │    0x00001373      c745e8000000.  mov dword [var_18h], 0x40000000
│      │    0x0000137a      488d8560ffff.  lea rax, [act]
│      │    0x00001381      ba00000000     mov edx, 0                  ; struct sigaction *oldact
│      │    0x00001386      4889c6         mov rsi, rax                ; const struct sigaction *act
│      │    0x00001389      bf0b000000     mov edi, 0xb                ; int signum
│      │    0x0000138e      e8bdfcffff     call sym.imp.sigaction      ; int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
│      │    0x00001393      83f8ff         cmp eax, 0xffffffff
│      │┌─< 0x00001396      750c           jne 0x13a4
│      ││   0x00001398      488d3db10c00.  lea rdi, str.____setup_handler_for_SIGSEGV_failed ; 0x2050 ; "[!] setup handler for SIGSEGV failed" ; const char *s
│      ││   0x0000139f      e81cfdffff     call sym.imp.perror         ; void perror(const char *s)
│      ││   ; CODE XREF from main @ 0x1396
│      │└─> 0x000013a4      488d8560ffff.  lea rax, [act]
│      │    0x000013ab      ba00000000     mov edx, 0                  ; struct sigaction *oldact
│      │    0x000013b0      4889c6         mov rsi, rax                ; const struct sigaction *act
│      │    0x000013b3      bf07000000     mov edi, 7                  ; int signum
│      │    0x000013b8      e893fcffff     call sym.imp.sigaction      ; int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
│      │    0x000013bd      83f8ff         cmp eax, 0xffffffff
│      │┌─< 0x000013c0      750c           jne 0x13ce
│      ││   0x000013c2      488d3daf0c00.  lea rdi, str.____setup_handlerfor_SIGBUS_failed ; 0x2078 ; "[!] setup handlerfor SIGBUS failed" ; const char *s
│      ││   0x000013c9      e8f2fcffff     call sym.imp.perror         ; void perror(const char *s)
│      ││   ; CODE XREF from main @ 0x13c0
│      │└─> 0x000013ce      488d8560ffff.  lea rax, [act]
│      │    0x000013d5      ba00000000     mov edx, 0                  ; struct sigaction *oldact
│      │    0x000013da      4889c6         mov rsi, rax                ; const struct sigaction *act
│      │    0x000013dd      bf08000000     mov edi, 8                  ; int signum
│      │    0x000013e2      e869fcffff     call sym.imp.sigaction      ; int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
│      │    0x000013e7      83f8ff         cmp eax, 0xffffffff
│      │┌─< 0x000013ea      750c           jne 0x13f8
│      ││   0x000013ec      488d3dad0c00.  lea rdi, str.____setup_handler_for_SIGFPE_failed ; 0x20a0 ; "[!] setup handler for SIGFPE failed" ; const char *s
│      ││   0x000013f3      e8c8fcffff     call sym.imp.perror         ; void perror(const char *s)
│      ││   ; CODE XREF from main @ 0x13ea
│      │└─> 0x000013f8      488d8560ffff.  lea rax, [act]
│      │    0x000013ff      ba00000000     mov edx, 0                  ; struct sigaction *oldact
│      │    0x00001404      4889c6         mov rsi, rax                ; const struct sigaction *act
│      │    0x00001407      bf04000000     mov edi, 4                  ; int signum
│      │    0x0000140c      e83ffcffff     call sym.imp.sigaction      ; int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
│      │    0x00001411      83f8ff         cmp eax, 0xffffffff
│      │    0x00001414      750c           jne 0x1422
│      │    0x00001416      488d3dab0c00.  lea rdi, str.____setup_handler_for_SIGILL_failed ; 0x20c8 ; "[!] setup handler for SIGILL failed" ; const char *s
│      │    0x0000141d      e81efcffff     call sym.imp.puts           ; int puts(const char *s)
│      │    ; CODE XREF from main @ 0x1414
│      │    0x00001422      488b8550ffff.  mov rax, qword [var_b0h]  ;; argv[0] / **argv
│      │    0x00001429      4883c008       add rax, 8
│      │    0x0000142d      488b00         mov rax, qword [rax]  ;; argv[1]
│      │    0x00001430      8b152e2d0000   mov edx, dword [obj.code_enc_len] ; [0x4164:4]=196
│      │    0x00001436      89d1           mov ecx, edx
│      │    0x00001438      4889c2         mov rdx, rax
│      │    0x0000143b      4889ce         mov rsi, rcx
│      │    0x0000143e      488d3d5b2c00.  lea rdi, obj.code_enc       ; 0x40a0
│      │    0x00001445      e8b0fdffff     call sym.execute  ;; execute(code_enc, code_enc_len, argv[1])
│      │    ; CODE XREF from main @ 0x134d
│      └──> 0x0000144a      488b4df8       mov rcx, qword [canary]
│           0x0000144e      64482b0c2528.  sub rcx, qword fs:[0x28]
│           0x00001457      7405           je 0x145e
│           0x00001459      e812fcffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│           ; CODE XREF from main @ 0x1457
│           0x0000145e      c9             leave
└           0x0000145f      c3             ret
```

### What is code_enc with code_enc_len = 196?
Dump 196 bytes of data *code_enc*
```objdump
r2 -q -c "aaa; x 196 @ obj.code_enc" module.wow 
Warning: run r2 with -e io.cache=true to fix relocations in disassembly
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x000040a0  161b f286 3afa 9c64 78d6 1c96 7ce7 3c8b  ....:..dx...|.<.                                                                                                                                        
0x000040b0  79fa 98d8 435f 6330 edf4 9543 537b 6327  y...C_c0...CS{c'
0x000040c0  31f9 9178 dc8d 7ebd 1185 f874 8f17 a826  1..x..~....t...&
0x000040d0  d6a4 78a3 f341 4353 7b6c 77f2 3588 b998  ..x..ACS{lw.5...
0x000040e0  89b4 cb93 8626 79fa ba78 edb3 4378 ed4e  .....&y..x..Cx.N
0x000040f0  9584 1687 6372 7970 3cbb 1a89 26bd 2989  ....cryp<...&.).
0x00004100  9838 f01a cc6f 17e0 7594 3235 c816 8b6c  .8...o..u.25...l
0x00004110  c479 f4b4 45b3 ea3b c824 f236 d93b d6f6  .y..E..;.$.6.;..
0x00004120  d15e 6330 64db 7f43 537b aab1 2c38 fdd5  .^c0d..CS{..,8..
0x00004130  d61c 827c e50c 93b8 26b7 bb2b b32b a82c  ...|....&..+.+.,
0x00004140  baba 0bd8 3e83 3af0 b6ff 75b7 29f6 7ce5  ....>.:...u.).|.
0x00004150  bb3b f6b3 5e30 6e5f 6c35 edf3 f406 aff0  .;..^0n_l5......
0x00004160  268e 24b3                                &.$.
```

### Disassembly of Function execute()
Use radare2 to disassemble function *execute* of module.wow (output is additionally commented with ;;)
```assembly
r2 -q -c "aaa; pd 68 @ sym.execute" module.wow 
Warning: run r2 with -e io.cache=true to fix relocations in disassembly
            ; CALL XREF from main @ 0x1445
┌ 256: sym.execute (size_t arg1, size_t arg2, char *arg3);
│           ; var char *s @ rbp-0x38
│           ; var size_t length @ rbp-0x30
│           ; var size_t s2 @ rbp-0x28
│           ; var size_t var_20h @ rbp-0x20
│           ; var size_t addr @ rbp-0x18
│           ; var int64_t var_8h @ rbp-0x8
│           ; arg size_t arg1 @ rdi
│           ; arg size_t arg2 @ rsi
│           ; arg char *arg3 @ rdx
│           0x000011fa      55             push rbp
│           0x000011fb      4889e5         mov rbp, rsp
│           0x000011fe      53             push rbx
│           0x000011ff      4883ec38       sub rsp, 0x38
│           0x00001203      48897dd8       mov qword [s2], rdi         ; arg1
│           0x00001207      488975d0       mov qword [length], rsi     ; arg2
│           0x0000120b      488955c8       mov qword [s], rdx          ; arg3
│           0x0000120f      488b45d0       mov rax, qword [length]
│           0x00001213      41b900000000   mov r9d, 0                  ; size_t offset
│           0x00001219      41b8ffffffff   mov r8d, 0xffffffff         ; -1 ; int fd
│           0x0000121f      b922000000     mov ecx, 0x22               ; '"' ; int flags
│           0x00001224      ba07000000     mov edx, 7                  ; int prot
│           0x00001229      4889c6         mov rsi, rax                ; size_t length
│           0x0000122c      bf00000000     mov edi, 0                  ; void*addr
│           0x00001231      e84afeffff     call sym.imp.mmap           ; void*mmap(void*addr, size_t length, int prot, int flags, int fd, size_t offset)
│           0x00001236      488945e8       mov qword [addr], rax
│           0x0000123a      48837de8ff     cmp qword [addr], 0xffffffffffffffff
│       ┌─< 0x0000123f      7516           jne 0x1257
│       │   0x00001241      488d3ddf0d00.  lea rdi, str.____mmap___failed ; 0x2027 ; "[!] mmap() failed" ; const char *s
│       │   0x00001248      e873feffff     call sym.imp.perror         ; void perror(const char *s)
│       │   0x0000124d      b8ffffffff     mov eax, 0xffffffff         ; -1
│      ┌──< 0x00001252      e99d000000     jmp 0x12f4
│      ││   ; CODE XREF from sym.execute @ 0x123f
│      │└─> 0x00001257      488b55d0       mov rdx, qword [length]     ; size_t n
│      │    0x0000125b      488b4dd8       mov rcx, qword [s2]
│      │    0x0000125f      488b45e8       mov rax, qword [addr]
│      │    0x00001263      4889ce         mov rsi, rcx                ; const void *s2
│      │    0x00001266      4889c7         mov rdi, rax                ; void *s1
│      │    0x00001269      e8c2fdffff     call sym.imp.memcpy         ; void *memcpy(void *s1, const void *s2, size_t n)
│      │    0x0000126e      48c745e00000.  mov qword [var_20h], 0
│      │┌─< 0x00001276      eb4d           jmp 0x12c5
│      ││   ; CODE XREF from sym.execute @ 0x12cd
│     ┌───> 0x00001278      488b55e8       mov rdx, qword [addr]
│     ╎││   0x0000127c      488b45e0       mov rax, qword [var_20h]
│     ╎││   0x00001280      4801d0         add rax, rdx
│     ╎││   0x00001283      0fb618         movzx ebx, byte [rax]
│     ╎││   0x00001286      488b45c8       mov rax, qword [s]
│     ╎││   0x0000128a      4889c7         mov rdi, rax                ; const char *s
│     ╎││   0x0000128d      e8cefdffff     call sym.imp.strlen         ; size_t strlen(const char *s)
│     ╎││   0x00001292      4889c6         mov rsi, rax
│     ╎││   0x00001295      488b45e0       mov rax, qword [var_20h]
│     ╎││   0x00001299      ba00000000     mov edx, 0
│     ╎││   0x0000129e      48f7f6         div rsi
│     ╎││   0x000012a1      4889d1         mov rcx, rdx
│     ╎││   0x000012a4      4889ca         mov rdx, rcx
│     ╎││   0x000012a7      488b45c8       mov rax, qword [s]
│     ╎││   0x000012ab      4801d0         add rax, rdx
│     ╎││   0x000012ae      0fb610         movzx edx, byte [rax]
│     ╎││   0x000012b1      488b4de8       mov rcx, qword [addr]
│     ╎││   0x000012b5      488b45e0       mov rax, qword [var_20h]
│     ╎││   0x000012b9      4801c8         add rax, rcx
│     ╎││   0x000012bc      31da           xor edx, ebx
│     ╎││   0x000012be      8810           mov byte [rax], dl
│     ╎││   0x000012c0      488345e001     add qword [var_20h], 1
│     ╎││   ; CODE XREF from sym.execute @ 0x1276
│     ╎│└─> 0x000012c5      488b45e0       mov rax, qword [var_20h]
│     ╎│    0x000012c9      483b45d0       cmp rax, qword [length]
│     └───< 0x000012cd      72a9           jb 0x1278
│      │    0x000012cf      488b55e8       mov rdx, qword [addr]
│      │    0x000012d3      488b45c8       mov rax, qword [s]
│      │    0x000012d7      4889c7         mov rdi, rax
│      │    0x000012da      ffd2           call rdx
│      │    0x000012dc      488b55d0       mov rdx, qword [length]
│      │    0x000012e0      488b45e8       mov rax, qword [addr]
│      │    0x000012e4      4889d6         mov rsi, rdx                ; size_t length
│      │    0x000012e7      4889c7         mov rdi, rax                ; void*addr
│      │    0x000012ea      e8c1fdffff     call sym.imp.munmap         ; int munmap(void*addr, size_t length)
│      │    0x000012ef      b800000000     mov eax, 0
│      │    ; CODE XREF from sym.execute @ 0x1252
│      └──> 0x000012f4      488b5df8       mov rbx, qword [var_8h]
│           0x000012f8      c9             leave
└           0x000012f9      c3             ret
```



```



