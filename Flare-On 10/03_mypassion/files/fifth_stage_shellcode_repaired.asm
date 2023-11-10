0000 48 89 5C 24 08          mov     [rsp+8], rbx
0005 48 89 7C 24 18          mov     [rsp+18h], rdi
000A 48 89 54 24 10          mov     [rsp+10h], rdx                  ; char * of API name to locate, "Beep"
000F 4C 8B C1                mov     r8, rcx
0012 48 85 C9                test    rcx, rcx                        ; VA of kernel32.dll
0015 74 63                   jz      short exit_fail
0017 B8 4D 5A 00 00          mov     eax, 'ZM'
001C 66 39 01                cmp     [rcx+IMAGE_DOS_HEADER.e_magic], ax
001F 75 59                   jnz     short exit_fail
0021 48 63 41 3C             movsxd  rax, [rcx+IMAGE_DOS_HEADER.e_lfanew]
0025 81 3C 08 50 45 00 00    cmp     [rax+rcx+IMAGE_NT_HEADERS.Signature], 'EP'
002C 75 4C                   jnz     short exit_fail
002E 44 8B 8C 08 88 00 00 00 mov     r9d, [rax+rcx+IMAGE_NT_HEADERS.OptionalHeader.DataDirectory.VirtualAddress] ; RVA export dir
0036 4C 03 C9                add     r9, rcx                         ; VA export dir
0039 45 8B 59 20             mov     r11d, [r9+IMAGE_EXPORT_DIRECTORY.AddressOfNames]
003D 4C 03 D9                add     r11, rcx                        ; VA of AddressOfNames
0040 33 C9                   xor     ecx, ecx
0042 41 39 49 18             cmp     [r9+IMAGE_EXPORT_DIRECTORY.NumberOfNames], ecx
0046 76 32                   jbe     short exit_fail
0048
0048                         try_next_export_name:                   ; CODE XREF: debug050:0000025943A40078↓j
0048 41 8B 04 8B             mov     eax, [r11+rcx*4]                ; RVA current export name
004C 48 8B 5C 24 10          mov     rbx, [rsp+10h]                  ; rbx = char * "Beep"
0051 49 03 C0                add     rax, r8                         ; VA of current export name
0054 48 2B D8                sub     rbx, rax
0057 8B F9                   mov     edi, ecx
0059
0059                         compare_next_char:                      ; CODE XREF: debug050:0000025943A4006C↓j
0059 0F B6 10                movzx   edx, byte ptr [rax]
005C 44 0F B6 14 18          movzx   r10d, byte ptr [rax+rbx]
0061 41 2B D2                sub     edx, r10d
0064 75 08                   jnz     short test_match
0066 48 FF C0                inc     rax                             ; next char in current name comparison
0069 45 85 D2                test    r10d, r10d                      ; hit null terminator?
006C 75 EB                   jnz     short compare_next_char
006E
006E                         test_match:                             ; CODE XREF: debug050:0000025943A40064↑j
006E 85 D2                   test    edx, edx
0070 74 15                   jz      short got_match
0072 FF C1                   inc     ecx                             ; increase counter for looping AddressOfNames
0074 41 3B 49 18             cmp     ecx, [r9+IMAGE_EXPORT_DIRECTORY.NumberOfNames] ; is there still something left?
0078 72 CE                   jb      short try_next_export_name
007A
007A                         exit_fail:                              ; CODE XREF: debug050:0000025943A40015↑j
007A                                                                 ; debug050:0000025943A4001F↑j ...
007A 33 C0                   xor     eax, eax
007C
007C                         exit_func:                              ; CODE XREF: debug050:0000025943A4009F↓j
007C 48 8B 5C 24 08          mov     rbx, [rsp+8]
0081 48 8B 7C 24 18          mov     rdi, [rsp+18h]
0086 C3                      retn
0087                         ; ---------------------------------------------------------------------------
0087
0087                         got_match:                              ; CODE XREF: debug050:0000025943A40070↑j
0087 41 8B 49 24             mov     ecx, [r9+IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals] ; RVA AddressOfNameOrdinals
008B 49 03 C8                add     rcx, r8                         ; VA of AddressOfOrdinals
008E 0F B7 14 79             movzx   edx, word ptr [rcx+rdi*2]       ; edx = ordinal as index into AddressOfFunctions
0092 41 8B 49 1C             mov     ecx, [r9+IMAGE_EXPORT_DIRECTORY.AddressOfFunctions]
0096 49 03 C8                add     rcx, r8                         ; VA of AddressOfFunctions
0099 8B 04 91                mov     eax, [rcx+rdx*4]                ; RVA of target export function
009C 49 03 C0                add     rax, r8                         ; VA of target export function
009F EB DB                   jmp     short exit_func