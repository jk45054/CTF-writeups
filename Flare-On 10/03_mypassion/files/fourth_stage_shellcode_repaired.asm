0000 65 48 8B 04 25 60 00 00 mov     rax, gs:TEB.ProcessEnvironmentBlock
0000 00
0009 48 8B 48 18             mov     rcx, [rax+PEB.Ldr]
000D 48 8B 51 20             mov     rdx, [rcx+_PEB_LDR_DATA.InMemoryOrderModuleList.Flink]
0011 48 83 EA 10             sub     rdx, 10h                        ; 0x10 bytes ahead in PEB_LDR_DATA struct is pointer to InLoadOrderModuleList
0015
0015                         check_list_entry:                       ; CODE XREF: debug053:000002D2114D005B↓j
0015 48 8B 42 60             mov     rax, [rdx+LDR_DATA_TABLE_ENTRY.BaseDllName.Buffer] ; first entry is L"mypassion.exe", then ntdll, then kernel32
0019 66 83 78 10 2E          cmp     word ptr [rax+10h], 2Eh ; '.'
001E 75 2E                   jnz     short skip_this_entry
0020 66 83 78 0E 32          cmp     word ptr [rax+0Eh], 32h ; '2'
0025 75 27                   jnz     short skip_this_entry
0027 66 83 78 0C 33          cmp     word ptr [rax+0Ch], 33h ; '3'
002C 75 20                   jnz     short skip_this_entry
002E 66 83 78 0A 4C          cmp     word ptr [rax+0Ah], 4Ch ; 'L'
0033 74 07                   jz      short match
0035 66 6D                   insw
0037 78 08                   js      short near ptr loc_2D2114D0040+1
0039 6C                      insb
003A 75 12                   jnz     short skip_this_entry
003C
003C                         match:                                  ; CODE XREF: debug053:000002D2114D0033↑j
003C 0F B7 40 08             movzx   eax, word ptr [rax+8]           ; get fourth wchar from Buffer, here L"E"
0040
0040                         loc_2D2114D0040:                        ; CODE XREF: debug053:000002D2114D0037↑j
0040 B9 DF FF 00 00          mov     ecx, 0FFDFh
0045 66 83 E8 45             sub     ax, 45h ; 'E'
0049 66 85 C1                test    cx, ax                          ; test = and, with 0x0000 and 0xFFDF = 0x0000
004C 74 12                   jz      short exit_success
004E
004E                         skip_this_entry:                        ; CODE XREF: debug053:000002D2114D001E↑j
004E                                                                 ; debug053:000002D2114D0025↑j ...
004E 48 8B 52 10             mov     rdx, [rdx+LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks.Flink] ; move flink
0052 48 83 EA 10             sub     rdx, 10h                        ; rdx = InLoadOrderModuleList
0056 48 83 7A 30 00          cmp     [rdx+LDR_DATA_TABLE_ENTRY.DllBase], 0 ; are we at the last entry already?
005B 75 B8                   jnz     short check_list_entry          ; if not, check current entry
005D 33 C0                   xor     eax, eax
005F C3                      retn
0060                         ; ---------------------------------------------------------------------------
0060
0060                         exit_success:                           ; CODE XREF: debug053:000002D2114D004C↑j
0060 48 8B 42 30             mov     rax, [rdx+LDR_DATA_TABLE_ENTRY.DllBase]
0064 C3                      retn