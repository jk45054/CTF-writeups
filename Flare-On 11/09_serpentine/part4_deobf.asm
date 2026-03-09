0x356E6B: 49BCDF72C21B01000000             mov     r12, 11BC272DFh
0x356EDC: 4981C40946C724                   add     r12, 24C74609h
0x047711: 498B5128                         mov     rdx, [r9+28h]
0x356FB0: 488BB280000000                   mov     rsi, [rdx+80h]
0x04771C: 480FB6F6                         movzx   rsi, sil
0x047803: 4D8B4128                         mov     r8, [r9+28h]
0x357083: 498B80A8000000                   mov     rax, [r8+0A8h]
0x3570EC: 49C7C4FD7084CC                   mov     r12, 0FFFFFFFFCC8470FDh
0x357159: 4981C4A76CE333                   add     r12, 33E36CA7h
0x04781C: 4154                             push    r12
0x04781E: 48F72424                         mul     qword ptr [rsp]
0x047822: 4889C3                           mov     rbx, rax
0x047906: 498B6928                         mov     rbp, [r9+28h]
0x357224: 488B8590000000                   mov     rax, [rbp+90h]
0x047911: 50                               push    rax
0x047912: 4989E5                           mov     r13, rsp
0x35728E: 4C8BB590000000                   mov     r14, [rbp+90h]
0x047A07: 4D8B7928                         mov     r15, [r9+28h]
0x357360: 498B8FE0000000                   mov     rcx, [r15+0E0h]
0x3573C8: 4D8BAFE8000000                   mov     r13, [r15+0E8h]
0x047A19: 51                               push    rcx
0x047A1A: 68BF3CF422                       push    22F43CBFh
0x047A1F: 680D72080C                       push    0C08720Dh
0x047A24: 68F3428F7F                       push    7F8F42F3h
0x047A29: 68405E0B55                       push    550B5E40h
0x047B1B: 498B6928                         mov     rbp, [r9+28h]
0x35749A: 4C8BADA8000000                   mov     r13, [rbp+0A8h]
0x357503: 4C8BBDE0000000                   mov     r15, [rbp+0E0h]
0x047B2D: 4D0FB6ED                         movzx   r13, r13b
0x047C0B: 498B7128                         mov     rsi, [r9+28h]
0x3575D0: 0FAE96E0000000                   ldmxcsr dword ptr [rsi+0E0h]
0x357638: 49BBDFEE4AEA00000000             mov     r11, 0EA4AEEDFh
0x3576A1: 4981C3E173BE55                   add     r11, 55BE73E1h
0x35770F: 4D8B9BE0070000                   mov     r11, [r11+7E0h]
0x357774: 4C039EE0000000                   add     r11, [rsi+0E0h]
0x047C35: 418A0B                           mov     cl, [r11]
0x047C38: 480FB6C9                         movzx   rcx, cl
0x047C3C: 48C1E108                         shl     rcx, 8
0x3577DA: 48018EF0000000                   add     [rsi+0F0h], rcx
0x357842: 49BFFF3390D100000000             mov     r15, 0D19033FFh
0x047C51: 4157                             push    r15
0x047C53: 68DA739056                       push    569073DAh
0x047C58: 688F7C1B6C                       push    6C1B7C8Fh
0x047C5D: 680D55EA1E                       push    1EEA550Dh
0x047C62: 681C73202F                       push    2F20731Ch
0x3578AA: 4881442420C126796E               add     [rsp-8+arg_20], 6E7926C1h
0x047C70: 4D8B6928                         mov     r13, [r9+28h]
0x357914: 498BB5F0000000                   mov     rsi, [r13+0F0h]
0x047D68: 4D8B4128                         mov     r8, [r9+28h]
0x047D6C: 410FAE5034                       ldmxcsr dword ptr [r8+34h]
0x3579E8: 498BA8D8000000                   mov     rbp, [r8+0D8h]
0x357A51: 498BB0A8000000                   mov     rsi, [r8+0A8h]
0x047E5F: 4D8B5128                         mov     r10, [r9+28h]
0x357B1E: 4D8BBAA8000000                   mov     r15, [r10+0A8h]
0x047E6A: 458B4234                         mov     r8d, [r10+34h]
0x357B86: 4D0382A0000000                   add     r8, [r10+0A0h]
0x047E75: 418A18                           mov     bl, [r8]
0x047E78: 4188DF                           mov     r15b, bl
0x047F63: 4D8B5128                         mov     r10, [r9+28h]
0x357C56: 498BBAF0000000                   mov     rdi, [r10+0F0h]
0x047F6E: 57                               push    rdi
0x047F6F: 4889E6                           mov     rsi, rsp
0x357CC1: 4D8BA2F0000000                   mov     r12, [r10+0F0h]
0x04804F: 4D8B7128                         mov     r14, [r9+28h]
0x357D8E: 498B8EA8000000                   mov     rcx, [r14+0A8h]
0x357DF9: 498BB6D8000000                   mov     rsi, [r14+0D8h]
0x048061: 51                               push    rcx
0x048062: 682301D72B                       push    2BD70123h
0x048067: 68C12C2315                       push    15232CC1h
0x04806C: 681110B862                       push    62B81011h
0x04815B: 498B7128                         mov     rsi, [r9+28h]
0x357ECB: 4C8BBEA0000000                   mov     r15, [rsi+0A0h]
0x357F38: 488BAEA8000000                   mov     rbp, [rsi+0A8h]
0x04816D: 4D0FB6FF                         movzx   r15, r15b
0x048255: 4D8B5928                         mov     r11, [r9+28h]
0x358010: 410FAE93F0000000                 ldmxcsr dword ptr [r11+0F0h]
0x358077: 48BB4127D20701000000             mov     rbx, 107D22741h
0x3580E7: 4881C37F3B3738                   add     rbx, 38373B7Fh
0x358150: 488B9BD0010000                   mov     rbx, [rbx+1D0h]
0x3581BC: 49039BF0000000                   add     rbx, [r11+0F0h]
0x048280: 8A13                             mov     dl, [rbx]
0x048282: 480FB6D2                         movzx   rdx, dl
0x048286: 48C1E210                         shl     rdx, 10h
0x358221: 490193A0000000                   add     [r11+0A0h], rdx
0x048291: 4D8B6928                         mov     r13, [r9+28h]
0x35828A: 498BB5A0000000                   mov     rsi, [r13+0A0h]
0x3582F0: 49BC483AC4C500000000             mov     r12, 0C5C43A48h
0x358359: 4981C47820457A                   add     r12, 7A452078h
0x048384: 498B4928                         mov     rcx, [r9+28h]
0x048388: 0FAE5134                         ldmxcsr dword ptr [rcx+34h]
0x35842D: 488BA990000000                   mov     rbp, [rcx+90h]
0x358492: 488BB1A8000000                   mov     rsi, [rcx+0A8h]
0x04847B: 498B4128                         mov     rax, [r9+28h]
0x358563: 4C8BB8A8000000                   mov     r15, [rax+0A8h]
0x048486: 448B6834                         mov     r13d, [rax+34h]
0x3585CB: 4C03A8A0000000                   add     r13, [rax+0A0h]
0x048491: 458A4500                         mov     r8b, [r13+0]
0x358632: 48C7C2FF000000                   mov     rdx, 0FFh
0x04849C: 48C1E208                         shl     rdx, 8
0x0484A0: 48F7D2                           not     rdx
0x0484A3: 4921D7                           and     r15, rdx
0x0484A6: 490FB6D0                         movzx   rdx, r8b
0x0484AA: 48C1E208                         shl     rdx, 8
0x0484AE: 4909D7                           or      r15, rdx
0x048595: 498B6928                         mov     rbp, [r9+28h]
0x358700: 488BB5F0000000                   mov     rsi, [rbp+0F0h]
0x0485A0: 56                               push    rsi
0x0485A1: 4989E4                           mov     r12, rsp
0x358765: 488BADF0000000                   mov     rbp, [rbp+0F0h]
0x0486A1: 4D8B5128                         mov     r10, [r9+28h]
0x358838: 498BB2C0000000                   mov     rsi, [r10+0C0h]
0x3588A5: 4D8BBAA0000000                   mov     r15, [r10+0A0h]
0x0486B3: 480FB6F6                         movzx   rsi, sil
0x0487A1: 498B5128                         mov     rdx, [r9+28h]
0x358972: 0FAE92A8000000                   ldmxcsr dword ptr [rdx+0A8h]
0x3589DA: 49BF430FE71401000000             mov     r15, 114E70F43h
0x358A4A: 4981C77D53222B                   add     r15, 2B22537Dh
0x358AB5: 4D8BBFA8030000                   mov     r15, [r15+3A8h]
0x358B1E: 4C03BAA8000000                   add     r15, [rdx+0A8h]
0x0487CB: 418A0F                           mov     cl, [r15]
0x0487CE: 480FB6C9                         movzx   rcx, cl
0x0487D2: 48C1E118                         shl     rcx, 18h
0x358B87: 48018AF0000000                   add     [rdx+0F0h], rcx
0x358BF5: 49B81FF961E100000000             mov     r8, 0E161F91Fh
0x0487E7: 4150                             push    r8
0x0487E9: 685761B032                       push    32B06157h
0x0487EE: 68571E7E38                       push    387E1E57h
0x0487F3: 68241E8E2E                       push    2E8E1E24h
0x358C64: 4881442418A161A75E               add     qword ptr [rsp+18h], 5EA761A1h
0x048801: 4D8B6928                         mov     r13, [r9+28h]
0x358CD2: 4D8BADF0000000                   mov     r13, [r13+0F0h]
0x0488E9: 498B4928                         mov     rcx, [r9+28h]
0x0488ED: 0FAE5134                         ldmxcsr dword ptr [rcx+34h]
0x358D9B: 4C8BA1D8000000                   mov     r12, [rcx+0D8h]
0x358E02: 488BB1E0000000                   mov     rsi, [rcx+0E0h]
0x0489CD: 498B4928                         mov     rcx, [r9+28h]
0x358ED6: 488BB1A8000000                   mov     rsi, [rcx+0A8h]
0x0489D8: 448B4934                         mov     r9d, [rcx+34h]
0x358F40: 4C0389D8000000                   add     r9, [rcx+0D8h]
0x0489E3: 418A11                           mov     dl, [r9]
0x358FA6: 49C7C6FF000000                   mov     r14, 0FFh
0x0489ED: 49C1E610                         shl     r14, 10h
0x0489F1: 49F7D6                           not     r14
0x0489F4: 4C21F6                           and     rsi, r14
0x0489F7: 4C0FB6F2                         movzx   r14, dl
0x0489FB: 49C1E610                         shl     r14, 10h
0x0489FF: 4C09F6                           or      rsi, r14
0x048AF0: 498B5128                         mov     rdx, [r9+28h]
0x359075: 488BBAA8000000                   mov     rdi, [rdx+0A8h]
0x048AFB: 57                               push    rdi
0x048AFC: 4889E6                           mov     rsi, rsp
0x3590DA: 4C8BB2A8000000                   mov     r14, [rdx+0A8h]
0x048BF9: 498B6928                         mov     rbp, [r9+28h]
0x3591A9: 4C8BADD8000000                   mov     r13, [rbp+0D8h]
0x359211: 488BBDE8000000                   mov     rdi, [rbp+0E8h]
0x048C0B: 4D0FB6ED                         movzx   r13, r13b
0x048CF8: 4D8B7928                         mov     r15, [r9+28h]
0x3592E2: 410FAE97E0000000                 ldmxcsr dword ptr [r15+0E0h]
0x35934D: 49BCB20235FE00000000             mov     r12, 0FE3502B2h
0x3593B5: 4981C40E60D441                   add     r12, 41D4600Eh
0x359421: 4D8BA424A0070000                 mov     r12, [r12+7A0h]
0x359488: 4D03A7E0000000                   add     r12, [r15+0E0h]
0x048D24: 418A3C24                         mov     dil, [r12]
0x048D28: 480FB6FF                         movzx   rdi, dil
0x048D2C: 48C1E720                         shl     rdi, 20h
0x3594F2: 4901BFB0000000                   add     [r15+0B0h], rdi
0x048D37: 4D8B4928                         mov     r9, [r9+28h]
0x35955F: 498B99B0000000                   mov     rbx, [r9+0B0h]
0x3595C9: 49BE8B1A29C900000000             mov     r14, 0C9291A8Bh
0x359638: 4981C63540E076                   add     r14, 76E04035h
0x048E47: 4D8B5128                         mov     r10, [r9+28h]
0x048E4B: 410FAE5234                       ldmxcsr dword ptr [r10+34h]
0x359711: 4D8BA288000000                   mov     r12, [r10+88h]
0x35977F: 4D8BB290000000                   mov     r14, [r10+90h]
0x048F46: 4D8B6128                         mov     r12, [r9+28h]
0x35984E: 498BB424E8000000                 mov     rsi, [r12+0E8h]
0x048F52: 458B542434                       mov     r10d, [r12+34h]
0x3598B7: 4D039424D8000000                 add     r10, [r12+0D8h]
0x048F5F: 418A2A                           mov     bpl, [r10]
0x359922: 49C7C3FF000000                   mov     r11, 0FFh
0x048F69: 49C1E318                         shl     r11, 18h
0x048F6D: 49F7D3                           not     r11
0x048F70: 4C21DE                           and     rsi, r11
0x048F73: 4C0FB6DD                         movzx   r11, bpl
0x048F77: 49C1E318                         shl     r11, 18h
0x048F7B: 4C09DE                           or      rsi, r11
0x049067: 4D8B5128                         mov     r10, [r9+28h]
0x3599EF: 498B92A8000000                   mov     rdx, [r10+0A8h]
0x049072: 52                               push    rdx
0x049073: 4989E7                           mov     r15, rsp
0x359A5A: 498BB2A8000000                   mov     rsi, [r10+0A8h]
0x049155: 4D8B6928                         mov     r13, [r9+28h]
0x359B2F: 498B85F0000000                   mov     rax, [r13+0F0h]
0x359B97: 498BADA8000000                   mov     rbp, [r13+0A8h]
0x049167: 50                               push    rax
0x049168: 683115C71A                       push    1AC71531h
0x04916D: 682849CA44                       push    44CA4928h
0x049172: 680231B134                       push    34B13102h
0x049266: 498B4928                         mov     rcx, [r9+28h]
0x359C69: 488BB980000000                   mov     rdi, [rcx+80h]
0x359CD4: 4C8BB1A0000000                   mov     r14, [rcx+0A0h]
0x049278: 480FB6FF                         movzx   rdi, dil
0x04935B: 4D8B7128                         mov     r14, [r9+28h]
0x359DAC: 410FAE96B0000000                 ldmxcsr dword ptr [r14+0B0h]
0x359E12: 48B870EF6A1501000000             mov     rax, 1156AEF70h
0x359E7B: 480550739E2A                     add     rax, 2A9E7350h
0x049377: 488B00                           mov     rax, [rax]
0x359EE6: 490386B0000000                   add     rax, [r14+0B0h]
0x049381: 408A38                           mov     dil, [rax]
0x049384: 480FB6FF                         movzx   rdi, dil
0x049388: 48C1E728                         shl     rdi, 28h
0x359F54: 4901BEE8000000                   add     [r14+0E8h], rdi
0x359FC2: 49BE32E8230501000000             mov     r14, 10523E832h
0x04939D: 4156                             push    r14
0x04939F: 6839182501                       push    1251839h
0x0493A4: 68DA17BE22                       push    22BE17DAh
0x0493A9: 68BD0AAE17                       push    17AE0ABDh
0x0493AE: 68D315EF54                       push    54EF15D3h
0x35A02F: 48814424208E72E53A               add     [rsp-8+arg_20], 3AE5728Eh
0x0493BC: 4D8B7128                         mov     r14, [r9+28h]
0x35A09A: 498BAEE8000000                   mov     rbp, [r14+0E8h]
0x0494C3: 4D8B6928                         mov     r13, [r9+28h]
0x0494C7: 410FAE5534                       ldmxcsr dword ptr [r13+34h]
0x35A16D: 4D8BBD90000000                   mov     r15, [r13+90h]
0x35A1DA: 498BBDA0000000                   mov     rdi, [r13+0A0h]
0x0495BC: 4D8B5928                         mov     r11, [r9+28h]
0x35A2AD: 4D8BBBB0000000                   mov     r15, [r11+0B0h]
0x0495C7: 418B4334                         mov     eax, [r11+34h]
0x35A31B: 490383F0000000                   add     rax, [r11+0F0h]
0x0495D2: 448A10                           mov     r10b, [rax]
0x35A388: 49C7C0FF000000                   mov     r8, 0FFh
0x0495DC: 49C1E020                         shl     r8, 20h
0x0495E0: 49F7D0                           not     r8
0x0495E3: 4D21C7                           and     r15, r8
0x0495E6: 4D0FB6C2                         movzx   r8, r10b
0x0495EA: 49C1E020                         shl     r8, 20h
0x0495EE: 4D09C7                           or      r15, r8
0x0496D7: 4D8B5128                         mov     r10, [r9+28h]
0x35A456: 498BAAF0000000                   mov     rbp, [r10+0F0h]
0x35A4BE: 49BE7B62C21B01000000             mov     r14, 11BC2627Bh
0x35A52F: 4981C66D56C724                   add     r14, 24C7566Dh
0x0497E9: 498B7128                         mov     rsi, [r9+28h]
0x35A5FC: 4C8BBEC0000000                   mov     r15, [rsi+0C0h]
0x35A663: 488BBEA0000000                   mov     rdi, [rsi+0A0h]
0x0497FB: 4D0FB6FF                         movzx   r15, r15b
0x0498D6: 498B4928                         mov     rcx, [r9+28h]
0x35A736: 488B81F0000000                   mov     rax, [rcx+0F0h]
0x35A7A2: 49C7C17C436A9B                   mov     r9, 0FFFFFFFF9B6A437Ch
0x35A807: 4981C1E474F164                   add     r9, 64F174E4h
0x0498EF: 4151                             push    r9
0x35A874: 488BB1B0000000                   mov     rsi, [rcx+0B0h]
0x0498F8: 48F72424                         mul     qword ptr [rsp]
0x0498FC: 4889C5                           mov     rbp, rax
0x0499DF: 498B4128                         mov     rax, [r9+28h]
0x35A945: 488B98A8000000                   mov     rbx, [rax+0A8h]
0x35A9B0: 480398A0000000                   add     rbx, [rax+0A0h]
0x049AC0: 4D8B5128                         mov     r10, [r9+28h]
0x35AA83: 498B8A90000000                   mov     rcx, [r10+90h]
0x049ACB: 51                               push    rcx
0x049ACC: 4889E6                           mov     rsi, rsp
0x35AAEE: 4D8BB290000000                   mov     r14, [r10+90h]
0x049BBF: 4D8B5928                         mov     r11, [r9+28h]
0x35ABC2: 4D8B83A8000000                   mov     r8, [r11+0A8h]
0x35AC2C: 498B9BE8000000                   mov     rbx, [r11+0E8h]
0x049BD1: 4150                             push    r8
0x049BD3: 68EC1EFB33                       push    33FB1EECh
0x049BD8: 68B862762F                       push    2F7662B8h
0x049BDD: 684B16CC32                       push    32CC164Bh
0x049BE2: 6846218C70                       push    708C2146h
0x049CD0: 498B5928                         mov     rbx, [r9+28h]
0x35AD01: 4C8BB3D0000000                   mov     r14, [rbx+0D0h]
0x35AD6D: 4C8BBB90000000                   mov     r15, [rbx+90h]
0x049CE2: 4D0FB6F6                         movzx   r14, r14b
0x049DC8: 498B7128                         mov     rsi, [r9+28h]
0x35AE42: 0FAE96E8000000                   ldmxcsr dword ptr [rsi+0E8h]
0x049DD3: 4D8B4128                         mov     r8, [r9+28h]
0x35AEAC: 498BB0F0000000                   mov     rsi, [r8+0F0h]
0x35AF16: 49BFEFF8980701000000             mov     r15, 10798F8EFh
0x35AF84: 4981C7D1517038                   add     r15, 387051D1h
0x049EEC: 498B7928                         mov     rdi, [r9+28h]
0x049EF0: 0FAE5734                         ldmxcsr dword ptr [rdi+34h]
0x35B059: 4C8BA7E0000000                   mov     r12, [rdi+0E0h]
0x35B0C7: 4C8BAFA8000000                   mov     r13, [rdi+0A8h]
0x049FEC: 498B7128                         mov     rsi, [r9+28h]
0x35B19A: 4C8BBEE0000000                   mov     r15, [rsi+0E0h]
0x049FF7: 8B6E34                           mov     ebp, [rsi+34h]
0x35B201: 4803AED8000000                   add     rbp, [rsi+0D8h]
0x04A001: 8A5500                           mov     dl, [rbp+0]
0x04A004: 4188D7                           mov     r15b, dl
0x04A0ED: 4D8B5928                         mov     r11, [r9+28h]
0x35B2CE: 498BB3F0000000                   mov     rsi, [r11+0F0h]
0x04A0F8: 56                               push    rsi
0x04A0F9: 4889E5                           mov     rbp, rsp
0x35B337: 4D8BB3F0000000                   mov     r14, [r11+0F0h]
0x04A1E8: 4D8B6928                         mov     r13, [r9+28h]
0x35B404: 4D8BA5A8000000                   mov     r12, [r13+0A8h]
0x35B469: 4D8BBDE8000000                   mov     r15, [r13+0E8h]
0x04A1FA: 4D0FB6E4                         movzx   r12, r12b
0x04A2D6: 498B5928                         mov     rbx, [r9+28h]
0x35B53A: 0FAE93D8000000                   ldmxcsr dword ptr [rbx+0D8h]
0x35B5A6: 49B8473E702201000000             mov     r8, 122703E47h
0x04A2EB: 4150                             push    r8
0x04A2ED: 684A5BB540                       push    40B55B4Ah
0x04A2F2: 68EC1F1553                       push    53151FECh
0x04A2F7: 689F099F6E                       push    6E9F099Fh
0x04A2FC: 684C5E5B1E                       push    1E5B5E4Ch
0x35B60F: 4881442420790C991D               add     qword ptr [rsp+20h], 1D990C79h
0x04A30A: 498B7128                         mov     rsi, [r9+28h]
0x35B679: 4C8BBEF0000000                   mov     r15, [rsi+0F0h]
0x04A3F5: 498B5128                         mov     rdx, [r9+28h]
0x04A3F9: 0FAE5234                         ldmxcsr dword ptr [rdx+34h]
0x35B747: 4C8BAAB0000000                   mov     r13, [rdx+0B0h]
0x35B7B1: 4C8BBAF0000000                   mov     r15, [rdx+0F0h]
0x04A4E1: 498B4928                         mov     rcx, [r9+28h]
0x35B884: 488BA9F0000000                   mov     rbp, [rcx+0F0h]
0x04A4EC: 8B5134                           mov     edx, [rcx+34h]
0x35B8E9: 480391E0000000                   add     rdx, [rcx+0E0h]
0x04A4F6: 408A32                           mov     sil, [rdx]
0x35B955: 48C7C0FF000000                   mov     rax, 0FFh
0x04A500: 48C1E008                         shl     rax, 8
0x04A504: 48F7D0                           not     rax
0x04A507: 4821C5                           and     rbp, rax
0x04A50A: 480FB6C6                         movzx   rax, sil
0x04A50E: 48C1E008                         shl     rax, 8
0x04A512: 4809C5                           or      rbp, rax
0x04A608: 4D8B5928                         mov     r11, [r9+28h]
0x35BA24: 498B93A0000000                   mov     rdx, [r11+0A0h]
0x04A613: 52                               push    rdx
0x04A614: 4989E7                           mov     r15, rsp
0x35BA8F: 4D8BABA0000000                   mov     r13, [r11+0A0h]
0x04A70E: 4D8B6128                         mov     r12, [r9+28h]
0x35BB5C: 4D8BB424A0000000                 mov     r14, [r12+0A0h]
0x35BBC8: 498B9C24E0000000                 mov     rbx, [r12+0E0h]
0x04A722: 4D0FB6F6                         movzx   r14, r14b
0x04A810: 4D8B6128                         mov     r12, [r9+28h]
0x35BC9D: 410FAE9424E8000000               ldmxcsr dword ptr [r12+0E8h]
0x04A81D: 498B7928                         mov     rdi, [r9+28h]
0x35BD0C: 488BBF90000000                   mov     rdi, [rdi+90h]
0x35BD73: 48BD2631CC0401000000             mov     rbp, 104CC3126h
0x35BDE2: 4881C59A193D3B                   add     rbp, 3B3D199Ah
0x04A91C: 498B5128                         mov     rdx, [r9+28h]
0x04A920: 0FAE5234                         ldmxcsr dword ptr [rdx+34h]
0x35BEB4: 4C8BAAE8000000                   mov     r13, [rdx+0E8h]
0x35BF21: 488BB2B0000000                   mov     rsi, [rdx+0B0h]
0x04AA14: 4D8B7928                         mov     r15, [r9+28h]
0x35BFF0: 4D8BAFA8000000                   mov     r13, [r15+0A8h]
0x04AA1F: 418B5F34                         mov     ebx, [r15+34h]
0x35C056: 49039FE0000000                   add     rbx, [r15+0E0h]
0x04AA2A: 408A33                           mov     sil, [rbx]
0x35C0BC: 48C7C5FF000000                   mov     rbp, 0FFh
0x04AA34: 48C1E510                         shl     rbp, 10h
0x04AA38: 48F7D5                           not     rbp
0x04AA3B: 4921ED                           and     r13, rbp
0x04AA3E: 480FB6EE                         movzx   rbp, sil
0x04AA42: 48C1E510                         shl     rbp, 10h
0x04AA46: 4909ED                           or      r13, rbp
0x04AB25: 4D8B4128                         mov     r8, [r9+28h]
0x35C191: 498BB0E0000000                   mov     rsi, [r8+0E0h]
0x04AB30: 56                               push    rsi
0x04AB31: 4989E4                           mov     r12, rsp
0x35C1FA: 4D8BA8E0000000                   mov     r13, [r8+0E0h]
0x04AC23: 4D8B6128                         mov     r12, [r9+28h]
0x35C2CD: 498B9C24C8000000                 mov     rbx, [r12+0C8h]
0x35C335: 498BAC24E0000000                 mov     rbp, [r12+0E0h]
0x04AC37: 480FB6DB                         movzx   rbx, bl
0x04AD25: 498B6928                         mov     rbp, [r9+28h]
0x35C40B: 0FAE9590000000                   ldmxcsr dword ptr [rbp+90h]
0x35C471: 48BE47EBCAD200000000             mov     rsi, 0D2CAEB47h
0x04AD3A: 56                               push    rsi
0x04AD3B: 68A4344335                       push    354334A4h
0x04AD40: 682774A765                       push    65A77427h
0x04AD45: 685275BB0D                       push    0DBB7552h
0x35C4DB: 4881442418795F3E6D               add     qword ptr [rsp+18h], 6D3E5F79h
0x04AD53: 4D8B5928                         mov     r11, [r9+28h]
0x35C549: 4D8BA3A0000000                   mov     r12, [r11+0A0h]
0x04AE4E: 4D8B7128                         mov     r14, [r9+28h]
0x04AE52: 410FAE5634                       ldmxcsr dword ptr [r14+34h]
0x35C61A: 498BAEC0000000                   mov     rbp, [r14+0C0h]
0x35C687: 498B9ED8000000                   mov     rbx, [r14+0D8h]
0x04AF3C: 498B4928                         mov     rcx, [r9+28h]
0x35C754: 4C8BA990000000                   mov     r13, [rcx+90h]
0x04AF47: 8B5134                           mov     edx, [rcx+34h]
0x35C7BA: 480391A0000000                   add     rdx, [rcx+0A0h]
0x04AF51: 448A32                           mov     r14b, [rdx]
0x35C823: 48C7C6FF000000                   mov     rsi, 0FFh
0x04AF5B: 48C1E618                         shl     rsi, 18h
0x04AF5F: 48F7D6                           not     rsi
0x04AF62: 4921F5                           and     r13, rsi
0x04AF65: 490FB6F6                         movzx   rsi, r14b
0x04AF69: 48C1E618                         shl     rsi, 18h
0x04AF6D: 4909F5                           or      r13, rsi
0x04B048: 4D8B5928                         mov     r11, [r9+28h]
0x35C8F4: 4D8BBBE0000000                   mov     r15, [r11+0E0h]
0x04B053: 4157                             push    r15
0x04B055: 4889E3                           mov     rbx, rsp
0x35C95B: 498BB3E0000000                   mov     rsi, [r11+0E0h]
0x04B159: 4D8B4928                         mov     r9, [r9+28h]
0x04B15D: 4D8B7178                         mov     r14, [r9+78h]
0x35CA32: 4D8BA9A8000000                   mov     r13, [r9+0A8h]
0x04B168: 4D0FB6F6                         movzx   r14, r14b
0x04B25E: 498B4928                         mov     rcx, [r9+28h]
0x35CB05: 0FAE91E8000000                   ldmxcsr dword ptr [rcx+0E8h]
0x35CB6C: 48BD7908641B01000000             mov     rbp, 11B640879h
0x04B273: 55                               push    rbp
0x04B274: 68EC141F4F                       push    4F1F14ECh
0x04B279: 68DD4B502E                       push    2E504BDDh
0x04B27E: 68E52C8C6F                       push    6F8C2CE5h
0x35CBD5: 48814424184742A524               add     [rsp-8+arg_18], 24A54247h
0x04B28C: 498B4928                         mov     rcx, [r9+28h]
0x35CC3F: 488BB1E0000000                   mov     rsi, [rcx+0E0h]
0x04B37D: 4D8B6928                         mov     r13, [r9+28h]
0x04B381: 410FAE5534                       ldmxcsr dword ptr [r13+34h]
0x35CD10: 498B9D90000000                   mov     rbx, [r13+90h]
0x35CD7E: 4D8BB5A8000000                   mov     r14, [r13+0A8h]
0x04B476: 498B7128                         mov     rsi, [r9+28h]
0x35CE54: 4C8BA6E8000000                   mov     r12, [rsi+0E8h]
0x04B481: 8B7E34                           mov     edi, [rsi+34h]
0x35CEBE: 4803BE90000000                   add     rdi, [rsi+90h]
0x04B48B: 448A37                           mov     r14b, [rdi]
0x35CF23: 48C7C5FF000000                   mov     rbp, 0FFh
0x04B495: 48C1E520                         shl     rbp, 20h
0x04B499: 48F7D5                           not     rbp
0x04B49C: 4921EC                           and     r12, rbp
0x04B49F: 490FB6EE                         movzx   rbp, r14b
0x04B4A3: 48C1E520                         shl     rbp, 20h
0x04B4A7: 4909EC                           or      r12, rbp
0x04B591: 4D8B7928                         mov     r15, [r9+28h]
0x35CFEB: 498BBFD8000000                   mov     rdi, [r15+0D8h]
0x04B59C: 57                               push    rdi
0x04B59D: 4889E7                           mov     rdi, rsp
0x35D053: 4D8BB7D8000000                   mov     r14, [r15+0D8h]
0x04B699: 4D8B5128                         mov     r10, [r9+28h]
0x35D11D: 498B9AB8000000                   mov     rbx, [r10+0B8h]
0x35D184: 4D8BA2E8000000                   mov     r12, [r10+0E8h]
0x04B6AB: 480FB6DB                         movzx   rbx, bl
0x04B786: 498B7128                         mov     rsi, [r9+28h]
0x35D255: 0FAE9690000000                   ldmxcsr dword ptr [rsi+90h]
0x04B791: 498B4128                         mov     rax, [r9+28h]
0x35D2BE: 4C8BB8D8000000                   mov     r15, [rax+0D8h]
0x35D329: 49BD0347031E01000000             mov     r13, 11E034703h
0x35D398: 4981C5BD030622                   add     r13, 220603BDh
0x04B890: 498B4128                         mov     rax, [r9+28h]
0x04B894: 0FAE5034                         ldmxcsr dword ptr [rax+34h]
0x35D472: 488B98A0000000                   mov     rbx, [rax+0A0h]
0x35D4DA: 4C8BB8F0000000                   mov     r15, [rax+0F0h]
0x04B98C: 4D8B6928                         mov     r13, [r9+28h]
0x35D5AF: 498BADF0000000                   mov     rbp, [r13+0F0h]
0x04B997: 458B4D34                         mov     r9d, [r13+34h]
0x35D61B: 4D038D90000000                   add     r9, [r13+90h]
0x04B9A2: 418A09                           mov     cl, [r9]
0x35D689: 49C7C3FF000000                   mov     r11, 0FFh
0x04B9AC: 49C1E328                         shl     r11, 28h
0x04B9B0: 49F7D3                           not     r11
0x04B9B3: 4C21DD                           and     rbp, r11
0x04B9B6: 4C0FB6D9                         movzx   r11, cl
0x04B9BA: 49C1E328                         shl     r11, 28h
0x04B9BE: 4C09DD                           or      rbp, r11
0x04BAB4: 4D8B6128                         mov     r12, [r9+28h]
0x35D75A: 498B9424A0000000                 mov     rdx, [r12+0A0h]
0x04BAC0: 52                               push    rdx
0x04BAC1: 4889E7                           mov     rdi, rsp
0x35D7C5: 4D8BAC24A0000000                 mov     r13, [r12+0A0h]
0x04BBB4: 498B6928                         mov     rbp, [r9+28h]
0x35D893: 4C8BBDF0000000                   mov     r15, [rbp+0F0h]
0x35D8FD: 4C8BADE0000000                   mov     r13, [rbp+0E0h]
0x04BBC6: 4D0FB6FF                         movzx   r15, r15b
0x04BCBC: 498B4928                         mov     rcx, [r9+28h]
0x35D9D2: 0FAE91F0000000                   ldmxcsr dword ptr [rcx+0F0h]
0x04BCC7: 498B7128                         mov     rsi, [r9+28h]
0x35DA39: 4C8BA6E0000000                   mov     r12, [rsi+0E0h]
0x35DA9E: 49BE73CCE41A01000000             mov     r14, 11AE4CC73h
0x35DB0E: 4981C64D7E2425                   add     r14, 25247E4Dh
0x04BDBA: 498B6928                         mov     rbp, [r9+28h]
0x04BDBE: 0FAE5534                         ldmxcsr dword ptr [rbp+34h]
0x35DBE4: 4C8BADE0000000                   mov     r13, [rbp+0E0h]
0x35DC49: 488BB5D8000000                   mov     rsi, [rbp+0D8h]
0x04BEB4: 4D8B7128                         mov     r14, [r9+28h]
0x35DD12: 498B9EA8000000                   mov     rbx, [r14+0A8h]
0x04BEBF: 458B5E34                         mov     r11d, [r14+34h]
0x35DD77: 4D039EE0000000                   add     r11, [r14+0E0h]
0x04BECA: 418A2B                           mov     bpl, [r11]
0x35DDE4: 48C7C6FF000000                   mov     rsi, 0FFh
0x04BED4: 48C1E630                         shl     rsi, 30h
0x04BED8: 48F7D6                           not     rsi
0x04BEDB: 4821F3                           and     rbx, rsi
0x04BEDE: 480FB6F5                         movzx   rsi, bpl
0x04BEE2: 48C1E630                         shl     rsi, 30h
0x04BEE6: 4809F3                           or      rbx, rsi
0x04BFD3: 4D8B7128                         mov     r14, [r9+28h]
0x35DEB7: 4D8BAE90000000                   mov     r13, [r14+90h]
0x04BFDE: 4155                             push    r13
0x04BFE0: 4889E3                           mov     rbx, rsp
0x35DF1E: 4D8BA690000000                   mov     r12, [r14+90h]
0x04C0DF: 4D8B4928                         mov     r9, [r9+28h]
0x35DFF4: 498B9990000000                   mov     rbx, [r9+90h]
0x35E062: 498BA9D8000000                   mov     rbp, [r9+0D8h]
0x04C0F1: 53                               push    rbx
0x04C0F2: 688726912D                       push    2D912687h
0x04C0F7: 68AD069B0B                       push    0B9B06ADh
0x04C0FC: 683C7B8A63                       push    638A7B3Ch
0x04C101: 68D30BC329                       push    29C30BD3h
0x04C1F9: 4D8B6128                         mov     r12, [r9+28h]
0x35E13B: 498BB42480000000                 mov     rsi, [r12+80h]
0x35E1A9: 4D8BA424A0000000                 mov     r12, [r12+0A0h]
0x04C20D: 480FB6F6                         movzx   rsi, sil
0x04C2E6: 4D8B6128                         mov     r12, [r9+28h]
0x35E27C: 410FAE9424A8000000               ldmxcsr dword ptr [r12+0A8h]
0x35E2E3: 49BAA2365A3001000000             mov     r10, 1305A36A2h
0x04C2FD: 4152                             push    r10
0x04C2FF: 68E506B361                       push    61B306E5h
0x04C304: 686255BE5D                       push    5DBE5562h
0x04C309: 68620B791B                       push    1B790B62h
0x35E352: 48814424181E14AF0F               add     qword ptr [rsp+18h], 0FAF141Eh
0x04C317: 498B5128                         mov     rdx, [r9+28h]
0x35E3BE: 4C8BAAD8000000                   mov     r13, [rdx+0D8h]
0x04C3F3: 4D8B6928                         mov     r13, [r9+28h]
0x04C3F7: 410FAE5534                       ldmxcsr dword ptr [r13+34h]
0x35E492: 4D8BB580000000                   mov     r14, [r13+80h]
0x35E4F7: 498B9DE0000000                   mov     rbx, [r13+0E0h]
0x04C4EA: 4D8B6128                         mov     r12, [r9+28h]
0x35E5C4: 4D8BBC2490000000                 mov     r15, [r12+90h]
0x04C4F6: 418B542434                       mov     edx, [r12+34h]
0x35E630: 49039424E8000000                 add     rdx, [r12+0E8h]
0x04C503: 448A2A                           mov     r13b, [rdx]
0x35E696: 49C7C1FF000000                   mov     r9, 0FFh
0x04C50D: 49C1E138                         shl     r9, 38h
0x04C511: 49F7D1                           not     r9
0x04C514: 4D21CF                           and     r15, r9
0x04C517: 4D0FB6CD                         movzx   r9, r13b
0x04C51B: 49C1E138                         shl     r9, 38h
0x04C51F: 4D09CF                           or      r15, r9
0x04C60B: 4D8B4928                         mov     r9, [r9+28h]
0x35E762: 498BB9F0000000                   mov     rdi, [r9+0F0h]
0x35E7CF: 49BE04A335CA00000000             mov     r14, 0CA35A304h
0x35E83F: 4981C6E4155476                   add     r14, 765415E4h
0x04C710: 4D8B6128                         mov     r12, [r9+28h]
0x35E918: 4D8BBC24D8000000                 mov     r15, [r12+0D8h]
0x35E982: 498BBC24B0000000                 mov     rdi, [r12+0B0h]
0x04C724: 4D0FB6FF                         movzx   r15, r15b
0x04C808: 4D8B5128                         mov     r10, [r9+28h]
0x35EA58: 498B82F0000000                   mov     rax, [r10+0F0h]
0x35EABE: 49C7C7380360C1                   mov     r15, 0FFFFFFFFC1600338h
0x35EB29: 4981C7AD094B3F                   add     r15, 3F4B09ADh
0x04C821: 4157                             push    r15
0x35EB96: 498BB2B0000000                   mov     rsi, [r10+0B0h]
0x04C82A: 48F72424                         mul     qword ptr [rsp]
0x04C82E: 4889C7                           mov     rdi, rax
0x04C900: 498B6928                         mov     rbp, [r9+28h]
0x35EC66: 488B9DA8000000                   mov     rbx, [rbp+0A8h]
0x35ECCC: 48339DB0000000                   xor     rbx, [rbp+0B0h]
0x04C9EE: 498B5128                         mov     rdx, [r9+28h]
0x35ED9A: 488BAA90000000                   mov     rbp, [rdx+90h]
0x04C9F9: 55                               push    rbp
0x04C9FA: 4989E4                           mov     r12, rsp
0x35EE07: 488BAA90000000                   mov     rbp, [rdx+90h]
0x04CAE1: 4D8B6128                         mov     r12, [r9+28h]
0x35EEDA: 498B8C24D8000000                 mov     rcx, [r12+0D8h]
0x35EF49: 4D8BB424A0000000                 mov     r14, [r12+0A0h]
0x04CAF5: 51                               push    rcx
0x04CAF6: 68B8390461                       push    610439B8h
0x04CAFB: 686742DA7E                       push    7EDA4267h
0x04CB00: 685E34296D                       push    6D29345Eh
0x04CBEC: 4D8B4128                         mov     r8, [r9+28h]
0x35F01E: 498B98B8000000                   mov     rbx, [r8+0B8h]
0x35F08B: 4D8BA8E8000000                   mov     r13, [r8+0E8h]
0x04CBFE: 480FB6DB                         movzx   rbx, bl
0x04CCDF: 4D8B5928                         mov     r11, [r9+28h]
0x35F15E: 410FAE9390000000                 ldmxcsr dword ptr [r11+90h]
0x35F1CD: 49BC4002893B01000000             mov     r12, 13B890240h
0x35F236: 4981C480608004                   add     r12, 4806080h
0x35F2A1: 4D8BA424B8030000                 mov     r12, [r12+3B8h]
0x35F310: 4D03A390000000                   add     r12, [r11+90h]
0x04CD0B: 458A1424                         mov     r10b, [r12]
0x04CD0F: 4D0FB6D2                         movzx   r10, r10b
0x04CD13: 49C1E208                         shl     r10, 8
0x35F377: 4D0193E0000000                   add     [r11+0E0h], r10
0x35F3E1: 48BD2FDD37C700000000             mov     rbp, 0C737DD2Fh
0x04CD28: 55                               push    rbp
0x04CD29: 68786AC36B                       push    6BC36A78h
0x04CD2E: 68D123C64B                       push    4BC623D1h
0x04CD33: 68B917DB0B                       push    0BDB17B9h
0x04CD38: 68C97E4E7C                       push    7C4E7EC9h
0x35F44B: 4881442420917DD178               add     [rsp-8+arg_20], 78D17D91h
0x04CD46: 498B4128                         mov     rax, [r9+28h]
0x35F4BA: 488BB0E0000000                   mov     rsi, [rax+0E0h]
0x04CE3B: 4D8B5128                         mov     r10, [r9+28h]
0x04CE3F: 410FAE5234                       ldmxcsr dword ptr [r10+34h]
0x35F58D: 4D8BB2A0000000                   mov     r14, [r10+0A0h]
0x35F5FB: 4D8BBAA8000000                   mov     r15, [r10+0A8h]
0x04CF2E: 4D8B5928                         mov     r11, [r9+28h]
0x35F6CE: 498BBBF0000000                   mov     rdi, [r11+0F0h]
0x04CF39: 418B5B34                         mov     ebx, [r11+34h]
0x35F735: 49039BE8000000                   add     rbx, [r11+0E8h]
0x04CF44: 448A1B                           mov     r11b, [rbx]
0x04CF47: 4488DF                           mov     dil, r11b
0x04D02B: 4D8B5928                         db  4Dh ; M
0x35F80B: 4D8BB3B0000000                   mov     r14, [r11+0B0h]
0x04D036: 4156                             push    r14
0x04D038: 4989E4                           mov     r12, rsp
0x35F877: 498B9BB0000000                   mov     rbx, [r11+0B0h]
0x04D119: 498B5128                         mov     rdx, [r9+28h]
0x35F94C: 488BB2D8000000                   mov     rsi, [rdx+0D8h]
0x35F9BA: 488B9A90000000                   mov     rbx, [rdx+90h]
0x04D12B: 56                               push    rsi
0x04D12C: 687355F869                       push    69F85573h
0x04D131: 68920BF74D                       push    4DF70B92h
0x04D136: 681E03DA58                       push    58DA031Eh
0x04D21A: 498B6928                         mov     rbp, [r9+28h]
0x35FA87: 488B9D88000000                   mov     rbx, [rbp+88h]
0x35FAF5: 488BBD90000000                   mov     rdi, [rbp+90h]
0x04D22C: 480FB6DB                         movzx   rbx, bl
0x04D308: 498B6928                         mov     rbp, [r9+28h]
0x35FBC0: 0FAE9590000000                   ldmxcsr dword ptr [rbp+90h]
0x35FC2C: 49B83010A0D600000000             mov     r8, 0D6A01030h
0x35FC99: 4981C090526969                   add     r8, 69695290h
0x35FCFE: 4D8B80C8070000                   mov     r8, [r8+7C8h]
0x35FD64: 4C038590000000                   add     r8, [rbp+90h]
0x04D332: 418A18                           mov     bl, [r8]
0x04D335: 480FB6DB                         movzx   rbx, bl
0x04D339: 48C1E310                         shl     rbx, 10h
0x35FDD0: 48019DB0000000                   add     [rbp+0B0h], rbx
0x35FE3A: 49BCFD034D0101000000             mov     r12, 1014D03FDh
0x04D34E: 4154                             push    r12
0x04D350: 68576DE309                       push    9E36D57h
0x04D355: 6856672471                       push    71246756h
0x04D35A: 68F37ACC7E                       push    7ECC7AF3h
0x04D35F: 68706FCC7C                       push    7CCC6F70h
0x35FEA9: 4881442420C356BC3E               add     qword ptr [rsp+20h], 3EBC56C3h
0x04D36D: 498B4128                         mov     rax, [r9+28h]
0x35FF11: 488BB0B0000000                   mov     rsi, [rax+0B0h]
0x04D45C: 4D8B7128                         mov     r14, [r9+28h]
0x04D460: 410FAE5634                       ldmxcsr dword ptr [r14+34h]
0x35FFDE: 498BBEB0000000                   mov     rdi, [r14+0B0h]
0x36004C: 4D8BBEA8000000                   mov     r15, [r14+0A8h]
0x04D566: 4D8B7128                         mov     r14, [r9+28h]
0x360115: 498BBEF0000000                   mov     rdi, [r14+0F0h]
0x04D571: 418B7634                         mov     esi, [r14+34h]
0x360180: 4903B6B0000000                   add     rsi, [r14+0B0h]
0x04D57C: 448A1E                           mov     r11b, [rsi]
0x3601E6: 49C7C4FF000000                   mov     r12, 0FFh
0x04D586: 49C1E408                         shl     r12, 8
0x04D58A: 49F7D4                           not     r12
0x04D58D: 4C21E7                           and     rdi, r12
0x04D590: 4D0FB6E3                         movzx   r12, r11b
0x04D594: 49C1E408                         shl     r12, 8
0x04D598: 4C09E7                           or      rdi, r12
0x04D692: 498B7928                         mov     rdi, [r9+28h]
0x3602B7: 488B8FB0000000                   mov     rcx, [rdi+0B0h]
0x04D69D: 51                               push    rcx
0x04D69E: 4989E6                           mov     r14, rsp
0x36031D: 488BAFB0000000                   mov     rbp, [rdi+0B0h]
0x04D793: 498B5128                         mov     rdx, [r9+28h]
0x3603F5: 4C8BB2F0000000                   mov     r14, [rdx+0F0h]
0x36045B: 4C8BA2A0000000                   mov     r12, [rdx+0A0h]
0x04D7A5: 4D0FB6F6                         movzx   r14, r14b
0x04D888: 498B4928                         mov     rcx, [r9+28h]
0x36052B: 0FAE91E8000000                   ldmxcsr dword ptr [rcx+0E8h]
0x360595: 49BD3AE6260001000000             mov     r13, 10026E63Ah
0x360605: 4981C5867CE23F                   add     r13, 3FE27C86h
0x36066D: 4D8BAD78020000                   mov     r13, [r13+278h]
0x3606D4: 4C03A9E8000000                   add     r13, [rcx+0E8h]
0x04D8B2: 458A6500                         mov     r12b, [r13+0]
0x04D8B6: 4D0FB6E4                         movzx   r12, r12b
0x04D8BA: 49C1E418                         shl     r12, 18h
0x360741: 4C01A1D8000000                   add     [rcx+0D8h], r12
0x3607AB: 48B87D2117DC00000000             mov     rax, 0DC17217Dh
0x04D8CF: 50                               push    rax
0x04D8D0: 689162A31A                       push    1AA36291h
0x04D8D5: 68D1068734                       push    348706D1h
0x04D8DA: 685406122B                       push    2B120654h
0x360819: 48814424184339F263               add     qword ptr [rsp+18h], 63F23943h
0x04D8E8: 498B4928                         mov     rcx, [r9+28h]
0x360884: 4C8BA9D8000000                   mov     r13, [rcx+0D8h]
0x04D9EC: 4D8B6128                         db  4Dh ; M
0x360955: 410FAE542434                     ldmxcsr dword ptr [r12+34h]
0x3609B9: 4D8BBC24C8000000                 mov     r15, [r12+0C8h]
0x360A1F: 4D8BB424E0000000                 mov     r14, [r12+0E0h]
0x04DADE: 4D8B6128                         mov     r12, [r9+28h]
0x360AEE: 498B9C24E8000000                 mov     rbx, [r12+0E8h]
0x04DAEA: 458B7C2434                       mov     r15d, [r12+34h]
0x360B56: 4D03BC24F0000000                 add     r15, [r12+0F0h]
0x04DAF7: 418A0F                           mov     cl, [r15]
0x360BC0: 49C7C1FF000000                   mov     r9, 0FFh
0x04DB01: 49C1E110                         shl     r9, 10h
0x04DB05: 49F7D1                           not     r9
0x04DB08: 4C21CB                           and     rbx, r9
0x04DB0B: 4C0FB6C9                         movzx   r9, cl
0x04DB0F: 49C1E110                         shl     r9, 10h
0x04DB13: 4C09CB                           or      rbx, r9
0x04DBF4: 4D8B6128                         mov     r12, [r9+28h]
0x360C8F: 498BAC2490000000                 mov     rbp, [r12+90h]
0x04DC00: 55                               push    rbp
0x04DC01: 4889E6                           mov     rsi, rsp
0x360CFA: 498BAC2490000000                 mov     rbp, [r12+90h]
0x04DD02: 4D8B5928                         mov     r11, [r9+28h]
0x360DCB: 4D8BBBB8000000                   mov     r15, [r11+0B8h]
0x360E36: 498B9BA0000000                   mov     rbx, [r11+0A0h]
0x04DD14: 4D0FB6FF                         movzx   r15, r15b
0x04DDFE: 4D8B6128                         mov     r12, [r9+28h]
0x360F03: 410FAE9424F0000000               ldmxcsr dword ptr [r12+0F0h]
0x360F6A: 49BB1F2030E200000000             mov     r11, 0E230201Fh
0x360FD5: 4981C3A142D95D                   add     r11, 5DD942A1h
0x36103F: 4D8B9BA0020000                   mov     r11, [r11+2A0h]
0x3610AC: 4D039C24F0000000                 add     r11, [r12+0F0h]
0x04DE2B: 418A33                           mov     sil, [r11]
0x04DE2E: 480FB6F6                         movzx   rsi, sil
0x04DE32: 48C1E620                         shl     rsi, 20h
0x361118: 4901B42490000000                 add     [r12+90h], rsi
0x361180: 48BD4C035BCC00000000             mov     rbp, 0CC5B034Ch
0x04DE48: 55                               push    rbp
0x04DE49: 68FD29D07F                       push    7FD029FDh
0x04DE4E: 680607853E                       push    3E850706h
0x04DE53: 68193BDB7C                       push    7CDB3B19h
0x04DE58: 685918546A                       push    6A541859h
0x3611ED: 48814424207457AE73               add     qword ptr [rsp+20h], 73AE5774h
0x04DE66: 4D8B7128                         mov     r14, [r9+28h]
0x36125C: 498BB690000000                   mov     rsi, [r14+90h]
0x04DF56: 498B5128                         mov     rdx, [r9+28h]
0x04DF5A: 0FAE5234                         ldmxcsr dword ptr [rdx+34h]
0x361331: 488BAAC0000000                   mov     rbp, [rdx+0C0h]
0x36139A: 4C8BAAA8000000                   mov     r13, [rdx+0A8h]
0x04E05A: 4D8B5128                         mov     r10, [r9+28h]
0x36146D: 498BB2E0000000                   mov     rsi, [r10+0E0h]
0x04E065: 458B7A34                         mov     r15d, [r10+34h]
0x3614D9: 4D03BAA0000000                   add     r15, [r10+0A0h]
0x04E070: 458A27                           mov     r12b, [r15]
0x36153E: 49C7C2FF000000                   mov     r10, 0FFh
0x04E07A: 49C1E218                         shl     r10, 18h
0x04E07E: 49F7D2                           not     r10
0x04E081: 4C21D6                           and     rsi, r10
0x04E084: 4D0FB6D4                         movzx   r10, r12b
0x04E088: 49C1E218                         shl     r10, 18h
0x04E08C: 4C09D6                           or      rsi, r10
0x04E179: 4D8B4128                         mov     r8, [r9+28h]
0x361613: 4D8BB8A8000000                   mov     r15, [r8+0A8h]
0x04E184: 4157                             push    r15
0x04E186: 4989E4                           mov     r12, rsp
0x36167D: 4D8BB8A8000000                   mov     r15, [r8+0A8h]
0x04E283: 4D8B6128                         mov     r12, [r9+28h]
0x36174C: 4D8BBC24C0000000                 mov     r15, [r12+0C0h]
0x3617BB: 498BBC24F0000000                 mov     rdi, [r12+0F0h]
0x04E297: 4D0FB6FF                         movzx   r15, r15b
0x04E384: 498B7128                         mov     rsi, [r9+28h]
0x36188E: 0FAE96F0000000                   ldmxcsr dword ptr [rsi+0F0h]
0x3618FC: 48BA1A54242F01000000             mov     rdx, 12F24541Ah
0x36196D: 4881C2A60EE510                   add     rdx, 10E50EA6h
0x04E3A0: 488B12                           mov     rdx, [rdx]
0x3619D7: 480396F0000000                   add     rdx, [rsi+0F0h]
0x04E3AA: 408A2A                           mov     bpl, [rdx]
0x04E3AD: 480FB6ED                         movzx   rbp, bpl
0x04E3B1: 48C1E530                         shl     rbp, 30h
0x361A3C: 4801AEB0000000                   add     [rsi+0B0h], rbp
0x04E3BC: 4D8B6128                         mov     r12, [r9+28h]
0x361AA4: 4D8BB424B0000000                 mov     r14, [r12+0B0h]
0x361B0D: 48BB840A300F01000000             mov     rbx, 10F300A84h
0x361B76: 4881C33C50D930                   add     rbx, 30D9503Ch
0x04E4C9: 4D8B6928                         mov     r13, [r9+28h]
0x04E4CD: 410FAE5534                       ldmxcsr dword ptr [r13+34h]
0x361C45: 4D8BBDA0000000                   mov     r15, [r13+0A0h]
0x361CB1: 4D8BADE8000000                   mov     r13, [r13+0E8h]
0x04E5BB: 498B5928                         mov     rbx, [r9+28h]
0x361D81: 488BABE0000000                   mov     rbp, [rbx+0E0h]
0x04E5C6: 448B4B34                         mov     r9d, [rbx+34h]
0x361DE9: 4C038BF0000000                   add     r9, [rbx+0F0h]
0x04E5D1: 458A09                           mov     r9b, [r9]
0x361E55: 48C7C1FF000000                   mov     rcx, 0FFh
0x04E5DB: 48C1E128                         shl     rcx, 28h
0x04E5DF: 48F7D1                           not     rcx
0x04E5E2: 4821CD                           and     rbp, rcx
0x04E5E5: 490FB6C9                         movzx   rcx, r9b
0x04E5E9: 48C1E128                         shl     rcx, 28h
0x04E5ED: 4809CD                           or      rbp, rcx
0x04E6CA: 4D8B5928                         mov     r11, [r9+28h]
0x361F29: 4D8BBBA0000000                   mov     r15, [r11+0A0h]
0x04E6D5: 4157                             push    r15
0x04E6D7: 4989E4                           mov     r12, rsp
0x361F97: 498BABA0000000                   mov     rbp, [r11+0A0h]
0x04E7C4: 498B4128                         mov     rax, [r9+28h]
0x36206C: 488B98D8000000                   mov     rbx, [rax+0D8h]
0x3620D2: 4C8BA0A0000000                   mov     r12, [rax+0A0h]
0x04E7D6: 53                               push    rbx
0x04E7D7: 6894271E2E                       push    2E1E2794h
0x04E7DC: 6825254C0E                       push    0E4C2525h
0x04E7E1: 688C5D612F                       push    2F615D8Ch
0x04E7E6: 68840C0040                       push    40000C84h
0x04E8DA: 498B6928                         mov     rbp, [r9+28h]
0x3621A1: 4C8BBD80000000                   mov     r15, [rbp+80h]
0x362209: 4C8BA5D8000000                   mov     r12, [rbp+0D8h]
0x04E8EC: 4D0FB6FF                         movzx   r15, r15b
0x04E9CF: 4D8B7928                         mov     r15, [r9+28h]
0x3622DB: 410FAE97F0000000                 ldmxcsr dword ptr [r15+0F0h]
0x04E9DB: 4D8B4928                         mov     r9, [r9+28h]
0x362343: 498BB1D8000000                   mov     rsi, [r9+0D8h]
0x3623AF: 49BCB532DF1201000000             mov     r12, 112DF32B5h
0x362419: 4981C40B282A2D                   add     r12, 2D2A280Bh
0x04EACC: 498B7928                         mov     rdi, [r9+28h]
0x04EAD0: 0FAE5734                         ldmxcsr dword ptr [rdi+34h]
0x3624E8: 4C8BBFA0000000                   mov     r15, [rdi+0A0h]
0x362555: 488BBFA8000000                   mov     rdi, [rdi+0A8h]
0x04EBCC: 498B4128                         mov     rax, [r9+28h]
0x362625: 4C8BB8B0000000                   mov     r15, [rax+0B0h]
0x04EBD7: 448B7034                         mov     r14d, [rax+34h]
0x36268A: 4C03B0F0000000                   add     r14, [rax+0F0h]
0x04EBE2: 418A2E                           mov     bpl, [r14]
0x3626F7: 49C7C5FF000000                   mov     r13, 0FFh
0x04EBEC: 49C1E538                         shl     r13, 38h
0x04EBF0: 49F7D5                           not     r13
0x04EBF3: 4D21EF                           and     r15, r13
0x04EBF6: 4C0FB6ED                         movzx   r13, bpl
0x04EBFA: 49C1E538                         shl     r13, 38h
0x04EBFE: 4D09EF                           or      r15, r13
0x04ECD2: 4D8B4928                         mov     r9, [r9+28h]
0x3627C4: 498B99F0000000                   mov     rbx, [r9+0F0h]
0x36282E: 48BD223A3C3F01000000             mov     rbp, 13F3C3A22h
0x362897: 4881C5C67E4D01                   add     rbp, 14D7EC6h
0x04EDD5: 4D8B5128                         mov     r10, [r9+28h]
0x362967: 498B9AB0000000                   mov     rbx, [r10+0B0h]
0x3629D3: 498BAA90000000                   mov     rbp, [r10+90h]
0x04EDE7: 480FB6DB                         movzx   rbx, bl
0x04EEE1: 4D8B7128                         mov     r14, [r9+28h]
0x362AA7: 498B8690000000                   mov     rax, [r14+90h]
0x362B11: 48C7C1BE87D3D0                   mov     rcx, 0FFFFFFFFD0D387BEh
0x362B7C: 4881C1D606412F                   add     rcx, 2F4106D6h
0x04EEFA: 51                               push    rcx
0x362BE9: 498BAEA0000000                   mov     rbp, [r14+0A0h]
0x04EF02: 48F72424                         mul     qword ptr [rsp]
0x04EF06: 4989C6                           mov     r14, rax
0x04EFE2: 498B4928                         mov     rcx, [r9+28h]
0x362CBC: 4C8BB9A0000000                   mov     r15, [rcx+0A0h]
0x362D26: 4C03B9E8000000                   add     r15, [rcx+0E8h]
0x04F0CB: 498B5928                         mov     rbx, [r9+28h]
0x362DF8: 488B8BF0000000                   mov     rcx, [rbx+0F0h]
0x04F0D6: 51                               push    rcx
0x04F0D7: 4889E5                           mov     rbp, rsp
0x362E60: 4C8BBBF0000000                   mov     r15, [rbx+0F0h]
0x04F1CA: 4D8B7128                         mov     r14, [r9+28h]
0x362F2D: 4D8BBEA0000000                   mov     r15, [r14+0A0h]
0x362F95: 498BBEF0000000                   mov     rdi, [r14+0F0h]
0x04F1DC: 4D0FB6FF                         movzx   r15, r15b
0x04F2BA: 498B7928                         mov     rdi, [r9+28h]
0x363067: 0FAE97F0000000                   ldmxcsr dword ptr [rdi+0F0h]
0x3630D4: 48BBE12EECDC00000000             mov     rbx, 0DCEC2EE1h
0x36313C: 4881C3DF431D63                   add     rbx, 631D43DFh
0x3631A2: 488B9BC8000000                   mov     rbx, [rbx+0C8h]
0x36320F: 48039FF0000000                   add     rbx, [rdi+0F0h]
0x04F2E4: 448A1B                           mov     r11b, [rbx]
0x04F2E7: 4D0FB6DB                         movzx   r11, r11b
0x04F2EB: 49C1E308                         shl     r11, 8
0x36327C: 4C299FB0000000                   sub     [rdi+0B0h], r11
0x3632E9: 49BE8D5B62D700000000             mov     r14, 0D7625B8Dh
0x04F300: 4156                             push    r14
0x04F302: 684163FE04                       push    4FE6341h
0x04F307: 68D6371631                       push    311637D6h
0x04F30C: 682F42C241                       push    41C2422Fh
0x04F311: 68A75C5617                       push    17565CA7h
0x36335A: 4881442420330FA768               add     qword ptr [rsp+20h], 68A70F33h
0x04F31F: 498B5928                         mov     rbx, [r9+28h]
0x3633C3: 4C8BABB0000000                   mov     r13, [rbx+0B0h]
0x04F428: 4D8B4928                         mov     r9, [r9+28h]
0x04F42C: 410FAE5134                       ldmxcsr dword ptr [r9+34h]
0x363491: 498B99D8000000                   mov     rbx, [r9+0D8h]
0x3634FD: 4D8BB9E0000000                   mov     r15, [r9+0E0h]
0x04F51A: 4D8B5128                         mov     r10, [r9+28h]
0x3635C9: 498BAAF0000000                   mov     rbp, [r10+0F0h]
0x04F525: 458B4234                         mov     r8d, [r10+34h]
0x363630: 4D038290000000                   add     r8, [r10+90h]
0x04F530: 458A10                           mov     r10b, [r8]
0x04F533: 4488D5                           mov     bpl, r10b
0x04F607: 498B4928                         mov     rcx, [r9+28h]
0x363702: 488BB1A0000000                   mov     rsi, [rcx+0A0h]
0x04F612: 56                               push    rsi
0x04F613: 4889E3                           mov     rbx, rsp
0x363770: 488BB9A0000000                   mov     rdi, [rcx+0A0h]
0x04F719: 498B7128                         mov     rsi, [r9+28h]
0x363841: 4C8BA680000000                   mov     r12, [rsi+80h]
0x3638AD: 488BBEB0000000                   mov     rdi, [rsi+0B0h]
0x04F72B: 4D0FB6E4                         movzx   r12, r12b
0x04F817: 4D8B6128                         mov     r12, [r9+28h]
0x363987: 410FAE9424D8000000               ldmxcsr dword ptr [r12+0D8h]
0x3639F2: 48BBF714393701000000             mov     rbx, 1373914F7h
0x363A63: 4881C3C95DD008                   add     rbx, 8D05DC9h
0x363ACC: 488B9B20070000                   mov     rbx, [rbx+720h]
0x363B3A: 49039C24D8000000                 add     rbx, [r12+0D8h]
0x04F844: 448A33                           mov     r14b, [rbx]
0x04F847: 4D0FB6F6                         movzx   r14, r14b
0x04F84B: 49C1E610                         shl     r14, 10h
0x363BA3: 4D29B424B0000000                 sub     [r12+0B0h], r14
0x04F857: 498B7128                         mov     rsi, [r9+28h]
0x363C0A: 488BB6B0000000                   mov     rsi, [rsi+0B0h]
0x363C76: 48BF6E08D50701000000             mov     rdi, 107D5086Eh
0x363CE5: 4881C752623438                   add     rdi, 38346252h
0x04F954: 4D8B5128                         mov     r10, [r9+28h]
0x04F958: 410FAE5234                       ldmxcsr dword ptr [r10+34h]
0x04F95D: 4D8B7278                         mov     r14, [r10+78h]
0x363DB7: 498BB2A8000000                   mov     rsi, [r10+0A8h]
0x04FA44: 4D8B5928                         mov     r11, [r9+28h]
0x363E86: 4D8BBBA8000000                   mov     r15, [r11+0A8h]
0x04FA4F: 418B4334                         mov     eax, [r11+34h]
0x363EEC: 490383E8000000                   add     rax, [r11+0E8h]
0x04FA5A: 448A20                           mov     r12b, [rax]
0x363F53: 48C7C5FF000000                   mov     rbp, 0FFh
0x04FA64: 48C1E508                         shl     rbp, 8
0x04FA68: 48F7D5                           not     rbp
0x04FA6B: 4921EF                           and     r15, rbp
0x04FA6E: 490FB6EC                         movzx   rbp, r12b
0x04FA72: 48C1E508                         shl     rbp, 8
0x04FA76: 4909EF                           or      r15, rbp
0x04FB51: 4D8B7128                         mov     r14, [r9+28h]
0x36401B: 498BAEF0000000                   mov     rbp, [r14+0F0h]
0x04FB5C: 55                               push    rbp
0x04FB5D: 4989E5                           mov     r13, rsp
0x364085: 4D8BBEF0000000                   mov     r15, [r14+0F0h]
0x04FC4B: 4D8B6128                         mov     r12, [r9+28h]
0x364154: 498B9C24E0000000                 mov     rbx, [r12+0E0h]
0x3641C2: 4D8BA424F0000000                 mov     r12, [r12+0F0h]
0x04FC5F: 53                               push    rbx
0x04FC60: 6852780F1C                       push    1C0F7852h
0x04FC65: 687A6DC426                       push    26C46D7Ah
0x04FC6A: 68F907103C                       push    3C1007F9h
0x04FC6F: 68D03EA82B                       push    2BA83ED0h
0x04FD64: 498B7928                         mov     rdi, [r9+28h]
0x36428B: 4C8BA7F0000000                   mov     r12, [rdi+0F0h]
0x3642F6: 488BBFD8000000                   mov     rdi, [rdi+0D8h]
0x04FD76: 4D0FB6E4                         movzx   r12, r12b
0x04FE56: 498B6928                         mov     rbp, [r9+28h]
0x3643C3: 0FAE95D8000000                   ldmxcsr dword ptr [rbp+0D8h]
0x36442D: 48B861298A3601000000             mov     rax, 1368A2961h
0x364497: 48055F497F09                     add     rax, 97F495Fh
0x3644FB: 488B8098050000                   mov     rax, [rax+598h]
0x364565: 480385D8000000                   add     rax, [rbp+0D8h]
0x04FE7F: 448A20                           mov     r12b, [rax]
0x04FE82: 4D0FB6E4                         movzx   r12, r12b
0x04FE86: 49C1E418                         shl     r12, 18h
0x3645CB: 4C29A5B0000000                   sub     [rbp+0B0h], r12
0x364632: 49BE2C07AAF500000000             mov     r14, 0F5AA072Ch
0x04FE9B: 4156                             push    r14
0x04FE9D: 6866770D1B                       push    1B0D7766h
0x04FEA2: 6815037118                       push    18710315h
0x04FEA7: 68B45CD77C                       push    7CD75CB4h
0x36469E: 488144241894635F4A               add     qword ptr [rsp+18h], 4A5F6394h
0x04FEB5: 498B7928                         mov     rdi, [r9+28h]
0x36470E: 488BAFB0000000                   mov     rbp, [rdi+0B0h]
0x04FFA4: 498B5928                         mov     rbx, [r9+28h]
0x04FFA8: 0FAE5334                         ldmxcsr dword ptr [rbx+34h]
0x3647E5: 488BABC0000000                   mov     rbp, [rbx+0C0h]
0x364852: 4C8BABA0000000                   mov     r13, [rbx+0A0h]
0x0500B4: 4D8B4928                         mov     r9, [r9+28h]
0x36491C: 498BB9E0000000                   mov     rdi, [r9+0E0h]
0x0500BF: 418B6934                         mov     ebp, [r9+34h]
0x364988: 4903A9A0000000                   add     rbp, [r9+0A0h]
0x0500CA: 448A6500                         mov     r12b, [rbp+0]
0x3649F6: 49C7C5FF000000                   mov     r13, 0FFh
0x0500D5: 49C1E510                         shl     r13, 10h
0x0500D9: 49F7D5                           not     r13
0x0500DC: 4C21EF                           and     rdi, r13
0x0500DF: 4D0FB6EC                         movzx   r13, r12b
0x0500E3: 49C1E510                         shl     r13, 10h
0x0500E7: 4C09EF                           or      rdi, r13
0x0501C3: 4D8B7128                         mov     r14, [r9+28h]
0x364ABF: 498B96B0000000                   mov     rdx, [r14+0B0h]
0x0501CE: 52                               push    rdx
0x0501CF: 4989E4                           mov     r12, rsp
0x364B2C: 4D8BB6B0000000                   mov     r14, [r14+0B0h]
0x0502DC: 4D8B6128                         mov     r12, [r9+28h]
0x364C05: 498BB424D0000000                 mov     rsi, [r12+0D0h]
0x364C72: 498B9C24E8000000                 mov     rbx, [r12+0E8h]
0x0502F0: 480FB6F6                         movzx   rsi, sil
0x0503CB: 4D8B7128                         mov     r14, [r9+28h]
0x364D41: 410FAE96A8000000                 ldmxcsr dword ptr [r14+0A8h]
0x364DAA: 48BD054B6F2B01000000             mov     rbp, 12B6F4B05h
0x364E15: 4881C5BB279A14                   add     rbp, 149A27BBh
0x364E7A: 488BADE0040000                   mov     rbp, [rbp+4E0h]
0x364EDF: 4903AEA8000000                   add     rbp, [r14+0A8h]
0x0503F6: 448A5500                         mov     r10b, [rbp+0]
0x0503FA: 4D0FB6D2                         movzx   r10, r10b
0x0503FE: 49C1E220                         shl     r10, 20h
0x364F46: 4D299690000000                   sub     [r14+90h], r10
0x050409: 498B5128                         mov     rdx, [r9+28h]
0x364FB4: 4C8BB290000000                   mov     r14, [rdx+90h]
0x365022: 48BE734A35C400000000             mov     rsi, 0C4354A73h
0x365092: 4881C64D20D47B                   add     rsi, 7BD4204Dh
0x050511: 4D8B7928                         mov     r15, [r9+28h]
0x050515: 410FAE5734                       ldmxcsr dword ptr [r15+34h]
0x365164: 498B9FA0000000                   mov     rbx, [r15+0A0h]
0x3651D2: 4D8BA7E8000000                   mov     r12, [r15+0E8h]
0x050606: 498B7128                         mov     rsi, [r9+28h]
0x3652A9: 4C8BBED8000000                   mov     r15, [rsi+0D8h]
0x050611: 448B7634                         mov     r14d, [rsi+34h]
0x365311: 4C03B690000000                   add     r14, [rsi+90h]
0x05061C: 458A0E                           mov     r9b, [r14]
0x365378: 48C7C3FF000000                   mov     rbx, 0FFh
0x050626: 48C1E318                         shl     rbx, 18h
0x05062A: 48F7D3                           not     rbx
0x05062D: 4921DF                           and     r15, rbx
0x050630: 490FB6D9                         movzx   rbx, r9b
0x050634: 48C1E318                         shl     rbx, 18h
0x050638: 4909DF                           or      r15, rbx
0x050723: 498B5128                         mov     rdx, [r9+28h]
0x365446: 4C8BA2F0000000                   mov     r12, [rdx+0F0h]
0x05072E: 4154                             push    r12
0x050730: 4889E3                           mov     rbx, rsp
0x3654B3: 488BBAF0000000                   mov     rdi, [rdx+0F0h]
0x050813: 498B7928                         mov     rdi, [r9+28h]
0x365588: 488BB790000000                   mov     rsi, [rdi+90h]
0x3655F0: 488BBFB0000000                   mov     rdi, [rdi+0B0h]
0x050825: 56                               push    rsi
0x050826: 68B1618831                       push    318861B1h
0x05082B: 68A31A9F6F                       push    6F9F1AA3h
0x050830: 6832319516                       push    16953132h
0x050925: 498B5128                         mov     rdx, [r9+28h]
0x3656BD: 4C8BBA90000000                   mov     r15, [rdx+90h]
0x365729: 488BB2B0000000                   mov     rsi, [rdx+0B0h]
0x050937: 4D0FB6FF                         movzx   r15, r15b
0x050A16: 4D8B6928                         mov     r13, [r9+28h]
0x3657F6: 410FAE95F0000000                 ldmxcsr dword ptr [r13+0F0h]
0x36585E: 48BF0AFB222701000000             mov     rdi, 12722FB0Ah
0x3658CF: 4881C7B677E618                   add     rdi, 18E677B6h
0x050A33: 488B3F                           mov     rdi, [rdi]
0x365934: 4903BDF0000000                   add     rdi, [r13+0F0h]
0x050A3D: 8A07                             mov     al, [rdi]
0x050A3F: 480FB6C0                         movzx   rax, al
0x050A43: 48C1E028                         shl     rax, 28h
0x3659A1: 492985A8000000                   sub     [r13+0A8h], rax
0x050A4E: 4D8B7128                         mov     r14, [r9+28h]
0x365A07: 498B9EA8000000                   mov     rbx, [r14+0A8h]
0x365A70: 48BFD8F6541B01000000             mov     rdi, 11B54F6D8h
0x365AE0: 4881C7E873B424                   add     rdi, 24B473E8h
0x050B5C: 498B4928                         mov     rcx, [r9+28h]
0x050B60: 0FAE5134                         ldmxcsr dword ptr [rcx+34h]
0x365BB4: 488B99F0000000                   mov     rbx, [rcx+0F0h]
0x365C1D: 4C8BB990000000                   mov     r15, [rcx+90h]
0x050C55: 4D8B6928                         mov     r13, [r9+28h]
0x365CE7: 4D8BB5F0000000                   mov     r14, [r13+0F0h]
0x050C60: 458B7D34                         mov     r15d, [r13+34h]
0x365D4D: 4D03BD90000000                   add     r15, [r13+90h]
0x050C6B: 418A37                           mov     sil, [r15]
0x365DBB: 48C7C7FF000000                   mov     rdi, 0FFh
0x050C75: 48C1E720                         shl     rdi, 20h
0x050C79: 48F7D7                           not     rdi
0x050C7C: 4921FE                           and     r14, rdi
0x050C7F: 480FB6FE                         movzx   rdi, sil
0x050C83: 48C1E720                         shl     rdi, 20h
0x050C87: 4909FE                           or      r14, rdi
0x050D74: 4D8B4128                         mov     r8, [r9+28h]
0x365E86: 498BB8E8000000                   mov     rdi, [r8+0E8h]
0x050D7F: 57                               push    rdi
0x050D80: 4889E3                           mov     rbx, rsp
0x365EEE: 4D8BB0E8000000                   mov     r14, [r8+0E8h]
0x050E65: 498B5128                         mov     rdx, [r9+28h]
0x365FBA: 488B9A90000000                   mov     rbx, [rdx+90h]
0x366023: 488BAAE8000000                   mov     rbp, [rdx+0E8h]
0x050E77: 53                               push    rbx
0x050E78: 68D404D952                       push    52D904D4h
0x050E7D: 68B254D96C                       push    6CD954B2h
0x050E82: 68FC66BF1D                       push    1DBF66FCh
0x050F76: 498B4128                         mov     rax, [r9+28h]
0x3660F4: 488BB888000000                   mov     rdi, [rax+88h]
0x36615F: 4C8BA8A0000000                   mov     r13, [rax+0A0h]
0x050F88: 480FB6FF                         movzx   rdi, dil
0x051064: 498B4928                         mov     rcx, [r9+28h]
0x366236: 0FAE91B0000000                   ldmxcsr dword ptr [rcx+0B0h]
0x3662A3: 48B87612820901000000             mov     rax, 109821276h
0x366311: 48054A608736                     add     rax, 3687604Ah
0x05107F: 488B00                           mov     rax, [rax]
0x366377: 480381B0000000                   add     rax, [rcx+0B0h]
0x051089: 448A00                           mov     r8b, [rax]
0x05108C: 4D0FB6C0                         movzx   r8, r8b
0x051090: 49C1E030                         shl     r8, 30h
0x3663DF: 4C2981E0000000                   sub     [rcx+0E0h], r8
0x36644B: 49BBA502B90901000000             mov     r11, 109B902A5h
0x0510A5: 4153                             push    r11
0x0510A7: 6816354353                       push    53433516h
0x0510AC: 6831653776                       push    76376531h
0x0510B1: 68230A1067                       push    67100A23h
0x0510B6: 687B0F2609                       push    9260F7Bh
0x3664B3: 48814424201B685036               add     qword ptr [rsp+20h], 3650681Bh
0x0510C4: 498B5928                         mov     rbx, [r9+28h]
0x366522: 4C8BBBE0000000                   mov     r15, [rbx+0E0h]
0x0511B5: 4D8B6928                         mov     r13, [r9+28h]
0x0511B9: 410FAE5534                       ldmxcsr dword ptr [r13+34h]
0x3665F7: 498BADE8000000                   mov     rbp, [r13+0E8h]
0x366661: 498BBDF0000000                   mov     rdi, [r13+0F0h]
0x0512AD: 498B6928                         mov     rbp, [r9+28h]
0x366730: 4C8BBDB0000000                   mov     r15, [rbp+0B0h]
0x0512B8: 448B6534                         mov     r12d, [rbp+34h]
0x366799: 4C03A5A0000000                   add     r12, [rbp+0A0h]
0x0512C3: 418A0424                         mov     al, [r12]
0x3667FE: 49C7C5FF000000                   mov     r13, 0FFh
0x0512CE: 49C1E528                         shl     r13, 28h
0x0512D2: 49F7D5                           not     r13
0x0512D5: 4D21EF                           and     r15, r13
0x0512D8: 4C0FB6E8                         movzx   r13, al
0x0512DC: 49C1E528                         shl     r13, 28h
0x0512E0: 4D09EF                           or      r15, r13
0x0513D2: 498B4128                         mov     rax, [r9+28h]
0x3668CB: 488BB0F0000000                   mov     rsi, [rax+0F0h]
0x366934: 48BB109CB51201000000             mov     rbx, 112B59C10h
0x36699C: 4881C3D81CD42D                   add     rbx, 2DD41CD8h
0x0514CD: 4D8B4928                         mov     r9, [r9+28h]
0x366A72: 4D8BA1B0000000                   mov     r12, [r9+0B0h]
0x366ADA: 4D8BB1A8000000                   mov     r14, [r9+0A8h]
0x0514DF: 4D0FB6E4                         movzx   r12, r12b
0x0515C7: 4D8B7928                         mov     r15, [r9+28h]
0x366BA9: 498B87D8000000                   mov     rax, [r15+0D8h]
0x366C16: 48C7C76CF95597                   mov     rdi, 0FFFFFFFF9755F96Ch
0x366C7E: 4881C7420D4869                   add     rdi, 69480D42h
0x0515E0: 57                               push    rdi
0x366CE5: 4D8BAFE8000000                   mov     r13, [r15+0E8h]
0x0515E8: 48F72424                         mul     qword ptr [rsp]
0x0515EC: 4889C5                           mov     rbp, rax
0x0516CD: 4D8B5928                         mov     r11, [r9+28h]
0x366DB4: 4D8BA3E0000000                   mov     r12, [r11+0E0h]
0x366E19: 4D2BA3A0000000                   sub     r12, [r11+0A0h]
0x0517D1: 498B5928                         mov     rbx, [r9+28h]
0x366EED: 4C8B83D8000000                   mov     r8, [rbx+0D8h]
0x0517DC: 4150                             push    r8
0x0517DE: 4989E4                           mov     r12, rsp
0x366F55: 4C8BB3D8000000                   mov     r14, [rbx+0D8h]
0x0518BF: 498B7928                         mov     rdi, [r9+28h]
0x367023: 4C8BAFD8000000                   mov     r13, [rdi+0D8h]
0x367088: 488BAFE8000000                   mov     rbp, [rdi+0E8h]
0x0518D1: 4155                             push    r13
0x0518D3: 6811698B5D                       push    5D8B6911h
0x0518D8: 6860658923                       push    23896560h
0x0518DD: 68C517D95F                       push    5FD917C5h
0x0519BE: 4D8B5128                         mov     r10, [r9+28h]
0x367155: 4D8BAAE0000000                   mov     r13, [r10+0E0h]
0x3671C3: 498BAAA0000000                   mov     rbp, [r10+0A0h]
0x0519D0: 4D0FB6ED                         movzx   r13, r13b
0x051AB2: 498B4928                         mov     rcx, [r9+28h]
0x367296: 0FAE91E0000000                   ldmxcsr dword ptr [rcx+0E0h]
0x3672FC: 49BB641ED5CB00000000             mov     r11, 0CBD51E64h
0x367364: 4981C35C543474                   add     r11, 7434545Ch
0x3673CE: 4D8B9B20030000                   mov     r11, [r11+320h]
0x367439: 4C0399E0000000                   add     r11, [rcx+0E0h]
0x051ADC: 418A2B                           mov     bpl, [r11]
0x051ADF: 480FB6ED                         movzx   rbp, bpl
0x051AE3: 48C1E508                         shl     rbp, 8
0x3674A0: 4829A9A0000000                   sub     [rcx+0A0h], rbp
0x36750B: 49BCC2FF75CC00000000             mov     r12, 0CC75FFC2h
0x051AF8: 4154                             push    r12
0x051AFA: 68533C0A0E                       push    0E0A3C53h
0x051AFF: 68B25A3E1E                       push    1E3E5AB2h
0x051B04: 68404AB648                       push    48B64A40h
0x051B09: 68383FCF4C                       push    4CCF3F38h
0x367576: 4881442420FE6A9373               add     qword ptr [rsp+20h], 73936AFEh
0x051B17: 498B7928                         mov     rdi, [r9+28h]
0x3675E4: 488B9FA0000000                   mov     rbx, [rdi+0A0h]
0x051C0F: 4D8B5128                         mov     r10, [r9+28h]
0x051C13: 410FAE5234                       ldmxcsr dword ptr [r10+34h]
0x3676B4: 4D8BBAF0000000                   mov     r15, [r10+0F0h]
0x36771E: 4D8BA290000000                   mov     r12, [r10+90h]
0x051D0C: 4D8B7128                         mov     r14, [r9+28h]
0x3677F7: 4D8BA6D8000000                   mov     r12, [r14+0D8h]
0x051D17: 418B5634                         mov     edx, [r14+34h]
0x36785E: 490396F0000000                   add     rdx, [r14+0F0h]
0x051D22: 408A2A                           mov     bpl, [rdx]
0x051D25: 4188EC                           mov     r12b, bpl
0x051E0C: 498B5128                         mov     rdx, [r9+28h]
0x367929: 4C8BBAD8000000                   mov     r15, [rdx+0D8h]
0x051E17: 4157                             push    r15
0x051E19: 4989E7                           mov     r15, rsp
0x367993: 488BB2D8000000                   mov     rsi, [rdx+0D8h]
0x051EF0: 498B5928                         mov     rbx, [r9+28h]
0x367A64: 4C8BBBF0000000                   mov     r15, [rbx+0F0h]
0x367ACC: 488B9BA8000000                   mov     rbx, [rbx+0A8h]
0x051F02: 4157                             push    r15
0x051F04: 6821124129                       push    29411221h
0x051F09: 685811DD06                       push    6DD1158h
0x051F0E: 68623A424B                       push    4B423A62h
0x051F13: 686934D111                       push    11D13469h
0x052003: 498B4128                         mov     rax, [r9+28h]
0x367B9F: 488B9888000000                   mov     rbx, [rax+88h]
0x367C05: 4C8BB890000000                   mov     r15, [rax+90h]
0x052015: 480FB6DB                         movzx   rbx, bl
0x0520E7: 498B7928                         mov     rdi, [r9+28h]
0x367CDD: 0FAE9790000000                   ldmxcsr dword ptr [rdi+90h]
0x367D43: 49BFCC4E411C01000000             mov     r15, 11C414ECCh
0x367DAB: 4981C7F423C823                   add     r15, 23C823F4h
0x367E15: 4D8BBF00010000                   mov     r15, [r15+100h]
0x367E7D: 4C03BF90000000                   add     r15, [rdi+90h]
0x052111: 458A3F                           mov     r15b, [r15]
0x052114: 4D0FB6FF                         movzx   r15, r15b
0x052118: 49C1E710                         shl     r15, 10h
0x367EE4: 4C29BFF0000000                   sub     [rdi+0F0h], r15
0x052123: 498B5128                         mov     rdx, [r9+28h]
0x367F4F: 488BB2F0000000                   mov     rsi, [rdx+0F0h]
0x367FBC: 49BE850F46F100000000             mov     r14, 0F1460F85h
0x36802D: 4981C63B5BC34E                   add     r14, 4EC35B3Bh
0x052226: 4D8B6128                         mov     r12, [r9+28h]
0x3680FE: 410FAE542434                     ldmxcsr dword ptr [r12+34h]
0x368167: 4D8BB42490000000                 mov     r14, [r12+90h]
0x3681CE: 4D8BA424A8000000                 mov     r12, [r12+0A8h]
0x052321: 498B4928                         mov     rcx, [r9+28h]
0x3682A1: 4C8BB9D8000000                   mov     r15, [rcx+0D8h]
0x05232C: 448B7134                         mov     r14d, [rcx+34h]
0x36830A: 4C03B1E8000000                   add     r14, [rcx+0E8h]
0x052337: 418A2E                           mov     bpl, [r14]
0x368373: 49C7C6FF000000                   mov     r14, 0FFh
0x052341: 49C1E608                         shl     r14, 8
0x052345: 49F7D6                           not     r14
0x052348: 4D21F7                           and     r15, r14
0x05234B: 4C0FB6F5                         movzx   r14, bpl
0x05234F: 49C1E608                         shl     r14, 8
0x052353: 4D09F7                           or      r15, r14
0x052436: 4D8B7928                         mov     r15, [r9+28h]
0x368445: 4D8B87F0000000                   mov     r8, [r15+0F0h]
0x052441: 4150                             push    r8
0x052443: 4889E6                           mov     rsi, rsp
0x3684B0: 4D8BAFF0000000                   mov     r13, [r15+0F0h]
0x052525: 4D8B6928                         mov     r13, [r9+28h]
0x368583: 498BADA8000000                   mov     rbp, [r13+0A8h]
0x3685E8: 498BB5E0000000                   mov     rsi, [r13+0E0h]
0x052537: 55                               push    rbp
0x052538: 681105427E                       push    7E420511h
0x05253D: 681434E277                       push    77E23414h
0x052542: 6858604520                       push    20456058h
0x05261F: 4D8B7928                         mov     r15, [r9+28h]
0x3686BA: 4D8BA788000000                   mov     r12, [r15+88h]
0x368725: 4D8BAFA8000000                   mov     r13, [r15+0A8h]
0x052631: 4D0FB6E4                         movzx   r12, r12b
0x052721: 4D8B7928                         mov     r15, [r9+28h]
0x3687F1: 410FAE97D8000000                 ldmxcsr dword ptr [r15+0D8h]
0x368858: 48BAC93D2FDC00000000             mov     rdx, 0DC2F3DC9h
0x3688C9: 4881C2F734DA63                   add     rdx, 63DA34F7h
0x368933: 488B9230060000                   mov     rdx, [rdx+630h]
0x36899B: 490397D8000000                   add     rdx, [r15+0D8h]
0x05274C: 8A12                             mov     dl, [rdx]
0x05274E: 480FB6D2                         movzx   rdx, dl
0x052752: 48C1E218                         shl     rdx, 18h
0x368A04: 492997E0000000                   sub     [r15+0E0h], rdx
0x05275D: 4D8B6128                         mov     r12, [r9+28h]
0x368A6D: 4D8BA424E0000000                 mov     r12, [r12+0E0h]
0x368AD6: 49BE6CF794FA00000000             mov     r14, 0FA94F76Ch
0x368B42: 4981C654737445                   add     r14, 45747354h
0x05285F: 498B5128                         mov     rdx, [r9+28h]
0x052863: 0FAE5234                         ldmxcsr dword ptr [rdx+34h]
0x368C12: 4C8BA2A8000000                   mov     r12, [rdx+0A8h]
0x368C7F: 4C8BBAD8000000                   mov     r15, [rdx+0D8h]
0x052946: 4D8B4128                         mov     r8, [r9+28h]
0x368D54: 4D8BA0F0000000                   mov     r12, [r8+0F0h]
0x052951: 458B4834                         mov     r9d, [r8+34h]
0x368DC1: 4D0388D8000000                   add     r9, [r8+0D8h]
0x05295C: 458A11                           mov     r10b, [r9]
0x368E2D: 49C7C7FF000000                   mov     r15, 0FFh
0x052966: 49C1E710                         shl     r15, 10h
0x05296A: 49F7D7                           not     r15
0x05296D: 4D21FC                           and     r12, r15
0x052970: 4D0FB6FA                         movzx   r15, r10b
0x052974: 49C1E710                         shl     r15, 10h
0x052978: 4D09FC                           or      r12, r15
0x052A56: 498B4928                         mov     rcx, [r9+28h]
0x368F00: 488BA9D8000000                   mov     rbp, [rcx+0D8h]
0x052A61: 55                               push    rbp
0x052A62: 4889E7                           mov     rdi, rsp
0x368F69: 4C8BB1D8000000                   mov     r14, [rcx+0D8h]
0x052B4C: 498B6928                         mov     rbp, [r9+28h]
0x369043: 4C8B8DB0000000                   mov     r9, [rbp+0B0h]
0x3690AA: 488BADE8000000                   mov     rbp, [rbp+0E8h]
0x052B5E: 4151                             push    r9
0x052B60: 6841639E4F                       push    4F9E6341h
0x052B65: 68DC6A0E07                       push    70E6ADCh
0x052B6A: 68E67B8347                       push    47837BE6h
0x052C51: 4D8B6928                         mov     r13, [r9+28h]
0x369179: 4D8BB5D8000000                   mov     r14, [r13+0D8h]
0x3691E5: 498BBDA0000000                   mov     rdi, [r13+0A0h]
0x052C63: 4D0FB6F6                         movzx   r14, r14b
0x052D4D: 498B4928                         mov     rcx, [r9+28h]
0x3692B8: 0FAE91E8000000                   ldmxcsr dword ptr [rcx+0E8h]
0x36931F: 48B8D31616CE00000000             mov     rax, 0CE1616D3h
0x36938A: 4805ED5BF371                     add     rax, 71F35BEDh
0x3693F1: 488B8068050000                   mov     rax, [rax+568h]
0x36945E: 480381E8000000                   add     rax, [rcx+0E8h]
0x052D76: 448A28                           mov     r13b, [rax]
0x052D79: 4D0FB6ED                         movzx   r13, r13b
0x052D7D: 49C1E520                         shl     r13, 20h
0x3694CC: 4C29A9B0000000                   sub     [rcx+0B0h], r13
0x052D88: 498B7128                         mov     rsi, [r9+28h]
0x369539: 488BBEB0000000                   mov     rdi, [rsi+0B0h]
0x3695A0: 49BD51F21A0401000000             mov     r13, 1041AF251h
0x36960C: 4981C56F78EE3B                   add     r13, 3BEE786Fh
0x052E8E: 498B7928                         mov     rdi, [r9+28h]
0x052E92: 0FAE5734                         ldmxcsr dword ptr [rdi+34h]
0x3696DC: 4C8BBFC8000000                   mov     r15, [rdi+0C8h]
0x36974A: 488B9FB0000000                   mov     rbx, [rdi+0B0h]
0x052F8F: 498B5128                         mov     rdx, [r9+28h]
0x369818: 488B9A90000000                   mov     rbx, [rdx+90h]
0x052F9A: 448B4A34                         mov     r9d, [rdx+34h]
0x369880: 4C038AF0000000                   add     r9, [rdx+0F0h]
0x052FA5: 458A31                           mov     r14b, [r9]
0x3698E8: 48C7C2FF000000                   mov     rdx, 0FFh
0x052FAF: 48C1E218                         shl     rdx, 18h
0x052FB3: 48F7D2                           not     rdx
0x052FB6: 4821D3                           and     rbx, rdx
0x052FB9: 490FB6D6                         movzx   rdx, r14b
0x052FBD: 48C1E218                         shl     rdx, 18h
0x052FC1: 4809D3                           or      rbx, rdx
0x053096: 498B6928                         mov     rbp, [r9+28h]
0x3699B6: 488B8D90000000                   mov     rcx, [rbp+90h]
0x0530A1: 51                               push    rcx
0x0530A2: 4889E3                           mov     rbx, rsp
0x369A1F: 4C8BBD90000000                   mov     r15, [rbp+90h]
0x0531A4: 498B5928                         mov     rbx, [r9+28h]
0x369AEB: 4C8BA3C8000000                   mov     r12, [rbx+0C8h]
0x369B58: 488BABF0000000                   mov     rbp, [rbx+0F0h]
0x0531B6: 4D0FB6E4                         movzx   r12, r12b
0x053299: 498B7928                         mov     rdi, [r9+28h]
0x369C2B: 0FAE97D8000000                   ldmxcsr dword ptr [rdi+0D8h]
0x369C90: 49BE2E1B25D000000000             mov     r14, 0D0251B2Eh
0x369CFB: 4981C69257E46F                   add     r14, 6FE45792h
0x0532B5: 4D8B36                           mov     r14, [r14]
0x369D67: 4C03B7D8000000                   add     r14, [rdi+0D8h]
0x0532BF: 458A16                           mov     r10b, [r14]
0x0532C2: 4D0FB6D2                         movzx   r10, r10b
0x0532C6: 49C1E228                         shl     r10, 28h
0x369DCD: 4C2997A0000000                   sub     [rdi+0A0h], r10
0x0532D1: 4D8B4928                         mov     r9, [r9+28h]
0x369E34: 4D8BA9A0000000                   mov     r13, [r9+0A0h]
0x369EA2: 49BFD70FECD500000000             mov     r15, 0D5EC0FD7h
0x369F0E: 4981C7E95A1D6A                   add     r15, 6A1D5AE9h
0x0533D1: 4D8B7928                         mov     r15, [r9+28h]
0x0533D5: 410FAE5734                       ldmxcsr dword ptr [r15+34h]
0x369FD8: 4D8BA7D8000000                   mov     r12, [r15+0D8h]
0x36A03F: 498BB7E0000000                   mov     rsi, [r15+0E0h]
0x0534CF: 498B7128                         mov     rsi, [r9+28h]
0x36A10D: 488BBEA8000000                   mov     rdi, [rsi+0A8h]
0x0534DA: 448B4634                         mov     r8d, [rsi+34h]
0x36A17A: 4C0386D8000000                   add     r8, [rsi+0D8h]
0x0534E5: 458A10                           mov     r10b, [r8]
0x36A1E3: 48C7C6FF000000                   mov     rsi, 0FFh
0x0534EF: 48C1E620                         shl     rsi, 20h
0x0534F3: 48F7D6                           not     rsi
0x0534F6: 4821F7                           and     rdi, rsi
0x0534F9: 490FB6F2                         movzx   rsi, r10b
0x0534FD: 48C1E620                         shl     rsi, 20h
0x053501: 4809F7                           or      rdi, rsi
0x36A2B0: 48B9FB38780C01000000             mov     rcx, 10C7838FBh
0x0535E6: 51                               push    rcx
0x0535E7: 68AD41701B                       push    1B7041ADh
0x0535EC: 685244582D                       push    2D584452h
0x0535F1: 68B274154F                       push    4F1574B2h
0x0535F6: 688F3CCF22                       push    22CF3C8Fh
0x36A31E: 4881442420ED7F1134               add     qword ptr [rsp+20h], 34117FEDh
0x053604: 498B7128                         mov     rsi, [r9+28h]
0x36A38B: 488BBEB0000000                   mov     rdi, [rsi+0B0h]
0x05370E: 4D8B4928                         mov     r9, [r9+28h]
0x36A461: 4D8BB1D0000000                   mov     r14, [r9+0D0h]
0x36A4C7: 4D8BB9B0000000                   mov     r15, [r9+0B0h]
0x053720: 4D0FB6F6                         movzx   r14, r14b
0x05380E: 4D8B4128                         mov     r8, [r9+28h]
0x36A59A: 498B80E8000000                   mov     rax, [r8+0E8h]
0x36A604: 49C7C2896CACF8                   mov     r10, 0FFFFFFFFF8AC6C89h
0x36A670: 4981C258314F08                   add     r10, 84F3158h
0x053827: 4152                             push    r10
0x36A6D9: 4D8BB8F0000000                   mov     r15, [r8+0F0h]
0x053830: 48F72424                         mul     qword ptr [rsp]
0x053834: 4989C6                           mov     r14, rax
0x05391E: 498B4928                         mov     rcx, [r9+28h]
0x36A7A8: 488BB1F0000000                   mov     rsi, [rcx+0F0h]
0x36A812: 4833B1E8000000                   xor     rsi, [rcx+0E8h]
0x053A05: 498B7128                         mov     rsi, [r9+28h]
0x36A8E2: 4C8B9EA8000000                   mov     r11, [rsi+0A8h]
0x053A10: 4153                             push    r11
0x053A12: 4989E7                           mov     r15, rsp
0x36A94F: 488BB6A8000000                   mov     rsi, [rsi+0A8h]
0x053B14: 4D8B6128                         mov     r12, [r9+28h]
0x36AA1F: 4D8BAC2490000000                 mov     r13, [r12+90h]
0x36AA8A: 498B9C24A8000000                 mov     rbx, [r12+0A8h]
0x053B28: 4D0FB6ED                         movzx   r13, r13b
0x053C01: 498B5128                         mov     rdx, [r9+28h]
0x36AB58: 0FAE92E0000000                   ldmxcsr dword ptr [rdx+0E0h]
0x36ABC2: 48B947FD2F3901000000             mov     rcx, 1392FFD47h
0x053C16: 51                               push    rcx
0x053C17: 68501DD779                       push    79D71D50h
0x053C1C: 686C0D667C                       push    7C660D6Ch
0x053C21: 68BB02A044                       push    44A002BBh
0x36AC2D: 4881442418794DD906               add     qword ptr [rsp+18h], 6D94D79h
0x053C2F: 4D8B7128                         mov     r14, [r9+28h]
0x36AC9B: 4D8BBE90000000                   mov     r15, [r14+90h]
0x053D27: 498B5928                         mov     rbx, [r9+28h]
0x053D2B: 0FAE5334                         ldmxcsr dword ptr [rbx+34h]
0x36AD70: 488BABD8000000                   mov     rbp, [rbx+0D8h]
0x36ADDA: 488BB3F0000000                   mov     rsi, [rbx+0F0h]
0x053E0F: 4D8B5928                         mov     r11, [r9+28h]
0x36AEAE: 4D8BA3A8000000                   mov     r12, [r11+0A8h]
0x053E1A: 458B7B34                         mov     r15d, [r11+34h]
0x36AF15: 4D03BBA0000000                   add     r15, [r11+0A0h]
0x053E25: 418A07                           mov     al, [r15]
0x053E28: 4188C4                           mov     r12b, al
0x053F02: 4D8B5128                         mov     r10, [r9+28h]
0x36AFE6: 4D8B9AD8000000                   mov     r11, [r10+0D8h]
0x053F0D: 4153                             push    r11
0x053F0F: 4889E3                           mov     rbx, rsp
0x36B050: 4D8BA2D8000000                   mov     r12, [r10+0D8h]
0x05400B: 4D8B4928                         mov     r9, [r9+28h]
0x36B122: 4D8BA1F0000000                   mov     r12, [r9+0F0h]
0x36B190: 4D8BB1D8000000                   mov     r14, [r9+0D8h]
0x05401D: 4D0FB6E4                         movzx   r12, r12b
0x054100: 498B5928                         mov     rbx, [r9+28h]
0x36B25E: 0FAE93D8000000                   ldmxcsr dword ptr [rbx+0D8h]
0x05410B: 4D8B7128                         mov     r14, [r9+28h]
0x36B2CA: 4D8BB6E8000000                   mov     r14, [r14+0E8h]
0x36B337: 49BDBD428A1501000000             mov     r13, 1158A42BDh
0x36B3A7: 4981C503087F2A                   add     r13, 2A7F0803h
0x05422C: 498B4928                         mov     rcx, [r9+28h]
0x054230: 0FAE5134                         ldmxcsr dword ptr [rcx+34h]
0x36B47F: 488BB9A0000000                   mov     rdi, [rcx+0A0h]
0x36B4EA: 4C8BA9E8000000                   mov     r13, [rcx+0E8h]
0x05431E: 4D8B5128                         mov     r10, [r9+28h]
0x36B5BA: 498BBAE0000000                   mov     rdi, [r10+0E0h]
0x054329: 418B5A34                         mov     ebx, [r10+34h]
0x36B620: 49039AB0000000                   add     rbx, [r10+0B0h]
0x054334: 448A13                           mov     r10b, [rbx]
0x36B68C: 48C7C2FF000000                   mov     rdx, 0FFh
0x05433E: 48C1E208                         shl     rdx, 8
0x054342: 48F7D2                           not     rdx
0x054345: 4821D7                           and     rdi, rdx
0x054348: 490FB6D2                         movzx   rdx, r10b
0x05434C: 48C1E208                         shl     rdx, 8
0x054350: 4809D7                           or      rdi, rdx
0x054421: 4D8B4128                         mov     r8, [r9+28h]
0x36B758: 498BA8B0000000                   mov     rbp, [r8+0B0h]
0x05442C: 55                               push    rbp
0x05442D: 4989E4                           mov     r12, rsp
0x36B7BE: 4D8BA8B0000000                   mov     r13, [r8+0B0h]
0x05451B: 4D8B6128                         mov     r12, [r9+28h]
0x36B88B: 4D8BBC24D8000000                 mov     r15, [r12+0D8h]
0x36B8F9: 498BAC24E0000000                 mov     rbp, [r12+0E0h]
0x05452F: 4157                             push    r15
0x054531: 688919A51F                       push    1FA51989h
0x054536: 68C368826F                       push    6F8268C3h
0x05453B: 68AB17F201                       push    1F217ABh
0x054540: 6864471F2D                       push    2D1F4764h
0x05464B: 4D8B4928                         mov     r9, [r9+28h]
0x36B9CD: 4D8BA9B0000000                   mov     r13, [r9+0B0h]
0x36BA3B: 498BB9A0000000                   mov     rdi, [r9+0A0h]
0x05465D: 4D0FB6ED                         movzx   r13, r13b
0x054737: 498B7928                         mov     rdi, [r9+28h]
0x36BB05: 0FAE97E0000000                   ldmxcsr dword ptr [rdi+0E0h]
0x054742: 4D8B7128                         mov     r14, [r9+28h]
0x36BB73: 4D8BB6B0000000                   mov     r14, [r14+0B0h]
0x36BBDC: 48BF61F87DF100000000             mov     rdi, 0F17DF861h
0x36BC45: 4881C75F528B4E                   add     rdi, 4E8B525Fh
0x054847: 498B7928                         mov     rdi, [r9+28h]
0x05484B: 0FAE5734                         ldmxcsr dword ptr [rdi+34h]
0x36BD0F: 488BAFA0000000                   mov     rbp, [rdi+0A0h]
0x36BD7C: 4C8BA7E8000000                   mov     r12, [rdi+0E8h]
0x054944: 498B4128                         mov     rax, [r9+28h]
0x36BE4C: 488BB8D8000000                   mov     rdi, [rax+0D8h]
0x05494F: 448B6034                         mov     r12d, [rax+34h]
0x36BEB2: 4C03A0A0000000                   add     r12, [rax+0A0h]
0x05495A: 458A1424                         mov     r10b, [r12]
0x36BF1A: 49C7C3FF000000                   mov     r11, 0FFh
0x054965: 49C1E310                         shl     r11, 10h
0x054969: 49F7D3                           not     r11
0x05496C: 4C21DF                           and     rdi, r11
0x05496F: 4D0FB6DA                         movzx   r11, r10b
0x054973: 49C1E310                         shl     r11, 10h
0x054977: 4C09DF                           or      rdi, r11
0x054A5D: 498B5928                         mov     rbx, [r9+28h]
0x36BFF4: 488B83B0000000                   mov     rax, [rbx+0B0h]
0x054A68: 50                               push    rax
0x054A69: 4989E4                           mov     r12, rsp
0x36C059: 488BB3B0000000                   mov     rsi, [rbx+0B0h]
0x054B62: 498B4128                         mov     rax, [r9+28h]
0x36C129: 488B88D8000000                   mov     rcx, [rax+0D8h]
0x36C190: 488BA8A8000000                   mov     rbp, [rax+0A8h]
0x054B74: 51                               push    rcx
0x054B75: 68657F901F                       push    1F907F65h
0x054B7A: 68483AE655                       push    55E63A48h
0x054B7F: 686967B84E                       push    4EB86769h
0x054C6E: 4D8B4128                         mov     r8, [r9+28h]
0x36C25D: 4D8BA0D0000000                   mov     r12, [r8+0D0h]
0x36C2C4: 498BA8A0000000                   mov     rbp, [r8+0A0h]
0x054C80: 4D0FB6E4                         movzx   r12, r12b
0x054D64: 498B7928                         mov     rdi, [r9+28h]
0x36C391: 0FAE97D8000000                   ldmxcsr dword ptr [rdi+0D8h]
0x054D6F: 4D8B4128                         mov     r8, [r9+28h]
0x36C3FD: 4D8BA0A0000000                   mov     r12, [r8+0A0h]
0x36C466: 49BDFD470A2901000000             mov     r13, 1290A47FDh
0x36C4D2: 4981C5C302FF16                   add     r13, 16FF02C3h
0x054E87: 498B7928                         mov     rdi, [r9+28h]
0x054E8B: 0FAE5734                         ldmxcsr dword ptr [rdi+34h]
0x36C5A4: 4C8BBF80000000                   mov     r15, [rdi+80h]
0x36C60D: 488BB7D8000000                   mov     rsi, [rdi+0D8h]
0x054F81: 4D8B4928                         mov     r9, [r9+28h]
0x36C6DD: 498BB1A8000000                   mov     rsi, [r9+0A8h]
0x054F8C: 458B5934                         mov     r11d, [r9+34h]
0x36C74A: 4D0399F0000000                   add     r11, [r9+0F0h]
0x054F97: 458A03                           mov     r8b, [r11]
0x36C7B4: 48C7C2FF000000                   mov     rdx, 0FFh
0x054FA1: 48C1E218                         shl     rdx, 18h
0x054FA5: 48F7D2                           not     rdx
0x054FA8: 4821D6                           and     rsi, rdx
0x054FAB: 490FB6D0                         movzx   rdx, r8b
0x054FAF: 48C1E218                         shl     rdx, 18h
0x054FB3: 4809D6                           or      rsi, rdx
0x055095: 498B4128                         mov     rax, [r9+28h]
0x36C884: 488BB0A8000000                   mov     rsi, [rax+0A8h]
0x36C8F1: 49BF77A9350401000000             mov     r15, 10435A977h
0x36C959: 4981C7710F543C                   add     r15, 3C540F71h
0x055185: 498B5128                         mov     rdx, [r9+28h]
0x36CA32: 4C8BB2A0000000                   mov     r14, [rdx+0A0h]
0x36CA9B: 4C8BA2A8000000                   mov     r12, [rdx+0A8h]
0x055197: 4D0FB6F6                         movzx   r14, r14b
0x055285: 4D8B7128                         mov     r14, [r9+28h]
0x36CB66: 498B86E8000000                   mov     rax, [r14+0E8h]
0x36CBD1: 49C7C5F96C7E8E                   mov     r13, 0FFFFFFFF8E7E6CF9h
0x36CC3A: 4981C518382A72                   add     r13, 722A3818h
0x05529E: 4155                             push    r13
0x36CCA6: 498B9ED8000000                   mov     rbx, [r14+0D8h]
0x0552A7: 48F72424                         mul     qword ptr [rsp]
0x0552AB: 4989C7                           mov     r15, rax
0x055397: 4D8B4928                         mov     r9, [r9+28h]
0x36CD76: 4D8BA190000000                   mov     r12, [r9+90h]
0x36CDDF: 4D2BA1F0000000                   sub     r12, [r9+0F0h]
0x055492: 498B7928                         mov     rdi, [r9+28h]
0x36CEB7: 488BAFD8000000                   mov     rbp, [rdi+0D8h]
0x05549D: 55                               push    rbp
0x05549E: 4889E5                           mov     rbp, rsp
0x36CF22: 4C8BAFD8000000                   mov     r13, [rdi+0D8h]
0x05558F: 498B5128                         mov     rdx, [r9+28h]
0x36CFEC: 488BBAA0000000                   mov     rdi, [rdx+0A0h]
0x36D056: 4C8BAAE0000000                   mov     r13, [rdx+0E0h]
0x0555A1: 57                               push    rdi
0x0555A2: 680500682B                       push    2B680005h
0x0555A7: 68AB67CE2C                       push    2CCE67ABh
0x0555AC: 680E10072D                       push    2D07100Eh
0x0555B1: 682E202A46                       push    462A202Eh
0x0556A0: 498B5128                         mov     rdx, [r9+28h]
0x36D126: 4C8BBAD0000000                   mov     r15, [rdx+0D0h]
0x36D18D: 4C8BA2E0000000                   mov     r12, [rdx+0E0h]
0x0556B2: 4D0FB6FF                         movzx   r15, r15b
0x055792: 4D8B7928                         mov     r15, [r9+28h]
0x36D265: 410FAE97F0000000                 ldmxcsr dword ptr [r15+0F0h]
0x36D2D1: 48BEAF1E0A3401000000             mov     rsi, 1340A1EAFh
0x0557A8: 56                               push    rsi
0x0557A9: 68C75DA670                       push    70A65DC7h
0x0557AE: 689148AC53                       push    53AC4891h
0x0557B3: 68756CBF5B                       push    5BBF6C75h
0x0557B8: 689E56EA16                       push    16EA569Eh
0x36D342: 4881442420112CFF0B               add     [rsp-8+arg_20], 0BFF2C11h
0x0557C6: 498B5128                         mov     rdx, [r9+28h]
0x36D3B1: 4C8BB2D8000000                   mov     r14, [rdx+0D8h]
0x0558AD: 498B5128                         mov     rdx, [r9+28h]
0x0558B1: 0FAE5234                         ldmxcsr dword ptr [rdx+34h]
0x36D47D: 488BB2A8000000                   mov     rsi, [rdx+0A8h]
0x36D4EB: 4C8BA2E8000000                   mov     r12, [rdx+0E8h]
0x05599C: 498B6928                         mov     rbp, [r9+28h]
0x36D5BB: 4C8BBDD8000000                   mov     r15, [rbp+0D8h]
0x0559A7: 448B6534                         mov     r12d, [rbp+34h]
0x36D625: 4C03A5A8000000                   add     r12, [rbp+0A8h]
0x0559B2: 458A0C24                         mov     r9b, [r12]
0x0559B6: 4588CF                           mov     r15b, r9b
0x055A94: 498B7128                         mov     rsi, [r9+28h]
0x36D6F7: 4C8BAEF0000000                   mov     r13, [rsi+0F0h]
0x055A9F: 4155                             push    r13
0x055AA1: 4989E7                           mov     r15, rsp
0x36D75C: 4C8BAEF0000000                   mov     r13, [rsi+0F0h]
0x055B7E: 498B4928                         mov     rcx, [r9+28h]
0x36D82F: 488B99F0000000                   mov     rbx, [rcx+0F0h]
0x36D896: 4C8BA9E0000000                   mov     r13, [rcx+0E0h]
0x055B90: 53                               push    rbx
0x055B91: 681C1E1E4D                       push    4D1E1E1Ch
0x055B96: 684906A11E                       push    1EA10649h
0x055B9B: 68C206D304                       push    4D306C2h
0x055BA0: 6874587108                       push    8715874h
0x055C8A: 498B4128                         mov     rax, [r9+28h]
0x36D95F: 4C8BA8E8000000                   mov     r13, [rax+0E8h]
0x36D9C8: 4C8BB0E0000000                   mov     r14, [rax+0E0h]
0x055C9C: 4D0FB6ED                         movzx   r13, r13b
0x055D72: 498B5128                         mov     rdx, [r9+28h]
0x36DA9A: 0FAE92E0000000                   ldmxcsr dword ptr [rdx+0E0h]
0x36DB07: 49B82DF0FE1101000000             mov     r8, 111FEF02Dh
0x055D87: 4150                             push    r8
0x055D89: 687070D249                       push    49D27070h
0x055D8E: 681C175D31                       push    315D171Ch
0x055D93: 68F0702209                       push    92270F0h
0x055D98: 6873209D59                       push    599D2073h
0x36DB73: 4881442420935A0A2E               add     [rsp-8+arg_20], 2E0A5A93h
0x055DA6: 4D8B4128                         mov     r8, [r9+28h]
0x36DBDF: 4D8BA8E8000000                   mov     r13, [r8+0E8h]
0x055E93: 4D8B4128                         mov     r8, [r9+28h]
0x055E97: 410FAE5034                       ldmxcsr dword ptr [r8+34h]
0x36DCB6: 4D8BB0C8000000                   mov     r14, [r8+0C8h]
0x36DD1B: 498BB8E0000000                   mov     rdi, [r8+0E0h]
0x055F96: 4D8B4128                         mov     r8, [r9+28h]
0x36DDE7: 498BB8B0000000                   mov     rdi, [r8+0B0h]
0x055FA1: 458B6034                         mov     r12d, [r8+34h]
0x36DE4C: 4D03A0E8000000                   add     r12, [r8+0E8h]
0x055FAC: 418A0C24                         mov     cl, [r12]
0x36DEB8: 49C7C7FF000000                   mov     r15, 0FFh
0x055FB7: 49C1E708                         shl     r15, 8
0x055FBB: 49F7D7                           not     r15
0x055FBE: 4C21FF                           and     rdi, r15
0x055FC1: 4C0FB6F9                         movzx   r15, cl
0x055FC5: 49C1E708                         shl     r15, 8
0x055FC9: 4C09FF                           or      rdi, r15
0x0560C7: 498B4128                         mov     rax, [r9+28h]
0x36DF8B: 4C8BA0B0000000                   mov     r12, [rax+0B0h]
0x0560D2: 4154                             push    r12
0x0560D4: 4889E5                           mov     rbp, rsp
0x36DFF8: 4C8BA8B0000000                   mov     r13, [rax+0B0h]
0x0561C8: 4D8B4128                         mov     r8, [r9+28h]
0x36E0C5: 498BA8F0000000                   mov     rbp, [r8+0F0h]
0x36E12C: 4D8BA8E0000000                   mov     r13, [r8+0E0h]
0x0561DA: 480FB6ED                         movzx   rbp, bpl
0x0562C5: 4D8B4128                         mov     r8, [r9+28h]
0x36E1FD: 410FAE90A0000000                 ldmxcsr dword ptr [r8+0A0h]
0x0562D1: 498B4128                         mov     rax, [r9+28h]
0x36E269: 4C8BA8E0000000                   mov     r13, [rax+0E0h]
0x36E2D1: 49BC8ADE963B01000000             mov     r12, 13B96DE8Ah
0x36E33D: 4981C4366C7204                   add     r12, 4726C36h
0x0563E3: 498B7128                         mov     rsi, [r9+28h]
0x0563E7: 0FAE5634                         ldmxcsr dword ptr [rsi+34h]
0x36E40E: 4C8BAED0000000                   mov     r13, [rsi+0D0h]
0x36E477: 488BB6E0000000                   mov     rsi, [rsi+0E0h]
0x0564C6: 4D8B6928                         mov     r13, [r9+28h]
0x36E547: 498BADA8000000                   mov     rbp, [r13+0A8h]
0x0564D1: 458B7D34                         mov     r15d, [r13+34h]
0x36E5AC: 4D03BDE0000000                   add     r15, [r13+0E0h]
0x0564DC: 458A3F                           mov     r15b, [r15]
0x36E618: 48C7C2FF000000                   mov     rdx, 0FFh
0x0564E6: 48C1E210                         shl     rdx, 10h
0x0564EA: 48F7D2                           not     rdx
0x0564ED: 4821D5                           and     rbp, rdx
0x0564F0: 490FB6D7                         movzx   rdx, r15b
0x0564F4: 48C1E210                         shl     rdx, 10h
0x0564F8: 4809D5                           or      rbp, rdx
0x0565D9: 4D8B7128                         mov     r14, [r9+28h]
0x36E6EA: 498BBEA0000000                   mov     rdi, [r14+0A0h]
0x0565E4: 57                               push    rdi
0x0565E5: 4989E4                           mov     r12, rsp
0x36E753: 4D8BBEA0000000                   mov     r15, [r14+0A0h]
0x0566DF: 4D8B5128                         mov     r10, [r9+28h]
0x36E824: 4D8BA288000000                   mov     r12, [r10+88h]
0x36E88E: 4D8BAAF0000000                   mov     r13, [r10+0F0h]
0x0566F1: 4D0FB6E4                         movzx   r12, r12b
0x0567DD: 4D8B5128                         mov     r10, [r9+28h]
0x36E95D: 410FAE92D8000000                 ldmxcsr dword ptr [r10+0D8h]
0x0567E9: 4D8B6928                         mov     r13, [r9+28h]
0x36E9C8: 498BADE0000000                   mov     rbp, [r13+0E0h]
0x36EA31: 49BD94F2D72F01000000             mov     r13, 12FD7F294h
0x36EA9B: 4981C52C583110                   add     r13, 1031582Ch
0x0568EE: 4D8B7128                         mov     r14, [r9+28h]
0x0568F2: 410FAE5634                       ldmxcsr dword ptr [r14+34h]
0x36EB6E: 4D8BAE80000000                   mov     r13, [r14+80h]
0x36EBD6: 498BBEA0000000                   mov     rdi, [r14+0A0h]
0x0569DA: 498B5128                         mov     rdx, [r9+28h]
0x36ECAE: 4C8BBAB0000000                   mov     r15, [rdx+0B0h]
0x0569E5: 448B4234                         mov     r8d, [rdx+34h]
0x36ED15: 4C0382E0000000                   add     r8, [rdx+0E0h]
0x0569F0: 458A20                           mov     r12b, [r8]
0x36ED80: 49C7C5FF000000                   mov     r13, 0FFh
0x0569FA: 49C1E518                         shl     r13, 18h
0x0569FE: 49F7D5                           not     r13
0x056A01: 4D21EF                           and     r15, r13
0x056A04: 4D0FB6EC                         movzx   r13, r12b
0x056A08: 49C1E518                         shl     r13, 18h
0x056A0C: 4D09EF                           or      r15, r13
0x056AED: 498B4928                         mov     rcx, [r9+28h]
0x36EE53: 4C8BA1F0000000                   mov     r12, [rcx+0F0h]
0x056AF8: 4154                             push    r12
0x056AFA: 4889E3                           mov     rbx, rsp
0x36EEB8: 488BB1F0000000                   mov     rsi, [rcx+0F0h]
0x056BE4: 498B7928                         mov     rdi, [r9+28h]
0x36EF89: 4C8BAFA0000000                   mov     r13, [rdi+0A0h]
0x36EFF3: 4C8BB7A8000000                   mov     r14, [rdi+0A8h]
0x056BF6: 4D0FB6ED                         movzx   r13, r13b
0x056CDC: 498B4928                         mov     rcx, [r9+28h]
0x36F0C2: 0FAE91E0000000                   ldmxcsr dword ptr [rcx+0E0h]
0x36F12B: 49BA7509C33001000000             mov     r10, 130C30975h
0x056CF1: 4152                             push    r10
0x056CF3: 68DD5D2F1A                       push    1A2F5DDDh
0x056CF8: 68E737E445                       push    45E437E7h
0x056CFD: 68ED088751                       push    518708EDh
0x36F194: 48814424184B41460F               add     qword ptr [rsp+18h], 0F46414Bh
0x056D0B: 498B7928                         mov     rdi, [r9+28h]
0x36F203: 4C8BAFE8000000                   mov     r13, [rdi+0E8h]
0x056DF4: 4D8B4928                         mov     r9, [r9+28h]
0x056DF8: 410FAE5134                       ldmxcsr dword ptr [r9+34h]
0x36F2D4: 498BB9B0000000                   mov     rdi, [r9+0B0h]
0x36F341: 4D8BB9E0000000                   mov     r15, [r9+0E0h]
0x056EDF: 4D8B5128                         mov     r10, [r9+28h]
0x36F415: 4D8BAAF0000000                   mov     r13, [r10+0F0h]
0x056EEA: 418B4234                         mov     eax, [r10+34h]
0x36F47B: 490382B0000000                   add     rax, [r10+0B0h]
0x056EF5: 408A30                           mov     sil, [rax]
0x36F4E8: 48C7C7FF000000                   mov     rdi, 0FFh
0x056EFF: 48C1E730                         shl     rdi, 30h
0x056F03: 48F7D7                           not     rdi
0x056F06: 4921FD                           and     r13, rdi
0x056F09: 480FB6FE                         movzx   rdi, sil
0x056F0D: 48C1E730                         shl     rdi, 30h
0x056F11: 4909FD                           or      r13, rdi
0x056FF1: 4D8B5928                         mov     r11, [r9+28h]
0x36F5B9: 498B9BE0000000                   mov     rbx, [r11+0E0h]
0x36F620: 49BCE9A2A13F01000000             mov     r12, 13FA1A2E9h
0x36F68A: 4981C4FF15E800                   add     r12, 0E815FFh
0x057102: 498B5128                         mov     rdx, [r9+28h]
0x36F756: 4C8BA2B0000000                   mov     r12, [rdx+0B0h]
0x36F7BD: 4C8BB290000000                   mov     r14, [rdx+90h]
0x057114: 4D0FB6E4                         movzx   r12, r12b
0x0571F1: 4D8B4128                         mov     r8, [r9+28h]
0x36F88D: 498B80D8000000                   mov     rax, [r8+0D8h]
0x36F8FB: 48C7C2211357FD                   mov     rdx, 0FFFFFFFFFD571321h
0x36F965: 4881C26C337C03                   add     rdx, 37C336Ch
0x05720A: 52                               push    rdx
0x36F9CB: 4D8BA0E8000000                   mov     r12, [r8+0E8h]
0x057212: 48F72424                         mul     qword ptr [rsp]
0x057216: 4889C6                           mov     rsi, rax
0x0572FD: 4D8B5928                         mov     r11, [r9+28h]
0x36FAA1: 4D8BB3D8000000                   mov     r14, [r11+0D8h]
0x36FB0D: 4D03B3A8000000                   add     r14, [r11+0A8h]
0x0573FF: 498B4928                         mov     rcx, [r9+28h]
0x36FBDF: 4C8BA9E8000000                   mov     r13, [rcx+0E8h]
0x05740A: 4155                             push    r13
0x05740C: 4989E7                           mov     r15, rsp
0x36FC4C: 488BA9E8000000                   mov     rbp, [rcx+0E8h]
0x0574F2: 498B5928                         mov     rbx, [r9+28h]
0x36FD1F: 4C8BB3D8000000                   mov     r14, [rbx+0D8h]
0x36FD87: 488BABA0000000                   mov     rbp, [rbx+0A0h]
0x057504: 4D0FB6F6                         movzx   r14, r14b
0x0575F7: 4D8B7928                         mov     r15, [r9+28h]
0x36FE5F: 410FAE97E8000000                 ldmxcsr dword ptr [r15+0E8h]
0x36FEC5: 48B80601ACD400000000             mov     rax, 0D4AC0106h
0x36FF2D: 4805BA615D6B                     add     rax, 6B5D61BAh
0x36FF95: 488B8040020000                   mov     rax, [rax+240h]
0x370002: 490387E8000000                   add     rax, [r15+0E8h]
0x057621: 8A18                             mov     bl, [rax]
0x057623: 480FB6DB                         movzx   rbx, bl
0x057627: 48C1E308                         shl     rbx, 8
0x370069: 49019FA0000000                   add     [r15+0A0h], rbx
0x057632: 4D8B4928                         mov     r9, [r9+28h]
0x3700CE: 498BA9A0000000                   mov     rbp, [r9+0A0h]
0x370137: 48BBFDEC63F000000000             mov     rbx, 0F063ECFDh
0x3701A4: 4881C3C36DA54F                   add     rbx, 4FA56DC3h
0x05773D: 498B7928                         mov     rdi, [r9+28h]
0x057741: 0FAE5734                         ldmxcsr dword ptr [rdi+34h]
0x370278: 4C8BAFA8000000                   mov     r13, [rdi+0A8h]
0x3702E2: 4C8BBFA0000000                   mov     r15, [rdi+0A0h]
0x057836: 4D8B7128                         mov     r14, [r9+28h]
0x3703BA: 4D8BBEF0000000                   mov     r15, [r14+0F0h]
0x057841: 418B7634                         mov     esi, [r14+34h]
0x370421: 4903B6E0000000                   add     rsi, [r14+0E0h]
0x05784C: 448A36                           mov     r14b, [rsi]
0x05784F: 4588F7                           mov     r15b, r14b
0x05792D: 4D8B6928                         mov     r13, [r9+28h]
0x3704F6: 4D8B95F0000000                   mov     r10, [r13+0F0h]
0x057938: 4152                             push    r10
0x05793A: 4989E4                           mov     r12, rsp
0x37055F: 4D8BBDF0000000                   mov     r15, [r13+0F0h]
0x057A22: 4D8B5928                         mov     r11, [r9+28h]
0x370630: 4D8BABD8000000                   mov     r13, [r11+0D8h]
0x37069B: 4D8BA3F0000000                   mov     r12, [r11+0F0h]
0x057A34: 4155                             push    r13
0x057A36: 68AC758F0B                       push    0B8F75ACh
0x057A3B: 688F470901                       push    109478Fh
0x057A40: 68D918A11E                       push    1EA118D9h
0x057A45: 680B76AC01                       push    1AC760Bh
0x057B2F: 4D8B5128                         mov     r10, [r9+28h]
0x370772: 4D8BA2C8000000                   mov     r12, [r10+0C8h]
0x3707DF: 498BBAD8000000                   mov     rdi, [r10+0D8h]
0x057B41: 4D0FB6E4                         movzx   r12, r12b
0x057C22: 498B5928                         mov     rbx, [r9+28h]
0x3708B7: 0FAE93D8000000                   ldmxcsr dword ptr [rbx+0D8h]
0x370920: 49BDA737AF3201000000             mov     r13, 132AF37A7h
0x37098C: 4981C5192B5A0D                   add     r13, 0D5A2B19h
0x3709F4: 4D8BADD8030000                   mov     r13, [r13+3D8h]
0x370A5B: 4C03ABD8000000                   add     r13, [rbx+0D8h]
0x057C4C: 458A7D00                         mov     r15b, [r13+0]
0x057C50: 4D0FB6FF                         movzx   r15, r15b
0x057C54: 49C1E710                         shl     r15, 10h
0x370AC9: 4C01BBB0000000                   add     [rbx+0B0h], r15
0x370B36: 49BC4DECE5F500000000             mov     r12, 0F5E5EC4Dh
0x057C69: 4154                             push    r12
0x057C6B: 68C6047543                       push    437504C6h
0x057C70: 688C740E2F                       push    2F0E748Ch
0x057C75: 68A9162759                       push    592716A9h
0x057C7A: 6852243713                       push    13372452h
0x370BA7: 4881442420736E234A               add     qword ptr [rsp+20h], 4A236E73h
0x057C88: 4D8B5128                         mov     r10, [r9+28h]
0x370C11: 498BB2B0000000                   mov     rsi, [r10+0B0h]
0x057D82: 498B5928                         mov     rbx, [r9+28h]
0x057D86: 0FAE5334                         ldmxcsr dword ptr [rbx+34h]
0x370CE0: 4C8BB390000000                   mov     r14, [rbx+90h]
0x370D4A: 4C8BABA8000000                   mov     r13, [rbx+0A8h]
0x057E75: 498B5128                         mov     rdx, [r9+28h]
0x370E1B: 488BAAE0000000                   mov     rbp, [rdx+0E0h]
0x057E80: 448B7234                         mov     r14d, [rdx+34h]
0x370E87: 4C03B2E8000000                   add     r14, [rdx+0E8h]
0x057E8B: 418A16                           mov     dl, [r14]
0x370EF3: 49C7C3FF000000                   mov     r11, 0FFh
0x057E95: 49C1E308                         shl     r11, 8
0x057E99: 49F7D3                           not     r11
0x057E9C: 4C21DD                           and     rbp, r11
0x057E9F: 4C0FB6DA                         movzx   r11, dl
0x057EA3: 49C1E308                         shl     r11, 8
0x057EA7: 4C09DD                           or      rbp, r11
0x057F7E: 4D8B7128                         mov     r14, [r9+28h]
0x370FC3: 498B9EA0000000                   mov     rbx, [r14+0A0h]
0x057F89: 53                               push    rbx
0x057F8A: 4889E3                           mov     rbx, rsp
0x37102C: 4D8BB6A0000000                   mov     r14, [r14+0A0h]
0x058075: 498B5928                         mov     rbx, [r9+28h]
0x371104: 4C8BBB90000000                   mov     r15, [rbx+90h]
0x371170: 488BABE8000000                   mov     rbp, [rbx+0E8h]
0x058087: 4157                             push    r15
0x058089: 68EE623233                       push    333262EEh
0x05808E: 685E739F02                       push    29F735Eh
0x058093: 687E7D2E0B                       push    0B2E7D7Eh
0x058098: 6871487851                       push    51784871h
0x05818A: 4D8B6928                         mov     r13, [r9+28h]
0x37123D: 498B9D88000000                   mov     rbx, [r13+88h]
0x3712A9: 498BBDA0000000                   mov     rdi, [r13+0A0h]
0x05819C: 480FB6DB                         movzx   rbx, bl
0x058278: 4D8B5128                         mov     r10, [r9+28h]
0x371372: 410FAE9290000000                 ldmxcsr dword ptr [r10+90h]
0x3713DD: 48BE5F44AADA00000000             mov     rsi, 0DAAA445Fh
0x37144A: 4881C6611E5F65                   add     rsi, 655F1E61h
0x3714B8: 488BB6E8020000                   mov     rsi, [rsi+2E8h]
0x371520: 4903B290000000                   add     rsi, [r10+90h]
0x0582A3: 448A1E                           mov     r11b, [rsi]
0x0582A6: 4D0FB6DB                         movzx   r11, r11b
0x0582AA: 49C1E318                         shl     r11, 18h
0x37158B: 4D019AB0000000                   add     [r10+0B0h], r11
0x3715F8: 49BAAD4893FF00000000             mov     r10, 0FF9348ADh
0x0582BF: 4152                             push    r10
0x0582C1: 68270A7716                       push    16770A27h
0x0582C6: 688B3DB50B                       push    0BB53D8Bh
0x0582CB: 68B5203146                       push    463120B5h
0x371669: 488144241813127640               add     qword ptr [rsp+18h], 40761213h
0x0582D9: 4D8B7128                         mov     r14, [r9+28h]
0x3716D4: 4D8BBEB0000000                   mov     r15, [r14+0B0h]
0x0583D5: 4D8B5128                         mov     r10, [r9+28h]
0x0583D9: 410FAE5234                       ldmxcsr dword ptr [r10+34h]
0x3717A2: 498BAAD8000000                   mov     rbp, [r10+0D8h]
0x371807: 498BBAF0000000                   mov     rdi, [r10+0F0h]
0x0584CD: 4D8B5128                         mov     r10, [r9+28h]
0x3718D8: 4D8BA2B0000000                   mov     r12, [r10+0B0h]
0x0584D8: 418B6A34                         mov     ebp, [r10+34h]
0x371940: 4903AAA0000000                   add     rbp, [r10+0A0h]
0x0584E3: 408A7500                         mov     sil, [rbp+0]
0x3719AE: 48C7C0FF000000                   mov     rax, 0FFh
0x0584EE: 48C1E010                         shl     rax, 10h
0x0584F2: 48F7D0                           not     rax
0x0584F5: 4921C4                           and     r12, rax
0x0584F8: 480FB6C6                         movzx   rax, sil
0x0584FC: 48C1E010                         shl     rax, 10h
0x058500: 4909C4                           or      r12, rax
0x0585DC: 498B6928                         mov     rbp, [r9+28h]
0x371A7B: 488B9DD8000000                   mov     rbx, [rbp+0D8h]
0x0585E7: 53                               push    rbx
0x0585E8: 4889E6                           mov     rsi, rsp
0x371AE7: 4C8BB5D8000000                   mov     r14, [rbp+0D8h]
0x0586DB: 498B7928                         mov     rdi, [r9+28h]
0x371BBA: 488BB788000000                   mov     rsi, [rdi+88h]
0x371C21: 4C8BAFE8000000                   mov     r13, [rdi+0E8h]
0x0586ED: 480FB6F6                         movzx   rsi, sil
0x0587DD: 498B4128                         mov     rax, [r9+28h]
0x371CEE: 0FAE90A8000000                   ldmxcsr dword ptr [rax+0A8h]
0x371D5C: 49B8D43A6FDB00000000             mov     r8, 0DB6F3AD4h
0x371DCB: 4981C0EC279A64                   add     r8, 649A27ECh
0x371E37: 4D8B8050020000                   mov     r8, [r8+250h]
0x371E9C: 4C0380A8000000                   add     r8, [rax+0A8h]
0x058807: 458A18                           mov     r11b, [r8]
0x05880A: 4D0FB6DB                         movzx   r11, r11b
0x05880E: 49C1E320                         shl     r11, 20h
0x371F04: 4C0198E0000000                   add     [rax+0E0h], r11
0x058819: 498B7128                         mov     rsi, [r9+28h]
0x371F71: 4C8BAEE0000000                   mov     r13, [rsi+0E0h]
0x371FDE: 48BF0EEF5E2201000000             mov     rdi, 1225EEF0Eh
0x37204E: 4881C7B26BAA1D                   add     rdi, 1DAA6BB2h
0x058932: 498B7128                         mov     rsi, [r9+28h]
0x058936: 0FAE5634                         ldmxcsr dword ptr [rsi+34h]
0x372127: 4C8BA6D0000000                   mov     r12, [rsi+0D0h]
0x372193: 488BBEE0000000                   mov     rdi, [rsi+0E0h]
0x058A2F: 498B4128                         mov     rax, [r9+28h]
0x37225D: 4C8BA0B0000000                   mov     r12, [rax+0B0h]
0x058A3A: 448B4034                         mov     r8d, [rax+34h]
0x3722CB: 4C0380D8000000                   add     r8, [rax+0D8h]
0x058A45: 458A10                           mov     r10b, [r8]
0x372337: 48C7C1FF000000                   mov     rcx, 0FFh
0x058A4F: 48C1E118                         shl     rcx, 18h
0x058A53: 48F7D1                           not     rcx
0x058A56: 4921CC                           and     r12, rcx
0x058A59: 490FB6CA                         movzx   rcx, r10b
0x058A5D: 48C1E118                         shl     rcx, 18h
0x058A61: 4909CC                           or      r12, rcx
0x058B4B: 4D8B6128                         mov     r12, [r9+28h]
0x372404: 4D8B8424D8000000                 mov     r8, [r12+0D8h]
0x058B57: 4150                             push    r8
0x058B59: 4889E6                           mov     rsi, rsp
0x37246E: 4D8BAC24D8000000                 mov     r13, [r12+0D8h]
0x058C48: 4D8B6128                         mov     r12, [r9+28h]
0x058C4C: 4D8B742478                       mov     r14, [r12+78h]
0x372540: 498BB424E0000000                 mov     rsi, [r12+0E0h]
0x058C59: 4D0FB6F6                         movzx   r14, r14b
0x058D3C: 498B4928                         mov     rcx, [r9+28h]
0x372614: 0FAE91E8000000                   ldmxcsr dword ptr [rcx+0E8h]
0x058D47: 4D8B6128                         mov     r12, [r9+28h]
0x372681: 498BBC24A8000000                 mov     rdi, [r12+0A8h]
0x3726E7: 49BE7722001901000000             mov     r14, 119002277h
0x372750: 4981C649380927                   add     r14, 27093849h
0x058E56: 4D8B4928                         mov     r9, [r9+28h]
0x058E5A: 410FAE5134                       ldmxcsr dword ptr [r9+34h]
0x37281F: 498BB1A8000000                   mov     rsi, [r9+0A8h]
0x372885: 498B99B0000000                   mov     rbx, [r9+0B0h]
0x058F4C: 498B7128                         mov     rsi, [r9+28h]
0x372955: 488BBE90000000                   mov     rdi, [rsi+90h]
0x058F57: 8B4634                           mov     eax, [rsi+34h]
0x3729BF: 480386A8000000                   add     rax, [rsi+0A8h]
0x058F61: 408A28                           mov     bpl, [rax]
0x372A27: 49C7C1FF000000                   mov     r9, 0FFh
0x058F6B: 49C1E138                         shl     r9, 38h
0x058F6F: 49F7D1                           not     r9
0x058F72: 4C21CF                           and     rdi, r9
0x058F75: 4C0FB6CD                         movzx   r9, bpl
0x058F79: 49C1E138                         shl     r9, 38h
0x058F7D: 4C09CF                           or      rdi, r9
0x059063: 498B5928                         mov     rbx, [r9+28h]
0x372AF3: 4C8BA3B0000000                   mov     r12, [rbx+0B0h]
0x05906E: 4154                             push    r12
0x059070: 4989E7                           mov     r15, rsp
0x372B5A: 488B9BB0000000                   mov     rbx, [rbx+0B0h]
0x05914B: 4D8B7928                         mov     r15, [r9+28h]
0x372C29: 498BAFF0000000                   mov     rbp, [r15+0F0h]
0x372C8F: 4D8BBF90000000                   mov     r15, [r15+90h]
0x05915D: 55                               push    rbp
0x05915E: 681E7D6D2E                       push    2E6D7D1Eh
0x059163: 68DA1AFC1C                       push    1CFC1ADAh
0x059168: 6807278163                       push    63812707h
0x059259: 498B5928                         mov     rbx, [r9+28h]
0x372D60: 4C8BBB80000000                   mov     r15, [rbx+80h]
0x372DCB: 488B9BF0000000                   mov     rbx, [rbx+0F0h]
0x05926B: 4D0FB6FF                         movzx   r15, r15b
0x059349: 4D8B6128                         mov     r12, [r9+28h]
0x372EA1: 410FAE9424F0000000               ldmxcsr dword ptr [r12+0F0h]
0x372F0E: 48BA1412F32001000000             mov     rdx, 120F31214h
0x372F7A: 4881C2AC60161F                   add     rdx, 1F1660ACh
0x372FE4: 488B9210050000                   mov     rdx, [rdx+510h]
0x373051: 49039424F0000000                 add     rdx, [r12+0F0h]
0x059376: 8A02                             mov     al, [rdx]
0x059378: 480FB6C0                         movzx   rax, al
0x05937C: 48C1E008                         shl     rax, 8
0x3730B9: 4929842490000000                 sub     [r12+90h], rax
0x059388: 4D8B7128                         mov     r14, [r9+28h]
0x373126: 498BAE90000000                   mov     rbp, [r14+90h]
0x373194: 48BB48F0E70601000000             mov     rbx, 106E7F048h
0x373200: 4881C3787A2139                   add     rbx, 39217A78h
0x059485: 498B7928                         mov     rdi, [r9+28h]
0x059489: 0FAE5734                         ldmxcsr dword ptr [rdi+34h]
0x3732CE: 4C8BA7E0000000                   mov     r12, [rdi+0E0h]
0x373333: 488B9FA0000000                   mov     rbx, [rdi+0A0h]
0x059574: 498B5928                         mov     rbx, [r9+28h]
0x3733FF: 488BB390000000                   mov     rsi, [rbx+90h]
0x05957F: 448B6B34                         mov     r13d, [rbx+34h]
0x373465: 4C03ABD8000000                   add     r13, [rbx+0D8h]
0x05958A: 458A7500                         mov     r14b, [r13+0]
0x05958E: 4488F6                           mov     sil, r14b
0x059677: 498B5128                         mov     rdx, [r9+28h]
0x37353B: 4C8B82A8000000                   mov     r8, [rdx+0A8h]
0x059682: 4150                             push    r8
0x059684: 4989E6                           mov     r14, rsp
0x3735A2: 488BAAA8000000                   mov     rbp, [rdx+0A8h]
0x05977C: 4D8B7928                         mov     r15, [r9+28h]
0x373672: 4D8BA7E8000000                   mov     r12, [r15+0E8h]
0x3736E0: 4D8BAFA0000000                   mov     r13, [r15+0A0h]
0x05978E: 4D0FB6E4                         movzx   r12, r12b
0x059878: 4D8B6128                         mov     r12, [r9+28h]
0x3737AE: 410FAE9424D8000000               ldmxcsr dword ptr [r12+0D8h]
0x37381E: 48BE28355BEF00000000             mov     rsi, 0EF5B3528h
0x373886: 4881C6983DAE50                   add     rsi, 50AE3D98h
0x3738F2: 488BB690000000                   mov     rsi, [rsi+90h]
0x373957: 4903B424D8000000                 add     rsi, [r12+0D8h]
0x0598A5: 448A3E                           mov     r15b, [rsi]
0x0598A8: 4D0FB6FF                         movzx   r15, r15b
0x0598AC: 49C1E710                         shl     r15, 10h
0x3739C3: 4D29BC24E0000000                 sub     [r12+0E0h], r15
0x0598B8: 4D8B5928                         mov     r11, [r9+28h]
0x373A30: 4D8BABE0000000                   mov     r13, [r11+0E0h]
0x373A99: 48BBBD03D1F400000000             mov     rbx, 0F4D103BDh
0x373B0A: 4881C30367384B                   add     rbx, 4B386703h
0x0599D1: 498B4928                         mov     rcx, [r9+28h]
0x0599D5: 0FAE5134                         ldmxcsr dword ptr [rcx+34h]
0x373BDC: 4C8BA188000000                   mov     r12, [rcx+88h]
0x373C42: 488B99E0000000                   mov     rbx, [rcx+0E0h]
0x059AD6: 4D8B4928                         mov     r9, [r9+28h]
0x373D16: 4D8BA190000000                   mov     r12, [r9+90h]
0x059AE1: 458B7134                         mov     r14d, [r9+34h]
0x373D81: 4D03B1D8000000                   add     r14, [r9+0D8h]
0x059AEC: 458A3E                           mov     r15b, [r14]
0x373DE6: 49C7C2FF000000                   mov     r10, 0FFh
0x059AF6: 49C1E208                         shl     r10, 8
0x059AFA: 49F7D2                           not     r10
0x059AFD: 4D21D4                           and     r12, r10
0x059B00: 4D0FB6D7                         movzx   r10, r15b
0x059B04: 49C1E208                         shl     r10, 8
0x059B08: 4D09D4                           or      r12, r10
0x059BEF: 4D8B5928                         mov     r11, [r9+28h]
0x373EB3: 498BABD8000000                   mov     rbp, [r11+0D8h]
0x059BFA: 55                               push    rbp
0x059BFB: 4889E5                           mov     rbp, rsp
0x373F20: 498B9BD8000000                   mov     rbx, [r11+0D8h]
0x059CF7: 4D8B6928                         mov     r13, [r9+28h]
0x373FEE: 498BB5D8000000                   mov     rsi, [r13+0D8h]
0x37405A: 4D8BA590000000                   mov     r12, [r13+90h]
0x059D09: 480FB6F6                         movzx   rsi, sil
0x059DE8: 4D8B4128                         mov     r8, [r9+28h]
0x374131: 410FAE90A8000000                 ldmxcsr dword ptr [r8+0A8h]
0x37419C: 49BA81538DED00000000             mov     r10, 0ED8D5381h
0x374207: 4981C23F1F7C52                   add     r10, 527C1F3Fh
0x37426D: 4D8B9220030000                   mov     r10, [r10+320h]
0x3742D8: 4D0390A8000000                   add     r10, [r8+0A8h]
0x059E13: 418A02                           mov     al, [r10]
0x059E16: 480FB6C0                         movzx   rax, al
0x059E1A: 48C1E018                         shl     rax, 18h
0x374342: 492980D8000000                   sub     [r8+0D8h], rax
0x3743A9: 49BA7DFC6C2901000000             mov     r10, 1296CFC7Dh
0x059E2F: 4152                             push    r10
0x059E31: 68451A5B76                       push    765B1A45h
0x059E36: 685A554625                       push    2546555Ah
0x059E3B: 68B35A0947                       push    47095AB3h
0x374412: 4881442418436E9C16               add     [rsp-8+arg_18], 169C6E43h
0x059E49: 4D8B7928                         mov     r15, [r9+28h]
0x374482: 4D8BBFD8000000                   mov     r15, [r15+0D8h]
0x059F2B: 4D8B6128                         mov     r12, [r9+28h]
0x374554: 410FAE542434                     ldmxcsr dword ptr [r12+34h]
0x3745B9: 4D8BB424A0000000                 mov     r14, [r12+0A0h]
0x37461F: 498BB424F0000000                 mov     rsi, [r12+0F0h]
0x05A01B: 498B6928                         mov     rbp, [r9+28h]
0x3746F7: 488BBDA8000000                   mov     rdi, [rbp+0A8h]
0x05A026: 8B5D34                           mov     ebx, [rbp+34h]
0x374765: 48039DE8000000                   add     rbx, [rbp+0E8h]
0x05A030: 8A1B                             mov     bl, [rbx]
0x3747D3: 48C7C0FF000000                   mov     rax, 0FFh
0x05A039: 48C1E010                         shl     rax, 10h
0x05A03D: 48F7D0                           not     rax
0x05A040: 4821C7                           and     rdi, rax
0x05A043: 480FB6C3                         movzx   rax, bl
0x05A047: 48C1E010                         shl     rax, 10h
0x05A04B: 4809C7                           or      rdi, rax
0x05A11F: 4D8B7928                         mov     r15, [r9+28h]
0x3748A0: 4D8B97B0000000                   mov     r10, [r15+0B0h]
0x05A12A: 4152                             push    r10
0x05A12C: 4989E5                           mov     r13, rsp
0x374906: 498BBFB0000000                   mov     rdi, [r15+0B0h]
0x05A21E: 498B5928                         mov     rbx, [r9+28h]
0x3749D5: 488BB3C8000000                   mov     rsi, [rbx+0C8h]
0x374A41: 488BBBB0000000                   mov     rdi, [rbx+0B0h]
0x05A230: 480FB6F6                         movzx   rsi, sil
0x05A312: 498B5928                         mov     rbx, [r9+28h]
0x374B0B: 0FAE93A8000000                   ldmxcsr dword ptr [rbx+0A8h]
0x374B70: 48BEDA23082901000000             mov     rsi, 1290823DAh
0x374BDE: 4881C6E64E0117                   add     rsi, 17014EE6h
0x374C43: 488BB678070000                   mov     rsi, [rsi+778h]
0x374CA8: 4803B3A8000000                   add     rsi, [rbx+0A8h]
0x05A33C: 448A26                           mov     r12b, [rsi]
0x05A33F: 4D0FB6E4                         movzx   r12, r12b
0x05A343: 49C1E420                         shl     r12, 20h
0x374D14: 4C29A3B0000000                   sub     [rbx+0B0h], r12
0x05A34E: 4D8B6128                         mov     r12, [r9+28h]
0x374D7B: 498BAC24B0000000                 mov     rbp, [r12+0B0h]
0x374DE6: 49BE0F4DF7C100000000             mov     r14, 0C1F74D0Fh
0x374E53: 4981C6B11D127E                   add     r14, 7E121DB1h
0x05A450: 498B5128                         mov     rdx, [r9+28h]
0x05A454: 0FAE5234                         ldmxcsr dword ptr [rdx+34h]
0x374F25: 4C8BBAE0000000                   mov     r15, [rdx+0E0h]
0x374F90: 488BAAA0000000                   mov     rbp, [rdx+0A0h]
0x05A53F: 4D8B6128                         mov     r12, [r9+28h]
0x37505F: 4D8BAC24A0000000                 mov     r13, [r12+0A0h]
0x05A54B: 418B6C2434                       mov     ebp, [r12+34h]
0x3750C9: 4903AC24F0000000                 add     rbp, [r12+0F0h]
0x05A558: 448A5D00                         mov     r11b, [rbp+0]
0x375135: 48C7C6FF000000                   mov     rsi, 0FFh
0x05A563: 48C1E618                         shl     rsi, 18h
0x05A567: 48F7D6                           not     rsi
0x05A56A: 4921F5                           and     r13, rsi
0x05A56D: 490FB6F3                         movzx   rsi, r11b
0x05A571: 48C1E618                         shl     rsi, 18h
0x05A575: 4909F5                           or      r13, rsi
0x05A658: 498B7928                         mov     rdi, [r9+28h]
0x37520A: 4C8BA7E0000000                   mov     r12, [rdi+0E0h]
0x05A663: 4154                             push    r12
0x05A665: 4989E7                           mov     r15, rsp
0x375277: 488BBFE0000000                   mov     rdi, [rdi+0E0h]
0x05A760: 4D8B6128                         mov     r12, [r9+28h]
0x37534B: 4D8BAC24E8000000                 mov     r13, [r12+0E8h]
0x3753B6: 4D8BB424B0000000                 mov     r14, [r12+0B0h]
0x05A774: 4D0FB6ED                         movzx   r13, r13b
0x05A867: 498B7928                         mov     rdi, [r9+28h]
0x375488: 0FAE97E0000000                   ldmxcsr dword ptr [rdi+0E0h]
0x3754F3: 49BD7E1DC0ED00000000             mov     r13, 0EDC01D7Eh
0x375562: 4981C542554952                   add     r13, 52495542h
0x3755C8: 4D8BADF8070000                   mov     r13, [r13+7F8h]
0x375636: 4C03AFE0000000                   add     r13, [rdi+0E0h]
0x05A891: 458A5D00                         mov     r11b, [r13+0]
0x05A895: 4D0FB6DB                         movzx   r11, r11b
0x05A899: 49C1E328                         shl     r11, 28h
0x3756A1: 4C299FE8000000                   sub     [rdi+0E8h], r11
0x05A8A4: 498B5928                         mov     rbx, [r9+28h]
0x37570F: 4C8BA3E8000000                   mov     r12, [rbx+0E8h]
0x37577C: 49BDC94C840001000000             mov     r13, 100844CC9h
0x3757E4: 4981C5F71D853F                   add     r13, 3F851DF7h
0x05A9B7: 498B7928                         mov     rdi, [r9+28h]
0x05A9BB: 0FAE5734                         ldmxcsr dword ptr [rdi+34h]
0x3758B7: 488B9FE0000000                   mov     rbx, [rdi+0E0h]
0x375920: 4C8BAFD8000000                   mov     r13, [rdi+0D8h]
0x05AABA: 4D8B6128                         mov     r12, [r9+28h]
0x3759F6: 4D8BAC24E0000000                 mov     r13, [r12+0E0h]
0x05AAC6: 458B742434                       mov     r14d, [r12+34h]
0x375A62: 4D03B42490000000                 add     r14, [r12+90h]
0x05AAD3: 458A0E                           mov     r9b, [r14]
0x375ACF: 48C7C0FF000000                   mov     rax, 0FFh
0x05AADD: 48C1E020                         shl     rax, 20h
0x05AAE1: 48F7D0                           not     rax
0x05AAE4: 4921C5                           and     r13, rax
0x05AAE7: 490FB6C1                         movzx   rax, r9b
0x05AAEB: 48C1E020                         shl     rax, 20h
0x05AAEF: 4909C5                           or      r13, rax
0x05ABDF: 4D8B6928                         mov     r13, [r9+28h]
0x375BA4: 4D8BA5E0000000                   mov     r12, [r13+0E0h]
0x05ABEA: 4154                             push    r12
0x05ABEC: 4989E7                           mov     r15, rsp
0x375C0F: 4D8BADE0000000                   mov     r13, [r13+0E0h]
0x05ACD0: 4D8B5928                         mov     r11, [r9+28h]
0x375CE2: 498BB3C0000000                   mov     rsi, [r11+0C0h]
0x375D4F: 4D8BB3E0000000                   mov     r14, [r11+0E0h]
0x05ACE2: 480FB6F6                         movzx   rsi, sil
0x05ADBE: 4D8B7128                         mov     r14, [r9+28h]
0x375E20: 410FAE96A8000000                 ldmxcsr dword ptr [r14+0A8h]
0x375E8C: 48BB3E409A3A01000000             mov     rbx, 13A9A403Eh
0x375EFC: 4881C382326F05                   add     rbx, 56F3282h
0x375F66: 488B9BF8070000                   mov     rbx, [rbx+7F8h]
0x375FD4: 49039EA8000000                   add     rbx, [r14+0A8h]
0x05ADE9: 448A13                           mov     r10b, [rbx]
0x05ADEC: 4D0FB6D2                         movzx   r10, r10b
0x05ADF0: 49C1E230                         shl     r10, 30h
0x37603D: 4D2996E8000000                   sub     [r14+0E8h], r10
0x05ADFB: 4D8B5128                         mov     r10, [r9+28h]
0x3760A2: 498B9AE8000000                   mov     rbx, [r10+0E8h]
0x37610D: 48BE05677FEA00000000             mov     rsi, 0EA7F6705h
0x376175: 4881C6BB038A55                   add     rsi, 558A03BBh
0x05AEF0: 4D8B7128                         mov     r14, [r9+28h]
0x05AEF4: 410FAE5634                       ldmxcsr dword ptr [r14+34h]
0x37624B: 498BB6C8000000                   mov     rsi, [r14+0C8h]
0x3762B3: 4D8BB690000000                   mov     r14, [r14+90h]
0x05AFDE: 4D8B5928                         mov     r11, [r9+28h]
0x37638A: 498BBBE8000000                   mov     rdi, [r11+0E8h]
0x05AFE9: 418B4334                         mov     eax, [r11+34h]
0x3763EF: 490383A8000000                   add     rax, [r11+0A8h]
0x05AFF4: 448A18                           mov     r11b, [rax]
0x376456: 48C7C5FF000000                   mov     rbp, 0FFh
0x05AFFE: 48C1E528                         shl     rbp, 28h
0x05B002: 48F7D5                           not     rbp
0x05B005: 4821EF                           and     rdi, rbp
0x05B008: 490FB6EB                         movzx   rbp, r11b
0x05B00C: 48C1E528                         shl     rbp, 28h
0x05B010: 4809EF                           or      rdi, rbp
0x05B101: 4D8B7128                         mov     r14, [r9+28h]
0x376528: 498BAEB0000000                   mov     rbp, [r14+0B0h]
0x05B10C: 55                               push    rbp
0x05B10D: 4889E5                           mov     rbp, rsp
0x37658D: 4D8BA6B0000000                   mov     r12, [r14+0B0h]
0x05B20C: 4D8B7128                         mov     r14, [r9+28h]
0x37665E: 4D8BAEB0000000                   mov     r13, [r14+0B0h]
0x3766CA: 4D8BB6D8000000                   mov     r14, [r14+0D8h]
0x05B21E: 4D0FB6ED                         movzx   r13, r13b
0x05B2F5: 498B5928                         mov     rbx, [r9+28h]
0x3767A2: 0FAE93E0000000                   ldmxcsr dword ptr [rbx+0E0h]
0x37680A: 48BD882844C000000000             mov     rbp, 0C0442888h
0x376876: 4881C5384AC57F                   add     rbp, 7FC54A38h
0x3768DC: 488BADF8070000                   mov     rbp, [rbp+7F8h]
0x376947: 4803ABE0000000                   add     rbp, [rbx+0E0h]
0x05B31F: 408A6D00                         mov     bpl, [rbp+0]
0x05B323: 480FB6ED                         movzx   rbp, bpl
0x05B327: 48C1E538                         shl     rbp, 38h
0x3769B1: 4829ABE8000000                   sub     [rbx+0E8h], rbp
0x05B332: 498B5128                         mov     rdx, [r9+28h]
0x376A16: 4C8BA2E8000000                   mov     r12, [rdx+0E8h]
0x376A80: 48BD41681E3001000000             mov     rbp, 1301E6841h
0x376AF1: 4881C57F02EB0F                   add     rbp, 0FEB027Fh
0x05B446: 498B7128                         mov     rsi, [r9+28h]
0x05B44A: 0FAE5634                         ldmxcsr dword ptr [rsi+34h]
0x376BC2: 488B9EA8000000                   mov     rbx, [rsi+0A8h]
0x376C2D: 4C8BA6D8000000                   mov     r12, [rsi+0D8h]
0x05B52F: 4D8B7128                         mov     r14, [r9+28h]
0x376D02: 4D8BAED8000000                   mov     r13, [r14+0D8h]
0x05B53A: 458B4E34                         mov     r9d, [r14+34h]
0x376D68: 4D038E90000000                   add     r9, [r14+90h]
0x05B545: 458A19                           mov     r11b, [r9]
0x376DD4: 49C7C7FF000000                   mov     r15, 0FFh
0x05B54F: 49C1E730                         shl     r15, 30h
0x05B553: 49F7D7                           not     r15
0x05B556: 4D21FD                           and     r13, r15
0x05B559: 4D0FB6FB                         movzx   r15, r11b
0x05B55D: 49C1E730                         shl     r15, 30h
0x05B561: 4D09FD                           or      r13, r15
0x05B648: 4D8B6928                         mov     r13, [r9+28h]
0x376EA4: 498B8DE0000000                   mov     rcx, [r13+0E0h]
0x05B653: 51                               push    rcx
0x05B654: 4989E6                           mov     r14, rsp
0x376F10: 498B9DE0000000                   mov     rbx, [r13+0E0h]
0x05B733: 4D8B7928                         mov     r15, [r9+28h]
0x376FDF: 498BBFA8000000                   mov     rdi, [r15+0A8h]
0x37704C: 498B9F90000000                   mov     rbx, [r15+90h]
0x05B745: 480FB6FF                         movzx   rdi, dil
0x05B828: 498B4928                         mov     rcx, [r9+28h]
0x37711C: 0FAE91B0000000                   ldmxcsr dword ptr [rcx+0B0h]
0x377185: 48BA8D07853901000000             mov     rdx, 13985078Dh
0x05B83D: 52                               push    rdx
0x05B83E: 68A7212911                       push    112921A7h
0x05B843: 684C4F9940                       push    40994F4Ch
0x05B848: 6881348F60                       push    608F3481h
0x05B84D: 68F7099132                       push    329109F7h
0x3771ED: 488144242033638406               add     qword ptr [rsp+20h], 6846333h
0x05B85B: 498B4128                         mov     rax, [r9+28h]
0x37725C: 488BB890000000                   mov     rdi, [rax+90h]
0x05B95D: 498B4928                         mov     rcx, [r9+28h]
0x05B961: 0FAE5134                         ldmxcsr dword ptr [rcx+34h]
0x377327: 488BB9D0000000                   mov     rdi, [rcx+0D0h]
0x37738F: 4C8BB1B0000000                   mov     r14, [rcx+0B0h]
0x05BA4F: 498B5928                         mov     rbx, [r9+28h]
0x377465: 4C8BA3E8000000                   mov     r12, [rbx+0E8h]
0x05BA5A: 448B7B34                         mov     r15d, [rbx+34h]
0x3774CC: 4C03BBB0000000                   add     r15, [rbx+0B0h]
0x05BA65: 418A07                           mov     al, [r15]
0x377531: 48C7C6FF000000                   mov     rsi, 0FFh
0x05BA6F: 48C1E638                         shl     rsi, 38h
0x05BA73: 48F7D6                           not     rsi
0x05BA76: 4921F4                           and     r12, rsi
0x05BA79: 480FB6F0                         movzx   rsi, al
0x05BA7D: 48C1E638                         shl     rsi, 38h
0x05BA81: 4909F4                           or      r12, rsi
0x05BB5E: 498B7928                         mov     rdi, [r9+28h]
0x377603: 488B87D8000000                   mov     rax, [rdi+0D8h]
0x05BB69: 50                               push    rax
0x05BB6A: 4889E5                           mov     rbp, rsp
0x377670: 488B9FD8000000                   mov     rbx, [rdi+0D8h]
0x05BC42: 498B5128                         mov     rdx, [r9+28h]
0x37773A: 488BAAA0000000                   mov     rbp, [rdx+0A0h]
0x3777A3: 4C8BA290000000                   mov     r12, [rdx+90h]
0x05BC54: 55                               push    rbp
0x05BC55: 68B10CCF02                       push    2CF0CB1h
0x05BC5A: 68CD0E7C3E                       push    3E7C0ECDh
0x05BC5F: 686818ED63                       push    63ED1868h
0x05BC64: 68E608FF0A                       push    0AFF08E6h
0x05BD4A: 4D8B6128                         mov     r12, [r9+28h]
0x37786E: 498B9C2488000000                 mov     rbx, [r12+88h]
0x3778DD: 4D8BAC24D8000000                 mov     r13, [r12+0D8h]
0x05BD5E: 480FB6DB                         movzx   rbx, bl
0x05BE4C: 4D8B5928                         mov     r11, [r9+28h]
0x3779AD: 410FAE9390000000                 ldmxcsr dword ptr [r11+90h]
0x05BE58: 498B6928                         mov     rbp, [r9+28h]
0x377A1B: 488B9DE0000000                   mov     rbx, [rbp+0E0h]
0x377A84: 49BD7623813E01000000             mov     r13, 13E812376h
0x377AF1: 4981C54A1F8801                   add     r13, 1881F4Ah
0x05BF60: 4D8B7128                         mov     r14, [r9+28h]
0x05BF64: 410FAE5634                       ldmxcsr dword ptr [r14+34h]
0x05BF69: 4D8B7E78                         mov     r15, [r14+78h]
0x377BC9: 4D8BA690000000                   mov     r12, [r14+90h]
0x05C052: 4D8B6128                         mov     r12, [r9+28h]
0x377C94: 4D8BBC24D8000000                 mov     r15, [r12+0D8h]
0x05C05E: 418B4C2434                       mov     ecx, [r12+34h]
0x377CFC: 49038C24F0000000                 add     rcx, [r12+0F0h]
0x05C06B: 448A01                           mov     r8b, [rcx]
0x377D66: 49C7C2FF000000                   mov     r10, 0FFh
0x05C075: 49C1E218                         shl     r10, 18h
0x05C079: 49F7D2                           not     r10
0x05C07C: 4D21D7                           and     r15, r10
0x05C07F: 4D0FB6D0                         movzx   r10, r8b
0x05C083: 49C1E218                         shl     r10, 18h
0x05C087: 4D09D7                           or      r15, r10
0x05C168: 4D8B6928                         mov     r13, [r9+28h]
0x377E40: 498B9DF0000000                   mov     rbx, [r13+0F0h]
0x05C173: 53                               push    rbx
0x05C174: 4989E4                           mov     r12, rsp
0x377EA8: 498BADF0000000                   mov     rbp, [r13+0F0h]
0x05C255: 498B6928                         mov     rbp, [r9+28h]
0x377F79: 488B95D8000000                   mov     rdx, [rbp+0D8h]
0x377FE5: 488BADA0000000                   mov     rbp, [rbp+0A0h]
0x05C267: 52                               push    rdx
0x05C268: 68A344A135                       push    35A144A3h
0x05C26D: 6836573630                       push    30365736h
0x05C272: 68A759F236                       push    36F259A7h
0x05C277: 68660DF517                       push    17F50D66h
0x05C373: 4D8B6128                         mov     r12, [r9+28h]
0x3780B0: 498BAC2488000000                 mov     rbp, [r12+88h]
0x37811A: 498BB424A0000000                 mov     rsi, [r12+0A0h]
0x05C387: 480FB6ED                         movzx   rbp, bpl
0x05C45D: 4D8B5128                         mov     r10, [r9+28h]
0x3781EE: 410FAE92A0000000                 ldmxcsr dword ptr [r10+0A0h]
0x05C469: 4D8B7928                         mov     r15, [r9+28h]
0x37825C: 4D8BB7A8000000                   mov     r14, [r15+0A8h]
0x3782C1: 48BF7302DD3701000000             mov     rdi, 137DD0273h
0x37832B: 4881C74D402C08                   add     rdi, 82C404Dh
0x05C574: 4D8B4928                         mov     r9, [r9+28h]
0x05C578: 410FAE5134                       ldmxcsr dword ptr [r9+34h]
0x3783FB: 498BB1A0000000                   mov     rsi, [r9+0A0h]
0x378462: 4D8BA9E8000000                   mov     r13, [r9+0E8h]
0x05C66C: 498B7128                         mov     rsi, [r9+28h]
0x37852E: 488B9EE0000000                   mov     rbx, [rsi+0E0h]
0x05C677: 8B4634                           mov     eax, [rsi+34h]
0x378595: 480386A8000000                   add     rax, [rsi+0A8h]
0x05C681: 8A10                             mov     dl, [rax]
0x3785FD: 49C7C2FF000000                   mov     r10, 0FFh
0x05C68A: 49C1E220                         shl     r10, 20h
0x05C68E: 49F7D2                           not     r10
0x05C691: 4C21D3                           and     rbx, r10
0x05C694: 4C0FB6D2                         movzx   r10, dl
0x05C698: 49C1E220                         shl     r10, 20h
0x05C69C: 4C09D3                           or      rbx, r10
0x05C77D: 498B4128                         mov     rax, [r9+28h]
0x3786D1: 4C8B8090000000                   mov     r8, [rax+90h]
0x05C788: 4150                             push    r8
0x05C78A: 4989E4                           mov     r12, rsp
0x37873E: 4C8BB890000000                   mov     r15, [rax+90h]
0x05C872: 4D8B4928                         mov     r9, [r9+28h]
0x378815: 498BB1B8000000                   mov     rsi, [r9+0B8h]
0x37887B: 498B99F0000000                   mov     rbx, [r9+0F0h]
0x05C884: 480FB6F6                         movzx   rsi, sil
0x05C96B: 4D8B6928                         mov     r13, [r9+28h]
0x378948: 410FAE95A8000000                 ldmxcsr dword ptr [r13+0A8h]
0x3789B3: 49BDBADC76F200000000             mov     r13, 0F276DCBAh
0x05C981: 4155                             push    r13
0x05C983: 687A3C0B15                       push    150B3C7Ah
0x05C988: 68AB194326                       push    264319ABh
0x05C98D: 68C2205E41                       push    415E20C2h
0x378A21: 48814424180666924D               add     qword ptr [rsp+18h], 4D926606h
0x05C99B: 498B4128                         mov     rax, [r9+28h]
0x378A8C: 488B9890000000                   mov     rbx, [rax+90h]
0x05CA99: 498B7128                         mov     rsi, [r9+28h]
0x05CA9D: 0FAE5634                         ldmxcsr dword ptr [rsi+34h]
0x05CAA1: 4C8B7678                         mov     r14, [rsi+78h]
0x378B5A: 488BAE90000000                   mov     rbp, [rsi+90h]
0x05CB89: 4D8B5128                         mov     r10, [r9+28h]
0x378C24: 498BBAA0000000                   mov     rdi, [r10+0A0h]
0x05CB94: 458B6234                         mov     r12d, [r10+34h]
0x378C8A: 4D03A2E8000000                   add     r12, [r10+0E8h]
0x05CB9F: 458A2C24                         mov     r13b, [r12]
0x378CF3: 49C7C3FF000000                   mov     r11, 0FFh
0x05CBAA: 49C1E328                         shl     r11, 28h
0x05CBAE: 49F7D3                           not     r11
0x05CBB1: 4C21DF                           and     rdi, r11
0x05CBB4: 4D0FB6DD                         movzx   r11, r13b
0x05CBB8: 49C1E328                         shl     r11, 28h
0x05CBBC: 4C09DF                           or      rdi, r11
0x05CC9A: 498B7128                         mov     rsi, [r9+28h]
0x378DCA: 488BAEB0000000                   mov     rbp, [rsi+0B0h]
0x05CCA5: 55                               push    rbp
0x05CCA6: 4989E5                           mov     r13, rsp
0x378E36: 488BBEB0000000                   mov     rdi, [rsi+0B0h]
0x05CD89: 498B5928                         mov     rbx, [r9+28h]
0x378F02: 4C8BA3E0000000                   mov     r12, [rbx+0E0h]
0x378F67: 4C8BB3B0000000                   mov     r14, [rbx+0B0h]
0x05CD9B: 4154                             push    r12
0x05CD9D: 68D46E732B                       push    2B736ED4h
0x05CDA2: 68AE6CAC0E                       push    0EAC6CAEh
0x05CDA7: 68D7565416                       push    165456D7h
0x05CE9C: 498B5928                         mov     rbx, [r9+28h]
0x379039: 488BBBB0000000                   mov     rdi, [rbx+0B0h]
0x3790A0: 488B9BE8000000                   mov     rbx, [rbx+0E8h]
0x05CEAE: 480FB6FF                         movzx   rdi, dil
0x05CF98: 4D8B4128                         mov     r8, [r9+28h]
0x379171: 410FAE90B0000000                 ldmxcsr dword ptr [r8+0B0h]
0x05CFA4: 4D8B7128                         mov     r14, [r9+28h]
0x3791DD: 498B9E90000000                   mov     rbx, [r14+90h]
0x379242: 48BDA32AED2701000000             mov     rbp, 127ED2AA3h
0x3792AF: 4881C51D181C18                   add     rbp, 181C181Dh
0x05D0A7: 498B5128                         mov     rdx, [r9+28h]
0x05D0AB: 0FAE5234                         ldmxcsr dword ptr [rdx+34h]
0x05D0AF: 488B6A78                         mov     rbp, [rdx+78h]
0x379380: 488B9A90000000                   mov     rbx, [rdx+90h]
0x05D19E: 498B5928                         mov     rbx, [r9+28h]
0x379456: 4C8BA390000000                   mov     r12, [rbx+90h]
0x05D1A9: 448B4B34                         mov     r9d, [rbx+34h]
0x3794C2: 4C038BA0000000                   add     r9, [rbx+0A0h]
0x05D1B4: 418A19                           mov     bl, [r9]
0x37952E: 48C7C6FF000000                   mov     rsi, 0FFh
0x05D1BE: 48C1E638                         shl     rsi, 38h
0x05D1C2: 48F7D6                           not     rsi
0x05D1C5: 4921F4                           and     r12, rsi
0x05D1C8: 480FB6F3                         movzx   rsi, bl
0x05D1CC: 48C1E638                         shl     rsi, 38h
0x05D1D0: 4909F4                           or      r12, rsi
0x05D2B1: 4D8B6928                         mov     r13, [r9+28h]
0x379605: 498BB5D8000000                   mov     rsi, [r13+0D8h]
0x379672: 48BD55AF84EF00000000             mov     rbp, 0EF84AF55h
0x3796E1: 4881C59B627B50                   add     rbp, 507B629Bh
0x05D2CD: 4885F6                           test    rsi, rsi
0x379747: 4C8D2D903BCEFF                   lea     r13, unk_6A7D2DE
0x05D2D7: 4C0F45ED                         cmovnz  r13, rbp
0x05D2DB: 41FFE5                           jmp     r13
