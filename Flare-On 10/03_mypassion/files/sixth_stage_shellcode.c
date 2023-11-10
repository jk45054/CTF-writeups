__int64 __fastcall sub_14BE1430000(custom_struct *cstruct)
{
  char *seventh_slash_string; // rax
  struct_2 *p_struct_2; // r9
  char *seventh_slash_string_copy; // rdi
  char *sixth_slash_string; // rax
  unsigned int sum; // r8d
  char *sixth_slash_string_copy; // rsi
  unsigned int sum_; // r9d
  unsigned int v9; // r10d
  unsigned int v10; // r11d
  unsigned __int64 v11; // rdx
  char v12; // cl
  char v13; // cl
  char v14; // cl
  char v15; // cl
  int v16; // ecx
  unsigned int v17; // r9d
  unsigned int v18; // r10d
  unsigned __int64 v19; // rdx
  int v20; // ecx
  struct_2 *p_struct_2__; // rcx
  __int64 result; // rax
  __int64 v23; // rdi
  _BYTE tea_key[14]; // [rsp+30h] [rbp-50h]
  __int16 tea_key_14; // [rsp+3Eh] [rbp-42h]
  char flag[15]; // [rsp+40h] [rbp-40h] BYREF
  unsigned int v27; // [rsp+4Fh] [rbp-31h]
  __int16 v28; // [rsp+53h] [rbp-2Dh]
  char v29; // [rsp+55h] [rbp-2Bh]
  unsigned int v30; // [rsp+56h] [rbp-2Ah]
  __int16 v31; // [rsp+5Ah] [rbp-26h]
  char v32; // [rsp+5Ch] [rbp-24h]
  __int64 v33; // [rsp+5Dh] [rbp-23h]
  __int64 v34; // [rsp+65h] [rbp-1Bh]
  __int64 v35; // [rsp+6Dh] [rbp-13h]
  __int64 v36; // [rsp+75h] [rbp-Bh]
  __int16 v37; // [rsp+7Dh] [rbp-3h]
  char v38; // [rsp+7Fh] [rbp-1h]
  int v39; // [rsp+A0h] [rbp+20h] BYREF
  unsigned int v40; // [rsp+A8h] [rbp+28h]
  unsigned int v41; // [rsp+ACh] [rbp+2Ch]

  cstruct->p_struct_2->stage = 8;
  seventh_slash_string = cstruct->get_slash_string_2300(cstruct, (unsigned int)cstruct->p_struct_2->stage);
  p_struct_2 = cstruct->p_struct_2;
  seventh_slash_string_copy = seventh_slash_string;
  if ( __PAIR64__(seventh_slash_string[1], *seventh_slash_string) != __PAIR64__(
                                                                       (unsigned __int8)p_struct_2->stuff[4],
                                                                       (unsigned __int8)p_struct_2->stuff[3])
    || seventh_slash_string[2] != (unsigned __int8)p_struct_2->stuff[5] )
  {
    ((void (__fastcall *)(_QWORD))cstruct->ExitProcess)((unsigned int)p_struct_2->stage);
  }
  sixth_slash_string = cstruct->get_slash_string_2300(cstruct, (unsigned int)(cstruct->p_struct_2->stage - 1));
  sum = 0xC6EF3720;
  sixth_slash_string_copy = sixth_slash_string;
  sum_ = 0xC6EF3720;
  v9 = 0xAEFCF63E;
  v10 = 0xD5C5DD5A;
  v11 = 0xC6EF3720i64;
  tea_key[0] = *sixth_slash_string;
  tea_key[1] = cstruct->fifth_slash_string[14];
  tea_key[2] = seventh_slash_string_copy[1];
  tea_key[3] = cstruct->fifth_slash_string[10];
  v12 = sixth_slash_string[6];
  tea_key[7] = cstruct->first_slash_string[8];
  tea_key[9] = cstruct->fourth_slash_string[1];
  tea_key[11] = cstruct->fifth_slash_string[6];
  LOBYTE(sixth_slash_string) = cstruct->fifth_slash_string[9];
  tea_key[4] = v12;
  v13 = cstruct->fifth_slash_string[24];
  tea_key[12] = (_BYTE)sixth_slash_string;
  LOBYTE(sixth_slash_string) = seventh_slash_string_copy[2];
  tea_key[5] = v13;
  v14 = cstruct->third_slash_string[2];
  tea_key[13] = (_BYTE)sixth_slash_string;
  LOBYTE(sixth_slash_string) = cstruct->fifth_slash_string[22];
  tea_key[6] = v14;
  v15 = cstruct->fourth_slash_string[0];
  tea_key_14 = (unsigned __int8)sixth_slash_string;
  tea_key[8] = v15;
  tea_key[10] = v15;
  do                                            // TEA-ish decrypt
  {
    v16 = (v9 ^ sum_) + *(_DWORD *)&tea_key[4 * ((v11 >> 11) & 3)] + ((16 * v9) ^ (v9 >> 5));
    sum_ += 0x61C88647;
    v10 -= v16;
    v11 = sum_;
    v9 -= (v10 ^ sum_) + *(_DWORD *)&tea_key[4 * (sum_ & 3)] + ((16 * v10) ^ (v10 >> 5));
  }
  while ( sum_ );
  v40 = v9;
  v17 = 0xAB30F482;
  v18 = 0xBE54376B;
  v41 = v10;
  v19 = 0xC6EF3720i64;
  do                                            // TEA-ish decrypt
  {
    v20 = (v17 ^ sum) + *(_DWORD *)&tea_key[4 * ((v19 >> 11) & 3)] + ((16 * v17) ^ (v17 >> 5));
    sum += 0x61C88647;
    v18 -= v20;
    v19 = sum;
    v17 -= (v18 ^ sum) + *(_DWORD *)&tea_key[4 * (sum & 3)] + ((16 * v18) ^ (v18 >> 5));
  }
  while ( sum );
  p_struct_2__ = cstruct->p_struct_2;
  flag[0] = cstruct->argv_1[7];                 // "b"
  flag[1] = cstruct->argv_1[0];                 // "0"
  flag[2] = cstruct->argv_1[19];                // "r"
  v33 = 0i64;
  v34 = 0i64;
  v35 = 0i64;
  v36 = 0i64;
  v37 = 0;
  v38 = 0;
  flag[3] = seventh_slash_string_copy[2];       // "n"
  flag[4] = p_struct_2__->stuff[0];             // "_"
  flag[5] = cstruct->argv_1[23];                // "t"?
  flag[6] = cstruct->fourth_slash_string[6];    // "0"
  flag[7] = '_';                                // "_"
  flag[8] = sixth_slash_string_copy[2];         // "5"
  flag[9] = 't';                                // "t"
  flag[10] = sixth_slash_string_copy[5];        // "r"
  flag[11] = cstruct->fourth_slash_string[2];   // "u"
  flag[12] = cstruct->fifth_slash_string[5] + 0x20;// "c"
  flag[13] = cstruct->argv_1[17];               // "7"
  flag[14] = p_struct_2__->stuff[0];            // "_"
  v27 = v40;
  v28 = v41;
  v29 = BYTE2(v41);
  v30 = v17;
  v31 = v18;
  v32 = BYTE2(v18);
  if ( ((unsigned int (__fastcall *)(char *, __int64))cstruct->VA_crc32_func)(flag, 29i64) != 0x59B1D2F1 )
    ((void (__fastcall *)(_QWORD))cstruct->ExitProcess)((unsigned int)cstruct->p_struct_2->stage);
  v39 = 0;
  result = ((__int64 (__fastcall *)(custom_struct *, int *))cstruct->temppath_html_writefile_open_21b0)(cstruct, &v39);
  if ( (_DWORD)result )
  {
    LOWORD(v33) = v39; // v39 points to "com"
    BYTE2(v33) = BYTE2(v39);
    BYTE3(v33) = 10;
    v23 = ((__int64 (__fastcall *)(__int64))cstruct->GetStdHandle)(4294967285i64);
    if ( v23 == -1 )
      ((void (__fastcall *)(_QWORD))cstruct->ExitProcess)((unsigned int)cstruct->p_struct_2->stage);
    result = ((__int64 (__fastcall *)(__int64, char *, __int64))cstruct->kernel32_WriteConsoleA)(v23, flag, 64i64);
    if ( (_DWORD)result )
      return ((__int64 (__fastcall *)(_QWORD))cstruct->ExitProcess)((unsigned int)cstruct->p_struct_2->stage);
  }
  return result;
}