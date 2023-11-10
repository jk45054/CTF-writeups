bool __fastcall first_stage_shellcode(const char *argv_1_7)
{
  char *ciphertext_; // r10
  char *plaintext; // r11
  int i; // r9d
  unsigned int key_idx; // kr00_4
  char cur_ciphertext_byte; // al
  char ciphertext[16]; // [rsp+0h] [rbp-10h] BYREF
  int key; // [rsp+28h] [rbp+18h]

  key = 'net';
  ciphertext_ = ciphertext;
  plaintext = ciphertext;
  i = 0;
  ciphertext[0] = 22;
  ciphertext[1] = 23;
  ciphertext[2] = 59;
  ciphertext[3] = 23;
  strcpy(&ciphertext[4], "V");
  do
  {
    key_idx = i++;
    cur_ciphertext_byte = *ciphertext_++;
    *plaintext++ = *((_BYTE *)&key + key_idx % 3) ^ cur_ciphertext_byte;
  }
  while ( i < 5 );
  return strcmp(ciphertext, argv_1_7) == 0;
}