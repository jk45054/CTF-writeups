struct __declspec(align(8)) custom_struct
{
  char argv_1[256];
  __int64 dw_first_tickcount_from_call_5d3;
  struct_2 *p_struct_2;
  WCHAR lpwszDropFilePath[260];
  DWORD (__stdcall *GetTickCount)();
  FARPROC (__stdcall *GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
  HMODULE (__stdcall *LoadLibraryW)(LPCWSTR lpLibFileName);
  DWORD (__stdcall *GetModuleFileNameW)(HMODULE hModule, LPWSTR lpFilename, DWORD nSize);
  HANDLE (__stdcall *CreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
  BOOL (__stdcall *ReadFile)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
  BOOL (__stdcall *WriteFile)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
  void (__stdcall *Sleep)(DWORD dwMilliseconds);
  void (__stdcall __noreturn *ExitProcess)(UINT uExitCode);
  LPVOID (__stdcall *VirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
  __int64 free;
  HANDLE (__stdcall *GetStdHandle)(DWORD nStdHandle);
  __int64 kernel32_WriteConsoleA;
  int (__fastcall *strtol)(const char *String, char **EndPtr, int Radix);
  __int64 strnlen;
  char *(__fastcall *get_slash_string_2300)(char *pw_str, int stage);
  __int64 crypthash_derivekey_2000;
  __int64 decrypt_shellcode_2120;
  __int64 temppath_html_writefile_open_21b0;
  __int64 convert_writeconsole_cb0;
  void *VA_crc32_func;
  QWORD result_of_fourth_stage_shellcode;
  void *VA_fifth_stage_shellcode;
  QWORD alloc_buffer_size;
  void *VA_buffer_size_174135;
  DWORD dropped_file_offset_0x38_crc32;
  char first_slash_string[32];
  char second_slash_string[32];
  char third_slash_string[32];
  char fourth_slash_string[32];
  char fifth_slash_string[32];
  char rev_translated_fifth_slash_string[30];
};

struct struct_2
{
  char *CAFE_stuff;
  int stage;
  char field_10[8];
  char field_18[8];
  char str_zipza[8];
  char *translation_alphabet;
  char stuff[8];
};
