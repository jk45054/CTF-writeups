14f0;section: [.text]
151c;kernel32.VirtualAlloc
VirtualAlloc:
	Arg[0] = 0
	Arg[1] = 0x0000000000800000 = 8388608
	Arg[2] = 0x0000000000003000 = 12288
	Arg[3] = 0x0000000000000040 = 64

15a1;ntdll.[RtlActivateActivationContextUnsafeFast+11d]*
21f5;CPUID:0
2218;CPUID:1
22b1;CPUID:7
2d29;kernel32.LoadLibraryExW
LoadLibraryExW:
	Arg[0] = ptr 0x0000000140018300 -> L"api-ms-win-core-synch-l1-2-0"
	Arg[1] = 0
	Arg[2] = 0x0000000000000800 = 2048

2ddb;kernel32.GetProcAddress
GetProcAddress:
	Arg[0] = ptr 0x00007ffef0070000 -> {MZ\x90\x00\x03\x00\x00\x00}
	Arg[1] = ptr 0x00000001400183c8 -> "InitializeCriticalSectionEx"

15770;kernelbase.InitializeCriticalSectionEx
2d29;kernel32.LoadLibraryExW
LoadLibraryExW:
	Arg[0] = ptr 0x00000001400182c0 -> L"api-ms-win-core-fibers-l1-1-1"
	Arg[1] = 0
	Arg[2] = 0x0000000000000800 = 2048

2ddb;kernel32.GetProcAddress
GetProcAddress:
	Arg[0] = ptr 0x00007ffef0070000 -> {MZ\x90\x00\x03\x00\x00\x00}
	Arg[1] = ptr 0x0000000140018370 -> "FlsAlloc"

15770;kernelbase.FlsAlloc
2ddb;kernel32.GetProcAddress
GetProcAddress:
	Arg[0] = ptr 0x00007ffef0070000 -> {MZ\x90\x00\x03\x00\x00\x00}
	Arg[1] = ptr 0x00000001400183b0 -> "FlsSetValue"

15770;kernelbase.FlsSetValue
90dc;kernel32.LoadLibraryExW
LoadLibraryExW:
	Arg[0] = ptr 0x0000000140018300 -> L"api-ms-win-core-synch-l1-2-0"
	Arg[1] = 0
	Arg[2] = 0x0000000000000800 = 2048

91c4;kernel32.GetProcAddress
GetProcAddress:
	Arg[0] = ptr 0x00007ffef0070000 -> {MZ\x90\x00\x03\x00\x00\x00}
	Arg[1] = ptr 0x00000001400183c8 -> "InitializeCriticalSectionEx"

15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
e85c;kernel32.GetProcessHeap
9380;kernel32.FlsAlloc
a51f;kernel32.GetLastError
9390;kernel32.FlsGetValue
9398;kernel32.FlsSetValue
8fdd;ntdll.RtlAllocateHeap
9398;kernel32.FlsSetValue
89e6;ntdll.RtlEnterCriticalSection
8a3a;ntdll.RtlLeaveCriticalSection
89e6;ntdll.RtlEnterCriticalSection
8a3a;ntdll.RtlLeaveCriticalSection
a5bf;kernel32.SetLastError
89e6;ntdll.RtlEnterCriticalSection
89e6;ntdll.RtlEnterCriticalSection
8fdd;ntdll.RtlAllocateHeap
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
8a3a;ntdll.RtlLeaveCriticalSection
9a24;kernel32.GetStartupInfoW
9b6d;kernel32.GetStdHandle
9b83;kernel32.GetFileType
9b6d;kernel32.GetStdHandle
9b83;kernel32.GetFileType
9b6d;kernel32.GetStdHandle
9b83;kernel32.GetFileType
8a3a;ntdll.RtlLeaveCriticalSection
80c4;kernel32.GetCommandLineA
80d1;kernel32.GetCommandLineW
9390;kernel32.FlsGetValue
89e6;ntdll.RtlEnterCriticalSection
8a3a;ntdll.RtlLeaveCriticalSection
cbbd;kernel32.GetACP
a736;ntdll.RtlAllocateHeap
d28d;kernel32.IsValidCodePage
d2d1;kernel32.GetCPInfo
ccd6;kernel32.GetCPInfo
d5b9;kernel32.MultiByteToWideChar
d5b9;kernel32.MultiByteToWideChar
e356;kernel32.GetStringTypeW
d5b9;kernel32.MultiByteToWideChar
d5b9;kernel32.MultiByteToWideChar
90dc;kernel32.LoadLibraryExW
LoadLibraryExW:
	Arg[0] = ptr 0x0000000140018b50 -> L"api-ms-win-core-localization-l1-2-1"
	Arg[1] = 0
	Arg[2] = 0x0000000000000800 = 2048

91c4;kernel32.GetProcAddress
GetProcAddress:
	Arg[0] = ptr 0x00007ffef0070000 -> {MZ\x90\x00\x03\x00\x00\x00}
	Arg[1] = ptr 0x0000000140018f88 -> "LCMapStringEx"

15770;kernelbase.LCMapStringEx
15770;kernelbase.LCMapStringEx
d6cf;kernel32.WideCharToMultiByte
d5b9;kernel32.MultiByteToWideChar
d5b9;kernel32.MultiByteToWideChar
15770;kernelbase.LCMapStringEx
15770;kernelbase.LCMapStringEx
d6cf;kernel32.WideCharToMultiByte
89e6;ntdll.RtlEnterCriticalSection
8a3a;ntdll.RtlLeaveCriticalSection
89e6;ntdll.RtlEnterCriticalSection
a736;ntdll.RtlAllocateHeap
8a3a;ntdll.RtlLeaveCriticalSection
c8c3;kernel32.GetModuleFileNameW
90dc;kernel32.LoadLibraryExW
LoadLibraryExW:
	Arg[0] = ptr 0x0000000140018340 -> L"kernel32"
	Arg[1] = 0
	Arg[2] = 0x0000000000000800 = 2048

91c4;kernel32.GetProcAddress
GetProcAddress:
	Arg[0] = ptr 0x00007ffef1370000 -> {MZ\x90\x00\x03\x00\x00\x00}
	Arg[1] = ptr 0x0000000140018f50 -> "AreFileApisANSI"

15770;kernel32.AreFileApisANSI
d6cf;kernel32.WideCharToMultiByte
d6cf;kernel32.WideCharToMultiByte
8fdd;ntdll.RtlAllocateHeap
1ec7;ntdll.RtlInitializeSListHead
a3a7;kernel32.GetLastError
9390;kernel32.FlsGetValue
a447;kernel32.SetLastError
d6f1;kernel32.GetEnvironmentStringsW
d6cf;kernel32.WideCharToMultiByte
a736;ntdll.RtlAllocateHeap
d6cf;kernel32.WideCharToMultiByte
d7c2;kernel32.FreeEnvironmentStringsW
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
8fdd;ntdll.RtlAllocateHeap
9016;kernel32.HeapFree
8fdd;ntdll.RtlAllocateHeap
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
15770;kernelbase.InitializeCriticalSectionEx
14ab9;CPUID:1
20cb;kernel32.SetUnhandledExceptionFilter
SetUnhandledExceptionFilter:
	Arg[0] = ptr 0x00000001400020d4 -> {H\x89\$\x08WH\x83}

14de;ntdll.RtlInstallFunctionTableCallback
15c4;kernel32.SetUnhandledExceptionFilter
SetUnhandledExceptionFilter:
	Arg[0] = ptr 0x0000000140001180 -> {H\x89L$\x08H\x83\xec}

1649;called: ?? [1aeb0000+0]
> 1aeb0000+0;ntdll.KiUserExceptionDispatcher
a736;ntdll.RtlAllocateHeap
116d;ntdll.[TpReleaseIoCompletion+1cc]*
> 1aeb0000+98;called: ?? [1b194000+d27]
