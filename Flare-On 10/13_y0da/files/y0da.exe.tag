32701;section: [.text]
6080b;kernel32.LoadLibraryA
LoadLibraryA:
	Arg[0] = ptr 0x000000000008f228 -> "ws2_32.dll"

6080b;kernel32.LoadLibraryA
LoadLibraryA:
	Arg[0] = ptr 0x000000000008f238 -> "user32.dll"

6080b;kernel32.VirtualAlloc
VirtualAlloc:
	Arg[0] = 0
	Arg[1] = 0x0000000000000058 = 88
	Arg[2] = 0x0000000000001000 = 4096
	Arg[3] = 0x0000000000000004 = 4

6080b;kernel32.VirtualAlloc
VirtualAlloc:
	Arg[0] = 0
	Arg[1] = 0x0000000000004000 = 16384
	Arg[2] = 0x0000000000001000 = 4096
	Arg[3] = 0x0000000000000004 = 4

6080b;kernel32.VirtualAlloc
VirtualAlloc:
	Arg[0] = 0
	Arg[1] = 0x0000000000004000 = 16384
	Arg[2] = 0x0000000000001000 = 4096
	Arg[3] = 0x0000000000000004 = 4

6080b;kernel32.VirtualAlloc
VirtualAlloc:
	Arg[0] = 0
	Arg[1] = 0x0000000000001000 = 4096
	Arg[2] = 0x0000000000001000 = 4096
	Arg[3] = 0x0000000000000004 = 4

6080b;ws2_32.WSAStartup
6080b;kernel32.CreatePipe
6080b;kernel32.CreatePipe
6080b;ws2_32.socket
6080b;ws2_32.bind
6080b;kernel32.GetStdHandle
6080b;kernel32.WriteConsoleA
6080b;ws2_32.listen
6080b;ws2_32.accept
6080b;kernel32.GetEnvironmentVariableA
6080b;kernel32.GetEnvironmentVariableA
47225;kernel32.CreateProcessA
CreateProcessA:
	Arg[0] = 0
	Arg[1] = ptr 0x000000000008fc10 -> "C:\Windows\system32\cmd.exe"
	Arg[2] = 0
	Arg[3] = 0
	Arg[4] = 0x0000000000000001 = 1
	Arg[5] = 0
	Arg[6] = 0
	Arg[7] = ptr 0x000000000008fb00 -> "C:\Windows"
	Arg[8] = ptr 0x000000000008fa90 -> L"h"
	Arg[9] = ptr 0x000000000008fa48 -> {\x00\x00\x00\x00\x00\x00\x00\x00}

6080b;ws2_32.send
5778d;kernel32.CreateThread
CreateThread:
	Arg[0] = 0
	Arg[1] = 0
	Arg[2] = ptr 0x000000018004928c -> {H\x89L$\x08\xe9Tu}
	Arg[3] = ptr 0x0000000018ad0000 -> {T\x01\x00\x00\x00\x00\x00\x00}
	Arg[4] = 0
	Arg[5] = 0

62fd5;kernel32.CreateThread
CreateThread:
	Arg[0] = 0
	Arg[1] = 0
	Arg[2] = ptr 0x000000018004e0e7 -> {H\x89L$\x08\xe9\xd9'}
	Arg[3] = ptr 0x0000000018ad0000 -> {T\x01\x00\x00\x00\x00\x00\x00}
	Arg[4] = 0
	Arg[5] = 0

6080b;kernel32.WaitForSingleObject
6080b;kernel32.VirtualAlloc
VirtualAlloc:
	Arg[0] = 0
	Arg[1] = 0x0000000000004000 = 16384
	Arg[2] = 0x0000000000001000 = 4096
	Arg[3] = 0x0000000000000004 = 4

6080b;kernel32.VirtualAlloc
VirtualAlloc:
	Arg[0] = 0
	Arg[1] = 0x0000000000004000 = 16384
	Arg[2] = 0x0000000000001000 = 4096
	Arg[3] = 0x0000000000000004 = 4

15b0f;kernel32.PeekNamedPipe
25410;kernel32.ReadFile
ReadFile:
	Arg[0] = 0x000000000000013c = 316
	Arg[1] = ptr 0x0000000018b20000 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[2] = 0x0000000000004000 = 16384
	Arg[3] = ptr 0x000000001a99fe48 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[4] = 0

6080b;ws2_32.recv
6080b;ws2_32.send
15b0f;kernel32.PeekNamedPipe
15b0f;kernel32.PeekNamedPipe
15b0f;kernel32.PeekNamedPipe
