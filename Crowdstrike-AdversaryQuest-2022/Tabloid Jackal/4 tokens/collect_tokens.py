#!/usr/bin/env python3

from string import ascii_lowercase
from random import randrange
from dateutil import parser as dp
from dateutil.tz import tzutc
import sys
import logging
import requests
from bs4 import BeautifulSoup
from http.client import HTTPConnection


# Set debug output level (1 = spam)

HTTPConnection.debuglevel = 0

SERVER = "http://116.202.83.208:42300"
PROXY = "http://127.0.0.1:8080"

AMOUNT_USERS = 1
AMOUNT_RESETS = 1
if len(sys.argv) >= 2:
  AMOUNT_USERS = int(sys.argv[1])
if len(sys.argv) == 3:
  AMOUNT_RESETS = int(sys.argv[2])



for j in range(AMOUNT_USERS):

  # Generate random account name
  name = "".join(ascii_lowercase[randrange(len(ascii_lowercase))] for i in range(10))
  pweditorial = "pwedit"
  pwmail = "pwmail"

  # Register the account
  print(f"[*] Registering user {name} with editorial pw={pweditorial} and mail pw={pwmail}")
  # requests.post(SERVER + "/register", data=f"name={name}&pweditorial={pweditorial}&pwmail={pwmail}", headers={'Content-Type': 'application/x-www-form-urlencoded'}, proxies={'http': PROXY})
  requests.post(SERVER + "/register", data=f"name={name}&pweditorial={pweditorial}&pwmail={pwmail}", headers={'Content-Type': 'application/x-www-form-urlencoded'})

  # Fire some password resets
  print(f"[*] Requesting {AMOUNT_RESETS} password reset tokens")
  for i in range(AMOUNT_RESETS):
    # requests.post(SERVER + "/reset", data=f"name={name}", headers={'Content-Type': 'application/x-www-form-urlencoded'}, proxies={'http': PROXY})
    requests.post(SERVER + "/reset", data=f"name={name}", headers={'Content-Type': 'application/x-www-form-urlencoded'})

  # Query mails
  print(f"[*] Gathering reset tokens from mailbox")
  # resp = requests.post(SERVER + "/mailbox", data=f"username={name}&pwmail={pwmail}", headers={'Content-Type': 'application/x-www-form-urlencoded'}, proxies={'http': PROXY})
  resp = requests.post(SERVER + "/mailbox", data=f"username={name}&pwmail={pwmail}", headers={'Content-Type': 'application/x-www-form-urlencoded'})

  # Parse respons for tokens
  soup = BeautifulSoup(resp.text, 'html.parser')

  # Get table row list
  trs = soup.select("table > tbody > tr")

  # Grab columns, skip first row (welcome mail)
  tokenlist = []
  for tr in trs[1:]:
    tds = tr.select("td")
    timestamp_epoch = int(dp.parse(tds[0].text + "Z").timestamp()) # added 'Z' for UTC, parsing seemd off
    token = int(tds[1].text.split(".")[0].split()[-1]) # split by '.', then space, last word is token
#    tokenlist.append([timestamp_epoch, token])
    tokenlist.append(token)
    print(f"[=] Timestamp = {tds[0].text} (epoch = {timestamp_epoch}), Token = {token} ({hex(token)})")

  print(f"[*] Tokenlist (epoch, token) = {tokenlist}\n")


