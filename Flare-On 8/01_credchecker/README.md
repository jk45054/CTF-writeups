# Flare-On 8, Challenge 1, Credchecker

## Task

Welcome to Flare-On 8! This challenge surves as your tutorial mission for the epic quest you are about to emark upon. Reverse engineer the Javascript code to determine the correct username and password the web page is looking for and it will show you the flag. Enter that flag here to advance to the next stage. All flags will be in the format of valid email addresses and all end with "@flare-on.com".

## Files

Filename | Size | SHA256
--- | --- | ---
admin.html | 3,873 bytes | 0fc92c8f1417e78959d9cc33a178f8c5cc1044a31d63dc7a1cf2a40da78617ad
img/goldenticket.png | 127,882 bytes | 0a68be1ffe7fc4dae4ecb4540f09f917435d52031fb65ae4e721b65716fda802
img/logo.png | 4,356 bytes | c88abef26c3d994e3b09a88e9fcba6d5d23d3ccfb44b9b3d51e70e2a538f8e15

## High Level Summary

- admin.html contains an **Administrator Verification Form** that does client-side password verification through the JavaScript function `checkCreds()`.
- The username has to be **Admin** and the password the base64 value of **goldenticket**, which is `Z29sZGVudGlja2V0`.
- Entering these credentials yields the flag `enter_the_funhouse@flare-on.com`.

![Flag Screenshot](pics/flag.png)
