# Crowdstrike Adversary Quest 2021 / Protective Penguin / #4 Exfiltrat0r

## Challenge Description
Additional analysis of the victim network allowed us to recover some PROTECTIVE PENGUIN tooling that appears to provide remote shell and data exfiltration capabilities. While we were able to capture some network traffic of these tools in action, all communications are encrypted. We have wrapped all relevant information into a TAR archive.
Are you able to identify any weaknesses that would allow us to recover the encryption key and figure out what data was exfiltrated?

## Approach
- Triage evidence files
- Hypothetize
- Experiment with cryptshell.sh and exfil.py
- Identify side channel information leak
- Decrypt transmitted files

### Triage Evidence Files

### Hypothetize

### Experiment with cryptshell.sh and exfil.py

### Identify Side Channel Information Leak

### Decrypt Transmitted Files for Flag Time

Flag: **CS{p4ck3t_siz3_sid3_ch4nn3l}**

## Conclusion
Using modern and cryptographically secure algorithms is a great start for securing the confidentiality and integrity of data transmissions.
But as this challenge shows quite nicely, that is not enough. Fancy ASCII art from tools used in an interactive shell might lead to information leaks.
