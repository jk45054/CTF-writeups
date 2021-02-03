# Crowdstrike Adversary Quest 2021 / Space Jackal / Injector

## Challenge Description
The decrypted forum messages revealed that a disgruntled employee at one of our customers joined SPACE JACKAL and backdoored a host at their employer before they quit. Our customer provided us with a snapshot of that machine.
Please identify the backdoor and validate your findings against our test instance of that host, which is available at injector.challenges.adversary.zone.


## Nmap Scan of Backdoored Target Server
```
# Nmap 7.91 scan initiated Wed Jan 20 00:13:42 2021 as: nmap -Pn -p4321,3322,1-1024 -oA nmap injector.challenges.adversary.zone
Nmap scan report for injector.challenges.adversary.zone (167.99.209.243)
Host is up (0.073s latency).
Not shown: 1023 filtered ports
PORT     STATE SERVICE
1022/tcp open  exp2
3322/tcp open  active-net
4321/tcp open  rwhois

# Nmap done at Wed Jan 20 00:15:34 2021 -- 1 IP address (1 host up) scanned in 111.64 seconds
```

