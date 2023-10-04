---
title: Hack The Box - Delivery
date: 2021-05-23 03:00:00 +0800
categories: [hackthebox]
tags: [linux]
image:
    path: /assets/images/delivery.png
---

# Configuration

The operating system that I will be using to tackle this machine is a Kali Linux VM.

What I learnt from other writeups is that it was a good habit to map a domain name to the machine's IP address so as that it will be easier to remember. This can done by appending a line to `/etc/hosts`.

```bash
$ echo "10.10.10.222 delivery.htb" | sudo tee -a /etc/hosts
```

# Reconnaissance

```bash 
$ nmap -sT -sV -sC -Pn -p- delivery.htb                                            130 ⨯
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-10 05:54 EST
Nmap scan report for delivery.htb (10.10.10.222)
Host is up (0.0099s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 9c:40:fa:85:9b:01:ac:ac:0e:bc:0c:19:51:8a:ee:27 (RSA)
|   256 5a:0c:c0:3b:9b:76:55:2e:6e:c4:f4:b9:5d:76:17:09 (ECDSA)
|_  256 b7:9d:f7:48:9d:a2:f2:76:30:fd:42:d3:35:3a:80:8c (ED25519)
80/tcp   open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Welcome
8065/tcp open  unknown
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Accept-Ranges: bytes
|     Cache-Control: no-cache, max-age=31556926, public
|     Content-Length: 3108
|     Content-Security-Policy: frame-ancestors 'self'; script-src 'self' cdn.rudderlabs.com
|     Content-Type: text/html; charset=utf-8
|     Last-Modified: Sun, 10 Jan 2021 08:42:24 GMT
|     X-Frame-Options: SAMEORIGIN
|     X-Request-Id: s5qoxo1kepgz8mon3oj1utj6ya
|     X-Version-Id: 5.30.0.5.30.1.57fb31b889bf81d99d8af8176d4bbaaa.false
|     Date: Sun, 10 Jan 2021 10:54:41 GMT
|     <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=0"><meta name="robots" content="noindex, nofollow"><meta name="referrer" content="no-referrer"><title>Mattermost</title><meta name="mobile-web-app-capable" content="yes"><meta name="application-name" content="Mattermost"><meta name="format-detection" content="telephone=no"><link re
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Date: Sun, 10 Jan 2021 10:54:41 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8065-TCP:V=7.91%I=7%D=1/10%Time=5FFADCF1%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request")%r(GetRequest,DF3,"HTTP/1\.0\x20200\x20OK\r\nAccept-Ranges:\
SF:x20bytes\r\nCache-Control:\x20no-cache,\x20max-age=31556926,\x20public\
SF:r\nContent-Length:\x203108\r\nContent-Security-Policy:\x20frame-ancesto
SF:rs\x20'self';\x20script-src\x20'self'\x20cdn\.rudderlabs\.com\r\nConten
SF:t-Type:\x20text/html;\x20charset=utf-8\r\nLast-Modified:\x20Sun,\x2010\
SF:x20Jan\x202021\x2008:42:24\x20GMT\r\nX-Frame-Options:\x20SAMEORIGIN\r\n
SF:X-Request-Id:\x20s5qoxo1kepgz8mon3oj1utj6ya\r\nX-Version-Id:\x205\.30\.
SF:0\.5\.30\.1\.57fb31b889bf81d99d8af8176d4bbaaa\.false\r\nDate:\x20Sun,\x
SF:2010\x20Jan\x202021\x2010:54:41\x20GMT\r\n\r\n<!doctype\x20html><html\x
SF:20lang=\"en\"><head><meta\x20charset=\"utf-8\"><meta\x20name=\"viewport
SF:\"\x20content=\"width=device-width,initial-scale=1,maximum-scale=1,user
SF:-scalable=0\"><meta\x20name=\"robots\"\x20content=\"noindex,\x20nofollo
SF:w\"><meta\x20name=\"referrer\"\x20content=\"no-referrer\"><title>Matter
SF:most</title><meta\x20name=\"mobile-web-app-capable\"\x20content=\"yes\"
SF:><meta\x20name=\"application-name\"\x20content=\"Mattermost\"><meta\x20
SF:name=\"format-detection\"\x20content=\"telephone=no\"><link\x20re")%r(H
SF:TTPOptions,5B,"HTTP/1\.0\x20405\x20Method\x20Not\x20Allowed\r\nDate:\x2
SF:0Sun,\x2010\x20Jan\x202021\x2010:54:41\x20GMT\r\nContent-Length:\x200\r
SF:\n\r\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConten
SF:t-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n
SF:400\x20Bad\x20Request")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r
SF:\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close
SF:\r\n\r\n400\x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x2
SF:0Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nCon
SF:nection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TerminalServerCookie
SF:,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;
SF:\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request"
SF:);
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 88.44 seconds
```

# Enumeration (1)

## Port 80 `nginx 1.14.2`

![](/assets/images/delivery1.png)

Clicking on the `CONTRACT US` button shows this:

![](/assets/images/delivery2.png)

The underlined `HelpDesk` brings us to another domain `helpdesk.delivery.htb` so lets add that to our `/etc/hosts`.

```bash
$ cat /etc/hosts
...
10.10.10.222 delivery.htb helpdesk.delivery.htb
```

![](/assets/images/delivery3.png)

It seems that `osTicket` is running on this domain. The `Contact Us` message says to use this website to get in touch with our team so lets try opening a new ticket by clicking on the `Open a New Ticket` button.

![](/assets/images/delivery4.png)

After filling up the fields marked with a red asterisk and hitting `Create a New Ticket`,

![](/assets/images/delivery5.png)

we have successfully created a support ticket. Note about the ticket id and especially the last bit `If you want to add more information to your ticket, just email 1339336@delivery.htb`. The `Contact Us` message did say as long we have a `@deliveryhtb` email, we could access the `Mattermost` server on port `8065`. However, as there was no mail services running, I wasn't sure how these would all click together.

Lets try check the status of our ticket by clicking on `Check Ticket Status` in the navbar.

![](/assets/images/delivery6.png)

After filling the email address that we used and the ticket id assigned to us,

![](/assets/images/delivery7.png)

we can view our support ticket thread but there are no responses yet.

## Port 8065 `Mattermost`

![](/assets/images/delivery8.png)

`Mattermost` was running on port `8065`. We didn't have any credentials so lets create an account. The `Contact Us` email said to use a `@delivery.htb` email so lets use the one we already have. After register with that email,

![](/assets/images/delivery9.png)

A confirmation email is sent and it was received in our support ticket thread! Turns out any email sent to our `@delivery.htb` email that we have will have its contents appended to this support ticket thread.

![](/assets/images/delivery10.png)

After clicking on the verification link, we see that we have successfully verified our account.

![](/assets/images/delivery11.png)

Logging in with the credentials we registered with, we see that there is already a team called `Internal` that we can join.

![](/assets/images/delivery12.png)

There were a few messages in the chat:

![](/assets/images/delivery13.png)

The `root` user had left the credentials of the `maildeliverer` account! He also talked about not using a password that is a variant of `PleaseSubscribe!`. Maybe we are suppose to find a hash and crack it?

## Port 22 `OpenSSH 7.9p1`

Using the `maildeliverer:Youve_G0t_Mail!` credentials we found, we can `ssh` as `maildeliverer`.

```bash
$ ssh maildeliverer@delivery.htb
Warning: Permanently added the ECDSA host key for IP address '10.10.10.222' to the list of known hosts.
maildeliverer@delivery.htb's password: Youve_G0t_Mail!
maildeliverer@Delivery:~$ id 
uid=1000(maildeliverer) gid=1000(maildeliverer) groups=1000(maildeliverer)
```
# user.txt

The user flag is in the home directory of `maildeliverer`.

```bash
maildeliverer@Delivery:~$ cat user.txt
730aXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

# Enumeration (2)

Since there was a `root` user with the email `root@delivery.htb` in the `Mattermost` server, lets check out its config files for any juicy information. Its config settings are stored in `/opt/mattermost/config/config.json`.

```bash
maildeliverer@Delivery:/opt/mattermost/config$ cat config.json
...
    "SqlSettings": {
        "DriverName": "mysql",
        "DataSource": "mmuser:Crack_The_MM_Admin_PW@tcp(127.0.0.1:3306)/mattermost?charset=utf8mb4,utf8\u0026readTimeout=30s\u0026writeTimeout=30s",
```

We spotted some `MySQL` credentials! The `Crack_The_MM_Admin_PW` is probably telling us to find a hash of the `root` account from the `Mattermost`'s database and crack it!

```bash
maildeliverer@Delivery:/opt/mattermost/config$ mysql -ummuser -p
Enter password: Crack_The_MM_Admin_PW

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mattermost         |
+--------------------+

MariaDB [mattermost]> select Username, Password,Email   from Users where Username="root";
+----------+--------------------------------------------------------------+-------------------+
| Username | Password                                                     | Email             |
+----------+--------------------------------------------------------------+-------------------+
| root     | $2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO | root@delivery.htb |
+----------+--------------------------------------------------------------+-------------------+
```

Nice, we got the password hash of `root`! Now we just need to crack it. `root`'s message in `Internal`'s chat said something using a variant of `PleaseSubscribe!`, hence we will need to perform some form of mutation to the password. I made use of a `hashcat` [rule file](https://github.com/NotSoSecure/password_cracking_rules/blob/master/OneRuleToRuleThemAll.rule) that I found online to crack the password. It took a while, but it was able to crack the hash.

```bash
$ echo "\$2a\$10\$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO" > hash.txt
$ echo "PleaseSubscribe!" > wordlist.txt
$ hashcat -m 3200 -a 0 -r OneRuleToRuleThemAll.rule hash.txt wordlist.txt
...
$2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO:PleaseSubscribe!21
...
```

If we `su` to `root` with the password, we see that we have a shell as `root`!

```bash
maildeliverer@Delivery:/opt/mattermost/config$ su
Password: PleaseSubscribe!21
root@Delivery:/opt/mattermost/config# id
uid=0(root) gid=0(root) groups=0(root)
```

# root.txt

The root flag is located at `/root` as always.

```bash
root@Delivery:/opt/mattermost/config# cat /root/root.txt
9b69XXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

### Rooted ! Thank you for reading and look forward for more writeups and articles !