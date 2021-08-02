---
title: STANDCON CTF - Interstellar Chat
date: 2021-08-02 17:19:00 +0800
categories: [ctf]
tags: [ctr]
---

# Description

> I've been trying to pirate interstellar chat for the longest time, however their super secure defences have been preventing me from doing so. Could you help me break in and get the flag?
> 
> `nc 20.198.209.142 55001`
> 
> _The flag is in the flag format: STC{...}_
> 
> **Author: PlatyPew**

# Solution

A `server.py` file was provided with the following contents:
```python
#!/usr/bin/env python3
# Author: github.com/PlatyPew

# File located at /opt/interstellar/server.py
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from json import dumps, loads

from random import randint
import traceback
import socket
import threading
import time

PORT = 9999
RECV = 2**16

with open('key', 'rb') as f:
    KEY = f.read()

with open('flag.txt', 'r') as f:
    FLAG = f.read()


def createMsg(id, text):
    msg = {'id': id, 'text': text, 'timestamp': time.time()}
    return dumps(msg).encode()


def enc(nonce, msg):
    crypto = AES.new(KEY, AES.MODE_CTR, nonce=nonce)
    ciphertext = crypto.encrypt(msg)
    enc = nonce + ciphertext
    return enc


def dec(reply):
    nonce = reply[:8]
    ciphertext = reply[8:]
    crypto = AES.new(KEY, AES.MODE_CTR, nonce=nonce)
    return crypto.decrypt(ciphertext)


def run(_, con):
    id = f'#{randint(10000,99999)}'
    text = 'Welcome to the interstellar chat! Our super ultra secure software that is powered ' + \
           'by cylomin technology! As a loyal subscriber of our service, we are offering you ' + \
           f'a flag!\n{FLAG}\n'
    text += 'Would you like to extend your subscription? (y/n)'
    nonce = get_random_bytes(8)

    data = enc(nonce, createMsg(id, text))
    con.sendall(data)

    reply = con.recv(RECV)
    try:
        text = loads(dec(reply).decode())['text']
        if text == 'y':
            print(FLAG)
        else:
            print('Fire the marketing team!')
    except:
        errorMsg = f'Oopsy Daisy we have done goofed. We apologise for our development team\'s incompetence\n{traceback.format_exc()}'
        error = enc(nonce, createMsg(None, errorMsg))
        con.sendall(error)
    finally:
        con.close()


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', PORT))
        s.listen(5)

        while True:
            con, addr = s.accept()
            threading.Thread(target=run, args=(None, con)).start()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(e)
    finally:
        s.close()


if __name__ == '__main__':
    main()
```

Breaking it down, we can first notice that the challenge use `AES` in `CTR` mode, which can be seen from both the `enc()` and `dec()` functions.

```python
# From enc()
crypto = AES.new(KEY, AES.MODE_CTR, nonce=nonce)
# From dec()
crypto = AES.new(KEY, AES.MODE_CTR, nonce=nonce)
```

The main code that handles a client is in the `run()` function, which mainly does the follow things:
1) Send an encrypted welcome message containing the `FLAG`.
2) Receive a response from the client, which when decrypted successfully, would print the `FLAG` to the server's standard output if it contained the correct `text` value. (Unfortunately, it doesn't send the `FLAG` to the client :()
3) If any exceptions occur, such as `JSONDecodeError` which could occur when performing `json.loads()` on the decrypted response from the client, it would send an encrypted version of an error message containing a stack trace of the exception.

The problem comes when reusing the same `key` and `nonce` to perform encryption. While the key is from the `key` file which will always be constant, we can cause the service to encrypt 2 different messages using the same `nonce` in the same session. The 2 different messages are actually the welcome message and the error message!

In order to decrypt the encrypted welcome message containing the `FLAG`, we can use the following explanation:
```python
# Explanation taken slightly from https://meowmeowxw.gitlab.io/ctf/utctf-2020-crypto/
welcome_enc                                           # Encrypted welcome message
error_enc                                             # Encrypted error message
error_clr                                             # Cleartext error message
welcome_clr = welcome_enc xor error_enc xor error_clr # Cleartext welcome message
```

We can easily get the encrypted encrypted welcome message and encrypted error message from the service:
```python
from pwn import *

r = remote("20.198.209.142", 55001)
welcome_enc = r.read()[8:]
r.send(b"something\n")  
error_enc = r.read()[8:]
```

Now we need the cleartext error message. To get it, we will need to run the `server.py` locally with our own custom `FLAG` and custom `key`. Some things to note about `Python` stack traces:

1) It contains the **absolute path** of the script 
2) and **line number** of the code that caused the exception.

Therefore, we would need to run the script from the exact same path (`/opt/interstellar/server.py`) that the service is running from on the server, which is nicely provided in the comments. We should avoid making changes to `server.py` and add no extra lines so that we can get the correct line numbers.

```bash
mkdir -p /opt/interstellar
cd /opt/interstellar
cp ~/Downloads/server.py ./server.py
echo "STC{TRYHARD}" > flag.txt                                 # Creating fake FLAG
python3 -c "import os; open('key','wb').write(os.urandom(16))" # Creating 128-bit key
```

We would also need to install the correct `Crypto` module so that the function calls will work properly:
```bash
pip3 install pycryptodome
```

Next we create our own client script to interact with the local `server.py` and automatically decrypt the encrypted messages.

`client.py`:
```python
from pwn import * 
from Crypto.Cipher import AES
from json import dumps, loads

with open('key', 'rb') as f:
    KEY = f.read()

with open('flag.txt', 'r') as f:
    FLAG = f.read()

def createMsg(id, text):
    msg = {'id': id, 'text': text, 'timestamp': time.time()}
    return dumps(msg).encode()

def dec(reply):
    nonce = reply[:8]
    ciphertext = reply[8:]
    crypto = AES.new(KEY, AES.MODE_CTR, nonce=nonce)
    return crypto.decrypt(ciphertext)

if __name__ == "__main__":
    # Get stack trace message
    r = remote("127.0.0.1", 9999)
    r.read()
    r.send(b"something\n") 
    enc = dec(r.read())
    msg = loads(enc)["text"][len("Oopsy Daisy we have done goofed. We apologise for our development team\'s incompetence\n"):]
    print(msg)
```

Running it will return us a similar stack trace as the server:
```bash
Traceback (most recent call last):
  File "/opt/interstellar/server.py", line 57, in run
    text = loads(dec(reply).decode())['text']
  File "/usr/lib/python3.9/json/__init__.py", line 346, in loads
    return _default_decoder.decode(s)
  File "/usr/lib/python3.9/json/decoder.py", line 337, in decode
    obj, end = self.raw_decode(s, idx=_w(s, 0).end())
  File "/usr/lib/python3.9/json/decoder.py", line 355, in raw_decode
    raise JSONDecodeError("Expecting value", s, err.value) from None
json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)
```

Now we can modify `client.py` to communicate with the actual server and perform the decryption. Here is the final script:
```python
from pwn import * 
from Crypto.Cipher import AES
from json import dumps, loads

with open('key', 'rb') as f:
    KEY = f.read()

with open('flag.txt', 'r') as f:
    FLAG = f.read()

def createMsg(id, text):
    msg = {'id': id, 'text': text, 'timestamp': time.time()}
    return dumps(msg).encode()

def dec(reply):
    nonce = reply[:8]
    ciphertext = reply[8:]
    crypto = AES.new(KEY, AES.MODE_CTR, nonce=nonce)
    return crypto.decrypt(ciphertext)

def xor(s1, s2):
    if(len(s1) == 1 and len(s1) == 1):
        return bytes([ord(s1) ^ ord(s2)])
    else:
        return bytes(x ^ y for x, y in zip(s1, s2))

if __name__ == "__main__":
    # Get stack trace message
    r = remote("127.0.0.1", 9999)
    r.read()
    r.send(b"something\n")
    enc = dec(r.read())
    msg = loads(enc)["text"][len("Oopsy Daisy we have done goofed. We apologise for our development team\'s incompetence\n"):]
    print(msg)

    # Decrypt encrypted welcome message
    r = remote("20.198.209.142", 55001)
    welcome_enc = r.read()[8:]
    r.send(b"something\n")  
    error_enc = r.read()[8:]
    errorMsg = f'Oopsy Daisy we have done goofed. We apologise for our development team\'s incompetence\n{msg}'
    welcome_clr = xor(createMsg(None, errorMsg), xor(welcome_enc, error_enc))

    print(welcome_clr)
```

We were able to make out a major portion of the `FLAG` but the end seemed cut-off.

```
b'{"id": "#19327", "text": "Welcome to the interstellar chat! Our super ultra secure software that is powered by cylomin technology! As a loyal subscriber of our service, we are offering you a flag!\\nSTC{435_15_0nly_600d_1f_y0u_kn0w_h0w_70_1mpl3m3n7_1B3sd_o\x12w2 ~7n\x05k;a4!<sit({njjgx+r#\nN(s;b\x0cX9zfL.c,*=#<?%|$ i%:9ny{d{^p"+:1-95%)1}N!?>!5z&\x12$}'
```

We weren't sure how to get the complete `FLAG`, but as we were racing against time so we simple tried to guess the flag and we got it!

# Flag
`STC{435_15_0nly_600d_1f_y0u_kn0w_h0w_70_1mpl3m3n7_17}`
