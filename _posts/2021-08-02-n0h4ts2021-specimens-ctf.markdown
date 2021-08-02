---
title: N0H4TS CTF - Specimens
date: 2021-08-02 17:19:00 +0800
categories: [ctf]
tags: [lfi]
---

# Description

> Collected a bunch of specimens on our last run, wonder if there is more we misplaced.
> 
> `http://20.198.209.142:55042`
> 
> _The flag is in the flag format: STC{...}_
> 
> **Author: LegPains**

# Solution

![](/assets/images/specimens_1.jpg)

The website didn't seem much at first, but looking into the `HTML` code, we see something interesting:

```html
<ul class="nav">
	<li class="nav-item">
		<a class="nav-link active" href="?specimen=turtle.php">Specimen 1</a>
	</li>
	<li class="nav-item">
		<a class="nav-link active" href="?specimen=meteorite.php">Specimen 2</a>
	</li>
	<li class="nav-item">
		<a class="nav-link active" href="?specimen=astronaut.php">Specimen 3</a>
	</li>
</ul>
```

We see that each of the links in the navbar are pointed to the same page, but with the location of another `.php` file specified in the `specimen` parameter! The next step would probably to test for `Local File Inclusion (LFI)` vulnerabilites.

We first tried `specimen=/etc/passwd` and got no result, so we appended multiple `../` to the front to get `specimen=../../../../../../../etc/passwd` and we still got no results! What's going on? Could the page be doing some form of filtering against `../`?

To summarize what we tried, here is a list of payloads and results that let us deduce that it was doing one pass of replacing all `../` with blanks:

```
turtle.php                                     => shows turtle page
../turtle.php                                  => show turtle page
....//turtle.php                               => no turtle page
....//....//....//....//....//....//etc/passwd => show contents of /etc/passwd
```

We also observed that submitting an absolute path in `specimen` will not work as the `specimen` value might be prefixed with some directory in the code before including it.

Now that we have a full understanding of the protective measures in place, the next step was figuring out where the flag was. CTFs tend to name their flag files as `flag.txt`, so we tried a few locations and `....//....//flag.txt` worked!

![](/assets/images/specimens_2.jpg)

# Flag
`STC{StRINg_r3PLace_I5_n0T_ReCUR5ive}`
