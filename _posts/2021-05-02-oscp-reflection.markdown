---
title: Post-OSCP Writeup
date: 2021-05-02 01:02:00 +0800
categories: []
tags: []
image:
    path: /assets/images/oscp.jpg
---

# Introduction

It's been a long 3 months since I took the OSCP exam and I still couldn't believe I passed on the **first** attempt, even till now. Receiving the email from Offensive Security informing me that I had "successfully completed the Penetration Testing with Kali Linux certification exam and have obtained your Offensive Security Certified Professional (OSCP) certification" was exhilarating and I was going around showing my friends and family the email. It felt like I was at the top of the world but soon after, I had to face the realities of university as I had tons of unwatched lecture recordings and school work to complete. Yesterday was the last day of my exams and the last day as a freshman, hence I finally had the time to reflect on my journey, as well as bring it to an end.

# How it all started

I had a friend who was thinking about pursuing the OSCP certification during the first-semester break while I was still on the fence about taking it. One day he told me that he had registered for the 30 days lab, so I was thinking "YOLO!" and did the same as well. I personally had quite a bit of experience in pentesting and if you see check out the posts on my blog, you will see that I had started owning boxes on `Hack The Box` since 2019 and was able to get to the rank of `Pro Hacker`. Even so, I was about to tackle an incredibly difficult exam and I needed to bring my A-game if I'm going to overcome it.

# The Preparation

Even though I had subscribed for the 30 day lab access, I did not access the labs in the first 7 days, not because I was reading the 700+ page PDF file, but rather I was just extremely and boy... I regret it immensely. There was a total of 66 machines in the network and I wanted to challenge myself to finish all 66 of the machines, hence I was rushing to finish 3-5 boxes per day! If only I had started earlier, I could have done them at a more leisurely pace and perhaps I could have written a writeup for each one of them but *oh well*. I had left buffer overflow to the last part, not because I didn't want to do it, but because I wanted to still retain as much of the buffer overflow knowledge even after I finish my lab access. Fortunately, I was able to finish **ALL** 66 machines and I definitely deserve a pat on my back for this one.

After I bid farewell to my lab access, I finally decided to prepare myself seriously for the exam. To learn and practise buffer overflow, I did the [`Buffer Overflow Prep`](https://tryhackme.com/room/bufferoverflowprep) by `Tib3rius`, like what many people had suggested to do. I practised doing all 10 overflows until it became muscle memory (so that I do not miss out on any steps and waste more time on it during the exam) and I strongly suggest doing it one more time right before the exam.

I then did as many boxes from [`TJNull`'s list of OSCP-like boxes](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=1839402159) on `Hack The Box`. Many of the boxes were retired, but fortunately I had previously won a 1-year VIP `Hack The Box` subscription from some random competition that I participated in where I had to rush to own a given VM and within 5 minutes, I got the root flag and became one of the few lucky winners to get the subscription. As I did the boxes, I tried to take down some of the common useful commands into a cheatsheet so that I can refer to them during the exam. I probably should have done this since the start of the lab access, and I strongly suggest you craft your own one too. I also crafted my own install script of all the tools/exploits that did not come with the default Kali installation.

I gave myself a few days before the exam and stopped doing boxes to mentally prepare myself as well as finalise my cheatsheet, my exam report template and my Kali machine. I seriously wished I had a written methodology containing the things to do and look out for, but I ended up just trusting my gut instinct and experiences. Often that would lead to me forgetting something, but thankfully I didn't during the exam.

# The Examination

I had postponed the exam a few times but a concern to me was that I wanted to get it done and over with so that I do not have to balance my focus between university and the OSCP exam. I was able to get a slot on a Friday, which was fortunate because if I had picked a slot on a weekend, I would probably end on a Monday and that would be terrible for me because I had classes on Monday mornings. People typically get a morning/afternoon timing (so that it is more synced up with their body clocks) but I instead got a slot at 8pm. I am at my best during the wee hours (Thank you university life) and I was planning to stay up all the way till I owned all the boxes.

The start of the exam did not go all that well for me as I struggled with the part where I had to show some form of identification to my proctor. Despite this issue, I did not have a time extension and was only able to properly start 8:30pm. My plan was originally to start with the buffer overflow box and finish it within in the first hour and fortunately, I was able to own it within 30 minutes with no mistakes and was back on track!

Of course, before doing the buffer overflow box, I was running an automated tool called [`nmapAutomator`](https://github.com/21y4d/nmapAutomator) to automate the process of scanning and enumerating the services found. It was only halfway through my second box then I realised that some ports were not shown in the results! I had to run a manual scan, this time with a super quick scanning tool called [`rustscan`](https://github.com/RustScan/RustScan) and I was able to capture all the exposed ports. I wished that I had experimented more with [`nmapAutomator`](https://github.com/21y4d/nmapAutomator) as well as perhaps [`AutoRecon`](https://github.com/Tib3rius/AutoRecon) before actually using them during the exam. Information that are missed out by accident can be deadly, especially when it could lead you to the vulnerability that you need to exploit.

After the buffer overflow box, I tackled the hardest box first. My friend (the one who registered for the OSCP certification with me) had once suggested to me to give myself 3 hours and if I cannot find anything to exploit, I should move on to the next target. Fortunately, I discovered the attack vector for this box towards the end of the 3 hours and was able to continue the pentest on this box.

After finishing the second box, I had a sigh of relief because I knew that if I could deal with the hardest, I could do anything. Without taking a break, I then continued with the next 2 medium boxes. While running some tools on the fourth box, I guessed that had nothing else to do, so I decided to give a shot at the last easy box. Within 10 minutes or so, I had captured the root flag of it! 

Around 8 hours after the start of the exam, I had owned all the machines! At this point I decided to take a break and surprisingly, my mom was awake, and I decided to chat with her while I replenished myself with some food and drinks. My mom told me that there was food set aside on my bed, in case I got hungry, but I did not realise and it ended up turning cold. After some rest, I then went back to my workstation and started documenting and screenshotting every step. After that is done, I decided to terminate my exam session early by a few hours since I had everything I needed and was ready to write my exam report.

I took my time with writing the exam report in the following 24 hours, even though I could have finished early and use the remaining time of my weekends to catch up on my schoolwork but I decided not to :P.

# OSCP tips

If you are ever considering on taking on the OSCP certification, here are some tips:

1) Before even registering for the lab access, try to do the [`TJNull`'s list of OSCP-like boxes](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=1839402159) to get a sensing of what to expect and you will be able to progress through the lab much quicker and put your time to better use. I know I did the boxes after my lab access but I strongly urge you do them before the lab access.  
2) Start creating your cheatsheet, methodology and toolbox early. With every machine you own, take down some of the common and useful commands that you know that you will need such as reverse shell commands or file transfer commands. Also take down things to check for, such as if you face a web server, check if there is a `robots.txt` or a `sitemap.xml`. Keep track of the tools you use and have them ready, accessible, and sorted so that you do not have to waste time installing it again and again and also take down the command syntax to use them. And most importantly, make sure to fully understand your tools and ensure that they do not infringe the exam guidelines.  
3) Practising documenting or simply just create a writeup for every box you own so that you can develop your writing style and understand what kind of steps to include to reduce the chance of failing due to incomplete documentation. You will also be able to understand what kind of screenshots you need for your exam report.  
4) Make sure to understand the exam guidelines completely, such as the things you can/cannot do, the things that you need to submit in your report and the format of submission. Not paying attention to small details like these can cause you to fail, even if you manage to own all the exam boxes.

There are plenty of OSCP-related videos and reviews out on the Internet so do check them out so that you can better inform yourself on how to prepare and what to expect. And last but not least, **Try Harder**.

