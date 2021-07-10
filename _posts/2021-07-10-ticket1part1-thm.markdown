---
title: TryHackMe - Pre Security Learning Path (Part 1) [PARTICIPATE IN THE GIVEAWAY!]
date: 2021-07-10 04:19:00 +0800
categories: [tryhackme]
tags: []
---

![](/assets/images/tickets1.jpg)

# Introduction

[TryHackMe](https://tryhackme.com) was promoting their brand new [`Pre Security` learning path](https://tryhackme.com/path/outline/presecurity), which was aimed at learning the basics of cyber security in a much beginner friendly way. I ain't exactly a beginner, but the prizes to be won were just too attractive so I immediately bought the premium subscription. Fortunately, I was still a student, so I was able to enjoy the `20%` discount! 

If you are interested in trying out [TryHackMe](https://tryhackme.com), please kindly use my [referral link](https://tryhackme.com/signup?referrer=df947ec74564a48cda33becfe50cfd85da3c49bd) and we will both earn a free ticket when you get 100 points on the platform!

# Cyber Security Introduction

## Room 1: [Learning Cyber Security](https://tryhackme.com/room/beginnerpathintro)

### Task 1: Web Application Security

![](/assets/images/tickets1-1.jpg)

We are presented with what seems to be a simulated website called `BookFace` and our job was to hack it, or in nicer terms, perform a test for security vulnerabilties. Pressing on the 👉 will allow us to proceed to the next instructions so make sure to read them carefully! 

There was a `Forgot Password` page where in order to reset a user `Ben`'s password, we will need to correctly guess a 4 digit PIN. We were provided with a simulated `Repeater` tool, which allows to repeatedly send requests and automatically increment the reset code for us! Well the reset code is 4 digits, so essentially we can just bruteforce from `1000` to `9999`. 

![](/assets/images/tickets1-6.jpg)

Unfortunately, my assumption was wrong and turns out we were to suppose to start from `1` since zeroes can be padded in front to get 4 digits! 

After resetting to a password of our choice, we immediately got the flag!


### Task 2: Network Security

A known cyber incident was introduced to illustrate the importance of properly segregating your assets.

![](/assets/images/tickets1-7.jpg)

### Task 3: Learning Roadmap

[TryHackMe](https://tryhackme.com) mainly provides 2 paths, each with numerous boxes of varying difficulty so quickly register now to learn as much as you can!

![](https://i.imgur.com/uWQ9HsM.png)

# Network Fundamentals

## Room 2: [What is Networking?](https://tryhackme.com/room/whatisnetworking)

### Task 3: Identifying Devices on a Network 


![](/assets/images/tickets1-8.jpg)

We have 2 machines `Bob` and `Alice`, with their own unique `MAC` address. We can click on `Request Site` and we will be able to send requests as `Bob` to the TryHackMe web server but our packets will get dropped to the trash bin by the oruter! To overcome this, we can set the `MAC` address of `Bob` to that of `Alice` in order to trick the router into thinking we are `Alice` and we will be able to access and get the flag!

### Task 4: Ping (ICMP) 

![](/assets/images/tickets1-9.jpg)

We are provided with a simulated terminal where we can insert any valid IP address and it will fake some `ping` output for us!

## Room 3: [Intro to LAN](https://tryhackme.com/room/introtolan)

The answers for most of the following questions can be found from the provided explanations so I won't be explaining much here.

### Task 1: Introducing LAN Topologies 

![](/assets/images/tickets1-10.jpg)

There was even a neat and interactive panel that was used to illustrate the weaknesses of various network topologies such as ring, star and bus.

## Room 4: [OSI Model](https://tryhackme.com/room/osimodelzi)

### Task 9: Practical - OSI Game

There was even a 8-bit game to test your memory of the order in the OSI Model!

![](/assets/images/tickets1-11.jpg)

## Room 5: [Packets & Frames](https://tryhackme.com/room/packetsframes)

### Task 3: Practical - Handshake 

![](/assets/images/tickets1-12.jpg)

This game aimed to show the how TCP works by simulating a conversation between this lady and us and we would need to figure what is the right order to get her message across to us.

### Task 5: Ports 101 (Practical) 

![](/assets/images/tickets1-13.jpg)

Here we have another simulated shell, but we are given 2 fields which appended to the `nc` command to allow us to connect to an exposed port.

## Room 6: [Extending Your Network](https://tryhackme.com/room/extendingyournetwork)

### Task 3: Practical - Firewall 

![](/assets/images/tickets1-14.jpg)

For this activity, you have to move fast and configure the necessary rules to block all traffic from `198.51.100.34` before the website `203.0.110.1` actually gets overloaded. Had to do it twice because it took me a while to look for the correct IP addresses in the dropdown lists.

### Task 6: Practical - Network Simulator 

![](/assets/images/tickets1-15.jpg)

The goal was to get a `TCP` packet from `computer1` to `computer3`. I really liked how it clearly illustrates the different steps and even provides a neat network log on the side. Beginners often get confused by the process so this will greatly help them.

# How The Web Works

## Room 7: [DNS in Detail](https://tryhackme.com/room/dnsindetail)

### Task 5: Practical

![](/assets/images/tickets1-16.jpg)

Another simulated shell, where we have to insert the correct arguments to the `nslookup` to query the required `DNS` information.

## Room 8: [HTTP in detail](https://tryhackme.com/room/httpindetail)

### Task 1: What is HTTP(S)? 

![](/assets/images/tickets1-17.jpg)

Since the task was about `HTTPS`, I wanted to add an `s` to the protocol in the URL bar but turns out I was supposed to just click on the lock.

### Task 7: Making Requests 

![](/assets/images/tickets1-18.jpg)

For this task, we were suppose to use this simulated browser (in my browser!) to manually manipulate the `HTTP`request to perform various actions. 

## Room 9: [How websites work](https://tryhackme.com/room/howwebsiteswork)

### Task 5: HTML Injection 

![](/assets/images/tickets1-19.jpg)

We are given a form, that when submitted, will render the data on the website. I tried to insert `javascript`, but it didn't work heh.

## Room 10: [Putting it all together](https://tryhackme.com/room/puttingitalltogether)

### Task 4: Quiz 

![](/assets/images/tickets1-20.jpg)

We are given some pieces and we need to figure out the right order that illustrates the full process of browsing to a page. When a piece is inserted into its correct slot, the box will turn green so use that to get the correct answer!