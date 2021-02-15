+++
tags = ["blog","thoughts","cybersecurity","learning"]
date = "2021-02-14T16:00:00Z"
title = "Q3liZXJzZWMgbXkgd2F 5IC0gUGFydCAxCg=="
images = ["https://ceso.github.io/images/blog/cybersecmyway/banner.jpg"]
toc = true
aliases = [
    "/posts/2021/02/q3lizxjzzwmgbxkgd2f5ic0gugfydcaxcg/"
]
description = "An insight about how I'm learning Cybersec"
+++

## Preface

Lot of things have happend since the last time I posted something here, such as moving back to my country at the middle of last year to also stopping studying for some months due prioritizing my mental health (2020 was a bitch to all of us). 

***I already talked a bit about my background and how I started to study Cybersec in my prior post related to [my experience with OSCP](https://ceso.github.io/posts/2020/04/a-journey-in-the-dark-an-adventures-tale-towards-oscp/), you can go there and read about it if you want, but I will repeat some stuff here.***

Well! This post will be an insight about how I'm learning Cybersec, at the moment, tools I use, channels Im watching, how I'm practicing, etc, said all of this...let's jump in!

### 0x000: Define goals, What do I want to do?

This is the first thing I do, define goals. Specifically talking in this case, Cybersec is a HUGEE world of things to learn (as almost anything in IT), and it has a lot of different domains of knowledge, so...is needed to have clear in mind what one want's to do and from here start climbing up the mountain.
For example, what do you want to know the most?

Web Pentesting?

Reversing?

Mobile Pentesting?

Malware development?

Physycall Assesments?

Network Pentesting?

Pentest embebed devices (such as IoT)?

In my case, after some months of thinking, **I made my mind and defined my goals: I want to learn WebApp Pentesting and Mobile/IoT pentesting. And end up doing Red Team stuff** Of course this is not a static thing, one is always changing, and what I want to do today, could not be the same I want to do in 1 week, but the onlye way you will realize about it, is putting your hands on the fire!!

{{< image src="/images/blog/cybersecmyway/goals.png" position="center" style="border-radius: 8px;" >}}

### 0x001: What do I need to do to achieve my goals? Define your way to learning

In Cybersec as any other domain knowledge of IT, everything has pre-requisites (or dependencies), things you should know or have an idea about it, if is the opposite when you are trying to learn something without that knowledge, you will a huge wall or either find an oportunity to learn that knowledge you are lacking.

Let's make clear what I'm talking about with a short example:

```console
I wanna learn:
- A
- B
- C
- X

'A' has as a pre-requisite knowing (or having an idea) about:

- Z
- D
- J

Now...to understand 'J' you first need to know about:

- C
- B

But in order to being able to understand what is all the noise 
regardless 'C' and 'B', you need to know about:

- D
- X
```

Or in a graphical way:

{{< image src="/images/blog/cybersecmyway/knowledge_domain.png" position="center" style="border-radius: 8px;" >}}

And here my dear reader, is where things tart to get 100% personal...why you may ask? Because you need to find what works best for you, what works for you might not work for me, as might work for other person and for another not.

Some people could prefer to NOT jump into learning about A, B, C, X until they know all that is needed from the basics, let's say they will start learning D and X, after they know about it they will continue with C and B, from that point they will continue with J and Z, now thay they got the basics, finally they will learn about A. It is a valid way to learn (and is the most extended one: highschool, university, etc. Every curricula is made up following the graph of dependencies), and it has a huge benefit you will have a really solid foundation, but in my personal case, that way of learning...it doesn't work for me.

Then...how do I approach learning (and cybersec which has a ton shit of dependencies)? In a really "exploratory way", if I go in the more dependencie graph way...I end up bored, unmotivated, etc. I personally feel it as forcing myself to do something I do not want.
I do not give to much attention to foundations/basics, ***I just define what I want to learn and get my hands dirty with the subject***, I wanna learn 'A'? Well nice I start reading/playing with labs related to 'A', if I reach a point where I no longer understand anything due to not knowing about the basic foundations it has, then well, I "open a branch" in my learning process, go to that branch and start learning about the basics I do need, if to understand those basics I do need to "open another branch" related to another subject, then I just do it, and at a given point of time, I have the needed knowledge to understand what I was trying to learn of 'A', at that moment I just "go back", to the root from the firsts "branchs" just opened and continue from it, if at a given moment there is needed again to learn a foundation, ok sure, I just repeat that process.
Tied to this "exploratory" way in which I approach learning, I'm also really practical, then I will learn mostly by doing things, getting my hands dirty, not just by reading.

**As I said, this is 100% and it's the way I learn, it might not be the most efficient, you might not have the most solid foundations, but it's the one that has been working the most for me, the one that feels the more natural and the one that keeps me the most motivated (I started the travel wanting to know about 'A', but I ended up knowing about more than A!!!).**

_By the way, this is the way I learned (and still doing it) english, it all started by creating a "basic" vocabulary by translating a bunch of words from Spanish to English. From there trying to read stuff in english if a wild new word appeared in front of me (let's say 'reassess), I jumped to google and typed 'reassess meaning' and tried to understand the definition of the word directly in english, if the definition used words I still didn't know, then opened tabs and searched for '<word I do not know> meaning', and repeat the process of trying to understand the definitions of every word, once I understood all the words/vocabulary I needed, at that moment I went back to the root of everything (googling the meaning of 'reassess') and with the new gathered vocabulary tried to understand what 'reassess' was, if I didn't I will repeat the process refreshing everything, and if I did: SUCCESS!! I understood what 'reassess' mean, but not only that, in the process I learned a ton of another words!_

_Note: if you see something that needs to be fixed (I wrote it really bad), feel free to let me know or open a PR :D_

Now that I talked about how I approach my learning, how this is transfered to Cybersec?? If you managed to read until this point, kudos to you! Let's take a look at it!

{{< image src="/images/blog/cybersecmyway/learn.png" position="center" style="border-radius: 8px;" >}}


## 0x010: Starting into Cybersec

My journey into IT started back in 2014 as a Jr. Linux Sysadmin, since then I have been climbing up some seniorities/companies in such position and also starting to move more to a DevOps role. I always have been quite attracted to the idea of breaking things (more being as a child I learned about the world and played with toys by breaking), but never got the spirit to study about it, late at 2019 I discovered Hack The Box, and since then I keep falling in love with Cybersec even more.

So, I started playing in HTB for some months, after that I went after OSCP and saved it at my first try <insert happy face expressions here> (struggled a lot during the exam, you can read more about it in my post, the link is in the preface). The sad news is that OSCP is just the tip of the iceberg, there is more and more things around to smash your head against it (best this way, you will always have something to keep you entertained), then now...what???

Well, as i said about the goals, I know I want to get better a WebApp pentesting, for this I'm doing the following things:

- Playing with [Web Security Academy](https://portswigger.net/web-security) by Portswigger (same people that maintains Burp Suite, let me know if you want some post about Burp).
- Reading disclosed bug bounty reports in Hacker1.
- Sometimes following content of [Bugcrowd University](https://github.com/bugcrowd/bugcrowd_university).
- Watching some well-known hackers in the community such as [STÖK](https://www.youtube.com/channel/UCQN2DsjnYH60SFBIA6IkNwg), [John Hammond](https://www.youtube.com/user/RootOfTheNull), [The Cyber Mentor](https://www.youtube.com/channel/UC0ArlFuFYMpEewyRBzdLHiw), among others.
- Once in a while I read some chapter of [The Web Application Hacker's Handbook 2nd Ed](https://www.amazon.com/Web-Application-Hackers-Handbook-Exploiting/dp/1118026470).
- I read and sometimes look up back at some chapters/links to reports in the book [Real-World Bug Hunting](https://www.amazon.com/Real-World-Bug-Hunting-Field-Hacking/dp/1593278616).
- I read blog articles from bug hunters, such as this serie about [Bug Hunting Methodology](https://blog.usejournal.com/bug-hunting-methodology-part-1-91295b2d2066). You can find more [Hacking resources as this one in this post of mine](https://ceso.github.io/posts/2020/12/hacking-resources/)
- I was playing with HTB until I moved back to my country, but I do not have a way to pay the subscription at the moment (also I don't like the latency of the free account), once I have a way to get the VIP account back, I will start playing with it (and so the write-ups will come again!). On top of this, I think I will start playing with the [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/), and the [OWASP NodeGoat](https://github.com/OWASP/NodeGoat) (If start playing with any of those, I will start to do live streamings of me playing with them :D).
Another Lab I want to play with (and also will do live streams) is [Kubernetes-Goat by madhuakula](https://github.com/madhuakula/kubernetes-goat) which is an intentionally vulnerable Kubernets cluster (and this one, goes quite hand-in-hand with my possible duties at my current workplace. More than I might go after [CKA](https://www.cncf.io/certification/cka/) as it is something I was advised to do at work, and also a pre-requisite to take the [CKS](https://www.cncf.io/certification/cks/)).
- And last, I play around with Bug Bountie Programs in [Hacker1](https://hackerone.com/) and [Intigriti](https://www.intigriti.com/). So far I haven't found anything, but what matters for me at the moment is not to get money, is to enjoy the process of learning, if I keep looking at programs (basically learning new techniques and applying them, sharping my eyes, my methdology, etc) the day I report a bounty will come alone, to have fun is the most important part :D.

### Web Security Academy

Currently, most of the time I spend it playing with Web Security Academy. **I Highly recommend jumping straight into this, the labs are pretty good, the explantions are clear, and the content is always up-to date!**
They way I'm using it is a bit a combination of their [Learning Path](https://portswigger.net/web-security/learning-path) and the way I approach learning that I explained before...this is: I look at the learning path and read the description of things, if something catch's my interest I open that subject and start reading and playing with their labs straight away.

Plenty of times I have needed to take a look at the solution of the labs and follow the steps along, but I do not consider it as cheating or whatever...from my point of view there isn't such thing as "cheating" when it comes to learning. What really matters is to end up with new knowledge, if the way to adquire it implies sometimes to read the "solution/how-to", then I do not see a problem, lot of times I don't even know where/how to start, or I know how to start but end up without knowing how to proceed from a certain point, and a pick at the solution or following the entire step-by step, ends up teaching me in the process a lot, so I will say do not neglect looking at it, or do not think you "failed" if you needed to help yourself with it, if there wasn't a point to look at solutions once in a while, there wouldn't be given solutions.

At the time of writing this blog post, my progress on Web Security Academy goes as follows:

{{< image src="/images/blog/cybersecmyway/progresswebacademy.png" position="center" style="border-radius: 8px;" >}}

As I mentioned before, I'm going through the stuff that takes my attention the most. For example I haven't done anything related to Path Traversal, but I know something about them thanks to HTB and OSCP, while I don't know nothing about Web Cache Poisioning, so I find more interesting to keep as priority what I don't know and takes my attention than what I already have some ideas but that doesn't take my attention.
Today (2021/02/14) for example, I was playing around with Insecure Deserialization, and I must say at first I was looking at it as something really dark and blablabla, but it's actually quite nice!!
Did you know insecure deserialization can be exploited using memory corruption? Or that you can inject arbitrary objects, even if are not valid and end up causing damage? Well even you could exploit deserialization by using "gadget chains" (basically gadgets are snippets of code that already exist inside the application. The use of individual gadgets with a user input can't do anything harmful, but by combinating multiple gadgets, AKA gadget-chains, it could allow an attacker to end up passing the input into a dangerous sink gadget where it could cause a lot of damage!!). All of this thanks to the insecure process of deserialization, which will deserialize things without verifying what is in, it could be through an error at the end, but it will be to late because stuff will be already executed.
Well I didn't know any of that some hours back, but I know about path traversal (just to continue the example), and I just got quite excited by learning it and playing around with the labs related to insecure deserialization...SO GO GO GO and start getting your hands really dirty!!

### Learning Web Development

As I have mentioned back, I'm not a Developer I come from a Sysadmin background (and I'm still one) I do not know nothing about web development, but I think is a really valuable tool to have in my belt, if I know something about it. To know a bit how does it feel to be one, what kind of complications one can found while working on a web, which ones are the workarounds needed to put in place thanks to business requirments, what kind of pressures due to deadlines they go through and with it what errores are more prone to do (basically understanding the web development also from a business perspective not only technical)
And on top of this, is quite nice to being able to do code review and pick up vulnerabilities with a glance at the code.

Following this reasoning I got interested and motivated into learning a bit of Web Development. I'm not talking about being one, or getting a deep knowledge, just the tip of the iceberg...If you can think and feel like the enemy, then you have extra cards under your sleeve!!
Well...not to mention I also really want to take [OSWE](https://www.offensive-security.com/awae-oswe/) in the future, so this motivates me even more.
By following such reasoning, I ended up in this post at reddit of some people talking about [the odin project, from sysadmin to webdev](https://www.reddit.com/r/learnprogramming/comments/cmm21n/shoutout_to_the_odin_project_sysadmin_to_full/).

After reading a bit about it, I decided to start going through it, and to be honest I feel more comfortable than with other courses I tried. [The Odin Project](https://www.theodinproject.com/) is basically a curricula that walks you through differents tutorial/courses of external pages, and in the end of every lesson you end up with projects to do...so, not just learning/watching, but most important: hands-on!

The Odin Project has 3 pahts: Foundations (Basic projects with javascript and HTML/CSS), Ruby on Rails, and Javascript. In my case i started with the Full Stack Javascript, but hit a wall and started to go through some lessons of the Foundations (as I say at the beggining, the way of learning that works for me xD).

{{< image src="/images/blog/cybersecmyway/odinproject.png" position="center" style="border-radius: 8px;" >}}

## 0x011: The road ahead

{{< image src="/images/blog/cybersecmyway/journey.jpg" position="center" style="border-radius: 8px;" >}}

I covered most than anything how and what I'm learning at the moment, but...what about the future?
As I said in the beggining I want to become better at WebApp pentest and described my way to approach it and what resources I'm relying on.
Once I end up with Web Security Academy, I will keep looking for bounties, and in parallel as I get better at code, I will start doing some CVE Hunting to improve my white pentest skills, you can watch a nice presentation about CVE Hunting given by [V1s3r10n](https://cyber-dragon.nl/) at the Dutch HTB Meetup 0x04 in [this video](https://youtu.be/GdV8a19AqUQ).

And as I said above, I wanna take OSWE in the future, so that's another thing I'm thinking to do once I end up with Web Security Academy and looking for some bounties (if I get to tackle down some bounties, better, money to pay OSWE! haha). In the same lines I'm pretty excited about [OSEP](https://www.offensive-security.com/pen300-osep/), because it covers avoiding detection and bypassing defense techniques (for example play around with Active Directories, Antivirus, etc), and all of that is quite interesting, is basically to learn more about Red Team techniques (thing that is wayyy to interesting, fun and excited. And is something I also would like to know more). There is another course/cert by Offsec I wanna do in some future, [OSED](https://www.offensive-security.com/exp301-osed/) which covers exploit development on Windows, and getting to know techniques, learn new methodologies about it. Those 3 goe hand-in-hand with my goals, which is covering a wide surface of knowledge on WebApp pentest, and red team stuff.

Now, when it comes to Mobile/IoT pentest, my way to learn about it will be to start learning/playing with the [UnCrackable Mobile Apps by OWASP](https://github.com/OWASP/owasp-mstg/tree/master/Crackmes) as they are used as examples throughout the [OWASP mobile security guide](https://owasp.org/www-project-mobile-security/) and with the [Oversecured Vulnerable Android App](https://github.com/oversecured/ovaa), good thing is that a lot of the Mobile pentest is basically to apply stuff from the ending journey of WebApp pentest.
Also I will put effort into learn something which is taking my attention the most in some way: Hardware. For this _my idea_ is to start playing around with ARM and some analogic electronic/PLC's (which I have been having in my TODO for a couple of years now).
Once is published, I'm thinking on getting [The Hardware Hacking Handbook](https://www.bookdepository.com/Hardware-Hacking-Handbook-Jasper-van-van-Woudenberg/9781593278748) and go through it.

Besides all of it...I do not have that much things in mind on how to approach Mobile/IoT pentest but is not something that has my mind that busy at the moment, I already have a long road ahead just with the things I explained through this post, and is what has all of my attention now, I will not worry about how to cross a bridge that I still didn't reach, not to mention that my mind could change in a couple of weeks/months/years related on how to approach Mobile/IoT, but hey!! Once I start the journey with them I will write a similar post to this one but related to those, let's say part 2, 3, 5?? I don't know it will depend in what thing I'm fighting at that moment, there's no need to think about it now (And doesn't help my anxiety).

## 0x100: Conclusion

I more or less talked about my way to learn stuff, and how I'm approaching Cybersec at the moment as how I'm thinking to approach it in the future (as well, domains of knowledge I'm interested on).
Due my daily work isn't anything related to Pentest/Offensive Attacks (again, I'm working as a Sysadmin/DevOps), the labs I mentioned and Bug Bounties (production environments) are my way at this moment to get some hands-on experience, and I will keep with them but with the aim to moving to a Cybersec position in the future.

All of that said, thanks if you read until this point, I will be doing a live stream talking about this as well and will update the post with the link, cya!!!