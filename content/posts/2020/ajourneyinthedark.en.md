+++
date = "2020-04-27"
tags = ["blog", "oscp", "hacking", "thoughts"]
title = "A Journey in the Dark - An adventure's tale towards OSCP"
description = "A tale about my adventures into OSCP"
images = ["https://ceso.github.io/images/blog/oscp/oscp_banner.png"]
toc = true
+++

{{< image src="/images/blog/oscp/oscp_banner.png" position="center" style="border-radius: 8px;" >}}

## Preface

This is the story of how I got my OSCP coming from a background as Linux Sysadmin/DevOps as also which ones are my plans for the future.

Every tale where there is an adventurer, starts with him (the adventurer) and his friends, these who share the journey providing support and advice through it, as the story moves forward, new characters tend to appear, joining the adventurer in his travel.

This story is no less , then before than anything thanks to my buddies [r0xas](https://www.hackthebox.eu/home/users/profile/186934), [MrBulldops](https://www.hackthebox.eu/home/users/profile/12286), [0x41](https://twitter.com/tagnullde) and [DutchPyro](https://www.hackthebox.eu/home/users/profile/43855), for helping and still help me in this adventures and the ones that will came.
And most than anything [Mauri](https://www.linkedin.com/in/mquerves/) because you just convinced to stop shitting myself, from "I can't" to "I can".

_By the way, I really really love books (guess why the title of the post!), and I'm really happy getting this cert during this C-19 thing (living abroad at this time, is though), so I just wanted to make this post in the way it makes me the happiest._

## 000: The background

At the ends of 2014 I started my first IT job, specifically as a Linux Sysadmin Junior, almost knowing nothing more than a few really basic concepts, in this place I got to learn a lot of stuff and was where I got to know awesome technicians and people, at this day all of them friends, and ones I consider the closest for me.
From this forward, I kept advancing some seniorities and changed 2 times of job and moving abroad last year, currently working as a DevOps Engineer (tl;dr, it's been 5 years and going to 6), all the time learning new stuff, either at work or by myself, but never without stop learning.

I don't hold any kind of degree most than High School. I started university but I moved abroad so, something I will neither earn in the future, all what I know, is by self-teaching. I'm someone who loves to be ALL the time learning new stuff, to understand how stuff works, trying to replicate it, break it, play with it and see what happens, always enjoying the process of learning, either if there is no light and all is an "I'm stupid/I suck/I can't" or that amazing moment when something clicks in and you turn into the most happiest person just because you learned something new regardless if it was something stupid or not.

## 001: My preparation

I always felt attracted to security but never felt confident to actually start learning about it, until November of last year that Mauri just made me make my mind. From this I started playing a bit in Hack The Box, all the time using hints, watching [Ippsec videos](https://ippsec.rocks/) or learning new stuff by reading machine write-ups by [0xrick](0xrick.github.io/) and by [0xdf](0xdf.gitlab.io/).
I did (in this order): Postman, Traverxec, Lame, Bitlab, Bashed, Obscurity, Mango, AI and Craft (first one without hints), tried to do OpenAdmin but was unable to get the second user without hints, I decided I did not want to read more hints, so just put it for later (after PWK was pretty easy :D).

I got 90 days and my lab time started the 5th of January, my way of approaching it was:

- I spent the first 2 weeks just going through the PDF and the Videos.
- Once I was done with this I started to the labs, but a few days after some personal problems arose and I was so stressed that I couldn't focus at nothing, so for around 1 - 2 weeks I stopped touching the labs (that I barely touched) or anything OSCP related.
- Storm ended, I started to play a bit everyday after work on the labs, this was around 1 - 2 hs per day, and on weekends tried to sessions of 8 - 12 hours.
- OSCP announced their upgrade to the new labs, being I still had time left (even going through some shit), and keeping in mind the amount of new material (from 300-ish pages on the PDF to 800-ish, and from 7-ish hs of videos to 18-ish hs of videos) I just decided it was worth to do the upgrade, so I did it.
- I got the new material and VPN, and started to play in the new labs, but at this time using the material more as reference on certain specific topics (example: Microsoft Office explotaition), this still being complemented with Ippsec + 0xrick and 0xdf write-ups.

## 010: My lab experience

As mentioned, of the 90 days I used way less than those for doing the labs, now before starting to play with them, I set some goals that I needed to achieve before the lab time ended, these goals were:

- Compromise in total at least 42 machines. 
- Gain access to all the extra nets.
- Root on no less than 3 hosts per extra net.
- Completly root an extra net. 

I achieved all those goals, of the 42 machines I got 46 (of a total 75), got access to the 3 extra nets, compromised more than 3 hosts per net and fully rooted one; Dev 5 hosts, IT 4 hosts and Admin fully rooted.

Personally for me, the labs are similar and at the same time different to Hack The Box, why? Because the labs are sort of like "real" basic nets, in the sense that there is a dependence between some hosts, you can't get one without first compromising another or even get to enumerate/discover other hosts, without first compromising N firewalls, the fact that there is nothing written, that you need to discover which host has dependence with which host, for me was really fun. Also in this aspect, it really helped having experience as sysadmin maintaining large amounts of servers across multiple networks, because in scale PWK nets were really small ones and without normal components you find in a real network, again basic "real" nets.

On the other hand, the OSCP Exam itself, yes it is really HTB-like, you are given N machines, every machine having specific points, there are no dependencies, there is no looting needed, the only thing that is needed is to break independent machines, tl;dr: enumerate, enumerate, enumerate...enumerate, try, try harder, keep trying, repeat.

**Now, one important point about PWK/OSCP vs HTB, with PWK/OSCP you pretty much 99% of the time will find a CVE (or just a public POC on exploit-db) for what you are trying to break, while HTB tends to be more misconfigurations and/or CTF stuff, this makes a lot of stuff on HTB harder than PWK/OSCP**

## 011: 20200411 - The Mock Exam

During the whole PWK, my biggest worry, was not breaking machines itself, no, it was two things:

- The report
- The proctored exam

This was going to be the first time in my life needing to write down a report of something like an exam in english (english, is not my native language, and as I'm self-teaching I lack a lot of stuff), so this was enough to put me in some sort of panic state, it was going to be so, so, so easy to fuck it up, I mean, I'm sure while you are reading this, a lot of stuff had made your eyes cry because something is WRONG, so just imagine how much worried I was in this aspect!!

And the second, the proctored exam, I'm good at working under pressure (I worked under strict SLAs), but doing something with a deadline of 24 hs as OSCP is, while _being watched_ that whole time? Personally for me, that was just a totally new thing, and one that made me to creep _A LOT_.

To deal with those things, I thought about doing a Mock Exam (ONE week before the real one), what do I mean with a mock exam? Basically I was going to pick up 5 random machines from [HTB/Vulnhub OSCP-alike](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=1839402159), and starting at a similar time as the one of my OSCP, hack them in a time frame of 23 hs 45 minutes, if I run out of time and I was not able to do it, then I was not able to do it, no way around it, on top of this to get used to the proctoring I was going to do a live stream on youtube for the whole time I needed to get the machines or until running out of time, whichever happend first.
For the report itself, I gave me more freedom with it, the aim yes, was to do something similar to what I should submit to Offensive Security, but as this was a completely new thing, and more easy for me to fuck up, I thought of it more as a learning experience, so no, no deadlines to do it. I'm really grateful of doing it, because I ended indeed learning quite a lot about the process of what is worth to document, what is not, what I should I avoid, what notes _I MUST_ always have to write down, etc.

#### 00 - The Live Streaming

Days before the exam I asked to be chosen random machines from the list of alike-ones (link above in HTB/Vulnhub alike) and assign points to them, the list ended like this:

- Brainpan - 25 pts - BOF
- Bart - 25 pts
- Lightweight - 20 pts
- Arctic - 20 pts
- Optimum - 10 pts

Something important to remark, the windows machine I used to the development of the exploit (BOF) was a free one provided by Microsoft that has a valid time of 3 months, so more than enough for this, it can be downloaded here:

```console
https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/
```

Finally, the 2020/04/11 I started doing a livestream on youtube, and ended rooting all the machines in around 14 hs. **Worth to mention I cut the live stream at around those 14 hs, but youtube only uploaded 12 hs of video, this also was the first time I was streaming something and I didn't know OBS by default didn't do a recording of the videos while streaming, so I don't have the original video to upload the 2 hs missing, but if wanted I just can record that missing parts**, said that, the streaming:

{{< youtube FwZc6JigIcE >}}

#### 01 - Note Taking

When I started my notes were pure shit, I'm sure they still are, but are way better than what they were before. For taking/keeping notes through all the PWK and OSCP, I used Cherrytree, I started with [this template](https://411hall.github.io/assets/files/CTF_template.ctb), but as I moved forward and my own methodology started to develop I modified some stuff, the result was having this template:

```console
https://ceso.github.io/files/oscp/template_pwk.ctb
```

**Note:** Something I didn't know during the exam, is that in the past some pepole has lost their notes of Cherrytree because the files got corrupted, then they were unable to  prepare their reports, my advice then is, maybe start with Cherrytree, and as time moves on, switch to some another tool for notetaking, such as [joplin](https://joplinapp.org/) or [Notion](https://notion.so/) to mention two examples, you will already have some methodology developed or starting to, so it will be easier to create a template adapted to yourself.

#### 10 - The Report

Now, for the report I decided to ditch the doc/.odf templates and just go with something I'm more comfortable: Markdown.
For that I ended using the [template created by noraj](https://github.com/noraj/OSCP-Exam-Report-Template-Markdown), which using Eisvogel and LaTeX, the markdown is converted to .pdf.
Keep in mind that this has some *HEAVY* requirements when it comes to packages, you need to install around 5 GB and I was too lazy to be honest for figuring out exactly which what packages were needed. 
In summary you need to install [pandoc](https://pandoc.org/installing.html), [LaTeX](https://github.com/Wandmalfarbe/pandoc-latex-template#required-latex-packages) and the [Eisvogel template](https://github.com/Wandmalfarbe/pandoc-latex-template/blob/master/eisvogel.tex). Having that done is just a matter of edition with your favourite text editor, I used VS Code.
If you want to read a bit more in deep about this, I recommend you to read [this post by 0x41](https://www.tagnull.de/post/oscp-reporting/), or watch the following video by John Hammond talking about this subject:

{{< youtube MQGozZzHUwQ >}}

This is the PDF report of the simulation done at the Live Streaming on Youtube:

```console
https://github.com/ceso/ceso.github.io/blob/master/files/oscp/OSCP-OS-42-Simulation-Report.pdf
```

And this, is the markdown code to generate the PDF above:

```console
https://github.com/ceso/ceso.github.io/blob/master/files/oscp/OSCP-OS-42-Simulation-Report.md
```

## 100: 20200418 - The Big Day

After the simulation, the big day of the exam just arrived, 2020/04/18 at 15 hs started my exam. I didn't do any kind of weird preparation for it, more than keeping a Cherrytree template with the 5 machines ready before the exam (using the one I posted above hosted on this blog), set a sharing folder between my host machine and kali (for not in the world, I wanted something crashing and end up losing everything just because I write only inside the VM), kept ready the templates on markdown for the report of the exam, and a FULL NIGHT OF SLEEP the day before (which I asked as day-off).

Describing now my exam, it went as follows:

I left running in parallel 4 Full NMaps against all the machines except for the one of the BOF and the Development one for it.
Afterwards I proceeded to start with the BOF really confident about it while the nmaps run, I got confused counting badchars, and ended spending quite some time on this...took me more than what it should. Once I was finished with the BOF, I jumped straight into reading the results of the nmaps.

Five hours after starting the exam, I was feeling really blue, I didn't got anything else than the BOF, was enumerating the two 20 points, in one I found a public exploit but no matter what I was trying, I couldn't make it to work, and the other one, I was extremely in a tunnel vision because I was not able to bypass a filter, this last thing I tried for over 3 hs I think or even more, I was feeling really really bad. The hours keep going and still, only BOF, only 25 pts, more than 5/7 hs used, and still nothing else, I stopped to have some dinner and try to cool down, once I came back I kept aside the the one for bypassing the filter and BANG ended in a post of 0xdf where he referenced an alternative exploit for the software I was trying to exploit in the 20 pts machine, and...foothold! it worked at first, I was still feeling pretty bad, I was going to lose...
I returned to the one with the bypass and, suddenly I realized what I was trying was a rabbit-hole, and literally the first thing I tried hours before was the way to go, I only didn't notice it worked at that time, awesome! in less than 1 hour or 2 I got user on the two 20 machines, the landscape started to be nice a gain. One or two hours later, I was submitting the proof of root of one of those 20 pts machine, now I had under my score 45 pts, with 25 more I was going to be able to pass...BUT nothing is always so nice...I ended spending ALL the night trying to get root in the remaining 20 pts machine, when I realized outside was already daylight again, it was around 7 am, my mental strenght was like shit, my mood was extremly blue, I was convinced I was going to fail the exam, only thing I wanted was to sleep, was to give up, and even maybe not taking a 2nd attempt again, the mix between feling sososo tired plus feeling so stupid because the performance I was having while on the simulation it went that good, it was raping me, I gave up and stopped to take a nap of around 1 h or 1 and half, once I woke up I came back to keep trying this root on the remaining 20 pts, no luck, I was destroyed, I was extremly sad, again...gave up with this machine and thought about tring the 10 pts to at least have something more, around 30 - 40 minutes later, 10 points more to the score, ok great it's 55 pts, is still NOT enough to pass the exam, I guess I will just try to get at least until user on the 25 pts, to have a bit more of confident with myself..."I tried, I tried", 2 hours later I had submitted the proof of the 25 machine, my mood literally changed, I was "re-charged" again, I had 80 pts, now I was sure I was able to pass, I couldn't belive it, restarted the machine and did this step once more to confirm it and YES, I indeed rooted it, I was now in the other side, but now with this re-charged mood, having enough points, I decided to keep fighting until the end, to try until the very end of the exam to see if I was able to root the remaining 20 pts machine, found quite a lot of stuff, nothing though that gave me the privilege escalation I needed. 
I decided was the time to have some refresh, stopped this and just started to re-do all the prior machines, to be sure the vectors were totally correct and 100% reproducible, that I had all the documentation about them that I needed, AND that I have had submitted the flags correctly, I'm extremely glad I did this last thing, because I noticed I submitted the root proof of the 20 machines I rooted, in the one that no.
Once ended with this, I came back to the game trying the root on the remaining 20 pts...hours later the exam had ended, but at least with enough points to pass, getting access to 5 out of 5, and without using my metasploit allowance :P (saved it, and never used it lol).

I took a nap of around 1 hour, and I had some lunch, from this I started to work on my report, when I realized I had it finished at 4 am, I reviewed it around 4 or 5 times, and went to sleep. Next day I did some more reviews and finally submitted it around 10 am, so between the 18 and 20, I only slept around 5/6 hs with luck.

Through all the exam, I took a lot of short rests of sometimes 10 minutes, sometimes 30 minutes, at some moments every 2 hours at others every 3 hours, you will notice when you need to take a break, just make sure you take them, don't let your self fall into the tempting of not doing it, thinking it will save you time, a break is important as keep pushing.

Talking a bit on the official chat of HTB, I was told that all the community thinks that when you get half-user, that's half the points, so I ended with the thought I got 90 pts (instead the 80 I thought at first), as the remaining 20 pts, I got the user, but not the root (even if I wasn't able to do PE, in my report I included all my findings and personal thoughts about it).

{{< image src="/images/blog/oscp/certificate.jpg" position="center" style="border-radius: 8px;" >}}

## 101: Cheatsheet

Something that I found really helpful during the exam, is the [cheatsheet](https://ceso.github.io/posts/2020/04/hacking/oscp-cheatsheet/) I made along the course as also all the different resources I normally tend to go looking for some references stuff (for example PayloadAllTheThings), you can find a direct link to my Cheatsheet always in the upper right corner of the blog.

Take cheatsheets from other people, start figuring out what stuff is the one you use the more, what's helpfull, what is granted you will not remember, try to develop your own as you progress to the labs, it is really helpfull and also helps to "solidify" more the stuff in your mind.

## 110: A look into the future

Yesterday 2020/04/26 I woke up having a message from Off Sec saying I passed, such a good way to wake up, passing OSCP at my first attempt during one of the most shitty moments I have ever lived :).
Now from here, my plans are keep learning more and more as I can about Infosec (HTB FTW), my next goal is to learn some basics of Binary Analysis/Reverse Engineering as also learn more in deep about Active Directory attacks as attacks to Clouds (either AWS/Azure/GCP), whichever it is, there is going to be a huge puzzle ahead, a neverending learning, and is there anything better than that? I don't really think so...

Thanks for reading until the end in case you were able to, and again as said at the beginning I really didn't want to do a "normal post", but more something of my own reflecting how do I feel and stuff I love to do. The name of the title is a reference to the chapter of a book, one I really like, and also I felt it goes well with this new world I'm trying to move, one where everything tends to be "dark" either from the impact it has on media (where terms are wrong used), and also I see it as a synonym of "deep", being there are some concepts that you need to "dig deep" to where is "dark" for stuff to click.

## 111: One last tip

Keep Trying, but keep trying harder, when you think there is no light and no hope, just don't give up, a lot of stuff can change in a few hours (I know it myself :P).
Don't think of "Try Harder" as you need to exprime more your brain, but as don't giving up and giving all you have until the very last second if is needed, of course trying to not get burn out and keeping in mind you are doing it for fun, because you enjoy it.
Take rests, eat, be aware what you are lacking on your documentation and what is excessing, learn to be self-aware of your weakness (mind SQLI and Windows).

**But again most important: Keep trying harder!!**

_Note: Please let me know any fix needed on the text or whatever, it also helps to keep improving my english :P_