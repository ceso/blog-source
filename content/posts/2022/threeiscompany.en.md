+++
date = "2022-01-25"
tags = ["blog", "osep", "hacking", "thoughts", "infosec", "tryharder"]
title = "Three is Company: My adventure getting OSEP towards landing OSCE3 "
description = "A little storytelling about my adventures into getting OSEP"
images = ["https://ceso.github.io/images/blog/osep/"]
toc = true
+++

{{< image src="/images/blog/osep/osep_banner.png" position="center" style="border-radius: 8px;" >}}

## Preface

Twenty months have passed since ceso obtained his OSCP and just now in January/2022 got his OSEP, during this time he traveled from the old continent back to his hometown on the other side of the world as there was stuff he needed to sort out. Covid-19 (c-19), the pandemic that started in 2020, was still leaving havoc behind any place where it arrived, and the situation didn't look like getting better any soon. His travel back was not the easiest one as it used to be before the c-19 attacked but still, as it was he was able to return without facing odds.
Ceso saved some money and made ambitious objectives when it was still 2021; "I will get OSCE3!!!", but...stuff doesn't always go as expected or how we want, and his life started to go downhill in some aspects of his life, health started to be quite
 an issue and all his plans needed to be pushed aside and improving his health turned the top priority.
Months passed and as he started to feel better, August of 2021 was running and decided it was time, he was ready to continue where he left, time to pick up before all started going downhill; time to go after OSEP and defeat it and the bosses that will be coming afterward (OSWE and OSED).

Finally, in January of 2022, he passed his OSEP not without being needed 2 battles to accomplish this, but still, he did it, and this is the story of his journey into this certification.

Sorry for that, I can't just resist nerding.

## 000: The background

A lot of stuff happened in my personal and work life since I got my OSCP in Apr. 2020 and now my OSEP in Jan. 2022, I needed to take a rest with studying hard anything, I needed to resolve stuff that was going on (with OSCP I also mentioned some issues, but they were way too far different, and different classes of, don't think I do always have them, just the normal as any person lol).
Thought among a few things that changed has been that I got a change of area at work, from CloudOps as DevOps to Cybersecurity, but I haven't been doing the most interesting thing which we all know what it is is...

{{< image src="/images/blog/osep/pwn-all-the-things.jpg" position="center" style="border-radius: 8px;" >}}

So...well my background is just the one from work, OSCP, some HTB machines, reading of articles/videos, but nothing like WOWWW or outstanding, just your normal IT things.

## 001: My preparation

Then, how did I prepare for the OSEP exam? Well...nothing crazy, I just went through the course that comes with it [Evasion Techniques and Breaching Defenses, PEN-300](https://www.offensive-security.com/pen300-osep/) and I DIDN'T KNOW anything related to Active Directory or Antivirus Evasion before.
I did pretty much every exercise (though I felt a bit lazy and didn't do extra miles hehe) and went through every challenge (from 1 to 6). On top of this researched a bit about stuff that wasn't in the course itself and either their existence was pointed out by offsec but not covered (example: Bloodhound) or that you ended up knowing about it while going all the way down the rabbit hole.

Something extremely important is to read a lot of content from people WHO REALLY REALLY REALLY (I can't stress this enough!) knows their stuff, for example [harmj0y](https://www.harmj0y.net/blog/), [S3cur3Th1sSh1t](https://s3cur3th1ssh1t.github.io/), [Mubix "Rob" Fuller](https://malicious.link/), [Cas van Cooten](https://casvancooten.com/), [Mr-Un1k0d3r](https://github.com/Mr-Un1k0d3r) and other big ones known in the field.

## 010: The challenges

As is normal with offsec, what's makes the experience of learning great is the labs as you are challenged with getting your hands dirty and start applying the knowledge you have been gathering (as also sharpening in a non-end way).
OSEP has 6 challenges, the first 3 challenges though they are challenging at the same time quite doable, each one of them makes up the foundations of several subjects studied along the course and incrementally go increasing their difficulty. Then finally arrive you get to challenges 4, 5 and 6 which are the toughest in the course. These simulate corporative Active Directory networks with a different number of antivirus running in them being your task to compromise as much as you can on this network while you evade detection.

Then making a summary with the information from above, what you will be putting in practice is pretty much what's mentioned in the [Syllabus](https://www.offensive-security.com/documentation/PEN300-Syllabus.pdf), Antivirus Evasion, Active Directory Exploitation, SQL Server attacks, Lateral Movement, among others.

I will neither recommend skipping any of these challenges or not following their strict order, as I stated they go on increasing on difficulty, so you end up doing each one of them based on the experience you have built on the previous one.

From my point of view, challenge 5 and 6 (especially 6) are the ones you must try to make the most out of them as you can, they are the closest to what the exam will look like, and they will make you grow gray hair green more than once, so be prepared for a lot of hours invested on suffering and joy :D.

One of the other aspects while going through them and I think the most important one if you want to take advantage of these challenges, is to go and ask on the forum's and offsec discord, about any doubts, techniques, tips, etc. Even if you already might know how to do something, getting in touch with people will be crucial to getting better, expanding and enriching your way of thinking/methodology, reaching out to more resources and techniques, etc. Among some of the people I could highlight who accompanied me during this journey are: [Suffer](https://twitter.com/0xredtm), htck, ak56, thehandy and [Octoberfest](https://github.com/Octoberfest7), plus I'm sure could be missing someone and sorry for doing it.

Now...all that glitters is not gold, I have a HUGE disclaimer regardless of the labs and it's that at least when I went through them, they felt buggy.
Since offsec migrated from their old control panel to their new one, stuff stopped to be what it used to be, and there were moments I didn't know if something wasn't working because either a buggy machine or my craft was incorrect, lots of the times it was the first, the environment was buggy or slow and stuff didn't work until a lot of reverts, things which at some point worked suddenly stopped doing it, and for them to work again a bunch of more reverts was needed.

## 011: 20211218 - The 1st attempt

First of all, I booked 2 days off from work, this way I knew beforehand I was gonna be able to only focus on the exam and nothing else, unless you are extremely confident of your skills and about being able to do this exam with your hands tied behind your back, I strongly advise you: book the exam on days you know you will be able to give your 100%, ask for days off at work if is needed.

Then, saturday 18 of Dec. 2021 at 17 hs GMT-3 marked the start of my first attempt and it ended the 21 at 17 hs GMT-3 (the 20 the time to break and 21 for the report), this...didn't go quite well.

Compared to OSCP which I had a simulation of the exam, with OSEP I didn't...and how the exam was structured, what kind of things to expect, how it was gonna work (besides what's in the guide of the exam), hit me hard, it wrecked me.

It took me around 15 - 30 minutes to find the first foothold, and about 1 - 2 hours being able to exploit it, after I was able to do it, I got the first flag, the first 10 points!
Around 30 minutes later I figured out how to do LPE, here is where stuff start started to go downhill...it was extremely stresful how inconsistent the environment was, between reverts my initial foothold sometimes worked and sometimes not, I ended up using around 15 reverts if I remember correctly, which each one of them took a lot, nothing wrong with this, it's understandable is a large environment so is just natural is gonna take a lot, but if you start adding up the time spent on reverts which is the same as being able to not do anything and how many I needed to use, damn...it's a lot of time wasted.

After I got the first 2 flags, I still felt ok with an opportunity to pass, after some hours I find out the next moves and started to compromise some additional machines and flags, but as time started to move forward, being able to pass started to look more and more beyond doable, I can't express how stressful this first attempt was, it drove nuts, it made me feel crazy, it made me feel hopeless, and what most important, to have a spirit of giving up, and anything else I could do was gonna be worthless.
By the end of the 48 hs completed, I only managed to get up to 60 points (6 flags), I felt bad about myself, and everything felt shitty, I was so mad I didn't even bother on writing the report, because which difference was it gonna made? From this on the only thing left was to start thinking about the next attempt.

Something important: BREAKS! I took A LOT of breaks varying in times: sometimes just 5 minutes every 1 hour, sometimes 15 minutes every 1 hour, sometimes 30 minutes every 2 hours, and finally sleeping, I slept around 4-5 hs as a minimum every night where the exam took place.

## 100: 20220115 - The re-take

Offsec has many cooldown policies which differ based on the kind of course/exam you took, in my case It was all outside their training library, so I will just explain a bit about it, after your first attempt you need to wait 4 weeks for a re-take, after 2nd attempt 8 weeks, and after a 3rd attempt onwards 12 weeks of waiting is stated ([here if you want to know more about their cooldown polciies](https://help.offensive-security.com/hc/en-us/articles/4406830092564-What-is-the-Exam-Retake-Policy-)), in my case I needed to wait 4 weeks as a minimum, a few days after I lost the exam, I already booked the closest date for the re-take, this was the 20220115 starting at 17 hs GMT-3 (yup, same hour than the previous attempt lol).

During all the time after failing the exam, I kept repeating to myself to get [HTB Prolabs](https://www.hackthebox.com/hacker/pro-labs) and there do maybe Offshore, Rastalabs or Cybernetics to get more hands-on, sharpen my skills and make me more likely to pass without trouble, the reality is...I didn't, as a lot of stuff in life I just pushed it to the side of the road and days for the exam just kept passing until the day it arrived, still I will definitely do some of these labs in the future as I'm craving more of this Red Team stuff.

Well, before leaving behind all that previous "chachara", first I must point out, have failed the exam and knowing how was supposed to be, what to expect, etc. notably made a difference, a huge one, that plus the exam environment wasn't buggy this time!

The clock reached the time that marked the 15 minutes before the exam for the set up with the proctor, anddddd I had a few technical difficulties with my camera and the feeding on the endpoint from the proctored side, which ended up in 30 minutes in total for being completed (the double of what's normal). With this, I already started to feel nervous as I thought I was not gonna be able to take the exam and I was needing to book it again, etc...luckily this didn't happen and as soon as it was all set up I started my exam, this time I WAS IN A RUSH!!! IT FELT AMAZING.

As in the previous attempt in 15-30 minutes, foothold identified, 30 minutes more and first foothold obtained, a couple of hours more and 2-3 flags more into my basket and so time started to move forward, at the end of 5 hours that passed I HAD 60 POINTS...60!!! EVERYTHING started to look wonderful and the sun was in the landscape...some hours more passed, and I decided it was time for looking into another foothold vector and...BINGO!!!, took me 15 minutes and around another 15-20 minutes to have a workable POC, but from here onwards is where everything started to get slower...even if I got a POC, it wasn't a useful POC that could even give me a read on the other side, just verifying my hypothesis was correct, tired as it was late and I wasn't going anywhere I went to sleep, once I woke up with a fresh mind it might have taken me between 3-4 hours being able to go from a POC to a reverse shell, but well...I DID IT! After I got this reverse shell I started to do some reconnaissance to know where I should go next, after a few hours and missing pieces in the puzzle and not understanding why, by looking with closer attention at every detail made the thing, and the pieces fall in their place, some hours working on this and on that, and finally I had 100 points, I was in the safe zone and I was gonna be able to start looking for more stuff without pressions, after some time I did got 1 flag more (10 points), giving me a rounded up score of 110, enough to pass.

Secured 110 points, I started to look at the exam in a relaxed manner, did recon here and there, identified highly likely possible next vectors and different paths into the objective, though after a couple of hours I wasn't able to exploit this vectors as I was unable to figure out how to exploit their respective footholds, then I just decided to go throughout my notes, revist them, re-exploit pwned stuff, verify my screenshots and take new ones if needed, and repeat this excersise a couple times more, if there was something I didn't want to go through was getting enough points but failing due a screwed report...being already too late and in a safe zone, I went to sleep a few hours, came back and again back to doing recon trying to identify how to exploit those identified paths, which I couldn't success on this, but I was 100% sure those were the paths, then finally reached the hour limit, the proctor announced the time ended and my VPN connection was terminated and was told how to proced from here.

{{< image src="/images/blog/osep/certificate.jpeg" position="center" style="border-radius: 8px;" >}}

## 101: Documentation

#### 00: Note Taking

On OSCP I did my note-taking leveraging Cherytree, it has had some complaints from people in the past as files got corrupt and all was lost. Even if there is 10 type of people: those who back up, and those who wish they did, I didn't want to put myself at that risk, so I started looking after some nice tools which allowed me to do note-taking in markdown, tried Obsidian, Triskel and Jopling, BUT none of these I liked them, nothing wrong with them but I can't deal with the fact of a text editor using Javascript, it ends up wasting a LOT of resources, and is just...a text editor, from my pov is nonsense so I kept moving, feeling unhappy as I couldn't find ANY text editor which made me feel ok and didn't consume an obscene amount of resources for such a simple task, at some point [fcr](https://fideo.info/) recommended me to try out Zim, and well, there wasn't a come back from it, I fall in love with this editor.

First of all, [you can find zim here](https://zim-wiki.org/), now what is it? Just from their page:

> Zim is a graphical text editor used to maintain a collection of wiki pages. Each page can contain links to other pages, simple formatting and images. Pages are stored in a folder structure, like in an outliner, and can have attachments. Creating a new page is as easy as linking to a nonexistent page. All data is stored in plain text files with wiki formatting. Various plugins provide additional functionality, like a task list manager, an equation editor, a tray icon, and support for version control.

Zim is just AWESOME! It has everything you need and more without neither compromising performance nor being complex to use, is extremely easy and comfortable to navigate around it, every file is a .txt and generating templates is just easy as creating a .txt with the base you want and copy/past it in the desired location post a "Tools -> Update-Index", it supports Version Control integration with Git/Bazaar/Mercurial, on top of this you can expand its functionalities through plugins and it also looks amazing.

Below is a screenshot of what Zim looks like:

{{< image src="/images/blog/osep/zim_example.png" position="center" style="border-radius: 8px;" >}}

There wasn't anything close to a template of Offsec stuff for Zim, so I took up the template I used with Cherrytree for OSCP and modified it a bit, then used it inside Zim.
Now, the template I have used with Zim can be found here:

```textinfo
https://github.com/ceso/ceso.github.io/blob/master/files/osep/zim_notes_template
```

As stated before, you can expand Zim throughout plugins (you go to: Edit -> Preferences -> Plugins), in my case the plugins not shipped with core I used were:

* Source View

```textinfo
https://zim-wiki.org/manual/Plugins/Source_View.html
```

* Table editor

```textinfo
https://zim-wiki.org/manual/Plugins/Table_Editor.html
```

If you are like me extremely tired of heavy ugly javascript text editors, then give a try also to Zim, I don't see myself ditching.

Shard the note-taking template, plugins and so I use, how did I use them?
The way I took notes was by making a copy of the "machine_template" directory as per IP for example if there were the machine 192.168.42.42 and the 192.168.42.43 I will do:

```console
for i in 2 3; do cp -r machine_template "192.168.42.4${i}"; done
```

And afterward updated the index, then there will be the same structure of notes for both, the .42 and the .43.
In the file "1-Exam_Objective.txt" I copy-pasted what were the exam objectives, as the information is given. On the file "2-AD_Enum-general.txt" I wrote down anything about AD recon which was transversal to everything, for example Bloodhound screenshots of paths of attack, juicy information, etc. "3-PathChain_of_Attack.txt" is a file I went to write every once and then, there I basically started to write down the flow of the attack in a high level, for example "192.168.42.42 (example.com) compromised with attack X and user obtained foo -> LPE on 192.168.42.42 (example.com) by abusing unquoted service path -> compromise on 192.168.42.43 from example.com via SprintPooler attack, NO LPE as received user was already a high priv one -> Dumped hashes on 192.168.42.43 used brute force script and obtained low priv access into 192.168.42.50... and so on, this way I had a quick reference for writing the report as per exploiting everything again if needed, in that file as well I kept a table showing in a high level which level of compromise I got there and the correspondence between IP-Hostname. In "4-HashesPasswords.txt" is self-explanatory there I saved the output from hashdumps, dumps from mimikatz, passwords cracked, etc. "5-Flags.txt" I used it for saving there as a summary the flags of every machine just the hostname followed by the flags and which file was it. And finally, the "0-REVISAR-PRE-TERMINAR.txt" was a dummy file I used for writing down stuff to take a look after it again before the exam time run out.
Regardless the rest of the structure, is pretty self-explanatory, for example in "enumeration/nmap.txt" I copy-pasted it's output from nmap, and so on.

#### 01: The Report

I had until the 21 of Jan. circa at 16:45 GMT-3 to send my report, I sent it at 16:15 GMT-3 (some minutes more/some minutes less), and this was extremely tiring to write it as well, I run into some issue with LaTeX, for example, shellcode went outside of the margins and it broke either the format or the generation as it were long lines, I just ended up putting a new line, clarifying this issue and a screenshot of the correct code of the ones I inserted a new line for not getting the format/generation broken.

As I did with OSCP I did my report using Markdown and converted it to pdf with pandoc ([you can read more about it here](https://ceso.github.io/posts/2020/04/a-journey-in-the-dark-an-adventures-tale-towards-oscp/#10---the-report)), also leveraged [a template by noraj](https://github.com/noraj/OSCP-Exam-Report-Template-Markdown/blob/master/src/OSEP-exam-report-template_OS_v1.md), but I didn't like the format it has (still not an issue from him, he just based it 1:1 in the one given by Offsec as an example), for me it was unnatural, the way stuff is structured feels like breaking the flow of the attack and places subjects in an inconvenient way making it confusing/hard to follow properly for this reason, I took his template and re-wrote it in my terms to reflect what I actually felt was a more natural way to follow the attack as it happened.

The .md template I modified you can found it here:

```textinfo
https://github.com/ceso/ceso.github.io/blob/master/files/osep/OSEP_report_template.md
```

And a generated .pdf example from the above template, you can find it here:

```textinfo
https://github.com/ceso/ceso.github.io/blob/master/files/osep/OSEP_report_EXAMPLE.pdf
```

Even if I didn't manage to compromise the objectives, I still spent some time on documenting my hypothesis about the likely vectors of compromise, I don't know if this was of any consideration for Offsec, but I still felt better by explaining how far did I get in reality.

## 110: Cheatsheet and Resources

I have leveraged a LOT my previous cheatsheet from OSCP, I have been updating it throughout the entire duration of the PEN-300 as I went learning new stuff, on top of this something I did at some moment was to put under another page links to resources so stuff wasn't that much bunched as it was (and still is, a lot of different stuff together lol), **FROM THE RESOURCES SECTION OF MY BLOG I SPECIALLY USED LINKS I PUT IN 2 SUBSECTIONS A LOTTT, ALL THE TIME DURING THE COURSE AND AS THROUGH THE EXAM, THIS ONES ARE:**

```textinfo
https://ceso.github.io/posts/2020/12/hacking-resources/#red-team
https://ceso.github.io/posts/2020/12/hacking-resources/#exploit-developmentreversingavedr-bypass
```

## 111: A last tip and a trip to the future

Hello friend, if you managed to read up to this point, thanks a lot for taking the time to, kudos to you!
Now, I wanna tell you that if you fail your 1st attempt or the N-th it is, I can understand is annoying, frustrating, whatever word you want to put it, but don't feel that bad about it, there's more to it than the eyes can meet! Remember that failing/making mistakes is one of the best indicators of self-feedback you have for actually knowing that yes, you are learning and making progress, so if you fail it's ok, you will pass at the next attempt, if you don't, still you will do it at the next, even if it keeps going reached some point you will, and not without leaving a nice track of learnings at your back, so...don't give up and keep trying harder, the pot of gold is at the end of the rainbow.

Now about what the future holds...a few days after knowing I passed OSEP, I already redeemed the voucher for OSWE and going through it now, these courses/exams might take me a lot to be done with them. I don't have a background with coding and I'm far to be the best one when it comes to it, so it's gonna be a hell of a ride, same thing applies to OSED which I will redeem but later...both OSWE and OSED means a huge change of paradigm to what I'm used to, but well as ambitious and stubborn as I'm I will nail them, even if it takes me all 2022 and part of 2023, I can't help myself with my addiction with learning something new all the time (Jag också lär svenska nu, jag ledsen mina fel :/, men jag tycker om hur låter) and I already put my eye into OSCE3 so I will get it to make my internal Gollum happy ;)

{{< image src="/images/blog/osep/we-wants-it-we-needs-it.jpg" position="center" style="border-radius: 8px;" >}}

And beyond Offsec, I also would like to learn more about Evasion, specifically start poking into EDR/XDR evasion which read/watched a bit, looks awesome but didn't play around. The same thing goes for doing Malware Analysis which I found out for example [this course](https://samsclass.info/126/126_F21.shtml) (more resources again, into the [resources section of my blog](https://ceso.github.io/posts/2020/12/hacking-resources/)).

Said all of this, again thanks for reading if you did, hope you didn't suffer THAT much by doing it, and: keep learning!!!