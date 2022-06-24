+++
date = "2022-06-24T02:43:00Z"
tags = ["letsdefend", "malware-analysis", "blue-team", "ransomware", "ctf"]
categories = ["Lets Defend"]
title = "SOC145 - Ransomware Detected"
images = ["https://ceso.github.io/images/letsdefend/soc145/letsdefend-socialv2.png"]
description = "My write-up/walkthrough for SOC-145 from Lets Defend."
toc = true

+++

{{< image src="/images/letsdefend/soc145/ransomware-card.png" position="center" style="border-radius: 8px;" >}}

## Quick Summary

Well, my lab time for OSWE/OSED courses just came to an end and I'm still way to far from being able to take their respective exams (still haven't even reached the challenges, stuck on the material/excersises), so just as a way to take a short rest and a change of air from it, I decided to take a look around if there was anything similar to HTB but for Blue Team stuff (I barely know stuff related to it, besides my tasks as Appsec/DevSecOps whatever you want to call it mehh!), by doing this I ended up finding a web page called "Lets Defend", it has some ctf alike games but focused exactly on the Blue Team side together with some Training content, which in a really easy and understandable way explains the 101 of SOC/Incident Response/SIEM, etc, pretty nice to have a quick and overview about that stuff, I liked it. 

```console
https://letsdefend.io/
```

Said that, this post is basically a walk-through of one of their challenges called "SOC-145 - Ransomware Detected", the name is self-explanatory about what it is about.

Let's start!

## Owning the Event

Lets Defend has a bunch of different tools built-in ([SIEM](https://en.wikipedia.org/wiki/Security_information_and_event_management), [EDR](https://en.wikipedia.org/wiki/Endpoint_detection_and_response), Mail, Threat Intel, Case Management, Log Management) as a way for you to play their games, once in we go to the Monitoring tool (SIEM) and there we will have a lot of different events, we will see there the event SOC-145 which is the one we will own by clicking in the highlited button as shown in the screenshot.

{{< image src="/images/letsdefend/soc145/1-take-ownership.png" position="center" style="border-radius: 8px;" >}}

Then we will go to the Investigation tab:

{{< image src="/images/letsdefend/soc145/2-take-note-hash.png" position="center" style="border-radius: 8px;" >}}

So, we we have the following:

|Source Addr|Source Hostname|File Name|File Hash|
|172.16.17.88|MarkPRD|ab.exe|0b486fe0503524cfe4726a4022fa6a68|

Then let's proceed to create a case:

{{< image src="/images/letsdefend/soc145/3-take-create-case.png" position="center" style="border-radius: 8px;" >}}


## Responding to the threat

With the data gathered, now we want to determine if this is a false positive or not, for this we pick up the File Hash obtained and search for it in Virus Total to see if there was some report of it previously and if is a malicious file (take into consideration that even if there is no finding, it still can be malicious and in that case some more in depth-analysis can be required as there can be bypasses such as layers of redirections, obfuscations, etc etc etc), what we obtain, is that indeed, it's a malicious file:

{{< image src="/images/letsdefend/soc145/4-virus-total-hash-1.png" position="center" style="border-radius: 8px;" >}}

{{< image src="/images/letsdefend/soc145/5-virus-total-hash-2.png" position="center" style="border-radius: 8px;" >}}

Knowing this, let's proceed to identify the machine with the IP we previously took not of in the EDR:

{{< image src="/images/letsdefend/soc145/6-identify-machine-edr.png" position="center" style="border-radius: 8px;" >}}

Identified the machine, let's proceed to isolate it:

{{< image src="/images/letsdefend/soc145/7-isolate-host.png" position="center" style="border-radius: 8px;" >}}

## Investigating the threat

Confirmed the presence of Malware and with the machine now isolated, we proceed on investigating what this malware does, continuing from the last action we take a look at the Process List, and compare that information with the one found in Virus Total under the "Behaviour" tab:

{{< image src="/images/letsdefend/soc145/8-correlate-behaviour.png" position="center" style="border-radius: 8px;" >}}

So, we see that this malware what it does is to start deleting shadow copies, but what are shadow copies, well from wikipedia...

```text
Shadow Copy (also known as Volume Snapshot Service, Volume Shadow Copy Service or VSS) is a technology included in Microsoft Windows that can create backup copies or snapshots of computer files or volumes, even when they are in use.```

So what it's doing is to delete volume snapshots (backups). Moving forward with the investigation we want to see if there's any activity on the logs, which isn't (the Network Connectivity also didn't have anything, but I don't feel like taking a screenshot again):

{{< image src="/images/letsdefend/soc145/9-investigation-log.png" position="center" style="border-radius: 8px;" >}}

Then, we want to know if this malware has any network activity (for example, connecting to a C2), for this we will leverage Hybrid Analysis (as a complement as we didn't find nothing in the "Network Activity" feature of the EDR), to carry out this task we will download the malware (remember at the time we look at the event at the beggining, the .zip to download was there), we extract it and upload that content into Hybrid Analysis, we get it flaged as malicious as expected, and proceed to take a look on one of the sandboxes where it was executed (`ab.bin` the file inside the .zip):

{{< image src="/images/letsdefend/soc145/10-investigation-hybrid-analysis.png" position="center" style="border-radius: 8px;" >}}

We scroll down until reaching the Network section and we find there wasn't registered any Network Activity:

{{< image src="/images/letsdefend/soc145/11-investigation-hybrid-analysis.png" position="center" style="border-radius: 8px;" >}}

## Closing the case

So, we were able to determine that the event on our SIEM was indeed a true positive alert, there was executed a binary called `ab.exe` which spanwed process for deleting shadow copies, and despite the machine being compromised, there wasn't connectivity against a C2.
Knwon this, we can proceed to close the case:

{{< image src="/images/letsdefend/soc145/12-close-alert.png" position="center" style="border-radius: 8px;" >}}

{{< image src="/images/letsdefend/soc145/13-closed-case.png" position="center" style="border-radius: 8px;" >}}

Didn't take screenshot of the process, but when closing the case, I used the following data:

```
Threat indicator: other
Quarantained: I put it as yes, because I didn't take a look before, this answer was wrong, it wasn't quarantained hehe
Malicious
C2 Not accessed

Artifacts:
    MD5 hash: 0b486fe0503524cfe4726a4022fa6a68
    172.16.17.88: MarkPRD machine
```

## Final

Well, that was all about it, an easy challenge but a nice look into the basics of how a blue team might behave when there's an event, from how some tools are used to the chain of thoughts made by the person who's working on the incident at hand.
Overall I liked the challenge and is something completly different to what I have been doing lately, and I sure learned something new even if it's quite basic is still nice.
I'm sure there might be still something to look for in the investigation, for example discovering how the compromise took place, I will keep reading a bit more about methodologies etc, play a bit more applying them and see if I can find the root cause, if I find it I will edit the post to show how I did it.

Hope this helps you in some way, until the next post!