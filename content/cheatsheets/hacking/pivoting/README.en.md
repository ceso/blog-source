---
title: "README !"
weight: 1
date: 2025-10-03
draft: false
type: wiki
---

It's possible to do pivoting by using proxychains, pure nc's or in case of linux just some fifo files (I will write them down this another methods down maybe in a future), I have used during all the OSCP an awesome tool called (sshuttle)[https://github.com/sshuttle/sshuttle] (it's a transparent proxy server that works like "a vpn", and doesn't require with super rights, only thing needed is that the bastion server you will use, needs to have installed python) and sometimes some SSH Forwarding. Something worth to mention nmap doesn't work through sshuttle.
