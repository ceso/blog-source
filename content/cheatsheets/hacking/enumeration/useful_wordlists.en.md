---
title: "Useful Wordlists"
date: 2025-10-03
draft: false
type: wiki
---

# Most usefull dictionaries (OSCP/HTB)

```console
/usr/share/wordlists/rockyou.txt
/usr/share/wordlists/wfuzz/others/common_pass.txt
```

-----------------------------

# In seclists-pkg

```
/usr/share/seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt
/usr/share/seclists/Passwords/Leaked-Databases/alleged-gmail-passwords.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

-----------------------------

# Assetnote

Up-to-date lists are in the general webpage and there are many more than the ones here listed

```
https://wordlists.assetnote.io/
```

Ideally, all of them can be downloaded just at once running

```
wget -r --no-parent -R "index.html*" https://wordlists-cdn.assetnote.io/data/ -nH -e robots=off
```

## API Fuzzing

```
https://wordlists-cdn.assetnote.io/data/automated/httparchive_apiroutes_2025_09_27.txt
```

## Kiterunner

```
https://wordlists-cdn.assetnote.io/rawdata/kiterunner/routes-large.json.tar.gz
https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite.tar.gz
https://wordlists-cdn.assetnote.io/rawdata/kiterunner/routes-small.json.tar.gz
https://wordlists-cdn.assetnote.io/data/kiterunner/routes-small.kite.tar.gz
https://wordlists-cdn.assetnote.io/rawdata/kiterunner/swagger-files.tar
https://wordlists-cdn.assetnote.io/data/kiterunner/swagger-wordlist.txt
```

-----------------------------

# Local File Inclusion (LFI)

## Linux

```console
/proc/self/status
/proc/self/environ
/etc/passwd
/etc/hosts
/etc/exports
```

## Windows

```
C:/Users/Administrator/NTUser.dat
C:/Documents and Settings/Administrator/NTUser.dat
C:/apache/logs/access.log
C:/apache/logs/error.log
C:/apache/php/php.ini
C:/boot.ini
C:/inetpub/wwwroot/global.asa
C:/MySQL/data/hostname.err
C:/MySQL/data/mysql.err
C:/MySQL/data/mysql.log
C:/MySQL/my.cnf
C:/MySQL/my.ini
C:/php4/php.ini
C:/php5/php.ini
C:/php/php.ini
C:/Program Files/Apache Group/Apache2/conf/httpd.conf
C:/Program Files/Apache Group/Apache/conf/httpd.conf
C:/Program Files/Apache Group/Apache/logs/access.log
C:/Program Files/Apache Group/Apache/logs/error.log
C:/Program Files/FileZilla Server/FileZilla Server.xml
C:/Program Files/MySQL/data/hostname.err
C:/Program Files/MySQL/data/mysql-bin.log
C:/Program Files/MySQL/data/mysql.err
C:/Program Files/MySQL/data/mysql.log
C:/Program Files/MySQL/my.ini
C:/Program Files/MySQL/my.cnf
C:/Program Files/MySQL/MySQL Server 5.0/data/hostname.err
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql-bin.log
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql.err
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql.log
C:/Program Files/MySQL/MySQL Server 5.0/my.cnf
C:/Program Files/MySQL/MySQL Server 5.0/my.ini
C:/Program Files (x86)/Apache Group/Apache2/conf/httpd.conf
C:/Program Files (x86)/Apache Group/Apache/conf/httpd.conf
C:/Program Files (x86)/Apache Group/Apache/conf/access.log
C:/Program Files (x86)/Apache Group/Apache/conf/error.log
C:/Program Files (x86)/FileZilla Server/FileZilla Server.xml
C:/Program Files (x86)/xampp/apache/conf/httpd.conf
C:/WINDOWS/php.ini C:/WINDOWS/Repair/SAM
C:/Windows/repair/system C:/Windows/repair/software
C:/Windows/repair/security
C:/WINDOWS/System32/drivers/etc/hosts
C:/Windows/win.ini
C:/WINNT/php.ini
C:/WINNT/win.ini
C:/xampp/apache/bin/php.ini
C:/xampp/apache/logs/access.log
C:/xampp/apache/logs/error.log
C:/Windows/Panther/Unattend/Unattended.xml
C:/Windows/Panther/Unattended.xml
C:/Windows/debug/NetSetup.log
C:/Windows/system32/config/AppEvent.Evt
C:/Windows/system32/config/SecEvent.Evt
C:/Windows/system32/config/default.sav
C:/Windows/system32/config/security.sav
C:/Windows/system32/config/software.sav
C:/Windows/system32/config/system.sav
C:/Windows/system32/config/regback/default
C:/Windows/system32/config/regback/sam
C:/Windows/system32/config/regback/security
C:/Windows/system32/config/regback/system
C:/Windows/system32/config/regback/software
C:/Program Files/MySQL/MySQL Server 5.1/my.ini
C:/Windows/System32/inetsrv/config/schema/ASPNET_schema.xml
C:/Windows/System32/inetsrv/config/applicationHost.config
C:/inetpub/logs/LogFiles/W3SVC1/u_ex[YYMMDD].log
```

-----------------------------
