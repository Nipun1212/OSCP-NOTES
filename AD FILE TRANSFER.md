
## SMB SHARE

### CMD

#### On MS01 (to create and share “tools” folder)

Create the directory (if it doesn’t exist):
```
mkdir C:\tools
```

Share it as “tools” with full access to Everyone:
```
net share tools=C:\tools /GRANT:Everyone,FULL
```

Verify the share:

```
net share tools
```

## On MS02 (to map the share and copy files)
#### without pass

```
net use Z: \\MS01\tools 
```

Create a local directory if needed
```
mkdir C:\Temp
```

Copy everything
```
copy Z:\* C:\Temp\
```

#### single file
```
net use Z: \\MS01\tools 
```
```
mkdir C:\Temp copy Z:\YourTool.exe C:\Temp\YourTool.exe 
```

## Example: mirror an entire tools folder


`xcopy \\MS01\tools C:\Temp\tools /E /H /C /I`

Switches used above:

- /E – copy all subdirs, even empty ones

- /H – include hidden and system files

- /C – continue on errors

- /I – assume destination is a directory when copying multiple files
#### with pass
Map the share to drive Z:
```
net use Z: \\MS01\tools /USER:DOMAIN\Administrator P@ssw0rd!
```
Copy your tools from Z: to a local folder (e.g., C:\Temp):
```
mkdir C:\Temp copy Z:\* C:\Temp\
```

Remove the mapped drive when done:
```
net use Z: /DELETE
```




### POWERSHELL


### On MS01 as Administrator

Create the tools directory (if it doesn't already exist)
```
New-Item -Path C:\tools -ItemType Directory -Force
```

Share it as "tools" and grant Everyone full control
```
net share tools=C:\tools /grant:Everyone,full
```



Create a PSDrive to the share

```
New-PSDrive -Name T -PSProvider FileSystem -Root \\MS01\tools -Persist
```

Copy files from the share

```
Copy-Item T:\* C:\Temp\ -Recurse
```

also to copy
```
# On MS02, anonymously (Everyone has full access)
Copy-Item -Path '\\MS01\tools\YourTool.exe' -Destination 'C:\Temp\YourTool.exe'
```



# USING PS REMOTING

```
# On MS01 as Administrator

# 1. Create a SecureString for the plaintext password
$plain = 'P@ssw0rd!'
$secure = ConvertTo-SecureString $plain -AsPlainText -Force

# 2. Create a PSCredential object for DOMAIN\Administrator
$cred = New-Object System.Management.Automation.PSCredential('DOMAIN\Administrator', $secure)

# 3. Establish a session to MS02
$sess = New-PSSession -ComputerName MS02 -Credential $cred

# 4. Copy your tool (e.g. SharpHound.exe) from C:\tools to C:\Temp on MS02
Copy-Item -Path C:\tools\SharpHound.exe -Destination 'C:\Temp\' -ToSession $sess

# 5. Tear down the session
Remove-PSSession $sess
```
