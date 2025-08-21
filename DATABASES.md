FOUND THIS RESOURCE FOR SQLI
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md#postgresql-command-execution
## MYSQL

cmd to connect to mysql 
```
mysql -u root -p'root' -h 192.168.50.16 -P 3306
```
if u have ssl certificate. errors try one of the two flags
```
--ssl=0
```
```
--ssl-mode=DISABLED
```
LIST THE USER RUNNING THIS SERVICE
```
select system_user();
```
VERSION OF THE DB
```
select version();
```
LIST ALL DBS ON THE SERVER
```
show databases;
```
CMD TO SHOW USER AND PWD FOR A SPECIFIC USER FOR A SPECIFIC TABLE
```
SELECT user, authentication_string FROM mysql.user WHERE user = 'offsec';
```


## MS SQL

```
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
```
VERSION OF THE DB
```
SELECT @@version;
```
LIST AVAILABLE DATABASES
```
SELECT name FROM sys.databases;
```
CHOOSE THE TABLES IN THE DB
```
SELECT * FROM <DB_NAME>.information_schema.tables;
```
LIST THE INFO IN THE TABLES
```
select * from <DB_NAME>.<TABLE_SCHEMA>.<TABLE_NAME>;
```


