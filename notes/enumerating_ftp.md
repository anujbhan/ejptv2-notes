---
id: 7ftnefdwpanw3kj992glald
title: Enumerating_ftp
desc: ''
updated: 1675113965059
created: 1675113959342
---
# Enumeration - FTP

* Nmap
    * Service detection: nmap <ip> -sV
    * Nmap <ip> -sV -p 21 —script ftp-brute —script-args userdb=/path/to/usernames/file
* ftp 
    * Anonymous login: ftp <ip>, don’t pass any username or password
        * ftp console:
            * Help
            * Ls
            * Get <file>
* Hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt <ip> ftp
    * To limit threads, add -t <threads>
* To login:
    * ftp ip
        * Enter username
        * Enter password
* Search for exploits from cmd
    * Searchsploit <keyword> 
        * searchsploit ProFTPD
