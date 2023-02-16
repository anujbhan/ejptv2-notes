---
id: ljl0ms02t55tnd2y19jmzj7
title: Enumerating_ssh
desc: ''
updated: 1675114077094
created: 1675114069941
---
# Enumeration - SSH

* Nmap:
    * Service directory: Nmap <ip> -sV
    * Nmap <ip> -sV -p 22 —script ssh2-enum-algos
    * Nmap <ip> -sV -p 22 —script ssh-hostkey —script-args ssh_hostkey=full
    * Nmap <ip> -sV -p 22 —script ssh-auth-methods —script-args=“ssh.user=<user>”
    * Nmap <ip> -sV -p 22 —script ssh-brute —script-args userdb=/path/to/usernames/file
* SSH:
    * Directly connect on root: ssh root@<ip>
* Netcat: nc <ip> <port> —> might give you some server info like the banner
* Hydra -l student -P /usr/share/wordlists/rockyou.txt <ip> ssh
* Msfconsole
        * Use auxiliary/scanner/ssh/ssh_login, set rhosts <ip>, set userpass_file /usr/share/wordlists/metasploit/root_userpass.txt, set stop_on_success TRUE 
* Two types of login supperted
    * User and pass (less secure)
    * Or Key based auth
