---
id: ujcs9wgn8u5hm2plccf1mhp
title: Enumerating_smb
desc: ''
updated: 1675114043631
created: 1675114022457
---
# Enumeration - SMB


## Servers and Services

SMB: Windows Discover & Mount

Server message block (SMB): This is a network file system used by windows. You can mount a network drive by providing the IP in windows machine on the same network. This step might require a username and password.

SMB service usually runs on port 445

Mount smb share using cmd prompt: “net use <local drive>: \\<ip>\<remote drive>$”


Refresh knowledge on networks:
* How to tell CIDR block if net mask and ip is given?

## Tools used:

### NMAP: 

Nmap has several inbuilt scripts to enumerate SMB shares. Get all the smb related scripts here: “ls /usr/share/nmap/scripts/ | grep smb”. The nmap scripts can also take arguments, example:

Nmap <host> —script smb-enum-shares —script-args smbusername=“administrator” smbpassword=“smbserver_771”


Smbmap: written in python, has several enumeration method along with RCE capability. Example:

Smbmap —H <host> -u administrator -p smbserver_771 -x <cmd>

Smbmap also has the capability to upload and download files from the smb shares.


### Metasploit: 

There are several enumeration modules in metasploit. All the smb auxiliary modules are listed in “auxiliary/scanner/smb/”, msfconsole supports tab auto complete, use it to check all the aux modules. From what I understand, auxiliary/scanner has enumeration modules. The lab used the following module:

Use auxiliary/scanner/smb/smb_version;

To list the options supported by this module, type “options”. This should list out the required and optional parameters.

A module can be run using “run” or “exploit”.


### Rpcclient: 

This will connect to the samba v2 share and enumerate information among many other things. The smb share in the lab allows a null session, so I was able to do:

Rpcclient -U “” -N <target> —> this should open a session

>> srvinfo —> will give server information
>> enumdomusers —> will list the system users —> this should be the same as enumerating with nmap
>> lookupnames <username> —> should give more user information like user SID, very critical in privilege escalation

### Enum4linux: 

can enumerate smb shares on linux , comes pre installed on kali.


### Smbclient: 

This tool is actually used to mount the smb share and interact with files. 

Smbclient //<target/<share_name> -N —> connects to a null session (no password)




