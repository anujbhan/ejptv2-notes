---
id: fuoo98wrhvv7ds8ul2950ld
title: Information_gathering
desc: ''
updated: 1675113881795
created: 1675113707621
---

# Information gathering

* Passive: without engaging the target directly (utilize publicly available info, ex: IP address, dns, whois etc)
* Active: with actively engaging the target (port scanning, enumeration etc)


## Passive Recon -  Website recon & foot printing

Example:

hackersploit.org

1. Host hackersploit.org
2. Hackersploit.org/robots.txt (search engine indexing, might reveal hidden directories and other info)
3. Hackersploit.org/page-sitemap.xml ( author info, publicly available pages/directory 

Tools 
* Browser plugins
    * Built with
    * Wappalyzer
* What web
* HTTrack : download website locally for analysis
        * Kali - webhttrack cli


### Passive Recon - Whois

* zonetransfer.me ( dns setup for learning about DNS zone transfers)

### Passive Recon - Netcraft

* netcraft.com : Gives passive recon information
    * DNS
    * SSL
        * Issues and vulnerabilities
    * Technologies used

### Passive Recon - DNS

* Tool - dnsrecon (available in kali)
    * Dnsrecon -d hackersploit.org

Insider tips:
* Cloud flare hides accurate A IPs
* Cloudflare does not hide MX (mail server) IPs


Tool - dnsdumpster.com


### Passive Recon - WAF with wafwoof

This tool is helpful in understanding if a website/app is protected by WAF solution.

tool: https://github.com/EnableSecurity/wafw00f  

Comes installed with kali.


### Passive Recon - Subdomain enumeration using sublistr

https://github.com/aboul3la/Sublist3r

Uses public information OSINT to enumerate subdomains.

### Passive recon - Google Dorks

“site:” operator: shows results for only that domain and subsequent subdomains

“inurl:” search keyword in the urls

Wildcards: example - “site: *.ine.com inurl: admin

“intitle:” keyword in site title

“filetype:” filetypes like pdf

“Cache:” google search engine cache

Waybackmachine 

ExploitDB has google dorks search “google hacking database”


### Passive Recon - Email harvesting using theHarvester

https://github.com/laramies/theHarvester

The harvester can find emails from domains. The harvester has other features like domain enumeration as well, this tool comes pre-installed with kali

Spyse - search engine for pen testing


### Passive Recon - leaked password databases

haveibeenpwned.com - collect email harvested in previous step and see if they have leaked password on this site

## Active Recon

### Active Recon - DNS Zone Transfer

DNS Zone transfer refers to attempting to transfer all DNS records from one server to another. If the DNS zone files are not protected, the attacker can potentially identify internal networks addresses and other DNS records.

Tools: dnsdunpster.com, dnsrecon (kali), dnsenum(kali), fierce (kali)

Use zonetansfer.me to study DNS

Tool - dnsenum automatically attempts dns zone transfer

Active Recon - Host Discovery with nmap

sudo nmap -sn <subnet mask> (-sn option tell nmap to perform ping sweep with not port scanning

Another tool to use would netdiscover

### Active Recon - Port scanning with nmap

nmap -Pn -F -sV -O -sC 10.3.28.109

-Pn - disable ping scan ( useful in case the host is blocking ICMP ping scan, like windows host)
-F - fast scan top ports
-sV - detects the services running on the host
-O - operation system detection
-sC - runs pre-install nmap scripts on identified ports, might reveal useful information.