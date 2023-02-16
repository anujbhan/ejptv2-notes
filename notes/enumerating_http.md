---
id: kyy3g6j3n0kys660r1l0q35
title: Enumerating_http
desc: ''
updated: 1675113983005
created: 1675113973388
---
# Enumeration - HTTP


## IIS servers:

* Dirb: directory listing, example: “dirb <url>” runs the default wordlist 
* Browsh: renders urls on terminal. “browsh —startup-urls <url>”. I found it not very useful, doesn’t give any extra information other than browser. Can be handy when web browser is not available
* Nmap -  Service detection, OS detection and HTTP scripts	
    * “Nmap <ip> -p 80 —script http-enum”
    * “Nmap <ip> -p 80 —script http-headers”
    * “Nmap <ip> -p 80 —script http-methods —script-args http-methods.url_path=“/webdav/”
    * “Nmap <ip> -p 80 —script http-webdav-scans —script-args http-methods.url_path=“/webdav

## Apache HTTPD:

Nmap:
- Nmap <ip> -p 80 -sV
- Nmap <ip> -p 80 -sV —script banner
- Curl <ip> can reveal some information
* Browsh: renders urls on terminal. “browsh —startup-urls <url>”. I found it not very useful, doesn’t give any extra information other than browser. Can be handy when web browser is not available
* Lynx <url>, similar to browsh but without graphics, just text
* Dirb <url> /usr/share/metasploit-framework/data/wordlists/directory.txt
- Msfconsole
    - Use auxiliary/scanner/http/http_version, set rhosts <ip>, run
    -  Use auxiliary/scanner/http/brute_dirs, set rhosts <ip>, run
    -  Use auxiliary/scanner/http/robots_txt, set rhosts <ip>, run 
