---
id: i5s3z3i1cxg82f508l620wq
title: Footprinting_and_scanning
desc: ''
updated: 1675113922129
created: 1675113908711
---

# Footprinting & Scanning


Scope & discovery should be identified before starting penetration testing.

## Mapping a Network:

Process:
- Physical access
    - Physical security: physical laptops, cameras etc
    - OSINT: make use of public information to discover dns, ip, email etc
    - Social Engineering: phish employee
- Sniffing
    - Passive recon
    - Watch network traffic
- ARP (address resolution protocol)
    - IP address to hostnames
- ICMP (internet control message protocol)
    - Traceroute
    - Ping


## Tools:
- Wireshark
- ARP-SCAN
- PING
- FPING
- NMAP
- ZENMAP

- Run Wireshark in the background
- sudo arp-scan -I eth0 -g 172.16.139.129/24 - Will scan all the host listening on that subnet mask
- fping -I eth0 -g 172.16.139.129/24 -a 2>/dev/null (Similar to above, but uses different tool. Using diff tool might result in diff output sometimes. Always a good practice to crosscheck)
- nmap -sn 172.16.139.129/24 (also offers similar functionality as above, but diff tech)


## Port Scanning:

- TCP 3 way handshake
    - Stealthy scan: SYN -> SYN+ ACK -> RST (Nmap)
- Service Detection
    - TCP 3 way handshake -> banner - RST + ACK

## Advanced Tools:

- Nmap automater
- Masscan
- Rustscan
- Autorecon
