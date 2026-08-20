# Task Stack: Active Enumeration and Network Mapping

> Outcome: Structured service inventory with precise versioning data for further exploitation phases.

## Task Group 1: Baseline Network Discovery
- [ ] Execute `masscan` for high-speed discovery:
  - `masscan 10.0.0.0/8 -p1-65535 --rate 20000 -e tun0 -oX evidence/enum/masscan_full.xml`
  - Parse to CIDR summary: `python3 scripts/masscan_to_cidr.py evidence/enum/masscan_full.xml > evidence/enum/masscan_summary.txt`
- [ ] Follow-up targeted `nmap` scans per /24:
  - `nmap -sS -sV -O -T3 -Pn -p- -oA evidence/enum/nmap_full_10.0.10.0_24 10.0.10.0/24`
- [ ] Run UDP top-ports: `nmap -sU --top-ports 200 -oA evidence/enum/nmap_udp_top200 10.0.10.0/24`
- [ ] Before adjusting scanning jump-host interfaces or VPN transport, consult the [Networking and VPN appendix](Appendix_Networking_and_VPN.md) for netplan templates, OpenVPN references, and troubleshooting commands.

## Task Group 2: Service Fingerprinting
- [ ] Apply `naabu` for port verification: `naabu -list hosts.txt -ports full -rate 5000 -c 25 -o evidence/enum/naabu_full.txt`
- [ ] Use `smbclient`, `rpcclient`, `enum4linux-ng` for SMB/NetBIOS domain discovery.
- [ ] For SNMP, gather community strings via `onesixtyone` then `snmpwalk -v2c -c <community> <target> 1.3.6.1.2.1`.

## Task Group 3: Directory and Application Mapping
- [ ] Run `httpx` to filter responsive hosts: `cat evidence/enum/naabu_full.txt | httpx -title -tech-detect -json -o evidence/web/httpx.json`
- [ ] Launch `gobuster` or `ffuf` for directory brute forcing:
  - `gobuster dir -u https://target -w /usr/share/wordlists/dirb/common.txt -k -t 100 -o evidence/web/gobuster_target.txt`
  - `ffuf -u https://target/FUZZ -w SecLists/Discovery/Web-Content/raft-medium-words.txt -ac -mc 200,204,301,302,403`
- [ ] Enumerate APIs using `swagger-hunter` and GraphQL introspection `python3 graphqlmap.py -u https://target/graphql`

## Task Group 4: Authentication Surface
- [ ] Identify login portals with `eyewitness --web --timeout 7 --threads 10 -f hosts.txt -d evidence/web/eyewitness`
- [ ] Capture TLS certificate data: `openssl s_client -connect target:443 -showcerts </dev/null | openssl x509 -text > evidence/web/target_cert.txt`
- [ ] Monitor credential lockout policies via safe sprays: `crowbar -b rdp -s 10.0.10.5/32 -u admin -C passwords.txt --delay 60`

## Task Group 5: Active Directory Specific Enumeration
- [ ] Run `bloodhound-python -c All -u user -p pass -d corp.local -dc dc01.corp.local -ns 10.0.10.10`
- [ ] Execute `GetUserSPNs.py corp.local/user:pass -dc-ip 10.0.10.10 -outputfile evidence/ad/spns.out`
- [ ] Build AD timeline: `python3 adenum.py --domain corp.local --dc-ip 10.0.10.10 --output evidence/ad/overview.json`

## Task Group 6: Container and Cloud Footprint
- [ ] Enumerate Kubernetes with `kubectl` using service accounts: `kubectl get pods -A -o wide`
- [ ] Query AWS using limited creds: `aws ec2 describe-instances --profile engagement --output json > evidence/cloud/aws_instances.json`
- [ ] Map Azure assets: `az graph query -q 'Resources | project name, type, location' > evidence/cloud/azure_resources.json`

## Task Group 7: Evidence Management
- [ ] Hash all scan files nightly: `find evidence/enum -type f -exec sha256sum {} \; > evidence/enum/hashes_$(date +%F).txt`
- [ ] Visualise data via `maltego`, `neo4j`, or `cytoscape` importing from `httpx.json` and `bloodhound` outputs.
- [ ] Update `attack_surface.csv` from recon with enumerated services and versions.
