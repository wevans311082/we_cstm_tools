# `nmap` Command Reference

## Overview
`nmap` (Network Mapper) is a network scanning and discovery tool used to identify hosts, services, and operating systems on a target network. It supports a wide array of scan techniques and output formats, making it a cornerstone for reconnaissance and security assessments.

## Syntax
```
nmap [scan types] [options] <target specification>
```
### Example Baseline Scan
```
nmap -sS -sV -O -Pn -p- 10.0.0.0/24 -oA evidence/enum/nmap_full
```

## Key Flags and Options
- `-sS`: TCP SYN scan that is stealthier than a full connect scan.
- `-sV`: Probe open ports to determine service/version information.
- `-O`: Enable OS detection through TCP/IP stack fingerprinting.
- `-Pn`: Treat all hosts as online, skipping host discovery.
- `-p-`: Scan all 65,535 TCP ports.
- `-sU`: Perform UDP scanning; often paired with `--top-ports` for performance.
- `-oA <basename>`: Output results in all major formats (`.nmap`, `.gnmap`, `.xml`).
- `--script <name>`: Run NSE scripts to extend functionality (e.g., vuln detection).
- `--min-rate` / `--max-rate`: Control the packet rate to tune stealth and speed.

## When and Where to Run
- **Initial reconnaissance** against target subnets to map exposed services.
- **Change monitoring** during ongoing engagements to track infrastructure updates.
- **Validation of remediation** to ensure ports/services are no longer exposed.
Run from a controlled assessment host with network access to the target range. Ensure engagement scoping allows active scanning.

## Why This Command Matters
- Quickly enumerates attack surface and prioritizes follow-up testing.
- Produces structured output that feeds reporting and automation pipelines.

## Business and Operational Risks
- High-intensity scans can trigger IDS/IPS alerts or impact fragile systems.
- Unauthorized use may violate acceptable use policies or legal agreements.
- Misinterpreting results can lead to inaccurate risk assessments.
Mitigate by coordinating with stakeholders, throttling scan rates, and documenting scope approvals.

## Related Commands and Enhancements
- `masscan` for high-speed scanning of large address spaces.
- `zmap` for Internet-wide scanning efforts focused on single ports.
- NSE scripts such as `vulners` or `http-enum` to deepen service analysis.
