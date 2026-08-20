# Business Risk & Security Practice Highlights

> Outcome: Rapidly surface findings that intersect offensive activity, business risk, and required defensive actions. Update this sheet during engagements and reference `Risk ID` values in reports and Metasploit modules.

## Usage Instructions

1. Populate the **Observation** column as events occur (e.g., exposed service, credential discovery, detection alert).
2. Link each observation to a **Business Impact** statement to communicate urgency to stakeholders.
3. Record the **Required Security Practice** that mitigates or controls the risk (policy, tooling, or process).
4. Tag the relevant **Evidence Location** for audit trails.
5. Use the **Status** field to track remediation progress (`Open`, `In Progress`, `Mitigated`).

## Highlight Register

| Risk ID | Observation | Business Impact | Required Security Practice | Evidence Location | Status | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| BR-001 | Legacy SMBv1 service discovered on production host. | High: Ransomware risk and compliance violation (PCI DSS). | Disable SMBv1; enforce SMB signing; patch OS. | `evidence/enum/nmap_full_*` | Open | Coordinate change window before disabling service. |
| BR-002 | Domain admin credentials recovered via `secretsdump`. | Critical: Unrestricted lateral movement, potential for total compromise. | Implement PAM, enforce MFA, rotate credentials immediately. | `evidence/cred/secretsdump_dc01.zip` | In Progress | Customer notified 2024-05-01 10:30Z. |
| BR-003 | Web application returns sensitive PII in unauthenticated responses. | High: Regulatory reporting (GDPR) and brand damage. | Apply access controls, implement data minimisation, enable detailed access logging. | `evidence/web/burp_target_pii.xml` | Open | Requires legal escalation. |
| BR-004 | Endpoint protection disabled on finance workstations (`Get-MpComputerStatus`). | Medium: Increased malware exposure, fails CIS controls. | Re-enable Defender with tamper protection; deploy monitoring. | `evidence/os/win_defender_status.csv` | Mitigated | IT re-enabled and confirmed via ticket CHG-2215. |
| BR-005 | Metasploit module triggered IDS alert on critical segment. | Medium: Potential service disruption, detection fatigue. | Update detection rules, schedule red/blue debrief, adjust module thread counts. | `evidence/blue_team/ids_alert_20240501.txt` | Open | Capture IDS packet samples for tuning. |
| BR-006 | Unencrypted backups accessible via anonymous FTP. | High: Data exfiltration path for sensitive archives. | Enforce authenticated access, encrypt backups at rest, monitor access logs. | `evidence/exfil/ftp_listing_20240502.txt` | Open | Validate if backups contain regulated data. |
| BR-007 | macOS Gatekeeper disabled on developer laptops. | Medium: Unsigned binaries can execute without review. | Re-enable Gatekeeper (`spctl --master-enable`), implement MDM enforcement. | `evidence/osx/gatekeeper_status.md` | In Progress | Awaiting MDM policy update. |
| BR-008 | Password spraying nearing lockout threshold. | Medium: Operational risk due to potential service desk involvement. | Implement rate limiting, notify stakeholders before continuing, adjust timers. | `evidence/cred/password_spray.log` | Open | Pause spraying until change window. |
| BR-009 | Critical service exposed without monitoring (no syslog forwarding). | High: No detection coverage on public-facing asset. | Deploy centralised logging, configure alerting, include in SOC runbooks. | `evidence/infra/syslog_gap.txt` | Open | Add to remediation plan. |
| BR-010 | Sensitive data staged for exfil without encryption. | High: Regulatory breach if intercepted. | Enforce encryption at rest, use secure transfer channels, limit staging windows. | `evidence/exfil/data_archive_manifest.csv` | In Progress | Encrypt archive with AES256 prior to transfer. |

## Watchlist Prompts

- **Segregation of Duties**: When exploitation requires elevated access, confirm approvals and document them alongside `Risk ID`.
- **Change Control Alignment**: Link each remediation action to the client's change ticket (e.g., `CHG-####`).
- **Detection Gaps**: Note any offensive activity not detected by defensive tooling; recommend logging enhancements.
- **Data Handling**: Highlight when sensitive data (PCI, PII, PHI) is accessed or moved. Ensure secure deletion after engagement.
- **Third-Party Dependencies**: Flag risks originating from vendors or SaaS services to inform supply-chain assessments.

> Revisit this sheet during wash-up meetings to confirm mitigations and to prioritise findings in the final report.
