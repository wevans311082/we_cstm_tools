# UK Cyber Scheme CSTM Task Catalogue

> This catalogue translates UK Cyber Scheme CSTM practical expectations into actionable task lists. Each markdown file under `docs/cstm/` focuses on a domain of assessment and enumerates the commands, tooling, and evidence artefacts required to complete the tasks. Flow charts and decision trees provide execution logic. Link these files directly in the accompanying HTML front end for quick reference during engagements or revision.

## File Guide
- [01_Pre-Engagement_and_Governance.md](01_Pre-Engagement_and_Governance.md)
- [02_Reconnaissance_and_Intelligence.md](02_Reconnaissance_and_Intelligence.md)
- [03_Enumeration_and_Mapping.md](03_Enumeration_and_Mapping.md)
- [04_Vulnerability_Discovery_and_Exploitation.md](04_Vulnerability_Discovery_and_Exploitation.md)
- [05_Post_Exploitation_and_PrivEsc.md](05_Post_Exploitation_and_PrivEsc.md)
- [06_Lateral_Movement_and_Persistence.md](06_Lateral_Movement_and_Persistence.md)
- [07_Web_Application_Testing.md](07_Web_Application_Testing.md)
- [08_Wireless_and_RF.md](08_Wireless_and_RF.md)
- [09_Social_Engineering.md](09_Social_Engineering.md)
- [10_Reporting_and_Evidence.md](10_Reporting_and_Evidence.md)
- [11_Command_Cheat_Sheets.md](11_Command_Cheat_Sheets.md)
- [12_Flowcharts_and_Decision_Trees.md](12_Flowcharts_and_Decision_Trees.md)
- [13_Business_Risk_and_Security_Highlights.md](13_Business_Risk_and_Security_Highlights.md)
- [CSTM v8 Slide Command & Tool Extract](ctsm_v8_command_map.md)
- [Tool Library](tools/README.md)
- [Appendix: Networking and VPN Operations](Appendix_Networking_and_VPN.md)

### Service Hosting Quickstarts
- [Apache HTTP Server Quickstart](commands/apache_setup.md)
- [Nginx Reverse Proxy Quickstart](commands/nginx_setup.md)
- [Python Secure HTTP Service Quickstart](commands/python_http.md)

## Usage Pattern
1. Select the relevant task file based on the engagement phase.
2. Execute checklist items sequentially; where a command is provided, copy, adapt parameters, and record outputs.
3. Capture evidence as described in the `Evidence` bullet for each task.
4. Use decision trees in [12_Flowcharts_and_Decision_Trees.md](12_Flowcharts_and_Decision_Trees.md) to adapt to real-time conditions.

## Evidence Logging Template
```markdown
### Task Reference
- **Timestamp (UTC)**: `2024-04-29T12:34:00Z`
- **Operator**: `<name>`
- **Tool/Command**: `nmap -sS -Pn -p- 10.0.10.0/24`
- **Output Path**: `/evidence/network/nmap_full_20240429.xml`
- **Hash (SHA256)**: `sha256sum <file>`
- **Notes**: Summary of findings, anomalies, follow-up actions.
```

## Operational Discipline
- Run all commands inside version-controlled scripts when possible to ensure reproducibility.
- Sync time across operator workstations and target infrastructure using NTP prior to starting the engagement.
- Archive markdown files and evidence alongside final report deliverables for peer review.
