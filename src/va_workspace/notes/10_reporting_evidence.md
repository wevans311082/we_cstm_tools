# Task Stack: Reporting, Evidence Management, and Quality Assurance

> Outcome: Deliverables that meet UK Cyber Scheme CSTM standards with defensible evidence trails.

## Task Group 1: Evidence Collection Discipline
- [ ] Store all logs under structured directories: `evidence/{governance,recon,enum,vuln,postex,wireless}`.
- [ ] Hash artefacts daily: `find evidence -type f -exec sha256sum {} \; > evidence/hashes_$(date +%F).txt`
- [ ] Capture screenshots with timestamp overlay (e.g., `gnome-screenshot`, `greenshot` with watermark).

## Task Group 2: Reporting Framework
- [ ] Draft executive summary focusing on risk to business objectives.
- [ ] Populate technical sections referencing MITRE ATT&CK IDs, CWE, CVSS.
- [ ] Maintain remediation tracker `remediation_register.xlsx` with columns `finding,owner,due_date,status`.

## Task Group 3: Peer Review and QA
- [ ] Conduct peer review using checklist `qa_checklist.md`.
- [ ] Run spell and grammar checks: `proselint report.md`, `codespell report.md`.
- [ ] Validate references: ensure each finding links to evidence path and timestamp.

## Task Group 4: Presentation Artefacts
- [ ] Prepare slide deck using `reveal.js` or PowerPoint summarising key issues.
- [ ] Include diagrams exported from Mermaid via `mmdc` CLI: `mmdc -i diagram.mmd -o diagram.png`.
- [ ] Create attack timeline with `timesketch` or `draw.io`.

## Task Group 5: Secure Delivery
- [ ] Package report and evidence in encrypted archive: `7z a -p '<passphrase>' -mhe=on deliverables.7z report.pdf evidence/` (link out to [`commands/tar.md`](./commands/tar.md) and [`commands/gzip.md`](./commands/gzip.md) when preparing staging bundles prior to encryption)
- [ ] Transfer via secure channel (SFTP, Matrix, ProtonDrive) as per RoE.
- [ ] Confirm receipt with client; log acknowledgement in `handover_log.md`.

## Task Group 6: Post-Engagement Clean-up
- [ ] Destroy temporary working copies: `srm -vz evidence/tmp/*`.
- [ ] Revoke any access keys or accounts created during engagement.
- [ ] Conduct lessons-learned session; record actions in `retro.md`.

---

## Executive Summary Blueprint

### Purpose and Audience
- The executive summary translates technical findings into board-ready language emphasising risk to mission, finance, and compliance.
- Assume the reader has five minutes and minimal technical background; prioritise the "so what?" over detailed exploit chains.

### Sample Outline
1. **Engagement Context**: Scope, objectives, testing window, constraints.
2. **Threat Narrative**: One paragraph on the adversary simulation storyline, including assumed threat actors or TTPs.
3. **Top Risks (3-5 bullets)**: Business impact, likelihood, and potential regulatory consequences.
4. **Risk Heat Map Snapshot**: Table or figure referencing the metrics checklist.
5. **Immediate Actions**: High-urgency mitigations required in the next 30 days.
6. **Assurance Statement**: Confirmation of evidence integrity, methodology adherence, and limitations.

### Writing Tips
- Lead with quantified impact (e.g., "Potential loss of £1.2M due to privilege escalation in payroll system").
- Use verbs that convey urgency: "exposes", "permits", "enables" rather than "may allow" unless uncertainty is justified.
- Keep sentences under 20 words; convert jargon into analogies or explainers in parentheses.

---

## Technical Findings Playbook

### Standard Finding Structure
1. **Identifier**: Unique ID `RTF-<phase>-<number>`.
2. **Title**: Clear, action-oriented statement ("Unpatched Confluence RCE enables domain takeover").
3. **Description**: Attack path, prerequisite conditions, affected assets.
4. **Impact Analysis**: CIA triad, business process disruption, safety implications.
5. **Evidence Summary**: Hash, timestamp, operator, repository path.
6. **Detections & Compensating Controls**: Existing controls and why they failed.
7. **Recommendations**: Prioritised actions with owners.
8. **References**: MITRE ATT&CK, CWE, vendor advisories.

### Writing Tips
- Anchor each assertion to an evidence artefact; if the evidence is visual, embed a thumbnail or hyperlink.
- Include reproduction steps with sanitized payloads; flag any destructive actions.
- Align severity scores with organisational methodology (CVSS, DREAD) and document rationale in the metrics checklist.

### Metrics Checklist
- [ ] Severity score assigned using agreed scoring model (record source and version).
- [ ] Likelihood justification references threat intelligence or control maturity.
- [ ] Business impact quantified (financial, regulatory, reputational) or tagged as "qualitative" with reason.
- [ ] Detection coverage evaluated (existing alerts, logging gaps, mean time to detect).
- [ ] Residual risk post-remediation estimated and captured in remediation tracker.

---

## Remediation Plan Architecture

### Plan Outline
1. **Workstream Overview**: Group findings by capability (identity, network, application, cloud).
2. **Action Register**: Table `finding_id | action | owner | dependencies | due_date | status` synced with `remediation_register.xlsx`.
3. **Resource Requirements**: Skill sets, tooling, budget, maintenance windows.
4. **Change Governance**: Required CAB approvals, rollback plans, stakeholder communication.
5. **Validation Strategy**: Retest plan, evidence acceptance criteria, sign-off authority.

### Writing Tips
- Tie remediation actions to control frameworks (ISO 27001, NIST CSF) to support audit conversations.
- Suggest phased delivery (e.g., quick wins vs strategic fixes) and note any prerequisites.
- Call out where compensating controls can temporarily reduce risk while permanent fixes are scheduled.

### Sign-off Workflow Checklist
- [ ] Remediation actions reviewed by technical lead and risk owner.
- [ ] Change requests submitted to governance board with evidence references.
- [ ] Validation tests executed, documented, and archived in evidence repository.
- [ ] Client sign-off captured (name, role, timestamp) and appended to final report.
- [ ] Post-implementation monitoring schedule agreed and recorded.

---

## Appendices and Supporting Material

### Suggested Appendices
- **A. Methodology**: Mapping of engagement phases to standards (CBEST, TIBER-EU, CREST).
- **B. Tooling Matrix**: Version numbers, execution context, hash of binaries.
- **C. Timeline**: Chronological list of major events with UTC timestamps.
- **D. Glossary**: Plain-language definitions for acronyms and technical terms.
- **E. Control Validation Logs**: Evidence of mitigations tested during engagement.

### Assembly Tips
- Use consistent naming (`Appendix-A_Methodology.md`) and cross-reference in the main report.
- Convert large datasets to CSV/XLSX and note storage location in evidence register.
- When including screenshots, ensure redactions are documented and reproducible.

### Style Review Checklist
- [ ] Appendix titles and references align with main body mentions.
- [ ] Figures/tables include captions and data sources.
- [ ] Document adheres to client branding (fonts, colour palette, cover page template).
- [ ] Pagination and table of contents regenerated after changes.
- [ ] Accessibility check completed (alt-text, heading hierarchy, colour contrast).

---

## Evidence Mapping Guide

### Evidence Traceability Matrix Template
| Finding ID | Evidence Path | Hash | Timestamp (UTC) | Operator | Notes |
|------------|---------------|------|-----------------|----------|-------|
| RTF-VULN-01 | `evidence/vuln/webapp/rce_poc.mp4` | `sha256:...` | `2025-04-22T18:45:00Z` | Alice | Screen capture of exploit chain |
| RTF-POST-03 | `evidence/postex/creds/dc_sync.txt` | `sha256:...` | `2025-04-23T09:12:00Z` | Bob | Secretsdump output for DC Sync |

### Evidence Mapping Procedure
1. **Index Creation**: Export `find evidence -type f` to CSV and enrich with hashes and tags.
2. **Linkage**: For each finding, list all supporting artefacts and embed hyperlinks in the report.
3. **Integrity Validation**: Run scheduled hash comparisons and log deviations.
4. **Access Control**: Document who can access each evidence folder and how access is revoked post-engagement.
5. **Retention**: Note retention policy (e.g., 12 months) and secure destruction workflow.

### Evidence QA Checklist
- [ ] Every finding references at least one evidence artefact in the matrix.
- [ ] Hash values verified within 24 hours of report submission.
- [ ] Timezones normalised to UTC with local time offset recorded where relevant.
- [ ] Sensitive data redacted or handled according to client data classification.
- [ ] Evidence repository audit trail exported and archived.

---

## Integrated Reporting Workflow

1. **Drafting**: Technical author compiles findings, executive summary, and appendices using templates.
2. **Metrics Review**: Risk analyst validates scoring using the metrics checklist.
3. **Style Review**: Editor executes the style review checklist and updates the change log.
4. **Stakeholder Validation**: Present draft to engagement lead and client sponsor for comments.
5. **Sign-off**: Capture approvals using the sign-off workflow checklist and update `handover_log.md`.
6. **Publication**: Generate final PDF, package evidence, and execute secure delivery tasks.
7. **Archive & Lessons Learned**: Store artefacts, schedule retro, and feed insights into future playbooks.
