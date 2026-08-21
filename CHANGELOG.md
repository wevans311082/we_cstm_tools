# Changelog

All notable changes to **va-workspace** are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [0.6.0] — current

### Added
- `va finding edit <ID>` — update title, CVSS, hosts, ports, or status on an existing finding note
- `va finding add --from-lead <path>` — pre-populate a finding from a lead note's frontmatter
- Severity distribution bar in `va status` (compact Rich table showing finding counts by severity)
- `--dry-run` flag on `va scan` — print nmap argv and planned tool jobs, then exit without running
- Finding diff in `va compare` output (added / removed finding IDs between two engagements)
- Operator notes (`va notes list`, `va notes show`) from `ca_misc_scripts` CSTM catalogue
- Evidence snapper (`va snap`, `va grab`) — fixed from `scrptn.py`; Wayland + X11; vault-native
- Custom NSE scripts (`va nse list`, `va nse path`) — shipped as package data
- `va split-ports` — Nmap port expression splitter (old `nsplit.py`)
- `va cert <host> [port]` — stdlib TLS certificate viewer
- `va compare <other>` — retest diff of hosts, ports, and findings

### Core
- Resumable multi-phase Nmap pipeline (discovery → TCP → UDP → NSE)
- YAML-extensible secondary tool dispatcher (`config/tool_mappings.yaml`); user override path
- Python probe modules (SMB signing, TLS versions, VPN portals, LDAP anon, HTTP intel, Postgres, Oracle TNS)
- CVSS 3.1 base score calculator (FIRST specification, stdlib-only)
- CHECK-shaped Obsidian vault: hosts, findings, leads, posture overview, Dataview dashboard, Canvas topology
- Atomic `state.json` checkpoint/resume (`.tmp` + replace)

### Changed
- Relaxed dependency version pins to minor-level compatible releases (`rich~=13.9`, etc.)

### Fixed
- `va snap` — Esc/cancel is no longer treated as an error; overlapping hotkey lock; `notify-send` failure is non-fatal
- Wayland detection now also checks `XDG_SESSION_TYPE=wayland`
- Finding frontmatter parser uses `yaml.safe_load` (correctly handles CVSS vectors containing colons)
- Port diff in `va compare` now includes all port states, not just `open`, so closed ports appear in "no longer seen"
- `orchestrator`: `import sys` moved to module level (was inside hot loop)
- `nmap_runner.run_nmap` back-compat fallback skips `discovery.xml`
- Credential placeholder check uses `FORBIDDEN_ARGV_PLACEHOLDERS` constant consistently

---

## [0.5.x] and earlier

Initial development: Nmap XML parser, vault writer, orchestrator, YAML plugin schema, CHECK report skeletons. See `SPEC.md` §1 for a description of gaps addressed in the rewrite.
