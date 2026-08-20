# va-workspace — Kali operator toolkit for CHECK-grade VA

This is the product spec. `plan.ai` is a pointer here. Implement against this document.

CLI name: `va`. Python package: `va_workspace`. Repo stays `we_cstm_tools`.

You passed the UK Cyber Scheme Team Member (CSTM) exam and may apply for CHECK Team Member status to perform NCSC CHECK ITHCs. This tool is your daily driver on Kali for **lab, internal, and CHECK engagement** work. It is **not** a CHECK company report factory and **not** a replacement for a Team Leader's judgement. It is an operator vault engine that captures evidence to ITHC-supporting-guidance standard (scope, named testers, CVSS 3.1, evidence, short-term + strategic remediation).

---

## 1. Critique of the current `plan.ai`

The existing file is a six-phase prompt for an LLM to emit a scanner-to-Obsidian pipeline. That is a useful sketch. It is not a professional tool spec.

| Gap | Why it matters on a CHECK/Kali box |
|---|---|
| No engagement identity, scope, RoE, or tester metadata | ITHC output must name people, scope, and context. A CIDR-in, markdown-out script cannot. |
| No intensity or mode | Feroxbuster + NetExec + Gowitness on a government range without rate limits is a RoE violation waiting to happen. |
| Dataview dashboards promised, never specified | The objective mentions them; phases never build them. |
| `init.py` instead of `__init__.py`; dual `requirements.txt` + `pyproject.toml` | Not an installable Kali package. |
| CLI is Phase 6 | A daily driver needs `va doctor` on day one, not after the vault exists. |
| Unbounded `ThreadPoolExecutor` | Can DoS the target and your own box. |
| Searchsploit hits dumped into host notes as if they were findings | False positives in a CHECK report. Tools produce **evidence** and **leads**. You author **findings**. |
| No ingest, resume, audit log, or `doctor` | Real scans die. ITHCs last days. You develop on Windows, run on Kali. |
| Hardcoded ports, no plugin schema | Cannot extend without editing Python. |
| No tests / fixtures | Cannot develop on Windows without live Nmap. |
| Matplotlib + Seaborn for one bar chart | Seaborn is unnecessary weight. Keep Matplotlib only. |
| `onesixtyone` in mappings, missing from the stack; `whatweb` in the stack, missing from mappings | Internally inconsistent. |

Keep from the original: Python 3.11+, Typer, Rich, Jinja2, PyYAML, stdlib ElementTree, Nmap `-oA`, per-host vault folders, YAML tool mappings, graceful degradation if a binary is missing, strict type hints, no placeholders.

---

## 2. Product, users, non-goals

**Product.** A pipx-installed CLI on Kali that:

1. Bootstraps an engagement vault under `~/va-engagements/<client>-<date>/`.
2. Runs (or ingests) Nmap, parses XML, writes a linked Obsidian vault.
3. Dispatches a **thin, YAML-extensible** set of unauthenticated secondary tools, gated by `--mode` and `--intensity`.
4. Checkpoints everything so a killed run resumes.
5. Gives you CHECK-shaped report Markdown to fill, plus Dataview dashboards and a Canvas topology.
6. Lets you **author** findings (`va finding add`) with CVSS 3.1, evidence links, and dual remediation — never auto-publishes exploits as findings.

**Users.** You, on Kali, as CSTM / prospective CHECK Team Member. Secondary: lab practice and internal ranges, switched by `--mode`.

**v1 non-goals**

- Authenticated scanning, password sprays, harvested-cred replay.
- Nuclei / Nikto / BloodHound / Impacket full kitchen sink (add later via YAML).
- Client PDF/HTML export (Obsidian is the product).
- Auto-confirmed vulnerabilities from Searchsploit.
- Windows as a runtime (Windows is the **dev** machine only).
- Anything that requires `shell=True` or puts secrets on `argv`.

Legal banner on every `va scan` / `va ingest` that enumerates: authorised targets only; operator is responsible for RoE.

---

## 3. Operator workflow

```text
va doctor                          # binaries, plugins, Kali apt hints
va init --client acme --mode check # optional; recommended for CHECK
va scan 10.10.0.0/24 --mode check --intensity stealth
# kill / laptop sleep / VPN drop
va scan --resume                   # from engagement cwd or --out
va ingest path/to/nmap.xml         # bonus path; still writes vault
va finding add --title "..." --cvss "CVSS:3.1/..." --hosts 10.10.0.5
va status                          # hosts, jobs, findings, remaining tools
```

`va init` is **not** required. `va scan CIDR` may create `~/va-engagements/scan-<timestamp>/` and infer in-scope from the CIDR. In `--mode check`, print a loud warning if `engagement.md` is missing testers/scope/client, but do not refuse (your choice: scope-optional).

Default `--out`: `~/va-engagements/<client-or-scan>-<YYYY-MM-DD>/`. Override with `--out`. If cwd already contains `engagement.md` or `state.json`, treat cwd as the engagement (so resume from inside the vault just works).

---

## 4. CLI surface (Typer)

| Command | Purpose |
|---|---|
| `va doctor` | Check Python, plugin YAML, and each mapped binary (`shutil.which`). Print apt install hints. Exit non-zero if **required** binaries (nmap) missing; warn on optional. |
| `va init` | Write vault skeleton + `engagement.md`, `scope.md`, `rules-of-engagement.md`, empty CHECK report tree, `state.json`. |
| `va scan TARGET` | Live Nmap → parse → vault → secondary jobs → visuals → report stubs. `TARGET` = CIDR, IP, hostname, or targets file. `--exclude`, `--mode`, `--intensity`, `--out`, `--resume`, `--nmap-args`. |
| `va ingest FILE` | Parse existing Nmap XML (bonus). Same vault + optional `--enum` to run secondary tools. |
| `va status` | Read `state.json`, print host/job/finding counts. |
| `va finding add` | Create a finding note from flags or an interactive form. |
| `va finding list` | Table of findings (severity, CVSS, status, hosts). |

Global: `--verbose`, `--yes` (skip confirmations except the legal banner on first scan in a vault).

Implementation order: `doctor` + packaging first, then `ingest` (no root, Windows-testable), then `scan`, then `finding`.

---

## 5. Mode and intensity (two flags)

`--mode check | lab | internal` — policy and templates, not packet rate.

| Mode | Behaviour |
|---|---|
| `check` | CHECK report tree always generated. Warn if engagement metadata incomplete. Prefer evidence-friendly filenames, tool-version appendix, named-tester fields. Default intensity if omitted: `stealth`. |
| `lab` | Same vault layout, shorter report stubs, less nagging. Default intensity: `standard`. |
| `internal` | Same as lab but templates mention creds-later / assumed-breach notes as **placeholders only** (v1 still unauthenticated). Default intensity: `standard`. |

`--intensity stealth | standard | loud` — Nmap shape, which YAML tools fire, concurrency, timeouts.

| | stealth | standard | loud |
|---|---|---|---|
| Nmap TCP | `--top-ports 1000` | `-p-` | `-p-` |
| Nmap UDP | off | top 20 if root | top 100 if root |
| Timing | `-T2` | `-T3` | `-T4` |
| `-sV` | yes, `--version-intensity 2` | yes | yes, intensity 9 |
| `-O` | no | yes if root | yes if root |
| NSE | none extra | `default` | `default` — **never** `vuln` unless `--nmap-args` |
| Scan type | `-sS` if euid 0 else `-sT`; UDP `-sU` only if root | same | same |
| Workers | 2 | 4 | 8 |
| Inter-job delay | 1.0s | 0.2s | 0 |
| Ferox | off | small wordlist, no recurse, 20s timeout cap extra | larger wordlist, shallow recurse |
| Gowitness | off | homepage only | all discovered HTTP URLs |
| Searchsploit | leads only | leads only | leads only |

Always pass through `--nmap-args` as an append/override escape hatch after the profile args (documented: you can shoot yourself in the foot).

Privilege: detect `os.geteuid() == 0`. If not root and the profile wanted SYN/UDP/OS, log the fallback (connect-scan, no UDP, no OS) and continue. Never sudo itself.

---

## 6. Architecture

Standard src layout, installable, Kali-native binaries out of process.

```text
we_cstm_tools/
├── pyproject.toml              # only dep file; no requirements.txt
├── README.md
├── plan.ai                     # short pointer to this spec after rewrite
├── tests/
│   ├── fixtures/nmap/          # real-ish XML (one host, mixed ports)
│   └── ...
├── src/va_workspace/
│   ├── __init__.py             # __version__
│   ├── cli.py                  # Typer app only — thin
│   ├── constants.py
│   ├── models.py               # dataclasses: Host, Port, Service, Finding, Job, Engagement
│   ├── config/
│   │   ├── load.py
│   │   ├── profiles.py         # mode + intensity tables
│   │   └── tool_mappings.yaml  # shipped default; user override path
│   ├── templates/              # Jinja2, packaged as package data
│   │   ├── engagement.md.j2
│   │   ├── host.md.j2
│   │   ├── overview.md.j2
│   │   ├── dashboard.md.j2     # Dataview
│   │   ├── finding.md.j2
│   │   ├── report/*.md.j2      # CHECK skeleton
│   │   └── canvas.json.j2      # or a Python canvas builder
│   ├── core/
│   │   ├── nmap_runner.py
│   │   ├── nmap_parser.py
│   │   ├── vault.py
│   │   ├── orchestrator.py
│   │   ├── plugins.py          # YAML → jobs
│   │   ├── visualizer.py
│   │   ├── leads.py            # searchsploit
│   │   ├── findings.py
│   │   └── state.py            # checkpoint / resume
│   └── util/
│       ├── shell.py            # run_command, which, timeouts, no shell=True
│       ├── net.py              # CIDR, exclude, IPv4/IPv6 parse
│       ├── scope.py
│       └── log.py              # Rich + engagement log file
```

Shipped YAML and templates live **inside the package** (`package-data`). User override: `~/.config/va-workspace/tool_mappings.yaml` merged on top (additive + replace-by-id).

**Data flow**

```text
targets + profile + exclude
        │
        ▼
   nmap_runner  ──►  raw/nmap/*.xml,*.nmap,*.gnmap
        │
        ▼
   nmap_parser  ──►  models.Host[]
        │
        ▼
     vault.write hosts + overview
        │
        ▼
  orchestrator (resume-aware ThreadPoolExecutor)
        │   each job: plugin argv, timeout, cwd, stdout/stderr → host/services|info|loot
        ▼
   visualizer (chart + canvas + dataview)
        │
        ▼
   leads.searchsploit  ──►  04-leads/  (not findings)
        │
        ▼
   report stubs if missing (never overwrite filled-in report notes)
        │
        ▼
   state.json + logs/va.log
```

`cli.py` must stay a compositor. No Nmap XML parsing inside Typer callbacks.

---

## 7. Vault layout (Obsidian is the product)

```text
~/va-engagements/<client>-<YYYY-MM-DD>/
├── engagement.md                 # YAML frontmatter: client, mode, testers, dates, classification
├── scope.md                      # in-scope, out-of-scope, inferred from CLI if no init
├── rules-of-engagement.md        # intensity, exclusions, authorised window
├── 00-report/                    # CHECK ITHC skeleton — operator fills
│   ├── 01-cover-and-people.md
│   ├── 02-executive-summary.md
│   ├── 03-background-scope-context.md
│   ├── 04-methodology.md
│   ├── 05-findings-index.md      # Dataview of 03-findings
│   ├── 06-conclusions.md
│   └── 07-appendix-tooling.md    # auto: versions from doctor snapshot
├── 01-overview/
│   ├── dashboard.md              # Dataview: hosts, ports, services, findings
│   ├── network-overview.md       # static tables (so vault is useful even if Dataview breaks)
│   ├── network.canvas
│   └── attachments/services-bar.png
├── 02-hosts/
│   └── <ip>/
│       ├── host.md               # frontmatter for Dataview
│       ├── services/             # per-tool markdown + raw
│       ├── info/
│       ├── loot/
│       └── evidence/             # screenshots you drop; gowitness output linked here
├── 03-findings/
│   └── F-001-<slug>.md
├── 04-leads/                     # searchsploit + unverified tool hints
├── 05-raw/
│   ├── nmap/
│   └── tools/<tool>/<ip>/
├── 06-logs/
│   └── va.log
├── .obsidian/                    # minimal: app.json enabling core Canvas; Dataview is operator-installed
├── state.json
└── run-config.snapshot.yaml      # frozen mappings + profile for reproducibility
```

Host note frontmatter (Dataview): `ip`, `hostname`, `os`, `status`, `open_ports`, `services`, `tags`.

Finding frontmatter: `id`, `title`, `cvss_vector`, `cvss_score`, `severity`, `status` (`draft|confirmed|retest|closed`), `hosts`, `ports`, `evidence`, `short_term_fix`, `strategic_fix`, `created`.

**CHECK skeleton content** (aligned to [ITHC supporting guidance](https://www.gov.uk/government/publications/it-health-check-ithc-supporting-guidance/it-health-check-ithc-supporting-guidance)):

- Named individuals (tester, reviewer placeholder, client contact).
- Background, scope, context in full.
- Summary counts by severity (Dataview + a generated static table).
- CVSS 3.1 base scores (preferred by the guidance).
- Each finding: accurate description, evidence wikilinks, **short-term** and **strategic** remediation fields.
- Tooling appendix: `va` version, nmap version, secondary binary versions, profile, command lines (from the audit log).

Regeneration rule: host notes, overview tables, canvas, chart, appendix-tooling, findings-index **are generated** and may be overwritten. `00-report` narrative files and `03-findings/*` **are never overwritten** once the operator has edited them (detect via `state.json` `generated: true` still, or a `<!-- va:managed -->` header on generated files only).

Canvas: one Network node, one node per host, edges labelled with top services. JSON must match current Obsidian canvas schema (`nodes`, `edges`, `id`, `x`, `y`, `width`, `height`, `type: file` pointing at `02-hosts/<ip>/host.md`).

---

## 8. Tool plugin model (YAML)

v1 shipped mappings (thin, excellent, extensible):

| id | Match | Binary | Intensity gate | Notes |
|---|---|---|---|---|
| whatweb | tcp 80, 443, 8080, 8443 or service http/ssl/http | `whatweb` | stealth+ | |
| sslscan | 443, 8443 or `tunnel=ssl` | `sslscan` | stealth+ | |
| feroxbuster | http(s) | `feroxbuster` | standard+ | wordlist from profile; never follow off-scope hosts |
| gowitness | http(s) | `gowitness` | standard+ | Chromium-backed; skip + warn if missing |
| netexec-smb | 445, 139 | `netexec` | stealth+ | **unauth only**: `smb <host>` (null/guest). No `-u/-p`. No spider/pwn modules. |
| netexec-ldap | 389, 636 | `netexec` | standard+ | unauth ldap |
| netexec-winrm | 5985, 5986 | `netexec` | standard+ | unauth check only |
| onesixtyone | udp/tcp 161 | `onesixtyone` | standard+ | skip if community wordlist missing |
| snmpwalk | 161 after onesixtyone hit | `snmpwalk` | loud | only if a community was found; v1 still unauth |
| searchsploit | product+version on any port | `searchsploit` | stealth+ | **leads** via `leads.py`, not a port job |

Schema (illustrative):

```yaml
tools:
  - id: feroxbuster
    binary: feroxbuster
    match:
      ports: [80, 443, 8080, 8443]
      services: ["http", "https", "ssl/http"]
    min_intensity: standard
    timeout_seconds: 300
    output: services
    argv:
      stealth: []          # not run
      standard: ["-u", "{url}", "-w", "{wordlist}", "--depth", "1", "-n", "-q", "-o", "{outfile}"]
      loud: ["-u", "{url}", "-w", "{wordlist_loud}", "--depth", "2", "-q", "-o", "{outfile}"]
```

`{url}`, `{host}`, `{port}`, `{outfile}`, `{wordlist}` interpolated. No operator-supplied format string from untrusted XML without escaping.

Missing binary: Rich warning, mark job `skipped`, continue (original graceful-degradation rule).

Wordlists: default to Kali Seclists paths if present (`/usr/share/seclists/...`), else skip ferox/onesixtyone with an explicit doctor hint. Do not vendor giant wordlists in the pipx package.

---

## 9. Safety, scope, OpSec

- **No `shell=True`.** `subprocess.run` with a list, `timeout=`, captured stdout/stderr, `check=False`.
- **Scope filter:** every secondary URL/host must be in the target set minus `--exclude`. Ferox/Gowitness must not follow redirects off-scope.
- **Timeouts** on every binary. Default 300s secondary, Nmap timeout = profile-dependent but overridable.
- **Bounded executor** (table in §5). Per-host job cap.
- **Output caps:** truncate captured stdout written into Markdown (e.g. 512 KiB) and keep full raw under `05-raw/`.
- **Unauthenticated v1:** plugin argv templates must not accept `{user}`/`{password}`. Reject any user override YAML that adds them until v2.
- **Legal banner** once per engagement, recorded in `va.log`.
- **Classification field** on `engagement.md` (default `OFFICIAL` placeholder — operator edits). Do not invent government markings beyond a free-text field.
- **IPv6:** parse and pass through if the user supplies it; v1 does not auto-expand v4+v6 dual scans.

---

## 10. State, resume, audit

`state.json` (atomic replace via temp + rename):

- engagement path, mode, intensity, targets, excludes
- nmap: status (`pending|running|complete|failed`), output paths, pid, started/finished
- hosts[]: parsed identity
- jobs[]: `{id, tool, host, port, status, skip_reason, paths}`
- findings[]: ids
- `va_version`, `binary_versions` snapshot from doctor

Resume:

- Nmap complete → skip Nmap, re-parse XML (cheap).
- Job `complete` → skip.
- Job `running` at crash → mark `failed`, retry once, then skip with warning.
- `va scan --resume` with no TARGET uses state.targets.

Audit: every command line, profile, and tool argv (no secrets in v1) appended to `06-logs/va.log`. This feeds `07-appendix-tooling.md`.

---

## 11. Packaging and Kali install

**Runtime (Kali):**

```bash
sudo apt update
sudo apt install -y nmap whatweb sslscan feroxbuster gowitness onesixtyone snmp \
  exploitdb seclists python3-pip pipx
pipx install git+https://...   # or pipx install /path/to/we_cstm_tools
# NetExec is often pipx, not apt:
pipx install netexec           # if not already on the box
va doctor
```

`pyproject.toml`:

- `requires-python = ">=3.11"` (Kali rolling is 3.12+; 3.11 keeps a bit of headroom).
- deps: `typer`, `rich`, `jinja2`, `pyyaml`, `matplotlib`.
- optional extra `dev`: `pytest`, `ruff`, `mypy`.
- script: `va = va_workspace.cli:app`.
- package-data for templates + default YAML.

No `requirements.txt`. Pin reasonably in pyproject (`~=`), not hashes, so pipx on Kali stays solvable.

**Dev (Windows):** pytest + fixtures only. Skip tests marked `kali` / `requires_nmap`. `util.shell.which` and path handling via `pathlib` only — no `~/` string concat, no hardcoded `/usr`. Vault paths POSIX on Kali, `Path.home()` everywhere.

Do not import Unix-only modules at CLI load time without guards (`os.geteuid` exists on Unix; on Windows doctor/scan live-path is unsupported and should error clearly: "va scan is supported on Kali/Linux"). `va ingest` + parser + vault builder **must** run on Windows so you can develop the product here.

---

## 12. Testing strategy (Windows-first unit tests)

| Layer | How |
|---|---|
| nmap_parser | Fixture XML: mixed OS, http+smb+filtered ports, NSE output, two hosts |
| vault | tmp_path, assert files, frontmatter, wikilinks, no overwrite of findings |
| plugins | YAML load, intensity gating, interpolation, off-scope rejection |
| orchestrator | fake `run_command`, resume skips completed jobs |
| findings | CVSS vector parse (reject garbage), id allocation F-001 |
| cli | Typer `CliRunner`: `doctor`, `ingest`, `finding add`, `status` |
| live nmap | `@pytest.mark.kali` optional, not in default CI |

Target: parser + vault + plugins covered well enough that a Kali smoke (`va doctor && va ingest fixture.xml && va status`) is the only box-side verification for PR1–PR3.

---

## 13. Implementation PRs (mergeable increments)

Each PR is independently reviewable. Stop and confirm with you only if a PR changes a Key Decision.

### PR1 — Installable skeleton + `va doctor`

- `pyproject.toml`, `src/va_workspace`, empty Typer app, `util.shell`, logging.
- Ship `tool_mappings.yaml` schema + loader.
- `va doctor` checks binaries and prints apt/pipx hints.
- README: Kali install, authorised-use warning, CSTM/CHECK context (not a claim of NCSC endorsement).

### PR2 — Models + Nmap parser + `va ingest`

- Dataclasses.
- ElementTree parser from fixtures.
- `va ingest file.xml --out DIR` writes raw copy + parsed model dump (even before pretty notes).

### PR3 — Vault + templates + `va init`

- Full directory tree, Jinja2 host + overview + dashboard + CHECK stubs.
- `va init --client --mode --out`.
- `va ingest` now produces a real Obsidian vault (hosts, wikilinks, frontmatter).
- Regeneration rules.

### PR4 — Nmap runner + `va scan` (no secondary yet)

- Profile → nmap argv, root detection, `-oA` under `05-raw/nmap`.
- Scope/exclude.
- `state.json` for the Nmap phase + resume.
- Legal banner.

### PR5 — Orchestrator + secondary tools + resume

- Plugin jobs, bounded executor, graceful skip, output routing.
- Intensity gates for ferox/gowitness/netexec/snmp.
- `va status`.
- Snapshot `run-config.snapshot.yaml`.

### PR6 — Visuals + leads

- Matplotlib bar chart of services → `01-overview/attachments/`.
- Obsidian `.canvas`.
- `leads.py` (`searchsploit --json`) → `04-leads/`, linked from host notes as *unverified*.

### PR7 — Findings + CHECK index

- `va finding add` / `list`.
- Finding template with CVSS 3.1, dual remediation, evidence wikilinks.
- Findings-index Dataview + static summary counts in `00-report`.

### PR8 — Polish

- ruff/mypy/pytest on Windows.
- README cookbook: CHECK stealth scan, lab loud, ingest-only.
- Rewrite `plan.ai` to a 20-line pointer at the spec so future agents do not follow the old prompt.

---

## 14. Key decisions

1. **Obsidian vault is the product**; no PDF in v1.
2. **`va` CLI**, package `va_workspace`, pipx + Kali apt/pipx binaries.
3. **Two flags:** `--mode check|lab|internal` and `--intensity stealth|standard|loud`. CHECK defaults to stealth.
4. **Live Nmap primary**, XML ingest first-class enough to develop on Windows.
5. **Unauthenticated only in v1.**
6. **Operator-authored findings**; Searchsploit is leads.
7. **Full CHECK report skeleton** in `00-report/`, never auto-filled with guessed vulns.
8. **Safe-by-default intensity**, bounded concurrency, no NSE `vuln` unless `--nmap-args`.
9. **Thin YAML plugins** with the agreed v1 tool set (whatweb, sslscan, ferox, gowitness, netexec smb/ldap/winrm, onesixtyone/snmpwalk, searchsploit).
10. **Checkpoint/resume** via `state.json`.
11. **Dataview + Canvas allowed**, plus static overviews so the vault is not plugin-hostage.
12. **Default vault root** `~/va-engagements/<client>-<date>/`.
13. **SYN if root, else connect**; UDP/OS detect require root.
14. **`va init` optional**; CIDR on the CLI is enough; CHECK mode warns if metadata is thin.
15. **Develop on Windows, run on Kali**; parser/vault/ingest must work without Nmap.
16. **Stdlib ElementTree**, no python-libnmap.
17. **Matplotlib only** (drop Seaborn).
18. **Never overwrite** operator report/finding notes.

---

## 15. What happens after you approve

1. Rewrite `plan.ai` to reference this spec (stop using it as a codegen prompt).
2. Implement PR1 in this repo, commit and push to the current branch.
3. Continue PR2–PR8 in order unless you pause.

No further product questions are blocking. Minor defaults above (worker counts, top-ports, wordlist paths, CVSS parser strictness) can be tuned when you use it on Kali.
