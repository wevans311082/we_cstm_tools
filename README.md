# va-workspace

Kali operator toolkit that turns **Nmap reconnaissance** into a **CHECK-shaped Obsidian vault**.

CLI: `va`. Package: `va_workspace`.

You passed the UK Cyber Scheme Team Member (CSTM) exam. This is a daily driver for lab, internal, and CHECK ITHC work. It is **not** an NCSC-endorsed product, **not** a CHECK company report factory, and **not** a substitute for a Team Leader's judgement.

**Authorised use only.** You own scope, Rules of Engagement, and the law.

Full product spec: [`SPEC.md`](SPEC.md).

## Install (Kali)

```bash
sudo apt update
sudo apt install -y nmap whatweb sslscan feroxbuster gowitness onesixtyone snmp \
  exploitdb seclists python3-pip pipx
pipx ensurepath
pipx install netexec          # if not already present
pipx install .
va doctor
```

From git:

```bash
pipx install git+https://github.com/wevans311082/we_cstm_tools.git
```

Obsidian: enable **Canvas** (core). Install the **Dataview** community plugin for dashboards. Static tables still render without Dataview.

## Workflow

```text
va doctor
va init --client acme --mode check --tester "Your Name"
cd ~/va-engagements/acme-YYYY-MM-DD
va scan 10.10.0.0/24 --mode check --intensity stealth
# VPN drop / laptop sleep
va scan --resume
va finding add --template smb-signing --hosts 10.10.0.5
va finding templates
va note "Confirmed SMB signing off on DC01"
va compare ../acme-2025-engagement
va status
```

Ingest an existing Nmap XML (works on Windows for development):

```text
va ingest path/to/scan.xml --client acme --mode lab --out ./vault
```

### Flags

| Flag | Meaning |
| --- | --- |
| `--mode check\|lab\|internal` | Policy and templates. `check` defaults intensity to `stealth` and warns if metadata is thin. |
| `--intensity stealth\|standard\|loud` | Nmap shape, which YAML tools fire, concurrency. |
| `--nmap-args "..."` | Escape hatch appended to the profiled Nmap command. Can disable safety; you own it. |
| `--enum` on ingest | Also run secondary tools (Linux). |
| `--pn` on scan | Skip host discovery (`-Pn`). |
| `--template` on `finding add` | Fill CVSS, description, dual remediation from the library. |

Unauthenticated only. Findings are **operator-authored**. NSE and Searchsploit write **leads**. Nmap uses named script packs (stealth/standard/loud), not `--script vuln`.

## Develop (Windows)

```powershell
uv sync --extra dev
uv run pytest
uv run va doctor
uv run va ingest tests/fixtures/nmap/mixed-lab.xml --out $env:TEMP\va-demo --client demo
```

Live `va scan` requires Kali/Linux.

## Custom NSE (Lua)

The Lua files are in the package: `src/va_workspace/nse/va-*.nse`. They are **ours**, not copies of `/usr/share/nmap/scripts`.

```text
va nse path
va nse list --mode check --intensity stealth
```

`va scan` passes those absolute paths to `nmap --script` together with the stock pack for the intensity. Stock Nmap Lua still lives on Kali under `/usr/share/nmap/scripts/`.

## Layout

See `SPEC.md` §7. Default vault root: `~/va-engagements/<client>-<date>/`.
