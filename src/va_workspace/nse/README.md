# Custom NSE (Lua)

These are **va-workspace's own** Nmap scripts, not copies of `/usr/share/nmap/scripts/*.nse`.

Nmap still executes them (they are Lua). We keep them here so CHECK ITHC checks are:

- **focused** — one posture script per surface, not a dozen generic scripts
- **structured** — `stdnse.output_table()` keys that `va` turns into leads
- **safe-by-default** — unauthenticated, no brute/DoS

`va scan` passes this directory into `nmap --script <absolute-paths>`.

On Kali, `va nse list` and `va nse path` show what will run.

Stock Nmap scripts remain available via `nse_packs.yaml` for standard/loud. Stealth prefers these custom scripts.

`va` parses NSE XML tables (`script.data`) plus the text `output=` so lead rules match keys such as `cors: wildcard` and `unauth: yes`. Results are summarised in `01-overview/nse-results.md` and promoted from `04-leads/`.
