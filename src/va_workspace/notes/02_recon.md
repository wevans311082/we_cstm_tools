# Task Stack: Reconnaissance and Intelligence Gathering

> Outcome: Exhaustive intelligence dossier to inform threat modelling, aligning with OSINT and passive recon best practices.

## Task Group 1: Domain Intelligence
- [ ] Pull WHOIS records and registrar history:
  - `whois example.com | tee evidence/recon/whois_example.com.txt`
  - `curl -s https://rdap.verisign.com/com/v1/domain/example.com -o evidence/recon/rdap_example.com.json`
- [ ] Enumerate DNS records:
  - `dig example.com ANY +noall +answer`
  - `dig example.com AXFR @ns1.example.com` (log refusal codes)
- [ ] Query Certificate Transparency logs:
  - `curl 'https://crt.sh/?q=%25example.com&output=json' | jq '.' > evidence/recon/ct_example.com.json`

## Task Group 2: Passive Footprinting
- [ ] Run `theHarvester` across multiple data sources:
  - `theHarvester -d example.com -b bing,linkedin,crtsh -f evidence/recon/theharvester_example.html`
- [ ] Execute `recon-ng` workspace automation:
  - `recon-ng -w example -r scripts/recon_init.rc`
- [ ] Pull leaks with `holehe` and `maigret` for credential exposure.

### Automation Snippet
```bash
cat <<'RC' > scripts/recon_init.rc
workspaces create example
modules load recon/domains-hosts/censys
set SOURCE example.com
run
modules load recon/domains-hosts/zoomeye
set SOURCE example.com
run
RC
recon-ng -r scripts/recon_init.rc
```

## Task Group 3: Infrastructure Mapping
- [ ] Query Shodan/Censys/BinaryEdge APIs:
  - `shodan download example_shodan "hostname:example.com" && shodan parse example_shodan.json.gz`
  - `censys hosts search 'services.tls.certificates.leaf_data.subject.common_name: example.com' --output evidence/recon/censys_example.json`
- [ ] Correlate hosting providers and cloud assets via `dnstwist --format csv` and ASN lookups (`whois -h whois.radb.net -- '-i origin AS12345'`).

## Task Group 4: Employee and Supply Chain Intelligence
- [ ] Run LinkedIn scraping (respecting TOS) via `sherlock` or `linkedin2username` to identify naming conventions.
- [ ] Identify third-party suppliers from procurement data; annotate risk in `supply_chain.md`.
- [ ] Map email patterns and DMARC alignment: `opendmarc-check example.com`.

## Task Group 5: Dark Web and Credential Leak Review
- [ ] Query `haveibeenpwned` API for domain exposures: `hibp-domain-search example.com --api-key <key>`.
- [ ] Use `ghunt` to inspect Google Workspace footprint (drive/sheets/meet links).
- [ ] Collate breach dumps securely; hash sets using `hashcat --benchmark --potfile-path evidence/recon/hash_benchmark.pot` to measure feasibility.

## Task Group 6: Threat Modelling Inputs
- [ ] Populate attack surface register `attack_surface.csv` with columns `asset,port,technology,exposure,notes`.
- [ ] Map discovered tech stacks to MITRE ATT&CK techniques; store mapping in `mitre_alignment.md`.
- [ ] Trigger intelligence review meeting; log decisions referencing `12_Flowcharts_and_Decision_Trees.md` for prioritisation.
