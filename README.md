# Epic OSINT Toolkit

A comprehensive Open Source Intelligence toolkit with a classic CLI **and** a full-terminal ASCII/ANSI TUI. Built for security researchers, bug bounty hunters, and penetration testers.

## What Makes This Epic?

Inspired by and combining ideas from:
- **Scilla** — DNS / subdomain enumeration  
- **OSGINT** — GitHub intelligence  
- **creepyCrawler** — deep web crawl + extraction  
- **urlhunter** — shortened / exposed URL hunting  
- **TorBot** — dark-web .onion analysis  
- **EmploLeaks** — employees + breach checks  
- **Emora / Profil3r / Sherlock-class** — username matrix  
- Plus: Wayback CDX, BGPView ASN, cloud buckets, takeover fingerprints, favicon/Shodan pivots, EXIF, dork packs, SaaS tenants, typosquats, package registries, company filings, person pivots, **Web3 multi-chain OSINT**

All in one toolkit with **auto target detection**, **entity correlation**, styled reports, and a keyboard-driven split-pane TUI.

---

## Features

### Core workflow
| Feature | Details |
|---------|---------|
| **Auto-detect** | Domain, IP, email, phone, username, URL, onion, company, person, wallet |
| **Full / Auto scan** | Multi-module suites per target type |
| **Correlation** | Cross-link emails, domains, IPs, usernames, URLs, phones, wallets |
| **Cases** | Investigation folders; attach scans |
| **Graph export** | JSON + GraphML entity graphs |
| **Plugins** | Drop-in `modules/plugins/*.py` |
| **Batch mode** | Multi-target file (`--batch`) |
| **Reports** | JSON / TXT / HTML / Markdown; TUI view + delete |
| **Polite probing** | Soft rate-limit + rotating User-Agents |

### Interactive TUI
- Split layout: **module menu left**, feature pane right (wide terminals)
- Large **EPIC OSINT TOOLKIT** logo when idle
- Per-module beginner help blurbs
- Styled intel reports (not raw JSON dumps)
- Settings for format, Tor, crawl defaults, rate limits, API keys
- Reports tab: browse / open / delete saved scans

**TUI modules:** Auto · Full · Domain · IP · ASN · Related Domains · Typosquats · SaaS Tenants · Company Biz · Person · Packages · Passive DNS · Abuse · IOC · Crypto/Web3 · Social · Perms · GitHub · Crawl · JS Secrets · Screenshot · Emails · Email Accounts · URLs · Wayback · Pastes · Dorks · Buckets · Takeover · Favicon · EXIF/Meta · Image Pivots · Phone · Ports · Shodan/Censys · Employees · Dark Web · Onion Search · Tor Health · Graph · Cases · Plugins · Reports · Settings

### Domain & DNS
- DNS: A, AAAA, MX, NS, TXT, CNAME, SOA, PTR
- Email auth: SPF, DMARC, DKIM selectors
- DNSSEC: DNSKEY / DS / RRSIG
- Subdomains: brute-force, crt.sh, HackerTarget
- WHOIS + SSL certificate analysis
- Related domains: CT SANs, live SSL SANs, same-IP neighbors
- Typosquat / lookalike generation + live DNS resolve
- Passive DNS historical host/IP pivots
- Abuse / DNSBL reputation lists

### IP / ASN / host surface
- Geo, ISP/org, reverse DNS, proxy/hosting risk (ip-api + BGPView)
- ASN netblocks, peers, upstreams
- Port scan + banners (+ optional nmap)
- Optional **Shodan** / **Censys** (API keys)
- IOC enrich: VirusTotal / AlienVault OTX (+ public pivots)

### Cloud, SaaS & supply chain
- Cloud buckets: S3, GCS, Azure Blob, DigitalOcean Spaces
- Subdomain takeover: dangling DNS + service fingerprints
- SaaS / tenant discovery: Azure AD, Google Workspace, Slack, Okta, Atlassian, Salesforce, GitHub/GitLab org, Notion, Zendesk, HubSpot, Webex
- Package registries: npm, PyPI, crates.io, RubyGems, Docker Hub

### Web crawl & URL surface
- creepyCrawler-style crawl, robots/sitemap, dirs, tech detect
- Extracts emails, phones, social, cloud links, files, comments, tags
- URL hunter (shorteners) + Wayback Machine CDX
- URLTeam archive search (optional)
- JS / page secret & API-path mining
- Headless Chrome/Chromium screenshots (when installed)
- Favicon mmh3 → Shodan `http.favicon.hash` pivot
- Search-engine **dork packs** (Google / DuckDuckGo / Bing)
- Paste / GitHub code leak hunt

### People, email & social
- **100+** platform username matrix (soft-404 aware)
- Username / name / email local-part permutations
- GitHub profile, orgs, emails, repos
- Email discover / MX + SMTP RCPT verify / sources
- Holehe-style email → account registration checks
- Person OSINT: full-name parse, username/email seeds, GitHub user hits, people-search pivots
- Employees (GitHub / GitLab / website) + HIBP leak checks
- Company business intel: OpenCorporates, SEC EDGAR tickers, registry pivots
- Phone: E.164 normalize, country hints, leak-style pivots

### Media & documents
- EXIF / metadata: JPEG (+ GPS) and light PDF Info (URL or local file)
- Reverse-image search pivot URLs (Google Lens, Yandex, TinEye, Bing, …)

### Dark web
- .onion analyze / crawl (Tor optional)
- Ahmia onion directory search
- Tor SOCKS health check (`127.0.0.1:9050`)

### Web3 / cryptocurrency

Select **what to query** so you are not sweeping every chain every time:

| Selection | Meaning |
|-----------|---------|
| `auto` (default) | Detected chain only — e.g. ETH mainnet for `0x…`, no L2 sweep |
| `evm` | **One bucket** — all Ethereum-compatible L1/L2s for the same `0x` address |
| Independent | `bitcoin`, `solana`, `near`, `starknet`, `monero`, … (comma-separated) |
| `all` | Everything applicable to the address type |

**EVM bucket members:** Ethereum, BSC, Polygon, Avalanche, Base, Arbitrum, Optimism, zkSync, Blast, Metis, Taiko, Boba, Immutable, Astar, Polygon zkEVM  

**Independent groups:** Bitcoin, Solana, TRON, XRP, Cardano, Dogecoin, Litecoin, Dash, Monero, Zcash, NEAR, Starknet, Polkadot, Filecoin, Stacks, Arweave, Celestia, Nervos, Oasis  

**Notes:**
- ERC-20 / DeFi tokens (UNI, AAVE, …) show under Ethplorer holdings when using Ethereum/`evm`
- Privacy coins: Monero is pivot-only; Zcash `t-addr` is traceable, shielded is not
- Refuses private-key / WIF shaped input
- List groups: `--crypto-chains` · TUI: Web3 menu toggles Auto / EVM / each independent chain

### Optional API keys
GitHub · Shodan · Censys · HIBP · VirusTotal · OTX · Etherscan

---

## Quick start

```bash
# Linux/Mac
./setup.sh && source venv/bin/activate

# Interactive TUI (recommended)
python osint_toolkit.py

# Auto-detect + full scan
python osint_toolkit.py -t example.com --auto
```

---

## Installation

**Prerequisites:** Python 3.10+, pip

Dependencies are **pin-locked with hashes** in `requirements.txt` (generated from `requirements.in`). Setup scripts install that lockfile with `--require-hashes` so you get the same artifacts the maintainers audited — not “latest matching the range”.

```bash
cd Epic-OSINT-Toolkit
python -m pip install --require-hashes -r requirements.txt
# or
./setup.sh && source venv/bin/activate   # Linux/Mac
# Windows: .\setup.ps1 then .\venv\Scripts\Activate.ps1
```

Regenerate the lockfile and CycloneDX SBOM after changing `requirements.in`:

```bash
./scripts/lock-deps.sh
```

Weekly Dependabot PRs update the lockfile. CI runs `pip-audit` on every PR and publishes a CycloneDX SBOM artifact. A committed SBOM lives at `sbom/cyclonedx.json`.

Optional: Tor on `127.0.0.1:9050` for dark-web mode. API keys are optional (see above).

---

## Usage

### Interactive TUI

```bash
python osint_toolkit.py
python osint_toolkit.py --tui
```

| Key | Action |
|-----|--------|
| ↑ / ↓ (or j/k) | Navigate menu |
| Enter / Space | Open module |
| Space (options) | Toggle flags |
| Esc / q | Back / quit (home) |
| d / D (Reports) | Delete one / delete all |

Wide terminal (≥100×22): left **MODULES** list, right content pane (logo when idle). Narrow terminals use a stacked full-screen layout.

### Classic CLI examples

```bash
# Full / auto
python osint_toolkit.py -t example.com --full
python osint_toolkit.py -t example.com --auto

# Domain stack
python osint_toolkit.py -t example.com --dns --subdomains --emails --ports
python osint_toolkit.py -t example.com --dorks --buckets --takeover --favicon
python osint_toolkit.py -t example.com --related --passive-dns --js-secrets --abuse
python osint_toolkit.py -t example.com --saas --typosquat --packages

# People / company / email
python osint_toolkit.py -t johndoe --type username --social --github --perms
python osint_toolkit.py -t user@example.com --email-accounts --perms
python osint_toolkit.py -t "Acme Corp" --type company --employees --leaks --company-biz
python osint_toolkit.py -t "Jane Doe" --type person --person --perms
python osint_toolkit.py -t "+15551234567" --phone

# IP / IOC / host APIs
python osint_toolkit.py -t 8.8.8.8 --ip --asn --ioc --vt-key YOUR_KEY
python osint_toolkit.py -t 1.2.3.4 --shodan --shodan-key YOUR_KEY

# Media / screenshots / graph
python osint_toolkit.py -t https://example.com/photo.jpg --meta --image-pivots
python osint_toolkit.py -t example.com --screenshot --graph --format md

# Web3 / crypto
python osint_toolkit.py --crypto-chains
python osint_toolkit.py -t 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 --crypto --chains auto
python osint_toolkit.py -t 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 --crypto --chains evm
python osint_toolkit.py -t vitalik.eth --crypto --chains evm --etherscan-key YOUR_KEY
python osint_toolkit.py -t root.near --crypto --chains near
python osint_toolkit.py -t bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq --crypto --chains bitcoin --pastes --dorks

# Dark web
python osint_toolkit.py -t "example.onion" --type onion --dark-web --tor --onion-search
python osint_toolkit.py --tor-check --tor

# Cases / batch / plugins
python osint_toolkit.py --case-create "Op Alpha"
python osint_toolkit.py -t example.com --auto --case CASE_ID
python osint_toolkit.py --batch targets.txt --format json
python osint_toolkit.py --list-plugins
python osint_toolkit.py -t example.com --plugin example_echo
```

### Command-line options (summary)

```
-t / --target TARGET
--tui
--type {domain,username,ip,url,company,person,onion,phone,email,wallet,auto}
--full · --auto

Modules:
  --dns --subdomains --whois --ssl
  --social --github --crawl --directories --emails
  --urls --urlteam --wayback --pastes
  --ip --asn --phone --ports
  --dorks --buckets --takeover --favicon --meta
  --email-accounts --perms --related --js-secrets
  --image-pivots --passive-dns --abuse --ioc --crypto --crypto-chains --screenshot
  --company-biz --saas --typosquat --packages --person
  --graph --plugin --list-plugins --tor-check
  --employees --leaks
  --comprehensive-crawl --robots --sitemap
  --dark-web --onion-search --tor
  --shodan --censys --correlate
  --case --case-create --case-list --batch

Keys / options:
  --chains {auto,all,evm,bitcoin,solana,…}   # comma-separated crypto groups
  --github-token --shodan-key --censys-id --censys-secret --hibp-api-key
  --vt-key --otx-key --etherscan-key --rate-limit
  --keywords-file --urlteam-date --max-pages --ports-range --depth
  -o/--output -f/--format {json,txt,html,md} --quiet
```

Run `python osint_toolkit.py --help` for the full list.

---

## Module map

| Module file | Capability |
|-------------|------------|
| `domain_intel.py` | DNS, CT subs, WHOIS, SSL, SPF/DMARC/DKIM, DNSSEC |
| `ip_intel.py` | Geo / risk / rDNS |
| `asn_intel.py` | ASN prefixes / peers / upstreams |
| `related_domains.py` | CT / SSL / same-IP |
| `typosquat_intel.py` | Lookalike domains + DNS resolve |
| `saas_intel.py` | Azure AD / Workspace / Slack / Okta tenants |
| `company_intel.py` | OpenCorporates / SEC EDGAR / business pivots |
| `person_intel.py` | Full-name seeds + people-search pivots |
| `package_intel.py` | npm / PyPI / crates / RubyGems / Docker Hub |
| `passive_dns.py` | Passive DNS |
| `abuse_intel.py` | DNSBL reputation |
| `ioc_intel.py` | VT / OTX enrichment |
| `crypto_intel.py` | Web3: selectable `evm` + independent chains, ENS, privacy OSINT |
| `social_intel.py` | 100+ username matrix |
| `username_perm.py` | Name / email permutations |
| `github_intel.py` | Profile, repos, emails |
| `web_crawler.py` | Crawl / extract / tech |
| `js_secrets.py` | JS / page secret mining |
| `screenshot_intel.py` | Headless Chrome capture |
| `email_intel.py` | Discover / verify / sources |
| `email_accounts.py` | Holehe-style account checks |
| `url_hunter.py` | Shorteners + Wayback fallback |
| `wayback_intel.py` | Archive.org CDX |
| `paste_intel.py` | GitHub code + paste dorks |
| `dork_intel.py` | Search-engine dork packs |
| `bucket_intel.py` | Cloud bucket probes |
| `takeover_intel.py` | Takeover fingerprints |
| `favicon_intel.py` | Favicon mmh3 / Shodan pivot |
| `meta_intel.py` | EXIF / metadata |
| `image_pivot.py` | Reverse-image search URLs |
| `phone_intel.py` | Phone OSINT |
| `port_scanner.py` | Ports / banners |
| `host_intel.py` | Shodan / Censys |
| `employee_intel.py` | Staff discovery / HIBP |
| `dark_web_intel.py` | Onion + Ahmia + Tor health |
| `cases.py` / `graph_export.py` | Cases + GraphML |
| `plugins_loader.py` | Drop-in plugins |
| `correlate.py` | Auto-detect + entity graph |
| `report_generator.py` | TXT / HTML / Markdown / summary + findings ledger |
| `result_quality.py` | Confidence scoring, provenance stamping, soft-404 |
| `tui.py` / `tui_style.py` | Split-pane ASCII UI + styled reports |
| `http_util.py` / `net_util.py` | Rate-limit, UA rotation, SSRF-safe hosts |

---

## Output

Reports are written under `reports/` (or `-o`) as JSON, TXT, HTML, or Markdown. Cases live under `cases/`. The TUI formats the same JSON into a readable intel report and can delete old `osint_*` files from the Reports tab.

Every scan attaches a **findings ledger**: finding, source, timestamp, method, confidence, evidence, and false-positive notes. Treat hits as scored claims, not proof — especially across social, buckets, takeover, SaaS, packages, and employee modules.

---

## Result quality

OSINT coverage here is broad (DNS, social, crawl, dark web, employees, breaches, buckets, takeover, Shodan, EXIF, Web3, packages, filings, correlation). Breadth is not certainty.

| Field | Meaning |
|-------|---------|
| **Finding** | The claim (URL, host, email, package, …) |
| **Source** | Where the signal came from |
| **Timestamp** | When this scan recorded it (UTC) |
| **Method** | How it was obtained |
| **Confidence** | `confirmed` > `high` > `medium` > `low` > `unknown` |
| **Evidence** | Status codes, fingerprints, match reasons |
| **False-positive notes** | Why this class of hit is often wrong |

Reports hide below-medium claims by default; they remain in JSON `findings[]`. Corroborate with a second independent source before acting.

---

## Legal / ethics

Use only on targets you are authorized to investigate. Respect laws, ToS, and rate limits. Optional APIs (Shodan, Censys, HIBP, GitHub, VirusTotal, OTX, Etherscan) require your own keys.

---

## License

[MIT](LICENSE). Copyright © 2026 [Vassbrekke AS](https://www.vassbrekke.no).

Source: https://github.com/Vassbrekke/Epic-OSINT-Toolkit

You may use, copy, modify, and distribute this software freely, including commercially, as long as you keep the copyright notice and license text. No warranty is provided; use responsibly and only on targets you are authorized to investigate.
