# Quick Start Guide

## Installation (Windows)

1. Open PowerShell in the project directory  
2. Run:
```powershell
.\setup.ps1
.\venv\Scripts\Activate.ps1
```

## Installation (Linux/Mac)

```bash
chmod +x setup.sh
./setup.sh
source venv/bin/activate
```

`setup.sh` creates the venv, installs the **hashed lockfile** (`pip install --require-hashes -r requirements.txt`), and prints TUI-first usage tips.

---

## Interactive TUI (recommended)

```bash
python osint_toolkit.py
# or
python osint_toolkit.py --tui
```

**Layout (wide terminal):** modules on the **left**, feature pane on the **right** (big logo when idle).

| Key | Action |
|-----|--------|
| ↑↓ / j k | Navigate |
| Enter | Open module |
| Space | Toggle options |
| Esc / q | Back / quit |
| d / D | Delete report / delete all (Reports) |

### Full module list (TUI)

| Group | Modules |
|-------|---------|
| Workflow | Auto Scan · Full Scan · Graph · Cases · Plugins · Reports · Settings |
| Domain / DNS | Domain Intel · Related Domains · Typosquats · Passive DNS · Abuse / DNSBL |
| Cloud / SaaS | SaaS Tenants · Cloud Buckets · Takeover · Packages |
| Host / IP | IP Intel · ASN / Netblocks · Ports · Shodan/Censys · IOC Enrich |
| Web | Crawl · JS Secrets · Screenshot · URLs · Wayback · Pastes · Dorks · Favicon |
| People | Social · Perms · GitHub · Emails · Email Accounts · Person · Employees · Company Biz · Phone |
| Media | EXIF / Meta · Image Pivots |
| Crypto | Web3 / Crypto |
| Dark web | Dark Web · Onion Search · Tor Health |

---

## Feature checklist

Everything the toolkit can do today:

- [x] Auto-detect target type (domain, IP, email, phone, username, URL, onion, company, person, wallet)
- [x] Full multi-module scans + entity correlation
- [x] DNS / WHOIS / SSL / SPF·DMARC·DKIM / DNSSEC / subdomains
- [x] Related domains, typosquats, passive DNS, DNSBL abuse
- [x] IP geo/risk, ASN netblocks, ports/banners, Shodan/Censys, VT/OTX IOC
- [x] SaaS tenants, cloud buckets, subdomain takeover, package registries
- [x] Web crawl, JS secrets, screenshots, URL hunter, Wayback, pastes, dorks, favicon hash
- [x] Social username matrix (100+), perms, GitHub, email discover/verify, Holehe-style accounts
- [x] Person OSINT, employees + HIBP, company registries / EDGAR
- [x] Phone E.164 pivots; EXIF/PDF meta; reverse-image pivots
- [x] Web3 multi-chain (EVM bucket + independent chains), ENS, privacy-coin pivots
- [x] Dark web .onion + Ahmia + Tor health
- [x] Cases, GraphML/JSON graphs, plugins, batch mode, JSON/TXT/HTML/MD reports

---

## CLI examples

### Auto / full
```bash
python osint_toolkit.py -t example.com --auto
python osint_toolkit.py -t example.com --full
python osint_toolkit.py -t 8.8.8.8 --type ip --full
python osint_toolkit.py -t "Jane Doe" --type person --full
```

### Domain & infra
```bash
python osint_toolkit.py -t example.com --dns --subdomains --emails --ports
python osint_toolkit.py -t example.com --wayback --pastes --ip --asn
python osint_toolkit.py -t example.com --dorks --buckets --takeover --favicon
python osint_toolkit.py -t example.com --related --passive-dns --js-secrets --abuse
python osint_toolkit.py -t example.com --saas --typosquat --packages
```

### People & company
```bash
python osint_toolkit.py -t johndoe --type username --social --github --perms
python osint_toolkit.py -t user@example.com --email-accounts
python osint_toolkit.py -t "Acme Corp" --type company --employees --leaks --company-biz
python osint_toolkit.py -t "Jane Doe" --type person --person --perms
python osint_toolkit.py -t "+15551234567" --phone
```

### Web3 / crypto

List selectable groups (`evm` = all Ethereum L1/L2 as **one** choice):

```bash
python osint_toolkit.py --crypto-chains
```

| Flag | Effect |
|------|--------|
| `--chains auto` | Detected chain only (default; fast) |
| `--chains evm` | Sweep ETH + Arb/OP/zkSync/Blast/… for a `0x` address |
| `--chains bitcoin,near` | Independent groups only |
| `--chains all` | Everything applicable |

```bash
python osint_toolkit.py -t 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 --crypto --chains auto
python osint_toolkit.py -t 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 --crypto --chains evm
python osint_toolkit.py -t vitalik.eth --crypto --chains evm --etherscan-key YOUR_KEY
python osint_toolkit.py -t root.near --crypto --chains near
python osint_toolkit.py -t bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq --crypto --chains bitcoin --dorks --pastes
```

In the TUI, open **Web3 / Crypto**, toggle **Auto** / **EVM** / independent chains, then enter the address.

### Meta / dark web / extras
```bash
python osint_toolkit.py -t https://example.com/img.jpg --meta --image-pivots
python osint_toolkit.py -t "example.onion" --type onion --dark-web --tor --onion-search
python osint_toolkit.py --tor-check --tor
python osint_toolkit.py -t example.com --screenshot --graph --format md
```

### Cases, batch, plugins
```bash
python osint_toolkit.py --case-create "Op Alpha"
python osint_toolkit.py -t example.com --auto --case CASE_ID
python osint_toolkit.py --batch targets.txt
python osint_toolkit.py --list-plugins
python osint_toolkit.py -t example.com --plugin example_echo
```

### Optional API keys
```bash
python osint_toolkit.py -t 1.2.3.4 --shodan --shodan-key YOUR_KEY
python osint_toolkit.py -t example.com --pastes --github-token YOUR_TOKEN
python osint_toolkit.py -t "Acme" --type company --leaks --hibp-api-key YOUR_KEY
python osint_toolkit.py -t 8.8.8.8 --ioc --vt-key YOUR_KEY --otx-key YOUR_KEY
python osint_toolkit.py -t vitalik.eth --crypto --etherscan-key YOUR_KEY
```

---

## Output

Saved under `reports/` as JSON, TXT, HTML, or Markdown (`-f`). Cases live under `cases/`. Open or delete reports from the TUI **Reports** tab.

Every report includes a **findings ledger** (finding, source, timestamp, method, confidence, evidence, false-positive notes). Hits are scored claims, not proof.

## Help

```bash
python osint_toolkit.py --help
python osint_toolkit.py --help | less   # long flag list
```

See [README.md](README.md) for the full feature catalog and module map.
