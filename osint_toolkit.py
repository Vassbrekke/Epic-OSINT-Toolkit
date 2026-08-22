#!/usr/bin/env python3
"""
Epic OSINT Toolkit - Comprehensive Open Source Intelligence Gathering Tool
A powerful CLI-based OSINT tool combining multiple intelligence gathering techniques
"""

import argparse
import sys
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from modules.domain_intel import DomainIntel
from modules.social_intel import SocialIntel
from modules.github_intel import GitHubIntel
from modules.web_crawler import WebCrawler
from modules.email_intel import EmailIntel
from modules.url_hunter import URLHunter
from modules.port_scanner import PortScanner
from modules.employee_intel import EmployeeIntel
from modules.dark_web_intel import DarkWebIntel
from modules.report_generator import ReportGenerator
from modules.ip_intel import IPIntel
from modules.wayback_intel import WaybackIntel
from modules.phone_intel import PhoneIntel
from modules.paste_intel import PasteIntel
from modules.host_intel import HostIntel
from modules.correlate import Correlator, detect_target_type
from modules.dork_intel import DorkIntel
from modules.asn_intel import ASNIntel
from modules.bucket_intel import BucketIntel
from modules.takeover_intel import TakeoverIntel
from modules.favicon_intel import FaviconIntel
from modules.meta_intel import MetaIntel
from modules.email_accounts import EmailAccountsIntel
from modules.username_perm import UsernamePermIntel
from modules.related_domains import RelatedDomainsIntel
from modules.cases import CaseManager
from modules.graph_export import GraphExport
from modules.js_secrets import JSSecretsIntel
from modules.image_pivot import ImagePivotIntel
from modules.passive_dns import PassiveDNSIntel
from modules.abuse_intel import AbuseIntel
from modules.ioc_intel import IOCIntel
from modules.screenshot_intel import ScreenshotIntel
from modules.crypto_intel import CryptoIntel
from modules.company_intel import CompanyIntel
from modules.saas_intel import SaaSIntel
from modules.typosquat_intel import TyposquatIntel
from modules.package_intel import PackageIntel
from modules.person_intel import PersonIntel
from modules.plugins_loader import PluginLoader
from modules.http_util import set_rate_limit
from modules.result_quality import annotate_results


class OSINTToolkit:
    """Main OSINT Toolkit class"""
    
    def __init__(self, output_dir: str = "reports", github_token: Optional[str] = None,
                 shodan_key: Optional[str] = None, censys_id: Optional[str] = None,
                 censys_secret: Optional[str] = None, vt_key: Optional[str] = None,
                 otx_key: Optional[str] = None, etherscan_key: Optional[str] = None,
                 rate_limit: float = 0.0):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.results = {}
        self.github_token = github_token
        if rate_limit and rate_limit > 0:
            set_rate_limit(rate_limit)
        
        # Initialize modules
        self.domain_intel = DomainIntel()
        self.social_intel = SocialIntel()
        self.github_intel = GitHubIntel()
        self.web_crawler = WebCrawler()
        self.email_intel = EmailIntel(github_token=github_token)
        self.url_hunter = URLHunter()
        self.port_scanner = PortScanner()
        self.employee_intel = EmployeeIntel()
        self.dark_web_intel = DarkWebIntel(use_tor=False)  # Tor disabled by default
        self.ip_intel = IPIntel()
        self.wayback_intel = WaybackIntel()
        self.phone_intel = PhoneIntel()
        self.paste_intel = PasteIntel(github_token=github_token)
        self.host_intel = HostIntel(shodan_key=shodan_key, censys_id=censys_id, censys_secret=censys_secret)
        self.dork_intel = DorkIntel()
        self.asn_intel = ASNIntel()
        self.bucket_intel = BucketIntel()
        self.takeover_intel = TakeoverIntel()
        self.favicon_intel = FaviconIntel()
        self.meta_intel = MetaIntel()
        self.email_accounts = EmailAccountsIntel()
        self.username_perm = UsernamePermIntel()
        self.related_domains = RelatedDomainsIntel()
        self.cases = CaseManager()
        self.graph_export = GraphExport()
        self.js_secrets = JSSecretsIntel()
        self.image_pivot = ImagePivotIntel()
        self.passive_dns = PassiveDNSIntel()
        self.abuse_intel = AbuseIntel()
        self.ioc_intel = IOCIntel(vt_key=vt_key, otx_key=otx_key)
        self.screenshot_intel = ScreenshotIntel()
        self.crypto_intel = CryptoIntel(etherscan_key=etherscan_key)
        self.company_biz = CompanyIntel()
        self.saas_intel = SaaSIntel()
        self.typosquat_intel = TyposquatIntel()
        self.package_intel = PackageIntel()
        self.person_intel = PersonIntel()
        self.plugins = PluginLoader()
        self.correlator = Correlator()
        self.report_gen = ReportGenerator()
    
    def gather_domain_intel(self, domain: str, options: Dict[str, Any]) -> Dict:
        """Gather domain intelligence"""
        print(f"\n[+] Gathering domain intelligence for: {domain}")
        results = {
            'domain': domain,
            'dns_records': {},
            'subdomains': [],
            'whois': {},
            'ssl_info': {},
            'dnssec': {},
            'email_security': {},
        }
        
        if options.get('dns', True):
            print("  [*] Enumerating DNS records...")
            dns = self.domain_intel.enumerate_dns(domain)
            results['dns_records'] = dns
            results['dnssec'] = dns.get('dnssec') or {}
            results['email_security'] = dns.get('email_security') or {}
        
        if options.get('subdomains', True):
            print("  [*] Discovering subdomains...")
            results['subdomains'] = self.domain_intel.discover_subdomains(domain)
        
        if options.get('whois', True):
            print("  [*] Gathering WHOIS information...")
            results['whois'] = self.domain_intel.get_whois(domain)
        
        if options.get('ssl', True):
            print("  [*] Analyzing SSL certificate...")
            results['ssl_info'] = self.domain_intel.analyze_ssl(domain)
        
        return results
    
    def gather_social_intel(self, username: str, options: Dict[str, Any]) -> Dict:
        """Gather social media intelligence"""
        print(f"\n[+] Gathering social media intelligence for: {username}")
        results = {
            'username': username,
            'profiles': {},
            'summary': {},
            'email_addresses': [],
            'email_guess_pivots': [],
            'associated_accounts': []
        }
        
        if options.get('search', True):
            print("  [*] Searching across social platforms...")
            results['profiles'] = self.social_intel.search_username(username)
            results['summary'] = self.social_intel.summarize_profiles(results['profiles'])
            rel = results['summary'].get('reliable_count', 0)
            low = results['summary'].get('low_confidence_count', 0)
            print(f"  [+] Reliable profiles: {rel}  (low-confidence excluded: {low})")
        
        if options.get('email', True):
            print("  [*] Discovering verified email addresses...")
            results['email_addresses'] = self.social_intel.discover_emails(username)
            # Unverified mailbox patterns as pivots only — never listed as found emails
            results['email_guess_pivots'] = self.social_intel.email_guess_pivots(username)
        
        if options.get('associated', True):
            print("  [*] Finding associated accounts...")
            # Reuse profiles already fetched when available (avoid double-scan)
            if results.get('profiles'):
                found = [
                    {
                        "platform": p,
                        "url": i.get("url"),
                        "confidence": i.get("confidence"),
                    }
                    for p, i in results['profiles'].items()
                    if i.get("exists") is True
                    and (i.get("confidence") or "") in ("confirmed", "high", "medium")
                ]
                results['associated_accounts'] = (
                    [{"source": "platform_matrix", "accounts": found}] if found else []
                )
            else:
                results['associated_accounts'] = self.social_intel.find_associated_accounts(username)
        
        return results
    
    def gather_github_intel(self, username: str, options: Dict[str, Any]) -> Dict:
        """Gather GitHub intelligence"""
        print(f"\n[+] Gathering GitHub intelligence for: {username}")
        results = {
            'username': username,
            'profile': {},
            'repositories': [],
            'email': None,
            'creation_date': None
        }
        
        if options.get('profile', True):
            print("  [*] Fetching GitHub profile...")
            results['profile'] = self.github_intel.get_profile(username)
        
        if options.get('repos', True):
            print("  [*] Analyzing repositories...")
            results['repositories'] = self.github_intel.analyze_repositories(username)
        
        if options.get('email', True):
            print("  [*] Discovering email address...")
            results['email'] = self.github_intel.discover_email(username)
        
        if options.get('creation', True):
            print("  [*] Finding account creation date...")
            results['creation_date'] = self.github_intel.get_creation_date(username)
        
        return results
    
    def crawl_website(self, url: str, options: Dict[str, Any]) -> Dict:
        """Crawl website for intelligence"""
        print(f"\n[+] Crawling website: {url}")
        
        # Use comprehensive crawl if requested
        if options.get('comprehensive', False):
            print("  [*] Running comprehensive crawl (creepyCrawler-style)...")
            return self.web_crawler.comprehensive_crawl(
                url,
                max_depth=options.get('depth', 2),
                max_pages=options.get('max_pages', 500),
                include_robots=options.get('robots', True),
                include_sitemap=options.get('sitemap', True),
                extract_all=True
            )
        
        # Standard crawl
        results = {
            'url': url,
            'pages': [],
            'directories': [],
            'technologies': [],
            'emails': [],
            'phone_numbers': [],
            'social_links': []
        }
        
        if options.get('crawl', True):
            print("  [*] Crawling pages...")
            results['pages'] = self.web_crawler.crawl(url, max_depth=options.get('depth', 2))
        
        if options.get('directories', True):
            print("  [*] Enumerating directories...")
            results['directories'] = self.web_crawler.enumerate_directories(url)
        
        if options.get('tech', True):
            print("  [*] Detecting technologies...")
            results['technologies'] = self.web_crawler.detect_technologies(url)
        
        if options.get('extract', True):
            print("  [*] Extracting information...")
            extracted = self.web_crawler.extract_information(url, extract_all=options.get('extract_all', False))
            results['emails'] = extracted.get('emails', [])
            results['phone_numbers'] = extracted.get('phone_numbers', [])
            results['social_links'] = extracted.get('social_links', [])
            if options.get('extract_all', False):
                results['subdomains'] = extracted.get('subdomains', [])
                results['cloud_storage'] = extracted.get('cloud_storage', [])
                results['files'] = extracted.get('files', [])
                results['login_pages'] = extracted.get('login_pages', [])
                results['ip_addresses'] = extracted.get('ip_addresses', [])
                results['html_comments'] = extracted.get('html_comments', [])
                results['marketing_tags'] = extracted.get('marketing_tags', [])
        
        return results
    
    def hunt_urls(self, domain: str, options: Dict[str, Any]) -> Dict:
        """Hunt for exposed URLs via shortener services"""
        print(f"\n[+] Hunting URLs for: {domain}")
        results = {
            'domain': domain,
            'shortened_urls': [],
            'exposed_urls': []
        }
        
        if options.get('hunt', True):
            print("  [*] Searching for shortened URLs...")
            results['shortened_urls'] = self.url_hunter.find_shortened_urls(domain)
        
        if options.get('exposed', True):
            print("  [*] Finding exposed URLs...")
            results['exposed_urls'] = self.url_hunter.find_exposed_urls(domain)
        
        if options.get('urlteam', False):
            print("  [*] Searching URLTeam archives...")
            keywords = options.get('keywords', [domain])
            date = options.get('date', 'latest')
            urlteam_results = self.url_hunter.search_urlteam_archives(keywords, date=date)
            results['urlteam_matches'] = urlteam_results
        
        return results
    
    def analyze_dark_web(self, onion_url: str, options: Dict[str, Any]) -> Dict:
        """Analyze dark web .onion domain"""
        print(f"\n[+] Analyzing dark web: {onion_url}")
        results = {
            'onion_url': onion_url,
            'analysis': {},
            'crawl': {}
        }
        
        if options.get('analyze', True):
            print("  [*] Analyzing .onion domain...")
            results['analysis'] = self.dark_web_intel.analyze_onion(onion_url)
        
        if options.get('crawl', False):
            print("  [*] Crawling .onion domain...")
            results['crawl'] = self.dark_web_intel.crawl_onion(
                onion_url,
                max_depth=options.get('depth', 2),
                max_pages=options.get('max_pages', 50)
            )
        
        if options.get('map_links', False):
            print("  [*] Mapping link relationships...")
            results['link_map'] = self.dark_web_intel.map_onion_links(
                onion_url,
                max_depth=options.get('depth', 2)
            )
        
        return results
    
    def scan_ports(self, target: str, options: Dict[str, Any]) -> Dict:
        """Scan ports and detect services"""
        print(f"\n[+] Scanning ports for: {target}")
        results = {
            'target': target,
            'open_ports': [],
            'services': {},
            'banners': {}
        }
        
        if options.get('scan', True):
            ports = options.get('ports', 'common')
            print(f"  [*] Scanning ports ({ports})...")
            scan_results = self.port_scanner.scan(target, ports=ports)
            results['open_ports'] = scan_results.get('open_ports', [])
            results['services'] = scan_results.get('services', {})
            results['banners'] = scan_results.get('banners', {})
        
        return results
    
    def discover_emails(self, domain: str, options: Dict[str, Any]) -> Dict:
        """Discover email addresses"""
        print(f"\n[+] Discovering emails for: {domain}")
        results = {
            'domain': domain,
            'emails': [],
            'verified': [],
            'sources': {}
        }
        
        if options.get('discover', True):
            print("  [*] Discovering email addresses...")
            results['emails'] = self.email_intel.discover(domain)
        
        if options.get('verify', True):
            print("  [*] Verifying email addresses...")
            results['verified'] = self.email_intel.verify(results['emails'])
        
        if options.get('sources', True):
            print("  [*] Finding email sources...")
            results['sources'] = self.email_intel.find_sources(domain)
        
        return results
    
    def analyze_company(self, company: str, options: Dict[str, Any]) -> Dict:
        """Analyze company and discover employees with leaked credentials"""
        print(f"\n[+] Analyzing company: {company}")
        results = {
            'company': company,
            'employees': [],
            'leaked_credentials': [],
            'repositories': []
        }
        
        if options.get('discover', True):
            print("  [*] Discovering employees...")
            analysis = self.employee_intel.analyze_company(company)
            results['employees'] = analysis.get('employees', [])
            results['leaked_credentials'] = analysis.get('leaked_credentials', [])
            results['repositories'] = analysis.get('repositories', [])
        
        if options.get('check_leaks', True):
            print("  [*] Checking for leaked credentials...")
            # This is already done in analyze_company, but we can add more checks
            api_key = options.get('hibp_api_key')
            for employee in results['employees']:
                email = employee.get('email')
                if email:
                    leak_check = self.employee_intel.check_leaked_credentials(email, api_key)
                    if leak_check.get('breached'):
                        results['leaked_credentials'].append({
                            'employee': employee.get('name'),
                            'email': email,
                            'breaches': leak_check.get('breaches', []),
                            'pastes': leak_check.get('pastes', [])
                        })
        
        return results
    
    def analyze_ip(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        """IP geo / ASN / risk intelligence"""
        print(f"\n[+] Analyzing IP: {target}")
        options = options or {}
        results = self.ip_intel.analyze(target)
        if options.get('shodan') or options.get('censys'):
            print("  [*] Querying host intel APIs...")
            results['host_intel'] = self.host_intel.analyze(target)
        return results

    def hunt_wayback(self, domain: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        """Historical URLs via Wayback CDX"""
        print(f"\n[+] Wayback hunt: {domain}")
        options = options or {}
        return self.wayback_intel.hunt(
            domain,
            limit=int(options.get('limit', 200)),
            interesting_only=bool(options.get('interesting_only', True)),
        )

    def analyze_phone(self, number: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        print(f"\n[+] Phone OSINT: {number}")
        return self.phone_intel.analyze(number)

    def hunt_pastes(self, query: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        print(f"\n[+] Paste / leak hunt: {query}")
        options = options or {}
        return self.paste_intel.hunt(query, limit=int(options.get('limit', 30)))

    def analyze_host_apis(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        print(f"\n[+] Host intel (Shodan/Censys): {target}")
        return self.host_intel.analyze(target)

    def search_onion_dirs(self, query: str) -> Dict:
        print(f"\n[+] Onion directory search: {query}")
        return {"query": query, "results": self.dark_web_intel.search_onion_directories(query)}

    def generate_dorks(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        print(f"\n[+] Generating dorks: {target}")
        options = options or {}
        return self.dork_intel.generate(target, kind=options.get("kind", "auto"))

    def analyze_asn(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        print(f"\n[+] ASN / netblock intel: {target}")
        return self.asn_intel.analyze(target)

    def hunt_buckets(self, name: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        print(f"\n[+] Cloud bucket hunt: {name}")
        return self.bucket_intel.hunt(name)

    def check_takeovers(self, domain: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        print(f"\n[+] Subdomain takeover check: {domain}")
        options = options or {}
        subs = options.get("subdomains")
        if subs is None and options.get("discover_subs", True):
            try:
                subs = self.domain_intel.discover_subdomains(domain)
            except Exception:
                subs = []
        return self.takeover_intel.check_domain(domain, subs)

    def analyze_favicon(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        print(f"\n[+] Favicon hash: {target}")
        return self.favicon_intel.analyze(target)

    def analyze_metadata(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        print(f"\n[+] Metadata / EXIF: {target}")
        return self.meta_intel.analyze(target)

    def check_email_accounts(self, email: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        print(f"\n[+] Email account check: {email}")
        return self.email_accounts.check(email)

    def generate_username_perms(self, seed: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        print(f"\n[+] Username permutations: {seed}")
        opts = options or {}
        return self.username_perm.generate(seed, years=opts.get("years", True), limit=int(opts.get("limit", 80)))

    def find_related_domains(self, domain: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        print(f"\n[+] Related domains: {domain}")
        return self.related_domains.find(domain)

    def mine_js_secrets(self, url: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        print(f"\n[+] JS / page secrets: {url}")
        return self.js_secrets.mine(url)

    def image_pivots(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        print(f"\n[+] Reverse-image pivots: {target}")
        return self.image_pivot.pivots(target)

    def lookup_passive_dns(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        print(f"\n[+] Passive DNS: {target}")
        return self.passive_dns.lookup(target)

    def check_abuse(self, ip_or_host: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        print(f"\n[+] Abuse / DNSBL: {ip_or_host}")
        return self.abuse_intel.check(ip_or_host)

    def enrich_ioc(self, indicator: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        print(f"\n[+] IOC enrichment: {indicator}")
        return self.ioc_intel.enrich(indicator)

    def analyze_crypto(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        print(f"\n[+] Web3 / crypto intel: {target}")
        return self.crypto_intel.analyze(target, options)

    def analyze_company_biz(self, company: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        print(f"\n[+] Company / business intel: {company}")
        return self.company_biz.analyze(company)

    def discover_saas(self, domain: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        print(f"\n[+] SaaS / tenant discovery: {domain}")
        return self.saas_intel.discover(domain)

    def analyze_typosquats(self, domain: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        print(f"\n[+] Typosquat / lookalikes: {domain}")
        opts = options or {}
        return self.typosquat_intel.analyze(
            domain,
            resolve=bool(opts.get("resolve", True)),
            limit=int(opts.get("limit", 200)),
        )

    def search_packages(self, query: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        print(f"\n[+] Package / supply-chain: {query}")
        return self.package_intel.search(query, limit=int((options or {}).get("limit", 8)))

    def analyze_person(self, name: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        print(f"\n[+] Person OSINT: {name}")
        return self.person_intel.analyze(name)

    def capture_screenshot(self, url: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        print(f"\n[+] Screenshot: {url}")
        out = (options or {}).get("output_dir") or str(self.output_dir / "screenshots")
        return self.screenshot_intel.capture(url, output_dir=out)

    def export_graph(self, results: Dict, options: Optional[Dict[str, Any]] = None) -> Dict:
        print("\n[+] Exporting investigation graph...")
        graph = self.graph_export.from_results(results)
        opts = options or {}
        base = self.output_dir / f"graph_{self.timestamp}"
        out = {"graph": graph, "files": {}}
        if opts.get("json", True):
            out["files"]["json"] = self.graph_export.write_json(graph, str(base) + ".json")
        if opts.get("graphml", True):
            out["files"]["graphml"] = self.graph_export.write_graphml(graph, str(base) + ".graphml")
        return out

    def run_plugin(self, plugin_id: str, target: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        print(f"\n[+] Plugin {plugin_id}: {target}")
        return self.plugins.run(plugin_id, target, options)

    def tor_health(self) -> Dict:
        print("\n[+] Tor health check...")
        return self.dark_web_intel.tor_health()

    def correlate_results(self, results: Dict) -> Dict:
        print("\n[+] Correlating entities...")
        return self.correlator.correlate(results)

    def run_auto_scan(self, target: str) -> Dict:
        """Detect target type and run an appropriate full scan."""
        detected = detect_target_type(target)
        print(f"\n[+] Auto-detected type: {detected}")
        return self.run_full_scan(target, detected)
    
    def run_full_scan(self, target: str, scan_type: str = "domain") -> Dict:
        """Run a full comprehensive scan"""
        print(f"\n{'='*60}")
        print(f"  EPIC OSINT TOOLKIT - Full Scan")
        print(f"  Target: {target}")
        print(f"  Type: {scan_type}")
        print(f"  Timestamp: {self.timestamp}")
        print(f"{'='*60}\n")
        
        all_results = {
            'target': target,
            'scan_type': scan_type,
            'timestamp': self.timestamp,
            'results': {}
        }
        
        if scan_type == "domain":
            all_results['results']['domain'] = self.gather_domain_intel(target, {
                'dns': True, 'subdomains': True, 'whois': True, 'ssl': True
            })
            try:
                url = f"https://{target}" if not target.startswith('http') else target
                all_results['results']['website'] = self.crawl_website(url, {
                    'crawl': True, 'directories': True, 'tech': True, 'extract': True
                })
            except Exception:
                pass
            all_results['results']['emails'] = self.discover_emails(target, {
                'discover': True, 'verify': False, 'sources': True
            })
            all_results['results']['urls'] = self.hunt_urls(target, {
                'hunt': True, 'exposed': True
            })
            all_results['results']['wayback'] = self.hunt_wayback(target, {
                'limit': 100, 'interesting_only': True
            })
            all_results['results']['pastes'] = self.hunt_pastes(target, {'limit': 20})
            all_results['results']['ports'] = self.scan_ports(target, {
                'scan': True, 'ports': 'common'
            })
            all_results['results']['dorks'] = self.generate_dorks(target, {'kind': 'domain'})
            all_results['results']['buckets'] = self.hunt_buckets(target)
            try:
                subs = (all_results['results']['domain'] or {}).get('subdomains') or []
                all_results['results']['takeover'] = self.takeover_intel.check_domain(target, subs)
            except Exception:
                pass
            try:
                all_results['results']['favicon'] = self.analyze_favicon(target)
            except Exception:
                pass
            try:
                all_results['results']['related_domains'] = self.find_related_domains(target)
            except Exception:
                pass
            try:
                all_results['results']['saas'] = self.discover_saas(target)
            except Exception:
                pass
            try:
                all_results['results']['typosquats'] = self.analyze_typosquats(target, {'limit': 120})
            except Exception:
                pass
            try:
                all_results['results']['packages'] = self.search_packages(target)
            except Exception:
                pass
            try:
                all_results['results']['passive_dns'] = self.lookup_passive_dns(target)
            except Exception:
                pass
            try:
                url = f"https://{target}" if not target.startswith('http') else target
                all_results['results']['js_secrets'] = self.mine_js_secrets(url)
            except Exception:
                pass
            try:
                ip = (all_results['results']['domain'].get('dns_records') or {}).get('IP')
                if ip:
                    all_results['results']['ip'] = self.analyze_ip(ip, {})
                    all_results['results']['asn'] = self.analyze_asn(ip)
                    try:
                        all_results['results']['abuse'] = self.check_abuse(ip)
                    except Exception:
                        pass
            except Exception:
                pass

        elif scan_type == "ip":
            all_results['results']['ip'] = self.analyze_ip(target, {})
            all_results['results']['asn'] = self.analyze_asn(target)
            all_results['results']['ports'] = self.scan_ports(target, {
                'scan': True, 'ports': 'common'
            })
            all_results['results']['host_intel'] = self.analyze_host_apis(target, {})
            all_results['results']['dorks'] = self.generate_dorks(target, {'kind': 'ip'})
            try:
                all_results['results']['passive_dns'] = self.lookup_passive_dns(target)
            except Exception:
                pass
            try:
                all_results['results']['abuse'] = self.check_abuse(target)
            except Exception:
                pass
            try:
                all_results['results']['ioc'] = self.enrich_ioc(target)
            except Exception:
                pass

        elif scan_type == "wallet":
            all_results['results']['crypto'] = self.analyze_crypto(target, {
                'tokens': True, 'txs': True, 'chains': 'auto',
            })
            all_results['results']['pastes'] = self.hunt_pastes(target, {'limit': 20})
            all_results['results']['dorks'] = self.generate_dorks(target, {'kind': 'wallet'})

        elif scan_type == "url":
            all_results['results']['website'] = self.crawl_website(target, {
                'crawl': True, 'directories': True, 'tech': True, 'extract': True
            })

        elif scan_type == "phone":
            all_results['results']['phone'] = self.analyze_phone(target, {})

        elif scan_type == "email":
            domain = target.split("@", 1)[-1]
            all_results['results']['pastes'] = self.hunt_pastes(target, {'limit': 25})
            all_results['results']['emails'] = {
                'domain': domain,
                'emails': [target],
                'verified': self.email_intel.verify([target]),
                'sources': self.email_intel.find_sources(domain),
            }
            all_results['results']['domain'] = self.gather_domain_intel(domain, {
                'dns': True, 'subdomains': False, 'whois': True, 'ssl': True
            })
            try:
                all_results['results']['email_accounts'] = self.check_email_accounts(target)
            except Exception:
                pass
            try:
                all_results['results']['perms'] = self.generate_username_perms(target)
            except Exception:
                pass

        elif scan_type == "onion":
            try:
                all_results['results']['tor_health'] = self.tor_health()
            except Exception:
                pass
            all_results['results']['dark_web'] = self.analyze_dark_web(target, {
                'analyze': True, 'crawl': True, 'map_links': False, 'depth': 1, 'max_pages': 30
            })
            all_results['results']['onion_dirs'] = self.search_onion_dirs(target)

        elif scan_type == "username":
            all_results['results']['social'] = self.gather_social_intel(target, {
                'search': True, 'email': True, 'associated': True
            })
            all_results['results']['github'] = self.gather_github_intel(target, {
                'profile': True, 'repos': True, 'email': True, 'creation': True
            })
            all_results['results']['pastes'] = self.hunt_pastes(target, {'limit': 15})
            try:
                all_results['results']['perms'] = self.generate_username_perms(target)
            except Exception:
                pass
        
        elif scan_type == "company":
            all_results['results']['company'] = self.analyze_company(target, {
                'discover': True, 'check_leaks': True, 'hibp_api_key': None
            })
            try:
                all_results['results']['company_biz'] = self.analyze_company_biz(target)
            except Exception:
                pass
            try:
                all_results['results']['packages'] = self.search_packages(target)
            except Exception:
                pass
            all_results['results']['pastes'] = self.hunt_pastes(target, {'limit': 15})

        elif scan_type == "person":
            all_results['results']['person'] = self.analyze_person(target)
            try:
                all_results['results']['perms'] = self.generate_username_perms(target)
            except Exception:
                pass
            all_results['results']['pastes'] = self.hunt_pastes(target, {'limit': 15})
            # Light social on first username seed
            seeds = (all_results['results']['person'] or {}).get('username_seeds') or []
            if seeds:
                try:
                    all_results['results']['social'] = self.gather_social_intel(seeds[0], {
                        'search': True, 'email': False, 'associated': False
                    })
                except Exception:
                    pass

        all_results['correlation'] = self.correlate_results(all_results)
        try:
            all_results['results']['graph'] = self.export_graph(all_results, {'json': True, 'graphml': True})
        except Exception:
            pass
        return all_results
    
    def save_results(self, results: Dict, format: str = "json") -> str:
        """Save results to file"""
        annotate_results(results)
        safe_target = "".join(c if c.isalnum() or c in "._-" else "_" for c in str(results.get('target', 'unknown')))[:80]
        filename = f"osint_{self.timestamp}_{safe_target}.{format}"
        filepath = self.output_dir / filename
        
        if format == "json":
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, default=str)
        elif format == "txt":
            report = self.report_gen.generate_text_report(results)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(report)
        elif format == "html":
            report = self.report_gen.generate_html_report(results)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(report)
        elif format == "md":
            report = self.report_gen.generate_markdown_report(results)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(report)
        
        return str(filepath)


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Epic OSINT Toolkit - Comprehensive Open Source Intelligence Gathering",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive TUI (recommended)
  python osint_toolkit.py
  python osint_toolkit.py --tui

  # Auto / full scan
  python osint_toolkit.py -t example.com --auto
  python osint_toolkit.py -t example.com --full

  # Domain recon extras
  python osint_toolkit.py -t example.com --saas --typosquat --packages --related

  # People / company
  python osint_toolkit.py -t johndoe --type username --social --github
  python osint_toolkit.py -t "Jane Doe" --type person --person --perms
  python osint_toolkit.py -t "Acme Corp" --type company --employees --leaks --company-biz

  # Web3
  python osint_toolkit.py -t vitalik.eth --crypto --chains evm

  # Save HTML report
  python osint_toolkit.py -t example.com --full --format html

See README.md / QUICKSTART.md for the full feature list.
        """
    )
    
    parser.add_argument('-t', '--target', help='Target (domain, username, IP, company, etc.)')
    parser.add_argument('--tui', action='store_true', help='Launch interactive ASCII/ANSI TUI')
    parser.add_argument('--type',
                       choices=['domain', 'username', 'ip', 'url', 'company', 'person', 'onion', 'phone', 'email', 'wallet', 'auto'],
                       default='auto',
                       help='Type of target (default: auto-detect)')
    parser.add_argument('--full', action='store_true', help='Run full comprehensive scan')
    parser.add_argument('--auto', action='store_true', help='Auto-detect target type and scan')
    
    # Module flags
    parser.add_argument('--dns', action='store_true', help='DNS enumeration')
    parser.add_argument('--subdomains', action='store_true', help='Subdomain discovery')
    parser.add_argument('--whois', action='store_true', help='WHOIS lookup')
    parser.add_argument('--ssl', action='store_true', help='SSL certificate analysis')
    parser.add_argument('--social', action='store_true', help='Social media search')
    parser.add_argument('--github', action='store_true', help='GitHub intelligence')
    parser.add_argument('--crawl', action='store_true', help='Website crawling')
    parser.add_argument('--directories', action='store_true', help='Directory enumeration')
    parser.add_argument('--emails', action='store_true', help='Email discovery')
    parser.add_argument('--urls', action='store_true', help='URL hunting')
    parser.add_argument('--wayback', action='store_true', help='Wayback Machine historical URLs')
    parser.add_argument('--pastes', action='store_true', help='Paste / code leak hunt')
    parser.add_argument('--ip', action='store_true', help='IP geo/ASN intelligence')
    parser.add_argument('--phone', action='store_true', help='Phone OSINT')
    parser.add_argument('--shodan', action='store_true', help='Shodan host lookup (needs API key)')
    parser.add_argument('--censys', action='store_true', help='Censys host lookup (needs API creds)')
    parser.add_argument('--ports', action='store_true', help='Port scanning')
    parser.add_argument('--employees', action='store_true', help='Discover company employees')
    parser.add_argument('--leaks', action='store_true', help='Check for leaked credentials')
    parser.add_argument('--comprehensive-crawl', action='store_true', help='Comprehensive crawl (creepyCrawler-style)')
    parser.add_argument('--robots', action='store_true', help='Parse robots.txt')
    parser.add_argument('--sitemap', action='store_true', help='Parse sitemap.xml')
    parser.add_argument('--urlteam', action='store_true', help='Search URLTeam archives')
    parser.add_argument('--dark-web', action='store_true', help='Analyze dark web .onion domain')
    parser.add_argument('--onion-search', action='store_true', help='Search onion directories (Ahmia)')
    parser.add_argument('--dorks', action='store_true', help='Generate search-engine dork packs')
    parser.add_argument('--asn', action='store_true', help='ASN / netblock intelligence')
    parser.add_argument('--buckets', action='store_true', help='Cloud bucket / blob exposure hunt')
    parser.add_argument('--takeover', action='store_true', help='Subdomain takeover fingerprint checks')
    parser.add_argument('--favicon', action='store_true', help='Favicon mmh3 hash + Shodan pivot')
    parser.add_argument('--meta', action='store_true', help='EXIF / metadata from image URL or local file')
    parser.add_argument('--email-accounts', action='store_true', help='Holehe-style email→account checks')
    parser.add_argument('--perms', action='store_true', help='Username / name permutations')
    parser.add_argument('--related', action='store_true', help='Related domains (CT / SSL / same IP)')
    parser.add_argument('--js-secrets', action='store_true', help='Mine JS/page for secrets & API paths')
    parser.add_argument('--image-pivots', action='store_true', help='Reverse-image search pivot URLs')
    parser.add_argument('--passive-dns', action='store_true', help='Passive DNS lookup')
    parser.add_argument('--abuse', action='store_true', help='DNSBL / abuse reputation')
    parser.add_argument('--ioc', action='store_true', help='IOC enrichment (VT/OTX if keyed)')
    parser.add_argument('--crypto', action='store_true', help='Web3 wallet / ENS / tx intelligence')
    parser.add_argument('--crypto-chains', action='store_true',
                        help='List selectable chain groups (evm = all EVM L1/L2)')
    parser.add_argument('--chains', default='auto',
                        help='Crypto chain groups: auto|all|evm|bitcoin|solana|… (comma-separated)')
    parser.add_argument('--screenshot', action='store_true', help='Headless Chrome screenshot if installed')
    parser.add_argument('--company-biz', action='store_true', help='Company registry / business intel')
    parser.add_argument('--saas', action='store_true', help='SaaS / cloud tenant discovery')
    parser.add_argument('--typosquat', action='store_true', help='Typosquat / lookalike domain hunt')
    parser.add_argument('--packages', action='store_true', help='Package registry / supply-chain search')
    parser.add_argument('--person', action='store_true', help='Person / full-name OSINT pivots')
    parser.add_argument('--graph', action='store_true', help='Export correlation graph (JSON + GraphML)')
    parser.add_argument('--tor-check', action='store_true', help='Check Tor SOCKS health')
    parser.add_argument('--plugin', help='Run a plugin by id from modules/plugins/')
    parser.add_argument('--list-plugins', action='store_true', help='List available plugins')
    parser.add_argument('--case', help='Attach scan to investigation case id')
    parser.add_argument('--case-create', help='Create investigation case with this name')
    parser.add_argument('--case-list', action='store_true', help='List investigation cases')
    parser.add_argument('--batch', help='Batch targets file (one per line); runs auto scan each')
    parser.add_argument('--tor', action='store_true', help='Use Tor proxy (requires Tor running)')
    parser.add_argument('--correlate', action='store_true', help='Build entity correlation graph')
    
    # Options
    parser.add_argument('--keywords-file', help='Keywords file for URLTeam search')
    parser.add_argument('--urlteam-date', default='latest', help='URLTeam archive date (latest, YYYY-MM-DD, YYYY, or range)')
    parser.add_argument('--max-pages', type=int, default=500, help='Maximum pages to crawl (default: 500)')
    parser.add_argument('--hibp-api-key', help='Have I Been Pwned API key (for leak checking)')
    parser.add_argument('--github-token', help='GitHub API token (raises rate limits)')
    parser.add_argument('--shodan-key', help='Shodan API key')
    parser.add_argument('--censys-id', help='Censys API ID')
    parser.add_argument('--censys-secret', help='Censys API secret')
    parser.add_argument('--vt-key', help='VirusTotal API key')
    parser.add_argument('--otx-key', help='AlienVault OTX API key')
    parser.add_argument('--etherscan-key', help='Etherscan API key (ETH tx history)')
    parser.add_argument('--rate-limit', type=float, default=0.0, help='Max requests/sec soft limit (0=off)')
    parser.add_argument('-o', '--output', default='reports', help='Output directory (default: reports)')
    parser.add_argument('-f', '--format', choices=['json', 'txt', 'html', 'md'], default='json',
                       help='Output format (default: json)')
    parser.add_argument('--ports-range', default='common', help='Port range to scan (default: common)')
    parser.add_argument('--depth', type=int, default=2, help='Crawl depth (default: 2)')
    parser.add_argument('--quiet', action='store_true', help='Quiet mode (minimal output)')
    
    args = parser.parse_args()
    
    # Initialize toolkit
    toolkit = OSINTToolkit(
        output_dir=args.output,
        github_token=args.github_token,
        shodan_key=args.shodan_key,
        censys_id=args.censys_id,
        censys_secret=args.censys_secret,
        vt_key=args.vt_key,
        otx_key=args.otx_key,
        etherscan_key=args.etherscan_key,
        rate_limit=args.rate_limit,
    )

    if args.case_list:
        for c in toolkit.cases.list_cases():
            print(f"{c['id']}\t{c['name']}\ttargets={c['targets']}\tscans={c['scans']}")
        return
    if args.case_create:
        case = toolkit.cases.create(args.case_create)
        print(json.dumps(case, indent=2, default=str))
        return
    if args.list_plugins:
        for p in toolkit.plugins.discover():
            print(f"{p.get('id')}\t{p.get('name')}\t{p.get('description', '')}")
        return
    if args.crypto_chains:
        from modules.crypto_intel import CryptoIntel, CHAIN_GROUPS, ERC20_VIA_EVM, _EVM_RPCS
        print("Selectable groups (pass via --chains):\n")
        print(f"  {'GROUP':12}  {'FAMILY':12}  NOTE")
        for name, meta in sorted(CHAIN_GROUPS.items()):
            print(f"  {name:12}  {str(meta.get('family', '')):12}  {meta.get('note', '')}")
        print(f"\n  evm expands to: {', '.join(sorted(_EVM_RPCS.keys()))}")
        print(f"\n  ERC-20 via evm: {', '.join(ERC20_VIA_EVM)}")
        print("\nExamples:")
        print("  --crypto --chains auto          # detected chain only (no full EVM sweep)")
        print("  --crypto --chains evm           # ETH + all EVM L2s for a 0x address")
        print("  --crypto --chains bitcoin,near  # independent groups only")
        print("  --crypto --chains all           # everything applicable")
        return
    if args.tor_check:
        print(json.dumps(toolkit.tor_health(), indent=2, default=str))
        return

    if args.batch:
        batch_path = Path(args.batch).expanduser()
        try:
            resolved = batch_path.resolve()
            resolved.relative_to(Path.cwd().resolve())
            lines = [
                ln.strip() for ln in resolved.read_text(encoding='utf-8', errors='replace').splitlines()
                if ln.strip() and not ln.strip().startswith('#')
            ][:100]
        except (ValueError, OSError) as exc:
            print(f"[!] Batch file error: {exc}")
            sys.exit(1)
        if args.tor:
            toolkit.dark_web_intel = DarkWebIntel(use_tor=True)
        for target in lines:
            print(f"\n[+] Batch target: {target}")
            results = toolkit.run_auto_scan(target)
            path = toolkit.save_results(results, args.format)
            if args.case:
                toolkit.cases.attach_scan(args.case, {
                    'target': target,
                    'scan_type': results.get('scan_type'),
                    'report_path': path,
                    'counts': (results.get('correlation') or {}).get('counts') or {},
                })
            if not args.quiet:
                print(f"  Saved: {path}")
        return
    
    # Interactive TUI when no target given, or --tui requested
    if args.tui or not args.target:
        from modules.tui import launch_tui
        if args.tor:
            toolkit.dark_web_intel = DarkWebIntel(use_tor=True)
        try:
            launch_tui(toolkit)
        except KeyboardInterrupt:
            print("\n[!] Exited")
            sys.exit(0)
        return

    # Enable Tor if requested
    if args.tor:
        toolkit.dark_web_intel = DarkWebIntel(use_tor=True)

    scan_type = args.type
    if args.auto or scan_type == 'auto':
        scan_type = detect_target_type(args.target)
    
    try:
        if args.full or args.auto:
            results = toolkit.run_full_scan(args.target, scan_type)
        else:
            # Run specific modules
            results = {
                'target': args.target,
                'scan_type': scan_type,
                'timestamp': toolkit.timestamp,
                'results': {}
            }

            # Type-agnostic module flags
            if args.ip:
                results['results']['ip'] = toolkit.analyze_ip(args.target, {
                    'shodan': args.shodan, 'censys': args.censys
                })
            if args.phone:
                results['results']['phone'] = toolkit.analyze_phone(args.target)
            if args.wayback:
                results['results']['wayback'] = toolkit.hunt_wayback(args.target, {
                    'limit': 200, 'interesting_only': True
                })
            if args.pastes:
                results['results']['pastes'] = toolkit.hunt_pastes(args.target, {'limit': 30})
            if args.shodan or args.censys:
                results['results']['host_intel'] = toolkit.analyze_host_apis(args.target)
            if args.onion_search:
                results['results']['onion_dirs'] = toolkit.search_onion_dirs(args.target)
            if args.dorks:
                results['results']['dorks'] = toolkit.generate_dorks(args.target)
            if args.asn:
                results['results']['asn'] = toolkit.analyze_asn(args.target)
            if args.buckets:
                results['results']['buckets'] = toolkit.hunt_buckets(args.target)
            if args.takeover:
                results['results']['takeover'] = toolkit.check_takeovers(args.target)
            if args.favicon:
                results['results']['favicon'] = toolkit.analyze_favicon(args.target)
            if args.meta:
                results['results']['meta'] = toolkit.analyze_metadata(args.target)
            if args.email_accounts:
                results['results']['email_accounts'] = toolkit.check_email_accounts(args.target)
            if args.perms:
                results['results']['perms'] = toolkit.generate_username_perms(args.target)
            if args.related:
                results['results']['related_domains'] = toolkit.find_related_domains(args.target)
            if args.js_secrets:
                url = args.target if args.target.startswith('http') else f"https://{args.target}"
                results['results']['js_secrets'] = toolkit.mine_js_secrets(url)
            if args.image_pivots:
                results['results']['image_pivots'] = toolkit.image_pivots(args.target)
            if args.passive_dns:
                results['results']['passive_dns'] = toolkit.lookup_passive_dns(args.target)
            if args.abuse:
                results['results']['abuse'] = toolkit.check_abuse(args.target)
            if args.ioc:
                results['results']['ioc'] = toolkit.enrich_ioc(args.target)
            if args.crypto:
                results['results']['crypto'] = toolkit.analyze_crypto(args.target, {
                    'tokens': True, 'txs': True, 'chains': args.chains,
                })
            if args.screenshot:
                url = args.target if args.target.startswith('http') else f"https://{args.target}"
                results['results']['screenshot'] = toolkit.capture_screenshot(url)
            if args.company_biz:
                results['results']['company_biz'] = toolkit.analyze_company_biz(args.target)
            if args.saas:
                results['results']['saas'] = toolkit.discover_saas(args.target)
            if args.typosquat:
                results['results']['typosquats'] = toolkit.analyze_typosquats(args.target)
            if args.packages:
                results['results']['packages'] = toolkit.search_packages(args.target)
            if args.person:
                results['results']['person'] = toolkit.analyze_person(args.target)
            if args.plugin:
                results['results']['plugin'] = toolkit.run_plugin(args.plugin, args.target)
            
            if scan_type == 'domain':
                module_flags = [
                    args.dns, args.subdomains, args.whois, args.ssl, args.crawl,
                    args.directories, args.comprehensive_crawl, args.emails,
                    args.urls, args.urlteam, args.ports, args.wayback, args.pastes, args.ip,
                    args.dorks, args.asn, args.buckets, args.takeover, args.favicon, args.meta,
                    args.email_accounts, args.perms, args.related, args.js_secrets,
                    args.image_pivots, args.passive_dns, args.abuse, args.ioc, args.crypto,
                    args.screenshot, args.company_biz, args.saas, args.typosquat, args.packages,
                    args.person,
                    bool(args.plugin),
                ]
                run_domain = args.dns or args.subdomains or args.whois or args.ssl or not any(module_flags)
                if run_domain:
                    results['results']['domain'] = toolkit.gather_domain_intel(args.target, {
                        'dns': args.dns or not any(module_flags),
                        'subdomains': args.subdomains,
                        'whois': args.whois,
                        'ssl': args.ssl
                    })
                
                if args.crawl or args.directories or args.comprehensive_crawl:
                    url = f"https://{args.target}" if not args.target.startswith('http') else args.target
                    results['results']['website'] = toolkit.crawl_website(url, {
                        'crawl': args.crawl or args.comprehensive_crawl,
                        'directories': args.directories,
                        'tech': True,
                        'extract': True,
                        'extract_all': args.comprehensive_crawl,
                        'comprehensive': args.comprehensive_crawl,
                        'robots': args.robots or args.comprehensive_crawl,
                        'sitemap': args.sitemap or args.comprehensive_crawl,
                        'depth': args.depth,
                        'max_pages': args.max_pages
                    })
                
                if args.emails:
                    results['results']['emails'] = toolkit.discover_emails(args.target, {
                        'discover': True,
                        'verify': False,
                        'sources': True
                    })
                
                if args.urls or args.urlteam:
                    keywords = [args.target]
                    if args.keywords_file:
                        try:
                            with open(args.keywords_file, 'r', encoding='utf-8') as f:
                                keywords = [line.strip() for line in f if line.strip()]
                        except OSError:
                            pass
                    
                    results['results']['urls'] = toolkit.hunt_urls(args.target, {
                        'hunt': args.urls,
                        'exposed': args.urls,
                        'urlteam': args.urlteam,
                        'keywords': keywords,
                        'date': args.urlteam_date
                    })

                if args.ports:
                    results['results']['ports'] = toolkit.scan_ports(args.target, {
                        'scan': True,
                        'ports': args.ports_range
                    })
            
            elif scan_type == 'ip':
                if 'ip' not in results['results']:
                    results['results']['ip'] = toolkit.analyze_ip(args.target, {
                        'shodan': args.shodan, 'censys': args.censys
                    })
                if args.ports or not any([args.shodan, args.censys, args.pastes]):
                    results['results']['ports'] = toolkit.scan_ports(args.target, {
                        'scan': True, 'ports': args.ports_range
                    })

            elif scan_type == 'phone':
                if 'phone' not in results['results']:
                    results['results']['phone'] = toolkit.analyze_phone(args.target)

            elif scan_type == 'email':
                domain = args.target.split('@', 1)[-1]
                results['results']['emails'] = {
                    'domain': domain,
                    'emails': [args.target],
                    'verified': toolkit.email_intel.verify([args.target]),
                    'sources': toolkit.email_intel.find_sources(domain),
                }
                results['results']['pastes'] = toolkit.hunt_pastes(args.target, {'limit': 25})

            elif scan_type == 'url':
                results['results']['website'] = toolkit.crawl_website(args.target, {
                    'crawl': True, 'directories': args.directories, 'tech': True, 'extract': True,
                    'depth': args.depth, 'max_pages': args.max_pages
                })
            
            elif scan_type == 'onion':
                if args.dark_web or args.onion_search or not args.ports:
                    results['results']['dark_web'] = toolkit.analyze_dark_web(args.target, {
                        'analyze': True,
                        'crawl': True,
                        'map_links': False,
                        'depth': args.depth,
                        'max_pages': args.max_pages
                    })
                if args.onion_search:
                    results['results']['onion_dirs'] = toolkit.search_onion_dirs(args.target)
                if args.ports:
                    results['results']['ports'] = toolkit.scan_ports(args.target, {
                        'scan': True,
                        'ports': args.ports_range
                    })
            
            elif scan_type == 'wallet':
                if 'crypto' not in results['results']:
                    results['results']['crypto'] = toolkit.analyze_crypto(args.target, {
                        'tokens': True, 'txs': True, 'chains': args.chains,
                    })
                if args.pastes:
                    results['results']['pastes'] = toolkit.hunt_pastes(args.target, {'limit': 20})
                if args.dorks:
                    results['results']['dorks'] = toolkit.generate_dorks(args.target, {'kind': 'wallet'})

            elif scan_type == 'username':
                if args.social or (not args.github):
                    results['results']['social'] = toolkit.gather_social_intel(args.target, {
                        'search': True,
                        'email': True,
                        'associated': True
                    })
                
                if args.github:
                    results['results']['github'] = toolkit.gather_github_intel(args.target, {
                        'profile': True,
                        'repos': True,
                        'email': True,
                        'creation': True
                    })
            
            elif scan_type == 'company':
                results['results']['company'] = toolkit.analyze_company(args.target, {
                    'discover': args.employees or not args.leaks,
                    'check_leaks': args.leaks or not args.employees,
                    'hibp_api_key': args.hibp_api_key
                })
                if args.company_biz or not any([args.employees, args.leaks, args.packages]):
                    if 'company_biz' not in results['results']:
                        results['results']['company_biz'] = toolkit.analyze_company_biz(args.target)

            elif scan_type == 'person':
                if 'person' not in results['results']:
                    results['results']['person'] = toolkit.analyze_person(args.target)
                if args.perms or args.social:
                    if args.perms:
                        results['results']['perms'] = toolkit.generate_username_perms(args.target)
                    if args.social:
                        seeds = (results['results'].get('person') or {}).get('username_seeds') or [args.target.split()[0]]
                        results['results']['social'] = toolkit.gather_social_intel(seeds[0], {
                            'search': True, 'email': False, 'associated': False
                        })

            if args.correlate or results.get('results'):
                results['correlation'] = toolkit.correlate_results(results)
            if args.graph and results.get('results'):
                results['results']['graph'] = toolkit.export_graph(results)
        
        # Save results
        if not args.quiet:
            print(f"\n[+] Saving results...")
        filepath = toolkit.save_results(results, args.format)
        if args.case:
            toolkit.cases.attach_scan(args.case, {
                'target': args.target,
                'scan_type': results.get('scan_type'),
                'report_path': filepath,
                'counts': (results.get('correlation') or {}).get('counts') or {},
            })
        
        if not args.quiet:
            print(f"\n{'='*60}")
            print(f"  Scan completed successfully!")
            print(f"  Results saved to: {filepath}")
            print(f"{'='*60}\n")
        
        # Print summary
        if not args.quiet:
            toolkit.report_gen.print_summary(results)
    
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        if not args.quiet:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

