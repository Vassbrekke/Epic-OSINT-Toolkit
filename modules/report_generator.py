"""Report Generator — structured, confidence-aware OSINT reports."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
import html as html_lib
import json

from modules.result_quality import (
    CONF_CONFIRMED,
    CONF_HIGH,
    CONF_MEDIUM,
    annotate_results,
    confidence_badge,
    meets_confidence,
)


def _esc(value: Any) -> str:
    return html_lib.escape(str(value if value is not None else ""), quote=True)


def _as_list(value: Any) -> List:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _fmt_val(value: Any, limit: int = 200) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (list, dict)):
        s = json.dumps(value, default=str)
    else:
        s = str(value)
    s = s.replace("\n", " ").strip()
    return s if len(s) <= limit else s[: limit - 3] + "..."


SECTION_ORDER = [
    "domain", "ip", "asn", "related_domains", "typosquats", "passive_dns",
    "abuse", "saas", "takeover", "buckets", "favicon", "host_intel", "ports",
    "website", "urls", "wayback", "js_secrets", "screenshot", "dorks",
    "social", "github", "perms", "person", "emails", "email_accounts",
    "company", "company_biz", "employees", "packages", "phone", "pastes",
    "ioc", "crypto", "dark_web", "onion_dirs", "tor_health", "meta",
    "image_pivots", "graph", "plugin",
]

SECTION_TITLES = {
    "domain": "DOMAIN INTELLIGENCE",
    "social": "SOCIAL MEDIA",
    "github": "GITHUB",
    "website": "WEB CRAWL",
    "emails": "EMAIL DISCOVERY",
    "email_accounts": "EMAIL ACCOUNT CHECKS",
    "perms": "USERNAME PERMUTATIONS",
    "urls": "URL HUNT",
    "wayback": "WAYBACK ARCHIVE",
    "pastes": "PASTE / LEAK HUNT",
    "ip": "IP INTELLIGENCE",
    "asn": "ASN / NETBLOCKS",
    "related_domains": "RELATED DOMAINS",
    "typosquats": "TYPOSQUAT / LOOKALIKES",
    "saas": "SAAS / TENANTS",
    "company_biz": "COMPANY / BUSINESS",
    "person": "PERSON OSINT",
    "packages": "PACKAGE REGISTRIES",
    "passive_dns": "PASSIVE DNS",
    "abuse": "ABUSE / DNSBL",
    "ioc": "IOC ENRICHMENT",
    "crypto": "CRYPTO / WEB3",
    "js_secrets": "JS / PAGE SECRETS",
    "image_pivots": "IMAGE PIVOTS",
    "screenshot": "SCREENSHOT",
    "phone": "PHONE OSINT",
    "ports": "PORT SCAN",
    "host_intel": "SHODAN / CENSYS",
    "company": "COMPANY / EMPLOYEES",
    "dark_web": "DARK WEB",
    "onion_dirs": "ONION DIRECTORY",
    "tor_health": "TOR HEALTH",
    "dorks": "SEARCH DORKS",
    "buckets": "CLOUD BUCKETS",
    "takeover": "TAKEOVER CHECKS",
    "favicon": "FAVICON HASH",
    "meta": "EXIF / METADATA",
    "graph": "INVESTIGATION GRAPH",
    "plugin": "PLUGIN",
}


class ReportGenerator:
    """Generate OSINT reports in text / HTML / Markdown with confidence filtering."""

    def __init__(self, min_confidence: str = CONF_MEDIUM):
        self.min_confidence = min_confidence

    # ------------------------------------------------------------------ text
    def generate_text_report(self, results: Dict) -> str:
        report: List[str] = []
        report.append("=" * 80)
        report.append("EPIC OSINT TOOLKIT - INTELLIGENCE REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Target: {results.get('target', 'Unknown')}")
        report.append(f"Scan Type: {results.get('scan_type', 'Unknown')}")
        report.append(f"Min confidence shown: {self.min_confidence}")
        report.append(
            "Caveat: findings are scored claims, not proof. "
            "See the ledger for source, method, evidence, and false-positive notes."
        )
        report.append("=" * 80)
        report.append("")
        report.extend(self._text_findings_ledger(results))

        blob = results.get("results") or {}
        for key in self._ordered_keys(blob):
            data = blob[key]
            title = SECTION_TITLES.get(key, key.replace("_", " ").upper())
            section_lines = self._render_section_text(key, data)
            if not section_lines:
                continue
            report.append(title)
            report.append("-" * 80)
            report.extend(section_lines)
            report.append("")

        if results.get("correlation"):
            report.extend(self._render_correlation_text(results["correlation"]))

        report.append("=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)
        return "\n".join(report)

    def _ordered_keys(self, blob: Dict) -> List[str]:
        keys = list(blob.keys())
        ordered = [k for k in SECTION_ORDER if k in blob]
        ordered.extend(k for k in keys if k not in ordered)
        return ordered

    def _ensure_findings(self, results: Dict) -> List[Dict]:
        if "findings" not in results:
            annotate_results(results)
        return results.get("findings") or []

    def _text_findings_ledger(self, results: Dict) -> List[str]:
        rows = self._ensure_findings(results)
        summary = results.get("findings_summary") or {}
        lines: List[str] = [
            "FINDINGS LEDGER",
            "-" * 80,
            (
                f"Scored claims: {summary.get('total', len(rows))}  "
                f"confirmed={summary.get('confirmed', 0)}  "
                f"high={summary.get('high', 0)}  "
                f"medium={summary.get('medium', 0)}  "
                f"low={summary.get('low', 0)}  "
                f"unknown={summary.get('unknown', 0)}"
            ),
        ]
        trunc = results.get("findings_truncated") or 0
        if trunc:
            lines.append(f"(+{trunc} additional claims omitted from ledger cap)")
        lines.append("Each row is a hypothesis: source + method + evidence, not a verdict.")
        lines.append("")
        if not rows:
            lines.append("No scored findings in this scan.")
            lines.append("")
            return lines
        shown = 0
        for row in rows:
            if not meets_confidence(row.get("confidence"), self.min_confidence):
                continue
            shown += 1
            badge = confidence_badge(row.get("confidence"))
            lines.append(f"  {badge} [{row.get('module') or '?'}] {row.get('finding')}")
            lines.append(f"      source: {row.get('source') or '-'}")
            lines.append(f"      time:   {row.get('timestamp') or '-'}")
            lines.append(f"      method: {row.get('method') or '-'}")
            ev = row.get("evidence") or {}
            if isinstance(ev, dict) and ev:
                bits = [f"{k}={_fmt_val(v, 60)}" for k, v in list(ev.items())[:6]]
                lines.append(f"      evidence: {'; '.join(bits)}")
            if row.get("fp_notes"):
                lines.append(f"      fp notes: {row['fp_notes']}")
        low_hidden = sum(
            1 for r in rows
            if not meets_confidence(r.get("confidence"), self.min_confidence)
        )
        if shown == 0:
            lines.append("No findings at or above the min confidence threshold.")
        if low_hidden:
            lines.append("")
            lines.append(
                f"{low_hidden} lower-confidence claims omitted here; "
                "they remain in JSON under findings[]."
            )
        lines.append("")
        return lines

    def _render_section_text(self, key: str, data: Any) -> List[str]:
        if data in (None, "", [], {}):
            return []
        if key == "social" and isinstance(data, dict):
            return self._text_social(data)
        if key == "takeover" and isinstance(data, dict):
            return self._text_takeover(data)
        if key == "saas" and isinstance(data, dict):
            return self._text_saas(data)
        if key == "buckets" and isinstance(data, dict):
            return self._text_buckets(data)
        if key == "domain" and isinstance(data, dict):
            return self._text_domain(data)
        if key == "github" and isinstance(data, dict):
            return self._text_github(data)
        if key == "company" and isinstance(data, dict):
            return self._text_company(data)
        if key == "company_biz" and isinstance(data, dict):
            return self._text_company_biz(data)
        if key == "ports" and isinstance(data, dict):
            return self._text_ports(data)
        if key == "emails" and isinstance(data, dict):
            return self._text_emails(data)
        if key == "email_accounts" and isinstance(data, dict):
            return self._text_email_accounts(data)
        if key == "packages" and isinstance(data, dict):
            return self._text_packages(data)
        if key == "typosquats" and isinstance(data, dict):
            return self._text_typosquats(data)
        if key == "ip" and isinstance(data, dict):
            return self._text_ip(data)
        # generic structured dump (readable)
        return self._text_generic(data)

    def _text_social(self, data: Dict) -> List[str]:
        lines: List[str] = []
        summary = data.get("summary") or {}
        profiles = data.get("profiles") or {}

        # Prefer precomputed summary; rebuild if missing
        if not summary and profiles:
            try:
                from modules.social_intel import SocialIntel
                summary = SocialIntel().summarize_profiles(profiles)
            except Exception:
                summary = {}

        reliable = summary.get("reliable") or []
        low = summary.get("low_confidence") or []
        lines.append(
            f"Reliable profiles: {summary.get('reliable_count', len(reliable))}  |  "
            f"Low-confidence: {summary.get('low_confidence_count', len(low))}  |  "
            f"Not found: {summary.get('not_found_count', 0)}  |  "
            f"Unknown/blocked: {summary.get('unknown_count', 0)}"
        )
        if summary.get("note"):
            lines.append(f"Note: {summary['note']}")
        lines.append("")

        if reliable:
            lines.append("CONFIRMED / HIGH / MEDIUM (shown as real findings):")
            for row in reliable:
                badge = confidence_badge(row.get("confidence"))
                lines.append(f"  {badge} {row.get('platform')}: {row.get('url', '')}")
        else:
            lines.append("No reliable profile hits.")

        if low:
            lines.append("")
            lines.append("LOW CONFIDENCE (possible false positives — verify manually):")
            for row in low[:25]:
                badge = confidence_badge(row.get("confidence"))
                lines.append(
                    f"  {badge} {row.get('platform')}: {row.get('url', '')} "
                    f"({row.get('reason') or 'weak'})"
                )

        emails = data.get("email_addresses") or []
        if emails:
            lines.append("")
            lines.append("Verified / observed emails:")
            for em in emails[:30]:
                if isinstance(em, dict):
                    lines.append(
                        f"  {confidence_badge(em.get('confidence'))} "
                        f"{em.get('email')}  (source: {em.get('source', '?')})"
                    )
                else:
                    lines.append(f"  - {em}")

        pivots = data.get("email_guess_pivots") or []
        if pivots:
            lines.append("")
            lines.append("Unverified email guess pivots (NOT confirmed accounts):")
            for p in pivots[:10]:
                if isinstance(p, dict):
                    lines.append(f"  ? {p.get('pattern')} — {p.get('note', 'guess')}")
                else:
                    lines.append(f"  ? {p}")
        return lines

    def _text_takeover(self, data: Dict) -> List[str]:
        lines: List[str] = []
        lines.append(f"Hosts checked: {data.get('checked', 0)}")
        lines.append(f"Suspicious (medium/high): {data.get('suspicious', 0)}")
        if data.get("low_confidence") is not None:
            lines.append(f"Low-confidence suppressed noise: {data.get('low_confidence')}")
        if data.get("note"):
            lines.append(f"Note: {data['note']}")
        high = data.get("high_risk") or []
        findings = data.get("findings") or []
        show = high or [
            f for f in findings
            if f.get("risk") in ("high", "medium") and f.get("candidates")
        ]
        if not show:
            lines.append("No credible takeover candidates.")
            # still mention low-risk if present
            low = [f for f in findings if f.get("risk") == "low" and f.get("candidates")]
            if low:
                lines.append(f"({len(low)} low-confidence body-only matches suppressed or listed below)")
                for f in low[:5]:
                    svcs = ", ".join(
                        c.get("service", "?") for c in (f.get("candidates") or [])[:5]
                    )
                    lines.append(f"  [LOW] {f.get('host')}: {svcs}")
            return lines
        lines.append("")
        for f in show:
            lines.append(
                f"  [{(f.get('risk') or '?').upper()}] {f.get('host')}  "
                f"cname={f.get('cname') or '-'}  nxdomain={f.get('nxdomain')}  "
                f"http={f.get('http_status')}"
            )
            for c in f.get("candidates") or []:
                lines.append(
                    f"      - {c.get('service')}: cname_match={c.get('cname_match')} "
                    f"fingerprint={c.get('fingerprint_match')} "
                    f"{confidence_badge(c.get('confidence'))}"
                )
        return lines

    def _text_saas(self, data: Dict) -> List[str]:
        lines: List[str] = []
        lines.append(f"Domain: {data.get('domain')}  slug: {data.get('slug')}")
        lines.append(f"Reliable tenants: {data.get('count', len(data.get('found') or []))}")
        if data.get("note"):
            lines.append(f"Note: {data['note']}")
        found = data.get("found") or []
        if found:
            lines.append("")
            lines.append("Found:")
            for f in found:
                lines.append(
                    f"  {confidence_badge(f.get('confidence'))} {f.get('service')}: "
                    f"{f.get('url') or f.get('issuer') or f.get('namespace_type') or ''} "
                    f"(http={f.get('http', '-')})"
                )
        else:
            lines.append("No reliable SaaS tenants found.")
        low = data.get("low_confidence") or []
        if low:
            lines.append("")
            lines.append("Low confidence (verify manually):")
            for f in low[:15]:
                lines.append(f"  [LOW] {f.get('service')}: {f.get('url', '')}")
        return lines

    def _text_buckets(self, data: Dict) -> List[str]:
        lines: List[str] = []
        lines.append(f"Name: {data.get('name')}  probed: {data.get('probed', 0)}  hits: {data.get('hits', 0)}")
        if data.get("note"):
            lines.append(f"Note: {data['note']}")
        public = data.get("public") or []
        exists = data.get("exists") or []
        if public:
            lines.append("")
            lines.append("Publicly listable:")
            for b in public[:30]:
                lines.append(
                    f"  {confidence_badge(b.get('confidence'))} [{b.get('provider')}] "
                    f"{b.get('bucket')} — {b.get('url')}"
                )
        if exists:
            private = [b for b in exists if not b.get("public_list")]
            if private:
                lines.append("")
                lines.append("Exists (private / access denied):")
                for b in private[:30]:
                    lines.append(
                        f"  {confidence_badge(b.get('confidence'))} [{b.get('provider')}] "
                        f"{b.get('bucket')} — http {b.get('status')}"
                    )
        if not public and not exists:
            lines.append("No credible bucket hits.")
        low = data.get("low_confidence") or []
        if low:
            lines.append(f"Low-confidence signals suppressed from hits: {len(low)}")
        return lines

    def _text_domain(self, data: Dict) -> List[str]:
        lines: List[str] = []
        if data.get("domain"):
            lines.append(f"Domain: {data['domain']}")
        dns = data.get("dns_records") or {}
        if dns:
            lines.append("DNS Records:")
            for rt, values in dns.items():
                if not values:
                    continue
                if isinstance(values, (list, tuple)):
                    formatted = ", ".join(str(v) for v in values)
                elif isinstance(values, dict):
                    formatted = _fmt_val(values, 160)
                else:
                    formatted = str(values)
                lines.append(f"  {rt}: {formatted}")
        subs = data.get("subdomains") or []
        if subs:
            lines.append(f"Subdomains ({len(subs)}):")
            for s in subs[:40]:
                lines.append(f"  - {s}")
            if len(subs) > 40:
                lines.append(f"  ... +{len(subs) - 40} more")
        for k in ("whois", "ssl_info", "dnssec", "email_security"):
            if data.get(k):
                lines.append(f"{k}:")
                val = data[k]
                if isinstance(val, dict):
                    for sk, sv in list(val.items())[:20]:
                        if sv in (None, "", [], {}):
                            continue
                        lines.append(f"  {sk}: {_fmt_val(sv, 120)}")
                else:
                    lines.append(f"  {_fmt_val(val, 200)}")
        return lines

    def _text_github(self, data: Dict) -> List[str]:
        lines: List[str] = []
        profile = data.get("profile") or {}
        if profile:
            for k in ("login", "name", "company", "location", "email", "bio",
                      "public_repos", "followers", "following", "html_url", "blog"):
                if profile.get(k) not in (None, ""):
                    lines.append(f"  {k}: {profile.get(k)}")
        repos = data.get("repositories") or []
        if repos:
            lines.append(f"Repositories ({len(repos)}):")
            for repo in repos[:25]:
                if isinstance(repo, dict):
                    lines.append(
                        f"  - {repo.get('name') or repo.get('full_name')}: "
                        f"{repo.get('html_url') or repo.get('url') or ''}"
                    )
                else:
                    lines.append(f"  - {repo}")
        if data.get("email"):
            lines.append(f"Email: {data['email']}")
        return lines or ["No GitHub data."]

    def _text_company(self, data: Dict) -> List[str]:
        lines: List[str] = []
        if data.get("company"):
            lines.append(f"Company: {data['company']}")
        emps = data.get("employees") or []
        real_emps = []
        for e in emps:
            if not isinstance(e, dict):
                continue
            # Pivot-only placeholders (LinkedIn) — show separately
            if e.get("pivots") and not e.get("name") and not e.get("github_url"):
                lines.append("LinkedIn pivots (manual):")
                for pk, pv in (e.get("pivots") or {}).items():
                    lines.append(f"  {pk}: {pv}")
                continue
            real_emps.append(e)
        if real_emps:
            lines.append(f"Employees ({len(real_emps)}):")
            for emp in real_emps[:40]:
                conf = confidence_badge(emp.get("confidence")) if emp.get("confidence") else ""
                lines.append(
                    f"  {conf} {emp.get('name', 'N/A')} | {emp.get('title', '')} | "
                    f"{emp.get('company', '')} | {emp.get('github_url') or emp.get('gitlab_url') or ''}"
                )
                if emp.get("email"):
                    lines.append(f"      email: {emp['email']}")
        leaks = data.get("leaked_credentials") or []
        if leaks:
            lines.append(f"Leaked credentials: {len(leaks)}")
            for leak in leaks[:20]:
                lines.append(
                    f"  - {leak.get('employee') or leak.get('email')}: "
                    f"{leak.get('type', '')} breaches={len(leak.get('breaches') or [])}"
                )
        repos = data.get("repositories") or []
        if repos:
            lines.append(f"Repositories linked to employees: {len(repos)}")
            for repo in repos[:20]:
                lines.append(
                    f"  - {repo.get('name')} ({repo.get('platform', '')}): {repo.get('url', '')}"
                )
        return lines or ["No company employee data."]

    def _text_company_biz(self, data: Dict) -> List[str]:
        lines: List[str] = []
        if data.get("company"):
            lines.append(f"Company: {data['company']}")
        lines.append(f"Hit count: {data.get('hit_count', 0)}")
        for oc in (data.get("opencorporates") or [])[:15]:
            lines.append(
                f"  [OC] {oc.get('name')} | {oc.get('jurisdiction')} | "
                f"{oc.get('company_number')} | {oc.get('current_status')} | "
                f"{oc.get('opencorporates_url') or ''}"
            )
        for sec in (data.get("sec_edgar") or [])[:15]:
            conf = confidence_badge(sec.get("confidence")) if sec.get("confidence") else ""
            lines.append(
                f"  {conf} [SEC] {sec.get('name')} ticker={sec.get('ticker')} "
                f"CIK={sec.get('cik')} {sec.get('edgar_url') or ''}"
            )
        pivots = data.get("pivots") or []
        if pivots:
            lines.append("Pivots:")
            for p in pivots[:10]:
                if isinstance(p, dict):
                    lines.append(f"  - {p.get('name')}: {p.get('url')}")
        return lines

    def _text_ports(self, data: Dict) -> List[str]:
        lines: List[str] = []
        ports = data.get("open_ports") or []
        lines.append(f"Open ports: {len(ports)}")
        services = data.get("services") or {}
        for port in ports:
            svc = services.get(port) or services.get(str(port)) or "Unknown"
            lines.append(f"  - {port}: {svc}")
        return lines

    def _text_emails(self, data: Dict) -> List[str]:
        lines: List[str] = []
        emails = data.get("emails") or []
        lines.append(f"Emails found: {len(emails)}")
        for em in emails[:40]:
            if isinstance(em, dict):
                lines.append(
                    f"  {confidence_badge(em.get('confidence'))} {em.get('email') or em} "
                    f"({em.get('source', '')})"
                )
            else:
                lines.append(f"  - {em}")
        for k in ("mx", "smtp", "patterns", "sources"):
            if data.get(k):
                lines.append(f"{k}: {_fmt_val(data[k], 200)}")
        return lines

    def _text_email_accounts(self, data: Dict) -> List[str]:
        lines: List[str] = []
        lines.append(f"Email: {data.get('email')}")
        summary = data.get("summary") or {}
        if summary:
            lines.append(
                f"Registered: {summary.get('registered', 0)}  "
                f"Not registered: {summary.get('not_registered', 0)}  "
                f"Unknown: {summary.get('unknown', 0)}"
            )
        for row in data.get("found") or []:
            lines.append(
                f"  [YES] {row.get('platform')} http={row.get('status')} {row.get('url') or ''}"
            )
        for row in data.get("not_found") or []:
            lines.append(f"  [no]  {row.get('platform')}")
        for row in (data.get("unknown") or [])[:15]:
            lines.append(f"  [?]   {row.get('platform')}: {row.get('note') or row.get('error') or ''}")
        return lines

    def _text_packages(self, data: Dict) -> List[str]:
        lines: List[str] = []
        lines.append(f"Query: {data.get('query')}  hits: {data.get('hit_count', 0)}")
        for reg in ("npm", "pypi", "crates", "rubygems", "dockerhub"):
            items = data.get(reg) or []
            if not items:
                continue
            lines.append(f"{reg} ({len(items)}):")
            for it in items[:10]:
                if isinstance(it, dict):
                    lines.append(
                        f"  {confidence_badge(it.get('confidence'))} {it.get('name')} "
                        f"{it.get('version') or ''} — {it.get('url') or ''}"
                    )
                    if it.get("description"):
                        lines.append(f"      {it['description'][:100]}")
        return lines

    def _text_typosquats(self, data: Dict) -> List[str]:
        lines: List[str] = []
        lines.append(
            f"Domain: {data.get('domain')}  generated: {data.get('generated')}  "
            f"resolved: {data.get('resolved_count', 0)}"
        )
        if data.get("note"):
            lines.append(f"Note: {data['note']}")
        resolved = data.get("resolved") or []
        if resolved:
            lines.append("Resolved lookalikes (verify manually):")
            for row in resolved[:40]:
                if isinstance(row, dict):
                    ips = ", ".join(row.get("ips") or [])
                    lines.append(f"  - {row.get('domain')}: {ips}")
                else:
                    lines.append(f"  - {row}")
        else:
            lines.append("No resolved lookalikes.")
        return lines

    def _text_ip(self, data: Dict) -> List[str]:
        lines: List[str] = []
        for k in ("ip", "hostname", "country", "city", "isp", "org", "as", "query"):
            if data.get(k) not in (None, ""):
                lines.append(f"  {k}: {data[k]}")
        for k in ("asn", "risk", "geo", "ptr"):
            if data.get(k):
                lines.append(f"  {k}: {_fmt_val(data[k], 160)}")
        # dump remaining scalars
        skip = {"ip", "hostname", "country", "city", "isp", "org", "as", "query", "asn", "risk", "geo", "ptr"}
        for k, v in data.items():
            if k in skip or v in (None, "", [], {}):
                continue
            if isinstance(v, (dict, list)):
                lines.append(f"  {k}: {_fmt_val(v, 160)}")
            else:
                lines.append(f"  {k}: {v}")
        return lines or ["No IP data."]

    def _text_generic(self, data: Any) -> List[str]:
        lines: List[str] = []
        if isinstance(data, dict):
            if data.get("error"):
                lines.append(f"Error: {data['error']}")
            for k, v in data.items():
                if k == "error" or v in (None, "", [], {}):
                    continue
                if isinstance(v, list):
                    lines.append(f"{k} ({len(v)}):")
                    for item in v[:30]:
                        if isinstance(item, dict):
                            label = (
                                item.get("name") or item.get("url") or item.get("email")
                                or item.get("host") or item.get("domain")
                                or item.get("platform") or item.get("onion")
                                or _fmt_val(item, 100)
                            )
                            conf = item.get("confidence")
                            prefix = f"{confidence_badge(conf)} " if conf else "  - "
                            lines.append(f"  {prefix}{label}")
                            # show a few extra fields
                            for sk in ("url", "status", "risk", "title", "version", "description"):
                                if sk in item and item[sk] not in (None, "", label):
                                    lines.append(f"      {sk}: {_fmt_val(item[sk], 100)}")
                        else:
                            lines.append(f"  - {_fmt_val(item, 120)}")
                    if len(v) > 30:
                        lines.append(f"  ... +{len(v) - 30} more")
                elif isinstance(v, dict):
                    lines.append(f"{k}:")
                    for sk, sv in list(v.items())[:25]:
                        if sv in (None, "", [], {}):
                            continue
                        lines.append(f"  {sk}: {_fmt_val(sv, 120)}")
                else:
                    lines.append(f"{k}: {_fmt_val(v, 160)}")
        else:
            lines.append(_fmt_val(data, 500))
        return lines

    def _render_correlation_text(self, corr: Dict) -> List[str]:
        lines = ["CORRELATION", "-" * 80]
        lines.append(f"  Detected type: {corr.get('detected_type')}")
        for k, n in (corr.get("counts") or {}).items():
            lines.append(f"  {k}: {n}")
        ents = corr.get("entities") or {}
        for etype, values in ents.items():
            if not values:
                continue
            lines.append(f"  {etype}:")
            for v in list(values)[:20]:
                lines.append(f"    - {v}")
        links = corr.get("links") or []
        if links:
            lines.append(f"  links ({len(links)}):")
            for link in links[:30]:
                if isinstance(link, dict):
                    lines.append(f"    {link.get('from', '?')} --> {link.get('to', '?')}")
        lines.append("")
        return lines

    # ------------------------------------------------------------------ html
    def generate_html_report(self, results: Dict) -> str:
        html: List[str] = []
        html.append("<!DOCTYPE html>")
        html.append("<html><head>")
        html.append("<meta charset='utf-8'/>")
        html.append("<title>OSINT Intelligence Report</title>")
        html.append("<style>")
        html.append("""
            body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #0f1419; color: #e7e9ea; }
            .header { background: linear-gradient(135deg,#1a2332,#243447); color: white; padding: 24px; border-radius: 8px; border: 1px solid #38444d; }
            .section { background: #15202b; margin: 18px 0; padding: 20px; border-radius: 8px; border: 1px solid #38444d; }
            .section h2 { color: #1d9bf0; border-bottom: 2px solid #1d9bf0; padding-bottom: 8px; margin-top: 0; }
            .item { margin: 8px 0; padding: 10px; background: #192734; border-left: 3px solid #1d9bf0; border-radius: 0 4px 4px 0; }
            .item.low { border-left-color: #f4212e; opacity: 0.85; }
            .item.ok { border-left-color: #00ba7c; }
            .badge { display: inline-block; font-size: 11px; padding: 2px 8px; border-radius: 10px; margin-right: 6px; font-weight: 600; }
            .badge.confirmed, .badge.high { background: #00ba7c; color: #000; }
            .badge.medium { background: #1d9bf0; color: #fff; }
            .badge.low { background: #f4212e; color: #fff; }
            .badge.unknown { background: #536471; color: #fff; }
            .meta { color: #8b98a5; font-size: 14px; }
            a.url { color: #1d9bf0; text-decoration: none; }
            a.url:hover { text-decoration: underline; }
            table { width: 100%; border-collapse: collapse; margin: 10px 0; }
            th, td { padding: 10px; text-align: left; border-bottom: 1px solid #38444d; }
            th { background: #192734; color: #e7e9ea; }
            .note { color: #8b98a5; font-style: italic; margin: 8px 0; }
            .port { display: inline-block; margin: 4px; padding: 4px 10px; background: #1d9bf0; color: #fff; border-radius: 4px; font-size: 13px; }
            table.findings td { vertical-align: top; font-size: 13px; }
            table.findings th { font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; }
        """)
        html.append("</style></head><body>")
        html.append("<div class='header'>")
        html.append("<h1>EPIC OSINT TOOLKIT — Intelligence Report</h1>")
        html.append(f"<p class='meta'>Generated: {_esc(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</p>")
        html.append(f"<p class='meta'>Target: <strong>{_esc(results.get('target', 'Unknown'))}</strong></p>")
        html.append(f"<p class='meta'>Scan Type: {_esc(results.get('scan_type', 'Unknown'))}</p>")
        html.append(f"<p class='meta'>Min confidence: {_esc(self.min_confidence)}</p>")
        html.append(
            "<p class='meta'>Findings are scored claims, not proof. "
            "Use the ledger for source, method, evidence, and false-positive notes.</p>"
        )
        html.append("</div>")
        html.extend(self._html_findings_ledger(results))

        # Convert text sections to HTML via structured render
        blob = results.get("results") or {}
        for key in self._ordered_keys(blob):
            data = blob[key]
            title = SECTION_TITLES.get(key, key.replace("_", " ").title())
            body_lines = self._render_section_text(key, data)
            if not body_lines:
                continue
            html.append("<div class='section'>")
            html.append(f"<h2>{_esc(title)}</h2>")
            html.extend(self._lines_to_html(body_lines))
            html.append("</div>")

        if results.get("correlation"):
            html.append("<div class='section'><h2>Correlation</h2>")
            html.extend(self._lines_to_html(self._render_correlation_text(results["correlation"])))
            html.append("</div>")

        html.append("</body></html>")
        return "\n".join(html)

    def _html_findings_ledger(self, results: Dict) -> List[str]:
        rows = [
            r for r in self._ensure_findings(results)
            if meets_confidence(r.get("confidence"), self.min_confidence)
        ]
        summary = results.get("findings_summary") or {}
        out = ["<div class='section'>", "<h2>Findings ledger</h2>"]
        out.append(
            "<p class='note'>Each row is a hypothesis with provenance. "
            "Corroborate before acting.</p>"
        )
        out.append(
            f"<p class='meta'>confirmed {summary.get('confirmed', 0)} · "
            f"high {summary.get('high', 0)} · medium {summary.get('medium', 0)} · "
            f"low {summary.get('low', 0)} · unknown {summary.get('unknown', 0)}</p>"
        )
        if not rows:
            out.append("<p>No scored findings at or above min confidence.</p></div>")
            return out
        out.append("<table class='findings'><thead><tr>")
        for col in (
            "Finding", "Source", "Timestamp", "Method",
            "Confidence", "Evidence", "False-positive notes",
        ):
            out.append(f"<th>{col}</th>")
        out.append("</tr></thead><tbody>")
        for row in rows:
            conf = str(row.get("confidence") or "unknown")
            ev = row.get("evidence") or {}
            if isinstance(ev, dict):
                ev_s = "; ".join(f"{k}={_fmt_val(v, 50)}" for k, v in list(ev.items())[:6])
            else:
                ev_s = _fmt_val(ev, 80)
            out.append("<tr>")
            out.append(f"<td>{self._linkify(_esc(row.get('finding')))}</td>")
            out.append(f"<td>{_esc(row.get('source'))}</td>")
            out.append(f"<td>{_esc(row.get('timestamp'))}</td>")
            out.append(f"<td>{_esc(row.get('method'))}</td>")
            out.append(
                f"<td><span class='badge {_esc(conf)}'>{_esc(conf.upper())}</span></td>"
            )
            out.append(f"<td>{_esc(ev_s)}</td>")
            out.append(f"<td>{_esc(row.get('fp_notes'))}</td>")
            out.append("</tr>")
        out.append("</tbody></table></div>")
        return out

    def _lines_to_html(self, lines: List[str]) -> List[str]:
        out: List[str] = []
        for line in lines:
            if not line.strip():
                continue
            low = line.lower()
            cls = "item"
            if "[low]" in low or "low confidence" in low:
                cls += " low"
            elif "[confirmed]" in low or "[high]" in low or "[yes]" in low:
                cls += " ok"
            # auto-link URLs
            escaped = _esc(line)
            escaped = self._linkify(escaped)
            # badge coloring
            for name in ("CONFIRMED", "HIGH", "MED", "MEDIUM", "LOW", "?"):
                token = f"[{name}]"
                if token in line or f"[{name.lower()}]" in line:
                    pass
            escaped = escaped.replace("[CONFIRMED]", "<span class='badge confirmed'>CONFIRMED</span>")
            escaped = escaped.replace("[HIGH]", "<span class='badge high'>HIGH</span>")
            escaped = escaped.replace("[MED]", "<span class='badge medium'>MED</span>")
            escaped = escaped.replace("[LOW]", "<span class='badge low'>LOW</span>")
            escaped = escaped.replace("[?]", "<span class='badge unknown'>?</span>")
            escaped = escaped.replace("[YES]", "<span class='badge confirmed'>YES</span>")
            if line.startswith("Note:"):
                out.append(f"<p class='note'>{escaped}</p>")
            elif line.endswith(":") and not line.startswith(" "):
                out.append(f"<h3>{escaped}</h3>")
            else:
                out.append(f"<div class='{cls}'>{escaped}</div>")
        return out

    @staticmethod
    def _linkify(escaped: str) -> str:
        import re
        return re.sub(
            r"(https?://[^\s&lt;]+)",
            r"<a class='url' href='\1' target='_blank' rel='noopener'>\1</a>",
            escaped,
        )

    # -------------------------------------------------------------- markdown
    def generate_markdown_report(self, results: Dict) -> str:
        lines = [
            "# Epic OSINT Toolkit — Intelligence Report",
            "",
            f"- **Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"- **Target:** `{results.get('target', 'Unknown')}`",
            f"- **Scan type:** `{results.get('scan_type', 'Unknown')}`",
            f"- **Timestamp:** `{results.get('timestamp', '')}`",
            f"- **Min confidence:** `{self.min_confidence}`",
            "",
            "> Findings are scored claims, not proof. "
            "Each ledger row has source, method, evidence, and false-positive notes.",
            "",
        ]
        lines.extend(self._md_findings_ledger(results))
        blob = results.get("results") or {}
        for key in self._ordered_keys(blob):
            data = blob[key]
            title = SECTION_TITLES.get(key, key.replace("_", " ").title())
            body = self._render_section_text(key, data)
            if not body:
                continue
            lines.append(f"## {title}")
            lines.append("")
            for bl in body:
                if not bl.strip():
                    lines.append("")
                elif bl.endswith(":") and not bl.startswith(" "):
                    lines.append(f"### {bl.rstrip(':')}")
                    lines.append("")
                else:
                    # keep indentation as markdown list-ish
                    if bl.startswith("  "):
                        lines.append(f"- {bl.strip()}")
                    else:
                        lines.append(bl)
            lines.append("")
        if results.get("correlation"):
            lines.append("## Correlation")
            lines.append("")
            for bl in self._render_correlation_text(results["correlation"]):
                if bl.strip() and bl not in ("CORRELATION", "-" * 80):
                    lines.append(bl if bl.startswith("  ") else f"- {bl}")
            lines.append("")
        return "\n".join(lines)

    def _md_findings_ledger(self, results: Dict) -> List[str]:
        rows = [
            r for r in self._ensure_findings(results)
            if meets_confidence(r.get("confidence"), self.min_confidence)
        ]
        summary = results.get("findings_summary") or {}
        out = [
            "## Findings ledger",
            "",
            (
                f"confirmed {summary.get('confirmed', 0)} · high {summary.get('high', 0)} · "
                f"medium {summary.get('medium', 0)} · low {summary.get('low', 0)} · "
                f"unknown {summary.get('unknown', 0)}"
            ),
            "",
        ]
        if not rows:
            out.extend(["No scored findings at or above min confidence.", ""])
            return out
        out.append(
            "| Finding | Source | Timestamp | Method | Confidence | Evidence | False-positive notes |"
        )
        out.append("|---|---|---|---|---|---|---|")
        for row in rows:
            ev = row.get("evidence") or {}
            if isinstance(ev, dict):
                ev_s = "; ".join(f"{k}={_fmt_val(v, 40)}" for k, v in list(ev.items())[:4])
            else:
                ev_s = _fmt_val(ev, 60)
            cells = [
                str(row.get("finding") or "").replace("|", "\\|"),
                str(row.get("source") or "").replace("|", "\\|"),
                str(row.get("timestamp") or ""),
                str(row.get("method") or ""),
                str(row.get("confidence") or ""),
                ev_s.replace("|", "\\|"),
                str(row.get("fp_notes") or "").replace("|", "\\|"),
            ]
            out.append("| " + " | ".join(cells) + " |")
        out.append("")
        return out

    # --------------------------------------------------------------- summary
    def print_summary(self, results: Dict):
        print("\n" + "=" * 60)
        print("SCAN SUMMARY")
        print("=" * 60)
        print(f"Target: {results.get('target', 'Unknown')}")
        print(f"Type: {results.get('scan_type', 'Unknown')}")
        self._ensure_findings(results)
        fs = results.get("findings_summary") or {}
        if fs.get("total"):
            print(
                f"Findings: {fs.get('total', 0)}  "
                f"(confirmed {fs.get('confirmed', 0)} / high {fs.get('high', 0)} / "
                f"medium {fs.get('medium', 0)} / low {fs.get('low', 0)})"
            )

        res = results.get("results", {})

        if "domain" in res:
            domain = res["domain"]
            if "subdomains" in domain:
                print(f"Subdomains Found: {len(domain.get('subdomains', []))}")
            if "dns_records" in domain:
                print(f"DNS Records: {len(domain.get('dns_records', {}))}")

        if "ports" in res:
            ports = res["ports"]
            print(f"Open Ports: {len(ports.get('open_ports', []))}")

        if "emails" in res:
            emails = res["emails"]
            print(f"Emails Found: {len(emails.get('emails', []))}")

        if "social" in res:
            social = res["social"]
            summary = social.get("summary") or {}
            if summary:
                print(
                    f"Social (reliable): {summary.get('reliable_count', 0)}  "
                    f"low-conf: {summary.get('low_confidence_count', 0)}"
                )
            elif "profiles" in social:
                found = sum(
                    1 for _, info in social["profiles"].items()
                    if info.get("exists") is True
                    and meets_confidence(info.get("confidence"), CONF_MEDIUM)
                )
                print(f"Social Profiles (medium+): {found}")

        if "takeover" in res:
            t = res["takeover"]
            print(f"Takeover suspicious: {t.get('suspicious', 0)}  high: {len(t.get('high_risk') or [])}")

        if "saas" in res:
            print(f"SaaS tenants (reliable): {res['saas'].get('count', 0)}")

        if "buckets" in res:
            print(f"Cloud buckets (reliable): {res['buckets'].get('hits', 0)}")

        if "github" in res:
            github = res["github"]
            profile = github.get("profile") or {}
            if profile.get("login"):
                print(f"GitHub User: {profile.get('login')}")
                print(f"GitHub Repos: {profile.get('public_repos', 0)}")

        if "company" in res:
            company = res["company"]
            emps = [
                e for e in (company.get("employees") or [])
                if isinstance(e, dict) and (e.get("name") or e.get("github_url"))
            ]
            print(f"Employees: {len(emps)}")
            print(f"Leaked Credentials: {len(company.get('leaked_credentials', []))}")

        if "wayback" in res:
            print(f"Wayback URLs: {res['wayback'].get('total', len(res['wayback'].get('urls') or []))}")
        if "ip" in res:
            ip = res["ip"]
            print(f"IP: {ip.get('ip')}  ASN: {(ip.get('asn') or {}).get('asn')}  Risk: {(ip.get('risk') or {}).get('score')}")
        if results.get("correlation"):
            c = results["correlation"].get("counts") or {}
            print(f"Correlated entities: {sum(c.values()) if c else 0}")

        print("=" * 60)
