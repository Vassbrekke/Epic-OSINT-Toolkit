"""Shared result-quality helpers — confidence scoring, provenance, soft-404.

Used by probe modules to cut false positives and by report generators
to surface high-confidence findings first. Every scored hit should carry
source, method, timestamp, evidence, and false-positive notes.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

# Confidence levels (ordered weakest → strongest)
CONF_UNKNOWN = "unknown"
CONF_LOW = "low"
CONF_MEDIUM = "medium"
CONF_HIGH = "high"
CONF_CONFIRMED = "confirmed"

_CONF_RANK = {
    CONF_UNKNOWN: 0,
    CONF_LOW: 1,
    CONF_MEDIUM: 2,
    CONF_HIGH: 3,
    CONF_CONFIRMED: 4,
}

# Generic soft-404 / empty-account body snippets (case-insensitive)
SOFT_404_HINTS: Tuple[str, ...] = (
    "not found",
    "doesn't exist",
    "does not exist",
    "page not found",
    "user not found",
    "profile not found",
    "account not found",
    "no such user",
    "couldn't find",
    "could not find",
    "sorry, this page",
    "this page isn't available",
    "this page is not available",
    "page does not exist",
    "nobody by that name",
    "no users found",
    "user does not exist",
    "account suspended",
    "account doesn't exist",
    "there isn't a github pages site here",
    "the page you were looking for doesn't exist",
    "we couldn't find that page",
    "sorry, nobody on reddit goes by that name",
    "hmm...this page doesn’t exist",
    "hmm...this page doesn't exist",
    "this account doesn’t exist",
    "this account doesn't exist",
    "sorry, that page doesn’t exist",
    "sorry, that page doesn't exist",
    "the specified key does not exist",
    "nosuchbucket",
    "the specified bucket does not exist",
    "no such app",
    "repository not found",
    "project not found",
    "nothing to see here",
    "content not found",
    "error 404",
    "404 error",
    "http 404",
    "status: 404",
)

# Paths / URL fragments that mean the probe landed on a generic page, not a profile
GENERIC_PATH_HINTS: Tuple[str, ...] = (
    "/login",
    "/signin",
    "/sign-in",
    "/signup",
    "/sign-up",
    "/register",
    "/join",
    "/explore",
    "/search",
    "/discover",
    "/consent",
    "/accounts/login",
    "/typo",
    "/404",
    "/error",
    "/not-found",
    "/home",
    "/about",
    "/pricing",
    "/download",
)

_TITLE_404_RE = re.compile(
    r"(404|not\s*found|doesn.?t exist|page not found|error|oops)",
    re.I,
)


def conf_rank(level: Optional[str]) -> int:
    return _CONF_RANK.get((level or CONF_UNKNOWN).lower(), 0)


def meets_confidence(level: Optional[str], minimum: str = CONF_MEDIUM) -> bool:
    return conf_rank(level) >= conf_rank(minimum)


def body_has_soft_404(text: str, extra_hints: Sequence[str] = ()) -> bool:
    """True when body strongly suggests a soft-404 / missing resource."""
    if not text:
        return False
    sample = text[:12000].lower()
    for h in SOFT_404_HINTS:
        if h in sample:
            return True
    for h in extra_hints:
        if h and h.lower() in sample:
            return True
    return False


def title_looks_missing(title: str) -> bool:
    if not title:
        return False
    return bool(_TITLE_404_RE.search(title))


def url_looks_generic(final_url: str, expected_username: str = "") -> bool:
    """True if final URL is a login/search/consent/home page rather than a profile."""
    if not final_url:
        return False
    try:
        parsed = urlparse(final_url)
    except ValueError:
        return False
    path = (parsed.path or "").lower()
    query = (parsed.query or "").lower()
    full = f"{path}?{query}"
    for hint in GENERIC_PATH_HINTS:
        if hint in full:
            return True
    # redirected to bare domain root
    if path in ("", "/"):
        # ok for some platforms (tumblr subdomain style handled elsewhere)
        if not expected_username:
            return True
    # username evaporated from path/host after redirects
    if expected_username:
        uname = expected_username.lower().strip()
        host = (parsed.netloc or "").lower()
        hay = f"{host}{path}"
        if uname and uname not in hay and uname.replace(".", "") not in hay:
            # allow numeric id redirects (roblox etc.) — path still has digits
            if not re.search(r"/\d{4,}", path):
                return True
    return False


def username_still_in_url(final_url: str, username: str) -> bool:
    if not final_url or not username:
        return False
    u = username.lower()
    try:
        p = urlparse(final_url)
        hay = f"{(p.netloc or '').lower()}{(p.path or '').lower()}"
    except ValueError:
        hay = final_url.lower()
    return u in hay or u.replace(".", "") in hay or u.replace("_", "") in hay


def extract_title(html: str) -> str:
    if not html:
        return ""
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:200]


def score_http_probe(
    *,
    status_code: Optional[int],
    final_url: str = "",
    request_url: str = "",
    body: str = "",
    username: str = "",
    soft_404_extra: Sequence[str] = (),
    require_username_in_url: bool = True,
    ok_codes: Sequence[int] = (200,),
) -> Tuple[Optional[bool], str, str]:
    """
    Generic HTTP existence decision.

    Returns (exists, confidence, reason):
      exists: True / False / None (unknown)
      confidence: confirmed|high|medium|low|unknown
      reason: short diagnostic string
    """
    if status_code is None:
        return None, CONF_UNKNOWN, "no_response"

    if status_code == 404 or status_code == 410:
        return False, CONF_HIGH, f"http_{status_code}"

    if status_code in (401, 403, 429):
        return None, CONF_UNKNOWN, f"blocked_{status_code}"

    if status_code >= 400:
        return False, CONF_MEDIUM, f"http_{status_code}"

    title = extract_title(body)
    if body_has_soft_404(body, soft_404_extra) or title_looks_missing(title):
        return False, CONF_HIGH, "soft_404"

    fu = final_url or request_url
    if fu and url_looks_generic(fu, username):
        return False, CONF_MEDIUM, "generic_redirect"

    if require_username_in_url and username and fu and not username_still_in_url(fu, username):
        # numeric profile redirects (e.g. roblox) are allowed above via digit path
        if not re.search(r"/\d{4,}", urlparse(fu).path or ""):
            return False, CONF_MEDIUM, "username_lost_in_redirect"

    if status_code in ok_codes:
        conf = CONF_HIGH if (not require_username_in_url or username_still_in_url(fu, username)) else CONF_MEDIUM
        return True, conf, f"http_{status_code}"

    if status_code in (301, 302, 303, 307, 308):
        # redirect without follow — weak signal
        return None, CONF_LOW, f"redirect_{status_code}"

    return None, CONF_UNKNOWN, f"http_{status_code}"


def filter_by_confidence(
    items: Iterable[Dict[str, Any]],
    *,
    min_confidence: str = CONF_MEDIUM,
    conf_key: str = "confidence",
    exists_key: str = "exists",
    require_exists: bool = True,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        if require_exists and it.get(exists_key) is not True:
            continue
        if meets_confidence(it.get(conf_key), min_confidence):
            out.append(it)
    return out


def summarize_confidence(items: Iterable[Dict[str, Any]], conf_key: str = "confidence") -> Dict[str, int]:
    counts = {c: 0 for c in _CONF_RANK}
    total = 0
    for it in items:
        if not isinstance(it, dict):
            continue
        total += 1
        c = (it.get(conf_key) or CONF_UNKNOWN).lower()
        if c not in counts:
            c = CONF_UNKNOWN
        counts[c] += 1
    counts["total"] = total
    return counts


def confidence_badge(level: Optional[str]) -> str:
    lv = (level or CONF_UNKNOWN).lower()
    return {
        CONF_CONFIRMED: "[CONFIRMED]",
        CONF_HIGH: "[HIGH]",
        CONF_MEDIUM: "[MED]",
        CONF_LOW: "[LOW]",
        CONF_UNKNOWN: "[?]",
    }.get(lv, "[?]")


# ---------------------------------------------------------------------------
# Provenance — every finding should be a scored claim, not implied fact
# ---------------------------------------------------------------------------

def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


DEFAULT_FP_NOTES = (
    "OSINT hits are hypotheses. Corroborate with a second independent source "
    "before treating this as fact."
)

# Per-module source / method / false-positive guidance
MODULE_PROVENANCE: Dict[str, Dict[str, str]] = {
    "social": {
        "source": "live HTTP profile probe",
        "method": "username_http_existence",
        "fp_notes": "Soft-404 and login redirects often return HTTP 200. Low-confidence hits are not confirmed accounts.",
    },
    "github": {
        "source": "api.github.com",
        "method": "github_rest",
        "fp_notes": "Login collisions and renamed users can look like a match. Confirm html_url and user id.",
    },
    "buckets": {
        "source": "cloud object-store HTTP probe",
        "method": "bucket_name_enumeration",
        "fp_notes": "Generic 403/redirects are weak. Treat as real only with ListBucket XML, AccessDenied XML, or equivalent.",
    },
    "takeover": {
        "source": "DNS CNAME + HTTP fingerprint",
        "method": "dangling_cname_fingerprint",
        "fp_notes": "Body-only fingerprint matches on live sites are usually collisions. High confidence requires CNAME + dangling claim page.",
    },
    "saas": {
        "source": "SaaS/IdP public endpoints",
        "method": "tenant_probe",
        "fp_notes": "HTTP 200 on a vanity host is not proof of a live tenant. Confirm via Azure realm / MX / TXT.",
    },
    "packages": {
        "source": "public package registries",
        "method": "registry_name_search",
        "fp_notes": "Fuzzy name search is noisy. Prefer exact/prefix matches; typosquat-like hits need manual review.",
    },
    "company": {
        "source": "GitHub/GitLab/website staff scrape",
        "method": "employee_discovery",
        "fp_notes": "Username or org-name collisions are common. Prefer company-field or group-membership matches.",
    },
    "company_biz": {
        "source": "OpenCorporates / SEC EDGAR",
        "method": "registry_name_match",
        "fp_notes": "Short company names collide. Ignore low-score substring hits; confirm CIK/jurisdiction.",
    },
    "employees": {
        "source": "GitHub/GitLab/website staff scrape",
        "method": "employee_discovery",
        "fp_notes": "Same-name people at other orgs will appear. Require a company-field or org-membership link.",
    },
    "emails": {
        "source": "crawl / pattern / SMTP",
        "method": "email_discovery",
        "fp_notes": "Generated patterns and crawled strings are not verified mailboxes unless SMTP/API confirms.",
    },
    "email_accounts": {
        "source": "site registration oracles",
        "method": "email_account_check",
        "fp_notes": "Registration oracles lie (rate-limit, catch-all, timing). Treat as a lead, not proof of an account.",
    },
    "person": {
        "source": "name parse + people-search pivots",
        "method": "person_seed_generation",
        "fp_notes": "Seeds and search URLs are not identified individuals. Common names produce heavy collisions.",
    },
    "domain": {
        "source": "DNS / CT / WHOIS / SSL",
        "method": "domain_record_lookup",
        "fp_notes": "WHOIS privacy and stale CT SANs are common. DNS answers depend on resolver view.",
    },
    "ip": {
        "source": "ip-api.com / BGPView",
        "method": "ip_geo_asn",
        "fp_notes": "Geo/ASN feeds lag and mis-attribute anycast/VPN ranges. Risk scores are heuristic.",
    },
    "asn": {
        "source": "bgpview.io",
        "method": "asn_netblock_lookup",
        "fp_notes": "Announced prefixes change; historical WHOIS on a prefix is not current ownership.",
    },
    "related_domains": {
        "source": "CT SANs / SSL / same-IP",
        "method": "domain_pivot",
        "fp_notes": "Shared hosting and CDN IPs associate unrelated tenants. CT SANs include expired names.",
    },
    "typosquats": {
        "source": "generated lookalikes + DNS",
        "method": "typosquat_resolve",
        "fp_notes": "A resolved lookalike is not proof of impersonation. Many are parking/MX catch-alls.",
    },
    "passive_dns": {
        "source": "passive DNS aggregator",
        "method": "historical_dns",
        "fp_notes": "Historical A/CNAME data is not current. Shared IPs over-associate hosts.",
    },
    "abuse": {
        "source": "DNSBL / reputation lists",
        "method": "dnsbl_lookup",
        "fp_notes": "Listings lag, false-list, and cover whole ranges. Not a malware verdict.",
    },
    "favicon": {
        "source": "favicon mmh3 hash",
        "method": "favicon_hash_pivot",
        "fp_notes": "Default CMS/favicon hashes collide across unrelated sites.",
    },
    "host_intel": {
        "source": "Shodan / Censys",
        "method": "host_api_enrichment",
        "fp_notes": "Banner/index age varies. Open ports in an index may already be closed.",
    },
    "ports": {
        "source": "TCP connect / optional nmap",
        "method": "port_scan",
        "fp_notes": "Filtered vs closed is easy to misread through middleboxes. Banners can be spoofed.",
    },
    "website": {
        "source": "HTTP crawl",
        "method": "web_crawl_extract",
        "fp_notes": "Extracted emails/phones/comments include third-party widgets and example text.",
    },
    "urls": {
        "source": "shortener / archive hunt",
        "method": "url_hunter",
        "fp_notes": "Shortener hits and CDX rows are not confirmation the resource still exists.",
    },
    "wayback": {
        "source": "web.archive.org CDX",
        "method": "wayback_cdx",
        "fp_notes": "Archive snapshots go stale; CDX can include scanner noise and unrelated query strings.",
    },
    "js_secrets": {
        "source": "JS / HTML regex",
        "method": "secret_pattern_scan",
        "fp_notes": "Regex hits include public tokens, examples, and hashes. Never assume a live secret.",
    },
    "screenshot": {
        "source": "headless Chrome",
        "method": "page_screenshot",
        "fp_notes": "A screenshot is a point-in-time render, not proof of ownership or current content.",
    },
    "dorks": {
        "source": "generated search queries",
        "method": "search_dork_pack",
        "fp_notes": "Dorks are queries, not results. Running them can hit unrelated documents.",
    },
    "pastes": {
        "source": "GitHub code search / paste dorks",
        "method": "paste_leak_hunt",
        "fp_notes": "Code-search snippets collide on common strings. Confirm the leak is this target.",
    },
    "perms": {
        "source": "local generation",
        "method": "username_permutation",
        "fp_notes": "Permutations are candidates only. They are not observed accounts.",
    },
    "phone": {
        "source": "E.164 parse + leak pivots",
        "method": "phone_normalize",
        "fp_notes": "Country hints from prefix are not geolocation. Pivot URLs are not confirmed listings.",
    },
    "ioc": {
        "source": "VirusTotal / AlienVault OTX",
        "method": "ioc_enrichment",
        "fp_notes": "Community scores include duplicates and context-free hashes. Not a compromise verdict.",
    },
    "crypto": {
        "source": "public chain explorers",
        "method": "address_lookup",
        "fp_notes": "Address reuse and mixers break attribution. Explorer labels are unverified.",
    },
    "dark_web": {
        "source": "onion HTTP via optional Tor",
        "method": "onion_fetch",
        "fp_notes": "Mirror/clone onions are common. Title/keyword matches are not the same hidden service.",
    },
    "onion_dirs": {
        "source": "Ahmia onion directory",
        "method": "onion_directory_search",
        "fp_notes": "Directory listings are operator-submitted and often outdated or unrelated.",
    },
    "tor_health": {
        "source": "local Tor SOCKS",
        "method": "socks_healthcheck",
        "fp_notes": "A listening SOCKS port is not proof of a working circuit.",
    },
    "meta": {
        "source": "file EXIF / PDF Info",
        "method": "metadata_extract",
        "fp_notes": "EXIF is trivially stripped or forged. GPS is not proof of photographer identity.",
    },
    "image_pivots": {
        "source": "reverse-image search URLs",
        "method": "image_search_pivot",
        "fp_notes": "These are search links, not matches. Visual similar-image results are frequently wrong.",
    },
    "plugin": {
        "source": "user plugin",
        "method": "plugin_hook",
        "fp_notes": "Plugin output is unvetted by the toolkit scoring rules.",
    },
}

_SKIP_WALK_KEYS = {
    "pivots",
    "email_guess_pivots",
    "graph",
    "dorks",
    "queries",
    "note",
    "error",
    "raw",
    "body",
    "headers",
    "robots",
    "sitemap",
    "checked",  # full negative probe lists — too noisy for the ledger
    "summary",  # derived from profiles
    "associated_accounts",  # derived from profiles
    "high_risk",  # subset of findings
    "public",  # subset of exists/hits
}

_VALUE_KEYS = (
    "finding",
    "url",
    "host",
    "email",
    "bucket",
    "service",
    "platform",
    "name",
    "domain",
    "onion",
    "ticker",
    "github_url",
    "gitlab_url",
    "html_url",
    "login",
)

_EVIDENCE_KEYS = (
    "status_code",
    "http_status",
    "status",
    "reason",
    "match_reason",
    "final_url",
    "cname",
    "nxdomain",
    "fingerprint_match",
    "cname_match",
    "public_list",
    "exists_hint",
    "relevance",
    "ticker",
    "cik",
    "http",
    "match_score",
    "exists",
    "risk",
)

_LEDGER_CAP = 300


def scan_timestamp(results: Optional[Dict[str, Any]] = None) -> str:
    ts = (results or {}).get("timestamp")
    if isinstance(ts, str) and len(ts) >= 15 and ts[8] == "_":
        try:
            return (
                datetime.strptime(ts[:15], "%Y%m%d_%H%M%S")
                .replace(tzinfo=timezone.utc)
                .strftime("%Y-%m-%dT%H:%M:%SZ")
            )
        except ValueError:
            pass
    if isinstance(ts, str) and "T" in ts:
        return ts
    return utc_now()


def make_finding(
    value: Any,
    *,
    source: str,
    method: str,
    confidence: str = CONF_MEDIUM,
    evidence: Optional[Dict[str, Any]] = None,
    fp_notes: str = DEFAULT_FP_NOTES,
    timestamp: Optional[str] = None,
    module: str = "",
    **extra: Any,
) -> Dict[str, Any]:
    """Standard provenance envelope for a single OSINT claim."""
    rec: Dict[str, Any] = {
        "finding": value,
        "source": source,
        "timestamp": timestamp or utc_now(),
        "method": method,
        "confidence": confidence,
        "evidence": evidence or {},
        "fp_notes": fp_notes,
    }
    if module:
        rec["module"] = module
    rec.update(extra)
    return rec


def finding_label(item: Dict[str, Any], parent_key: str = "") -> str:
    for key in _VALUE_KEYS:
        val = item.get(key)
        if val not in (None, "", [], {}):
            label = str(val)
            if parent_key and key != "finding" and parent_key not in label:
                return f"{parent_key}: {label}"
            return label
    if parent_key:
        return parent_key
    return "(unnamed)"


def is_finding_like(item: Dict[str, Any]) -> bool:
    if not item:
        return False
    if "finding" in item and "confidence" in item:
        return True
    if "confidence" in item and any(k in item for k in _VALUE_KEYS):
        return True
    if item.get("exists") is True and ("url" in item or "final_url" in item):
        return True
    if item.get("risk") in ("high", "medium", "low") and any(
        k in item for k in ("host", "candidates", "url")
    ):
        return True
    return False


def is_reportable_finding(item: Dict[str, Any]) -> bool:
    """Positive or uncertain claims — not confirmed-negatives."""
    if item.get("exists") is False:
        return False
    if str(item.get("status") or "").lower() in ("not_found", "missing", "error"):
        return False
    if item.get("risk") == "info" and not item.get("candidates"):
        return False
    if item.get("exists") is True or item.get("exists_hint") is True:
        return True
    if str(item.get("status") or "").lower() == "found":
        return True
    if item.get("risk") in ("high", "medium", "low"):
        return True
    if item.get("confidence") in (CONF_CONFIRMED, CONF_HIGH, CONF_MEDIUM, CONF_LOW):
        return True
    return False


def _evidence_from(item: Dict[str, Any]) -> Dict[str, Any]:
    existing = item.get("evidence")
    if isinstance(existing, dict) and existing:
        return dict(existing)
    out: Dict[str, Any] = {}
    for key in _EVIDENCE_KEYS:
        val = item.get(key)
        if val in (None, "", [], {}):
            continue
        out[key] = val
    return out


def stamp_finding(
    item: Dict[str, Any],
    *,
    module: str,
    scanned_at: str,
    parent_key: str = "",
) -> Dict[str, Any]:
    """Fill missing provenance fields on an existing finding dict (in place)."""
    meta = MODULE_PROVENANCE.get(module, {})
    item.setdefault("source", meta.get("source", f"{module} probe" if module else "module probe"))
    item.setdefault("method", meta.get("method", "unspecified"))
    item.setdefault("fp_notes", meta.get("fp_notes", DEFAULT_FP_NOTES))
    item.setdefault("timestamp", scanned_at)
    item.setdefault("module", module)
    if not item.get("finding"):
        item["finding"] = finding_label(item, parent_key)
    if not item.get("evidence"):
        ev = _evidence_from(item)
        if ev:
            item["evidence"] = ev
    if not item.get("confidence"):
        item["confidence"] = CONF_UNKNOWN
    return item


def _compact_finding(item: Dict[str, Any]) -> Dict[str, Any]:
    ev = item.get("evidence")
    if not isinstance(ev, dict):
        ev = _evidence_from(item)
    return {
        "finding": item.get("finding") or finding_label(item),
        "module": item.get("module") or "",
        "source": item.get("source") or "",
        "timestamp": item.get("timestamp") or "",
        "method": item.get("method") or "",
        "confidence": item.get("confidence") or CONF_UNKNOWN,
        "evidence": ev,
        "fp_notes": item.get("fp_notes") or DEFAULT_FP_NOTES,
    }


def _walk_findings(
    obj: Any,
    module: str,
    scanned_at: str,
    ledger: List[Dict[str, Any]],
    parent_key: str = "",
) -> None:
    if isinstance(obj, dict):
        if is_finding_like(obj):
            stamp_finding(obj, module=module, scanned_at=scanned_at, parent_key=parent_key)
            if is_reportable_finding(obj):
                ledger.append(_compact_finding(obj))
            return
        for key, val in obj.items():
            if key in _SKIP_WALK_KEYS or val in (None, "", [], {}):
                continue
            _walk_findings(val, module, scanned_at, ledger, parent_key=str(key))
        return
    if isinstance(obj, list):
        for item in obj:
            _walk_findings(item, module, scanned_at, ledger, parent_key=parent_key)


def annotate_results(results: Dict[str, Any]) -> Dict[str, Any]:
    """Stamp provenance on nested findings and attach a top-level ledger."""
    if not isinstance(results, dict):
        return results
    scanned_at = scan_timestamp(results)
    results.setdefault("timestamp_iso", scanned_at)
    ledger: List[Dict[str, Any]] = []
    blob = results.get("results")
    if isinstance(blob, dict):
        for module, data in blob.items():
            if module in ("graph",):
                continue
            _walk_findings(data, str(module), scanned_at, ledger)
    ledger.sort(
        key=lambda row: (
            -conf_rank(row.get("confidence")),
            str(row.get("module") or ""),
            str(row.get("finding") or ""),
        )
    )
    truncated = max(0, len(ledger) - _LEDGER_CAP)
    results["findings"] = ledger[:_LEDGER_CAP]
    results["findings_truncated"] = truncated
    results["findings_summary"] = summarize_confidence(results["findings"])
    return results
