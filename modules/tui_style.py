"""
ASCII/ANSI report formatting — turn scan JSON into readable TUI lines.
Each line is (text, style) where style is a Theme tag name.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

Line = Tuple[str, str]  # text, style: header|section|rule|key|val|bullet|ok|warn|err|dim|meta|blank


def _rule(width: int = 62, char: str = "=") -> Line:
    return (char * width, "rule")


def _blank() -> Line:
    return ("", "blank")


def _hdr(text: str) -> Line:
    return (text, "header")


def _sec(text: str) -> Line:
    return (text, "section")


def _meta(text: str) -> Line:
    return (text, "meta")


def _key(text: str) -> Line:
    return (text, "key")


def _val(text: str) -> Line:
    return (text, "val")


def _bul(text: str) -> Line:
    return (text, "bullet")


def _ok(text: str) -> Line:
    return (text, "ok")


def _warn(text: str) -> Line:
    return (text, "warn")


def _err(text: str) -> Line:
    return (text, "err")


def _dim(text: str) -> Line:
    return (text, "dim")


def _box_title(title: str, width: int = 62) -> List[Line]:
    inner = width - 2
    t = f" {title} "
    pad = max(0, inner - len(t))
    left = pad // 2
    right = pad - left
    return [
        _rule(width, "#"),
        _hdr("#" + (" " * left) + t + (" " * right) + "#"),
        _rule(width, "#"),
    ]


def _section_bar(name: str, width: int = 62) -> List[Line]:
    label = f"[ {name.upper()} ]"
    fill = max(0, width - len(label) - 4)
    return [
        _blank(),
        _sec("+--" + label + "-" * fill + "+"),
    ]


def _kv(key: str, value: Any, indent: int = 0, width: int = 56) -> Line:
    pad = " " * indent
    k = str(key).replace("_", " ")
    v = _fmt_scalar(value)
    dots = max(2, width - indent - len(k) - len(v) - 2)
    return _key(f"{pad}{k} {'.' * dots} {v}")


def _fmt_scalar(value: Any, limit: int = 90) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "YES" if value else "NO"
    if isinstance(value, float):
        return f"{value:.4g}"
    s = str(value).replace("\n", " ").strip()
    if len(s) > limit:
        return s[: limit - 3] + "..."
    return s or "-"


def _emit_value(key: str, value: Any, indent: int = 0, depth: int = 0) -> List[Line]:
    """Recursively emit styled lines for any JSON-ish value."""
    if depth > 6:
        return [_dim(" " * indent + "...")]
    lines: List[Line] = []
    pad = " " * indent

    if value is None or value == "" or value == [] or value == {}:
        return lines

    if isinstance(value, bool):
        sty = _ok if value else _dim
        lines.append(sty(f"{pad}{key.replace('_', ' ')} .... {_fmt_scalar(value)}"))
        return lines

    if isinstance(value, (str, int, float)):
        lines.append(_kv(key, value, indent=indent))
        return lines

    if isinstance(value, list):
        if not value:
            return lines
        # list of scalars
        if all(not isinstance(x, (dict, list)) for x in value):
            lines.append(_key(f"{pad}{key.replace('_', ' ')} ({len(value)})"))
            for item in value[:80]:
                lines.append(_bul(f"{pad}  + {_fmt_scalar(item, 100)}"))
            if len(value) > 80:
                lines.append(_dim(f"{pad}  ... +{len(value) - 80} more"))
            return lines
        # list of dicts / mixed — prefer high-confidence / high-risk first
        def _item_rank(it: Any) -> int:
            if not isinstance(it, dict):
                return 0
            risk = {"high": 3, "medium": 2, "low": 1, "info": 0}.get(str(it.get("risk") or "").lower(), 0)
            conf = {"confirmed": 4, "high": 3, "medium": 2, "low": 1}.get(str(it.get("confidence") or "").lower(), 0)
            return risk * 10 + conf

        # For takeover/saas-style lists, hide pure low/info noise when better items exist
        filtered = list(value)
        if key in ("findings", "candidates", "exists", "found", "high_risk"):
            strong = [x for x in filtered if isinstance(x, dict) and _item_rank(x) >= 2]
            if strong and key == "findings":
                # keep medium+ risk only for primary list
                med = [
                    x for x in filtered
                    if isinstance(x, dict) and str(x.get("risk") or "").lower() in ("high", "medium")
                ]
                if med:
                    filtered = med

        filtered = sorted(filtered, key=_item_rank, reverse=True)
        lines.append(_key(f"{pad}{key.replace('_', ' ')} ({len(filtered)})"))
        for i, item in enumerate(filtered[:40], 1):
            if isinstance(item, dict):
                label = (
                    item.get("name")
                    or item.get("host")
                    or item.get("domain")
                    or item.get("url")
                    or item.get("email")
                    or item.get("login")
                    or item.get("platform")
                    or item.get("service")
                    or item.get("onion")
                    or f"#{i}"
                )
                conf = item.get("confidence")
                risk = item.get("risk")
                tag = ""
                if risk:
                    tag = f"[{str(risk).upper()}] "
                elif conf:
                    tag = f"[{str(conf).upper()}] "
                sty = _ok if (risk in ("high", "medium") or conf in ("confirmed", "high", "medium")) else _bul
                if risk == "low" or conf == "low":
                    sty = _warn
                lines.append(sty(f"{pad}  [{i:02d}] {tag}{_fmt_scalar(label, 70)}"))
                for sk, sv in list(item.items())[:12]:
                    if sk in ("name", "url", "email", "login", "host", "domain") and sv == label:
                        continue
                    if sv in (None, "", [], {}):
                        continue
                    if isinstance(sv, (dict, list)):
                        lines.extend(_emit_value(str(sk), sv, indent=indent + 4, depth=depth + 1))
                    else:
                        lines.append(_dim(f"{pad}      {str(sk).replace('_', ' ')} : {_fmt_scalar(sv, 70)}"))
            else:
                lines.append(_bul(f"{pad}  + {_fmt_scalar(item)}"))
        if len(filtered) > 40:
            lines.append(_dim(f"{pad}  ... +{len(filtered) - 40} more"))
        return lines

    if isinstance(value, dict):
        # Special-case social profiles: tier by confidence
        if key == "profiles" and any(isinstance(v, dict) and "exists" in v for v in value.values()):
            _rank = {"confirmed": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
            reliable, low_hits = [], []
            for p, info in value.items():
                if not isinstance(info, dict) or info.get("exists") is not True:
                    continue
                conf = (info.get("confidence") or "medium").lower()
                row = (p, info, conf)
                if _rank.get(conf, 2) >= 2:
                    reliable.append(row)
                else:
                    low_hits.append(row)
            unknown = sum(1 for info in value.values() if isinstance(info, dict) and info.get("exists") is None)
            missing = sum(1 for info in value.values() if isinstance(info, dict) and info.get("exists") is False)
            lines.append(_key(f"{pad}profiles reliable ({len(reliable)} / {len(value)})"))
            for p, info, conf in sorted(reliable, key=lambda x: -_rank.get(x[2], 0))[:60]:
                url = info.get("url") or ""
                lines.append(_ok(f"{pad}  [*] [{conf.upper()}] {p}"))
                if url:
                    lines.append(_dim(f"{pad}      {url}"))
            if low_hits:
                lines.append(_warn(f"{pad}low confidence ({len(low_hits)}) — verify manually:"))
                for p, info, conf in low_hits[:20]:
                    lines.append(_warn(f"{pad}  [?] {p} ({info.get('reason') or conf})"))
                    if info.get("url"):
                        lines.append(_dim(f"{pad}      {info['url']}"))
            if missing:
                lines.append(_dim(f"{pad}  (not found on {missing} platforms)"))
            if unknown:
                lines.append(_warn(f"{pad}  (blocked/unknown on {unknown} platforms)"))
            return lines

        lines.append(_key(f"{pad}{key.replace('_', ' ')}"))
        for sk, sv in value.items():
            if sv in (None, "", [], {}):
                continue
            # skip full raw profile matrix when summary already present at parent
            if sk == "profiles" and isinstance(sv, dict) and depth == 0:
                lines.extend(_emit_value(str(sk), sv, indent=indent + 2, depth=depth + 1))
                continue
            lines.extend(_emit_value(str(sk), sv, indent=indent + 2, depth=depth + 1))
        return lines

    lines.append(_kv(key, value, indent=indent))
    return lines


def _emit_social_section(data: Dict[str, Any], indent: int = 2) -> List[Line]:
    """Confidence-tiered social section without dumping every platform twice."""
    lines: List[Line] = []
    pad = " " * indent
    if data.get("username"):
        lines.append(_kv("username", data["username"], indent=indent))

    summary = data.get("summary") or {}
    profiles = data.get("profiles") or {}
    if summary:
        lines.append(
            _ok(
                f"{pad}reliable {summary.get('reliable_count', 0)}  |  "
                f"low {summary.get('low_confidence_count', 0)}  |  "
                f"missing {summary.get('not_found_count', 0)}  |  "
                f"unknown {summary.get('unknown_count', 0)}"
            )
        )
        if summary.get("note"):
            lines.append(_dim(f"{pad}{summary['note'][:100]}"))
        for row in summary.get("reliable") or []:
            conf = str(row.get("confidence") or "?").upper()
            lines.append(_ok(f"{pad}  [*] [{conf}] {row.get('platform')}"))
            if row.get("url"):
                lines.append(_dim(f"{pad}      {row['url']}"))
        low = summary.get("low_confidence") or []
        if low:
            lines.append(_warn(f"{pad}low confidence (verify manually):"))
            for row in low[:20]:
                lines.append(_warn(f"{pad}  [?] {row.get('platform')} ({row.get('reason') or ''})"))
    elif profiles:
        lines.extend(_emit_value("profiles", profiles, indent=indent, depth=0))

    emails = data.get("email_addresses") or []
    if emails:
        lines.append(_key(f"{pad}verified emails ({len(emails)})"))
        for em in emails[:20]:
            if isinstance(em, dict):
                lines.append(
                    _ok(
                        f"{pad}  + {em.get('email')} "
                        f"[{em.get('confidence', '?')}] via {em.get('source', '?')}"
                    )
                )
            else:
                lines.append(_ok(f"{pad}  + {em}"))

    pivots = data.get("email_guess_pivots") or []
    if pivots:
        lines.append(_dim(f"{pad}unverified email pivots ({len(pivots)}) — not real findings"))
        for p in pivots[:6]:
            if isinstance(p, dict):
                lines.append(_dim(f"{pad}  ? {p.get('pattern')}"))

    return lines


def _emit_takeover_section(data: Dict[str, Any], indent: int = 2) -> List[Line]:
    lines: List[Line] = []
    pad = " " * indent
    lines.append(_kv("checked", data.get("checked"), indent=indent))
    lines.append(_kv("suspicious", data.get("suspicious"), indent=indent))
    if data.get("note"):
        lines.append(_dim(f"{pad}{str(data['note'])[:110]}"))
    findings = [
        f for f in (data.get("findings") or [])
        if isinstance(f, dict) and f.get("risk") in ("high", "medium")
    ]
    if not findings:
        lines.append(_ok(f"{pad}no credible takeover candidates"))
        low = [
            f for f in (data.get("findings") or [])
            if isinstance(f, dict) and f.get("risk") == "low"
        ]
        if low:
            lines.append(_dim(f"{pad}({len(low)} low-confidence body matches suppressed)"))
        return lines
    for f in findings:
        risk = str(f.get("risk") or "?").upper()
        sty = _err if risk == "HIGH" else _warn
        lines.append(sty(f"{pad}[{risk}] {f.get('host')} cname={f.get('cname') or '-'}"))
        for c in f.get("candidates") or []:
            lines.append(
                _dim(
                    f"{pad}    {c.get('service')}: cname={c.get('cname_match')} "
                    f"fp={c.get('fingerprint_match')} conf={c.get('confidence')}"
                )
            )
    return lines


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
    "correlation": "CORRELATION GRAPH",
}


def _emit_findings_ledger(results: Dict[str, Any], indent: int = 2) -> List[Line]:
    from modules.result_quality import annotate_results, confidence_badge, meets_confidence

    if "findings" not in results and results.get("results"):
        annotate_results(results)
    rows = results.get("findings") or []
    summary = results.get("findings_summary") or {}
    pad = " " * indent
    lines: List[Line] = list(_section_bar("FINDINGS LEDGER"))
    lines.append(
        _ok(
            f"{pad}confirmed {summary.get('confirmed', 0)}  high {summary.get('high', 0)}  "
            f"medium {summary.get('medium', 0)}  low {summary.get('low', 0)}"
        )
    )
    shown = [r for r in rows if isinstance(r, dict) and meets_confidence(r.get("confidence"))]
    if not shown:
        lines.append(_dim(f"{pad}no scored findings at medium+ confidence"))
        return lines
    for row in shown[:80]:
        badge = confidence_badge(row.get("confidence")).strip("[]")
        lines.append(
            _ok(f"{pad}[{badge}] {row.get('module') or '?'}  {_fmt_scalar(row.get('finding'), 70)}")
        )
        lines.append(_dim(f"{pad}    src={_fmt_scalar(row.get('source'), 40)}  method={_fmt_scalar(row.get('method'), 28)}"))
        ev = row.get("evidence") or {}
        if isinstance(ev, dict) and ev:
            bits = " ".join(f"{k}={_fmt_scalar(v, 24)}" for k, v in list(ev.items())[:4])
            lines.append(_dim(f"{pad}    {bits}"))
        if row.get("fp_notes"):
            lines.append(_dim(f"{pad}    fp: {_fmt_scalar(row.get('fp_notes'), 90)}"))
    if len(shown) > 80:
        lines.append(_dim(f"{pad}... +{len(shown) - 80} more in JSON findings[]"))
    return lines


def format_scan_report(results: Dict[str, Any], saved_path: Optional[str] = None) -> List[Line]:
    """Build a full styled report from a scan results dict."""
    width = 62
    lines: List[Line] = []
    lines.extend(_box_title("EPIC OSINT  ::  INTEL REPORT", width))
    lines.append(_blank())
    lines.append(_meta(f"  TARGET .... {_fmt_scalar(results.get('target'), 40)}"))
    lines.append(_meta(f"  TYPE ...... {_fmt_scalar(results.get('scan_type'), 40)}"))
    lines.append(_meta(f"  TIME ...... {_fmt_scalar(results.get('timestamp'), 40)}"))
    if saved_path:
        lines.append(_ok(f"  SAVED ..... {_fmt_scalar(saved_path, 48)}"))
    lines.append(_dim("  Findings are scored claims, not proof — see ledger."))
    lines.append(_rule(width, "-"))
    lines.extend(_emit_findings_ledger(results, indent=2))

    blob = results.get("results") or {}
    if not blob and any(k in results for k in ("domain", "ip", "social")):
        blob = {k: results[k] for k in results if k not in ("target", "scan_type", "timestamp", "correlation")}

    for section, data in blob.items():
        if section in ("findings", "findings_summary", "findings_truncated"):
            continue
        title = SECTION_TITLES.get(section, section.replace("_", " ").upper())
        lines.extend(_section_bar(title, width))
        if isinstance(data, dict):
            # Social: prefer summary + tiered profiles; skip redundant nested lists
            if section == "social":
                lines.extend(_emit_social_section(data, indent=2))
                continue
            if section == "takeover":
                lines.extend(_emit_takeover_section(data, indent=2))
                continue
            for k, v in data.items():
                if v in (None, "", [], {}):
                    continue
                lines.extend(_emit_value(str(k), v, indent=2, depth=0))
        else:
            lines.extend(_emit_value(section, data, indent=2, depth=0))

    corr = results.get("correlation")
    if corr:
        lines.extend(_section_bar(SECTION_TITLES["correlation"], width))
        for k, v in corr.items():
            if k == "links":
                links = v or []
                lines.append(_key(f"  links ({len(links)})"))
                for link in links[:40]:
                    lines.append(_bul(f"    {link.get('from', '?')}  -->  {link.get('to', '?')}"))
                if len(links) > 40:
                    lines.append(_dim(f"    ... +{len(links) - 40} more"))
            else:
                lines.extend(_emit_value(str(k), v, indent=2, depth=0))

    lines.append(_blank())
    lines.append(_rule(width, "#"))
    lines.append(_hdr("#" + " END OF REPORT ".center(width - 2) + "#"))
    lines.append(_rule(width, "#"))
    return lines


def format_json_file(text: str) -> List[Line]:
    """Parse a saved JSON report into styled lines; fall back to raw text."""
    import json

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return [(line, "val") for line in text.splitlines()[:2000]]
    if isinstance(data, dict) and ("results" in data or "target" in data):
        return format_scan_report(data)
    # generic object
    lines = list(_box_title("SAVED DATA"))
    if isinstance(data, dict):
        for k, v in data.items():
            lines.extend(_emit_value(str(k), v, indent=2))
    else:
        lines.extend(_emit_value("data", data, indent=2))
    return lines


def plain_text(lines: Iterable[Line]) -> str:
    return "\n".join(t for t, _ in lines)
