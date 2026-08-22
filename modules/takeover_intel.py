"""Subdomain takeover fingerprint checks — CNAME-aware, low false positives."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

import requests

from modules.net_util import DEFAULT_HEADERS, is_safe_host
from modules.result_quality import CONF_HIGH, CONF_LOW, CONF_MEDIUM

# service -> (cname needles, body fingerprints that are UNIQUE to dangling service)
# Body fingerprints alone are NOT enough for high risk without CNAME match.
FINGERPRINTS: List[Tuple[str, Tuple[str, ...], Tuple[str, ...]]] = [
    ("GitHub Pages", ("github.io", "githubmap.com"),
     ("There isn't a GitHub Pages site here.", "For root URLs (like http://example.com/) that are directories")),
    ("Heroku", ("herokuapp.com", "herokudns.com", "herokussl.com"),
     ("No such app", "no-such-app.herokuapp.com")),
    ("AWS/S3", ("s3.amazonaws.com", "s3-website", "s3-website-"),
     ("NoSuchBucket", "The specified bucket does not exist")),
    ("Ghost", ("ghost.io",),
     ("The thing you were looking for is no longer here", "Domain has expired or is unavailable")),
    ("Shopify", ("myshopify.com", "shopify.com"),
     ("Sorry, this shop is currently unavailable.", "Only one step left")),
    ("Tumblr", ("tumblr.com", "domains.tumblr.com"),
     ("There's nothing here.", "Whatever you were looking for doesn't currently exist at this address")),
    ("WordPress.com", ("wordpress.com",),
     ("Do you want to register", "doesn't exist")),
    ("Pantheon", ("pantheonsite.io", "pantheon.io"),
     ("404 error unknown site", "The gods are wise")),
    ("Fastly", ("fastly.net", "fastlylb.net"),
     ("Fastly error: unknown domain", "Please check that this domain has been added to a service")),
    ("Azure", ("azurewebsites.net", "cloudapp.azure.com", "trafficmanager.net", "azure-api.net", "cloudapp.net"),
     ("404 Web Site not found", "Error 404 - Web app not found.")),
    ("Surge.sh", ("surge.sh",),
     ("project not found", "repository not found")),
    ("Bitbucket", ("bitbucket.io",),
     ("Repository not found")),
    ("Netlify", ("netlify.app", "netlify.com"),
     ("Not Found - Request ID:", "page not found")),
    ("Cargo", ("cargocollective.com",),
     ("404 Not Found for")),
    ("Feedpress", ("feedpress.me",),
     ("The feed has not been found.")),
    ("Readme.io", ("readme.io",),
     ("Project doesnt exist", "project not found")),
    ("Help Scout", ("helpscoutdocs.com",),
     ("No settings were found for this company:")),
    ("JetBrains", ("myjetbrains.com",),
     ("is not a registered InCloud YouTrack")),
    ("Unbounce", ("unbouncepages.com",),
     ("The requested URL was not found on this server")),
    ("SmugMug", ("smugmug.com",),
     ('"status":"error"', "Page Not Found")),
]


class TakeoverIntel:
    """Check hosts for dangling DNS / takeover fingerprints."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)

    def check(self, hosts: List[str], threads: int = 15) -> Dict[str, Any]:
        cleaned = []
        for h in hosts:
            h = (h or "").strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]
            if h and is_safe_host(h) and h not in cleaned:
                cleaned.append(h)
        if not cleaned:
            return {"error": "No valid hosts", "hosts": hosts}

        findings: List[Dict[str, Any]] = []

        def one(host: str) -> Optional[Dict[str, Any]]:
            cname = self._cname(host)
            nx = self._is_nxdomain(host)
            body = ""
            status = None
            try:
                r = self.session.get(f"https://{host}", timeout=8, allow_redirects=True)
                status = r.status_code
                body = (r.text or "")[:8000]
            except requests.RequestException:
                try:
                    r = self.session.get(f"http://{host}", timeout=8, allow_redirects=True)
                    status = r.status_code
                    body = (r.text or "")[:8000]
                except requests.RequestException:
                    pass

            matched = []
            cname_l = (cname or "").lower()
            body_l = body.lower()
            for service, needles, fps in FINGERPRINTS:
                cname_hit = bool(cname_l) and any(n.strip().lower() in cname_l for n in needles if n.strip())
                # Require fingerprint strings to be specific enough (len>=12) and exact-ish
                body_hit = any(fp.lower() in body_l for fp in fps if fp and len(fp) >= 10)
                if not cname_hit and not body_hit:
                    continue

                # CRITICAL anti-FP rule:
                # Body-only matches without CNAME to that service are almost always generic
                # page text collisions. Only keep body-only when NXDOMAIN (dangling) or
                # fingerprint is very specific AND page is nearly empty / error-like.
                if body_hit and not cname_hit:
                    if nx:
                        conf = CONF_MEDIUM
                        keep = True
                    elif self._body_is_error_page(body_l, status):
                        conf = CONF_LOW
                        keep = True
                    else:
                        # discard pure body collision on live site
                        keep = False
                        conf = CONF_LOW
                    if not keep:
                        continue
                elif cname_hit and body_hit:
                    conf = CONF_HIGH
                elif cname_hit and not body_hit:
                    # dangling CNAME without claim page — medium (possible takeover)
                    conf = CONF_MEDIUM if nx or status in (404, None) else CONF_LOW
                else:
                    conf = CONF_LOW

                matched.append({
                    "service": service,
                    "cname_match": cname_hit,
                    "fingerprint_match": body_hit,
                    "confidence": conf,
                })

            if not matched and not nx:
                return None

            # risk only elevated when CNAME + fingerprint or NX dangling CNAME
            high = any(
                m.get("cname_match") and m.get("fingerprint_match")
                for m in matched
            )
            medium = any(m.get("cname_match") for m in matched) or (
                nx and any(m.get("fingerprint_match") for m in matched)
            )
            if high:
                risk = "high"
            elif medium:
                risk = "medium"
            elif matched:
                risk = "low"
            elif nx:
                risk = "info"
            else:
                risk = "low"

            # Drop pure info NXDOMAIN with no service match from "suspicious" noise
            if not matched and nx:
                return {
                    "host": host,
                    "cname": cname,
                    "nxdomain": nx,
                    "http_status": status,
                    "candidates": [],
                    "risk": "info",
                    "confidence": CONF_LOW,
                    "note": "NXDOMAIN only — not a takeover signal by itself",
                }

            best_conf = CONF_HIGH if high else (CONF_MEDIUM if medium else CONF_LOW)
            return {
                "host": host,
                "cname": cname,
                "nxdomain": nx,
                "http_status": status,
                "candidates": matched,
                "risk": risk,
                "confidence": best_conf,
            }

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futs = {pool.submit(one, h): h for h in cleaned[:80]}
            for fut in as_completed(futs):
                res = fut.result()
                if res:
                    findings.append(res)

        # Only count medium+ as suspicious for summary
        suspicious = [
            f for f in findings
            if f.get("risk") in ("high", "medium")
            and f.get("candidates")
        ]
        low = [f for f in findings if f.get("risk") == "low" and f.get("candidates")]
        findings.sort(key=lambda x: {"high": 0, "medium": 1, "low": 2, "info": 3}.get(x.get("risk"), 9))
        return {
            "checked": len(cleaned[:80]),
            "suspicious": len(suspicious),
            "low_confidence": len(low),
            "findings": findings,
            "high_risk": [f for f in findings if f.get("risk") == "high"],
            "note": (
                "High risk = CNAME points at provider AND dangling fingerprint. "
                "Body-only matches on live sites are suppressed to avoid false positives."
            ),
        }

    def check_domain(self, domain: str, subdomains: Optional[List[str]] = None) -> Dict[str, Any]:
        hosts = [domain]
        if subdomains:
            hosts.extend(subdomains[:50])
        # always include www
        if domain and not domain.startswith("www."):
            hosts.append(f"www.{domain}")
        result = self.check(hosts)
        result["domain"] = domain
        return result

    @staticmethod
    def _body_is_error_page(body_l: str, status: Optional[int]) -> bool:
        if status in (404, 410):
            return True
        if not body_l:
            return True
        if len(body_l) < 400:
            return True
        markers = ("404", "not found", "no such", "doesn't exist", "does not exist", "error")
        return sum(1 for m in markers if m in body_l) >= 2

    @staticmethod
    def _cname(host: str) -> Optional[str]:
        try:
            import dns.resolver
            answers = dns.resolver.resolve(host, "CNAME")
            return str(answers[0].target).rstrip(".")
        except Exception:
            return None

    @staticmethod
    def _is_nxdomain(host: str) -> bool:
        try:
            socket.getaddrinfo(host, None)
            return False
        except socket.gaierror as exc:
            return "Name or service not known" in str(exc) or getattr(exc, "errno", None) in (8, -2, -5)
        except OSError:
            return False
