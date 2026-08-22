"""SaaS / cloud tenant discovery for a domain (Azure AD, Workspace, etc.)."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import requests

from modules.http_util import pace, rotate_headers
from modules.net_util import is_safe_host

_DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,48}[a-z0-9]$")


class SaaSIntel:
    """Probe public SaaS/IdP endpoints that hint at tenant ownership."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(rotate_headers())

    def discover(self, domain: str) -> Dict[str, Any]:
        domain = self._normalize(domain)
        if not domain or not is_safe_host(domain):
            return {"error": "Invalid domain", "domain": domain}

        slug = domain.split(".")[0].lower()
        findings: List[Dict[str, Any]] = []

        # Sequential IdP checks (share domain context)
        for fn in (self._azure_realm, self._azure_oidc, self._google_workspace):
            try:
                hit = fn(domain)
                if hit:
                    findings.append(hit)
            except (requests.RequestException, ValueError, ET.ParseError):
                pass

        # Parallel slug-based SaaS probes (allowlisted hosts only)
        slug_checks = self._slug_probes(slug)
        with ThreadPoolExecutor(max_workers=8) as pool:
            futs = {pool.submit(self._probe_url, c): c for c in slug_checks}
            for fut in as_completed(futs):
                res = fut.result()
                if res:
                    findings.append(res)

        findings.sort(key=lambda x: (x.get("status") != "found", x.get("service", "")))
        # Only medium+ confidence "found" count as real hits
        _rank = {"confirmed": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
        reliable = [
            f for f in findings
            if f.get("status") == "found" and _rank.get((f.get("confidence") or "medium").lower(), 2) >= 2
        ]
        low = [
            f for f in findings
            if f.get("status") == "found" and _rank.get((f.get("confidence") or "").lower(), 0) < 2
        ]
        return {
            "domain": domain,
            "slug": slug,
            "found": reliable,
            "low_confidence": low,
            "checked": findings,
            "count": len(reliable),
            "note": "Only medium/high confidence tenants listed under found. Confirm via DNS MX/TXT.",
            "pivots": [
                {"name": "Azure AD login", "url": f"https://login.microsoftonline.com/{quote(domain)}"},
                {"name": "Google Workspace", "url": f"https://admin.google.com/"},
                {"name": "MX / SPF (manual)", "url": f"https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{quote(domain)}"},
            ],
        }

    def _normalize(self, raw: str) -> str:
        d = (raw or "").strip().lower()
        d = d.removeprefix("http://").removeprefix("https://").split("/")[0]
        d = d.split("@")[-1] if "@" in d else d
        if not _DOMAIN_RE.match(d):
            return ""
        return d

    def _azure_realm(self, domain: str) -> Optional[Dict[str, Any]]:
        pace()
        url = (
            "https://login.microsoftonline.com/getuserrealm.srf"
            f"?login=user@{quote(domain)}&xml=1"
        )
        r = self.session.get(url, headers=rotate_headers(), timeout=12)
        if r.status_code != 200 or not r.text:
            return {"service": "azure_ad_realm", "status": "unknown", "http": r.status_code}
        root = ET.fromstring(r.text)
        ns = ""
        name_tag = root.find(f".//{ns}NameSpaceType")
        fed = root.find(f".//{ns}FederationBrandName")
        auth = root.find(f".//{ns}AuthURL")
        nstype = (name_tag.text or "").strip() if name_tag is not None else ""
        brand = (fed.text or "").strip() if fed is not None else ""
        auth_url = (auth.text or "").strip() if auth is not None else ""
        # Federated / Managed = tenant exists; Unknown = often not claimed
        found = nstype.lower() in ("federated", "managed")
        return {
            "service": "azure_ad_realm",
            "status": "found" if found else "not_found",
            "confidence": "high" if found else "high",
            "namespace_type": nstype or None,
            "federation_brand": brand or None,
            "auth_url": auth_url or None,
            "http": r.status_code,
        }

    def _azure_oidc(self, domain: str) -> Optional[Dict[str, Any]]:
        pace()
        url = f"https://login.microsoftonline.com/{quote(domain)}/.well-known/openid-configuration"
        r = self.session.get(url, headers=rotate_headers({"Accept": "application/json"}), timeout=12)
        if r.status_code == 200:
            try:
                data = r.json()
            except ValueError:
                data = {}
            tid = None
            issuer = str(data.get("issuer") or "")
            m = re.search(r"([0-9a-fA-F\-]{36})", issuer)
            if m:
                tid = m.group(1)
            return {
                "service": "azure_ad_oidc",
                "status": "found",
                "confidence": "confirmed" if tid else "high",
                "tenant_id": tid,
                "issuer": issuer or None,
                "token_endpoint": data.get("token_endpoint"),
                "http": 200,
            }
        return {
            "service": "azure_ad_oidc",
            "status": "not_found" if r.status_code in (400, 404) else "unknown",
            "confidence": "high" if r.status_code in (400, 404) else "unknown",
            "http": r.status_code,
        }

    def _google_workspace(self, domain: str) -> Optional[Dict[str, Any]]:
        pace()
        # Public endpoint is noisy — only treat as found on clear positive markers
        url = f"https://www.google.com/a/{quote(domain)}/ServiceLogin"
        r = self.session.get(url, headers=rotate_headers(), timeout=12, allow_redirects=False)
        loc = r.headers.get("Location") or ""
        text = r.text or ""
        low = text.lower()
        if "AccountDomainNotFound" in text or "not a valid" in low or "does not exist" in low:
            found = False
            conf = "high"
        elif r.status_code in (200, 302) and (
            "accounts.google.com" in loc.lower()
            or "ServiceLogin" in loc
            or "google.com/a/" in (loc or url)
        ) and "AccountDomainNotFound" not in text:
            # Still medium — many consumer domains redirect generically
            found = True
            conf = "medium"
        else:
            found = False
            conf = "medium"
        return {
            "service": "google_workspace",
            "status": "found" if found else "not_found",
            "confidence": conf,
            "http": r.status_code,
            "redirect": loc[:200] if loc else None,
            "note": "Heuristic — confirm via MX (ASPMX/google) or admin console",
        }

    def _slug_probes(self, slug: str) -> List[Dict[str, str]]:
        if not _SLUG_RE.match(slug):
            return []
        # Host templates are fixed allowlist — never user-controlled hosts
        return [
            {"service": "slack", "url": f"https://{slug}.slack.com"},
            {"service": "atlassian", "url": f"https://{slug}.atlassian.net"},
            {"service": "okta", "url": f"https://{slug}.okta.com"},
            {"service": "salesforce", "url": f"https://{slug}.my.salesforce.com"},
            {"service": "github_org", "url": f"https://github.com/{slug}"},
            {"service": "gitlab_group", "url": f"https://gitlab.com/{slug}"},
            {"service": "notion", "url": f"https://{slug}.notion.site"},
            {"service": "zendesk", "url": f"https://{slug}.zendesk.com"},
            {"service": "hubspot", "url": f"https://{slug}.hubspot.com"},
            {"service": "webex", "url": f"https://{slug}.webex.com"},
        ]

    def _probe_url(self, item: Dict[str, str]) -> Optional[Dict[str, Any]]:
        url = item["url"]
        host = url.split("/")[2] if "://" in url else ""
        if not is_safe_host(host):
            return None
        pace()
        body = ""
        final_url = url
        try:
            r = self.session.get(url, headers=rotate_headers(), timeout=8, allow_redirects=True)
            status_code = r.status_code
            body = (r.text or "")[:6000]
            final_url = r.url or url
        except requests.RequestException:
            return {
                "service": item["service"],
                "status": "unknown",
                "confidence": "unknown",
                "url": url,
            }

        service = item["service"]
        low = body.lower()
        final_host = final_url.split("/")[2].lower() if "://" in final_url else host.lower()

        # Hard negatives
        if status_code in (404, 410):
            return {
                "service": service, "status": "not_found", "confidence": "high",
                "url": url, "http": status_code, "final_url": final_url,
            }

        soft_miss = (
            "does not exist", "doesn't exist", "not found", "no such",
            "couldn't find", "there is no", "invalid workspace",
            "workspace not found", "team not found", "site not found",
            "this page doesn't exist", "this page does not exist",
        )
        if any(s in low for s in soft_miss):
            return {
                "service": service, "status": "not_found", "confidence": "high",
                "url": url, "http": status_code, "final_url": final_url,
            }

        # Service-specific positives
        conf = "medium"
        st = "unknown"
        slug = host.split(".")[0].lower()

        if service == "slack":
            # Free/unused slacks often 404; existing workspaces show sign-in
            if status_code == 200 and ("signin" in low or "workspace" in low or "slack.com" in final_host):
                if slug and slug in final_host:
                    st, conf = "found", "high"
                else:
                    st, conf = "not_found", "medium"
            elif status_code in (401, 403):
                st, conf = "found", "medium"
        elif service in ("github_org", "gitlab_group"):
            if status_code == 200 and slug in final_url.lower():
                st, conf = "found", "high"
            else:
                st, conf = "not_found" if status_code == 404 else "unknown", "medium"
        elif service == "okta":
            # Unclaimed often lands on okta.com marketing or 404
            if "okta.com" in final_host and slug in final_host and status_code in (200, 401, 403):
                if "page not found" in low or "doesn't exist" in low:
                    st, conf = "not_found", "high"
                else:
                    st, conf = "found", "high"
            else:
                st = "not_found" if status_code in (404, 301, 302) and slug not in final_host else "unknown"
                conf = "medium"
        elif service in ("atlassian", "zendesk", "hubspot", "webex", "notion", "salesforce"):
            # Require slug still present in final host; 401/403 = tenant likely exists
            if slug in final_host:
                if status_code in (200, 401, 403):
                    st, conf = "found", "high" if status_code in (401, 403) else "medium"
                elif status_code in (301, 302):
                    st, conf = "found", "low"
            else:
                st, conf = "not_found", "medium"
        else:
            if status_code in (200, 401, 403) and slug in final_host:
                st, conf = "found", "medium"
            elif status_code in (404, 410):
                st, conf = "not_found", "high"

        return {
            "service": service,
            "status": st,
            "confidence": conf,
            "url": url,
            "http": status_code,
            "final_url": final_url,
        }
