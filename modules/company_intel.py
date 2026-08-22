"""Company / business intelligence — registries, filings, public pivots."""

from __future__ import annotations

import re
from typing import Any, Dict, List
from urllib.parse import quote

import requests

from modules.http_util import pace, rotate_headers

_COMPANY_RE = re.compile(r"^[\w\s.&'\-]{2,120}$", re.UNICODE)


class CompanyIntel:
    """Enrich a company name via free public registries + search pivots."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(rotate_headers())

    def analyze(self, company: str) -> Dict[str, Any]:
        name = " ".join((company or "").split()).strip()
        if not name or not _COMPANY_RE.match(name) or "@" in name or "/" in name:
            return {"error": "Invalid company name", "company": company}

        out: Dict[str, Any] = {
            "company": name,
            "opencorporates": [],
            "sec_edgar": [],
            "pivots": self._pivots(name),
        }

        oc = self._opencorporates(name)
        if oc is not None:
            out["opencorporates"] = oc

        sec = self._sec_edgar(name)
        if sec is not None:
            out["sec_edgar"] = sec

        out["hit_count"] = len(out["opencorporates"]) + len(out["sec_edgar"])
        return out

    def _opencorporates(self, name: str) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        try:
            pace()
            r = self.session.get(
                "https://api.opencorporates.com/v0.4/companies/search",
                params={"q": name, "per_page": 10},
                headers=rotate_headers({"Accept": "application/json"}),
                timeout=20,
            )
            if r.status_code != 200:
                return hits
            data = r.json()
            companies = ((data.get("results") or {}).get("companies")) or []
            for item in companies[:10]:
                c = item.get("company") or {}
                hits.append({
                    "name": c.get("name"),
                    "company_number": c.get("company_number"),
                    "jurisdiction": c.get("jurisdiction_code"),
                    "incorporation_date": c.get("incorporation_date"),
                    "dissolution_date": c.get("dissolution_date"),
                    "company_type": c.get("company_type"),
                    "current_status": c.get("current_status"),
                    "registered_address": (c.get("registered_address_in_full") or "")[:200] or None,
                    "opencorporates_url": c.get("opencorporates_url"),
                })
        except (requests.RequestException, ValueError, TypeError):
            pass
        return hits

    def _sec_edgar(self, name: str) -> List[Dict[str, Any]]:
        """Match against SEC company tickers (US public companies)."""
        needle = name.lower()
        hits: List[Dict[str, Any]] = []
        try:
            pace()
            r = self.session.get(
                "https://www.sec.gov/files/company_tickers.json",
                headers=rotate_headers({
                    "Accept": "application/json",
                    "User-Agent": "EpicOSINT/2.0 research@local",
                }),
                timeout=25,
            )
            if r.status_code != 200:
                return hits
            data = r.json()
            # Score matches — avoid substring FPs for short names like "Arcus"
            scored: List[tuple] = []
            tokens = [t for t in re.split(r"\s+", needle) if len(t) >= 2]
            for row in data.values() if isinstance(data, dict) else []:
                title = str(row.get("title") or "")
                ticker = str(row.get("ticker") or "")
                cik = row.get("cik_str")
                if not title:
                    continue
                tl = title.lower().strip()
                score = 0
                conf = "low"
                if tl == needle or ticker.lower() == needle:
                    score, conf = 100, "confirmed"
                elif tl.startswith(needle + " ") or tl.endswith(" " + needle) or f" {needle} " in f" {tl} ":
                    score, conf = 80, "high"
                elif len(needle) >= 6 and needle in tl:
                    score, conf = 60, "medium"
                elif len(needle) >= 5 and tokens and all(t in tl for t in tokens):
                    score, conf = 50, "medium"
                else:
                    # reject short/partial substring matches (major FP source)
                    continue
                cik_pad = str(cik).zfill(10) if cik is not None else ""
                scored.append((score, {
                    "name": title,
                    "ticker": ticker,
                    "cik": cik,
                    "confidence": conf,
                    "match_score": score,
                    "edgar_url": (
                        f"https://www.sec.gov/cgi-bin/browse-edgar"
                        f"?action=getcompany&CIK={cik_pad}&owner=exclude&count=40"
                        if cik_pad else None
                    ),
                }))
            scored.sort(key=lambda x: -x[0])
            for _, hit in scored[:15]:
                hits.append(hit)
        except (requests.RequestException, ValueError, TypeError, AttributeError):
            pass
        return hits

    @staticmethod
    def _pivots(name: str) -> List[Dict[str, str]]:
        q = quote(name)
        return [
            {"name": "OpenCorporates", "url": f"https://opencorporates.com/companies?q={q}"},
            {"name": "SEC EDGAR search", "url": f"https://www.sec.gov/edgar/search/#/q={q}"},
            {"name": "Companies House (UK)", "url": f"https://find-and-update.company-information.service.gov.uk/search?q={q}"},
            {"name": "GLEIF search", "url": f"https://search.gleif.org/#/search/{q}"},
            {"name": "LinkedIn companies", "url": f"https://www.linkedin.com/search/results/companies/?keywords={q}"},
            {"name": "Google company", "url": f"https://www.google.com/search?q={q}+company+OR+corporation+OR+inc"},
            {"name": "Wikipedia", "url": f"https://en.wikipedia.org/w/index.php?search={q}"},
        ]
