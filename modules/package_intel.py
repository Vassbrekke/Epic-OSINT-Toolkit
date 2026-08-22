"""Package / supply-chain OSINT — npm, PyPI, crates, RubyGems, Docker Hub."""

from __future__ import annotations

import re
from typing import Any, Dict, List
from urllib.parse import quote

import requests

from modules.http_util import pace, rotate_headers

_QUERY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-@/]{0,80}$")


class PackageIntel:
    """Search public package registries for a name, user, or org slug."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(rotate_headers())

    def search(self, query: str, limit: int = 8) -> Dict[str, Any]:
        q = (query or "").strip()
        # domain → slug
        if "." in q and "/" not in q and "@" not in q and " " not in q:
            q = q.split(".")[0]
        q = q.lstrip("@")
        if not q or not _QUERY_RE.match(q) or ".." in q:
            return {"error": "Invalid package/user query", "query": query}

        limit = max(1, min(int(limit), 15))
        out: Dict[str, Any] = {
            "query": q,
            "npm": self._npm(q, limit),
            "pypi": self._pypi(q, limit),
            "crates": self._crates(q, limit),
            "rubygems": self._rubygems(q, limit),
            "dockerhub": self._dockerhub(q, limit),
            "pivots": [
                {"name": "npm search", "url": f"https://www.npmjs.com/search?q={quote(q)}"},
                {"name": "PyPI search", "url": f"https://pypi.org/search/?q={quote(q)}"},
                {"name": "crates.io", "url": f"https://crates.io/search?q={quote(q)}"},
                {"name": "RubyGems", "url": f"https://rubygems.org/search?query={quote(q)}"},
                {"name": "Docker Hub", "url": f"https://hub.docker.com/search?q={quote(q)}"},
            ],
        }
        # Annotate relevance — exact / prefix matches preferred over fuzzy search noise
        for reg in ("npm", "pypi", "crates", "rubygems", "dockerhub"):
            items = out.get(reg) or []
            if not isinstance(items, list):
                continue
            scored = []
            for it in items:
                if not isinstance(it, dict):
                    continue
                name = str(it.get("name") or "").lower()
                ql = q.lower()
                if name == ql:
                    it["confidence"] = "confirmed"
                    it["relevance"] = 100
                elif name.startswith(ql) or ql.startswith(name):
                    it["confidence"] = "high"
                    it["relevance"] = 80
                elif ql in name:
                    it["confidence"] = "medium"
                    it["relevance"] = 50
                else:
                    it["confidence"] = "low"
                    it["relevance"] = 20
                scored.append(it)
            scored.sort(key=lambda x: -int(x.get("relevance") or 0))
            # Drop very weak fuzzy noise unless nothing better
            strong = [s for s in scored if (s.get("relevance") or 0) >= 50]
            out[reg] = strong if strong else scored[:3]
        out["hit_count"] = sum(
            len(out[k]) for k in ("npm", "pypi", "crates", "rubygems", "dockerhub")
            if isinstance(out.get(k), list)
        )
        out["note"] = "Package hits ranked by name relevance; low-relevance fuzzy matches filtered."
        return out

    def _npm(self, q: str, limit: int) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        try:
            pace()
            r = self.session.get(
                "https://registry.npmjs.org/-/v1/search",
                params={"text": q, "size": limit},
                headers=rotate_headers({"Accept": "application/json"}),
                timeout=15,
            )
            if r.status_code != 200:
                return hits
            for obj in (r.json().get("objects") or [])[:limit]:
                pkg = obj.get("package") or {}
                hits.append({
                    "name": pkg.get("name"),
                    "version": pkg.get("version"),
                    "description": (pkg.get("description") or "")[:160] or None,
                    "publisher": ((pkg.get("publisher") or {}).get("username")),
                    "url": pkg.get("links", {}).get("npm") or f"https://www.npmjs.com/package/{pkg.get('name')}",
                })
        except (requests.RequestException, ValueError, TypeError):
            pass
        return hits

    def _pypi(self, q: str, limit: int) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        # Direct package lookup first
        try:
            pace()
            r = self.session.get(
                f"https://pypi.org/pypi/{quote(q, safe='')}/json",
                headers=rotate_headers({"Accept": "application/json"}),
                timeout=12,
            )
            if r.status_code == 200:
                info = (r.json().get("info") or {})
                hits.append({
                    "name": info.get("name"),
                    "version": info.get("version"),
                    "description": (info.get("summary") or "")[:160] or None,
                    "author": info.get("author"),
                    "home_page": info.get("home_page") or info.get("project_url"),
                    "url": f"https://pypi.org/project/{info.get('name')}/",
                })
                return hits
        except (requests.RequestException, ValueError, TypeError):
            pass
        # Fallback: XML-RPC-less simple search via warehouse JSON (limited)
        try:
            pace()
            r = self.session.get(
                "https://pypi.org/search/",
                params={"q": q},
                headers=rotate_headers(),
                timeout=12,
            )
            if r.status_code == 200:
                # Parse package links lightly without HTML parser dep
                names = re.findall(r'/project/([A-Za-z0-9._\-]+)/', r.text or "")
                seen = []
                for n in names:
                    if n not in seen:
                        seen.append(n)
                    if len(seen) >= limit:
                        break
                for n in seen:
                    hits.append({
                        "name": n,
                        "url": f"https://pypi.org/project/{n}/",
                    })
        except (requests.RequestException, ValueError, TypeError):
            pass
        return hits

    def _crates(self, q: str, limit: int) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        try:
            pace()
            r = self.session.get(
                "https://crates.io/api/v1/crates",
                params={"q": q, "per_page": limit},
                headers=rotate_headers({
                    "Accept": "application/json",
                    "User-Agent": "EpicOSINT/2.0 (OSINT research)",
                }),
                timeout=15,
            )
            if r.status_code != 200:
                return hits
            for c in (r.json().get("crates") or [])[:limit]:
                hits.append({
                    "name": c.get("name"),
                    "version": c.get("max_version") or c.get("newest_version"),
                    "description": (c.get("description") or "")[:160] or None,
                    "downloads": c.get("downloads"),
                    "url": f"https://crates.io/crates/{c.get('name')}",
                })
        except (requests.RequestException, ValueError, TypeError):
            pass
        return hits

    def _rubygems(self, q: str, limit: int) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        try:
            pace()
            r = self.session.get(
                "https://rubygems.org/api/v1/search.json",
                params={"query": q},
                headers=rotate_headers({"Accept": "application/json"}),
                timeout=15,
            )
            if r.status_code != 200:
                return hits
            for g in (r.json() or [])[:limit]:
                hits.append({
                    "name": g.get("name"),
                    "version": g.get("version"),
                    "description": (g.get("info") or "")[:160] or None,
                    "url": g.get("project_uri") or f"https://rubygems.org/gems/{g.get('name')}",
                })
        except (requests.RequestException, ValueError, TypeError):
            pass
        return hits

    def _dockerhub(self, q: str, limit: int) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        try:
            pace()
            r = self.session.get(
                "https://hub.docker.com/v2/search/repositories/",
                params={"query": q, "page_size": limit},
                headers=rotate_headers({"Accept": "application/json"}),
                timeout=15,
            )
            if r.status_code != 200:
                return hits
            for repo in (r.json().get("results") or [])[:limit]:
                name = repo.get("repo_name") or repo.get("name")
                hits.append({
                    "name": name,
                    "description": (repo.get("short_description") or "")[:160] or None,
                    "stars": repo.get("star_count"),
                    "pulls": repo.get("pull_count"),
                    "official": bool(repo.get("is_official")),
                    "url": f"https://hub.docker.com/r/{name}" if name and "/" in str(name)
                    else f"https://hub.docker.com/_/{name}",
                })
        except (requests.RequestException, ValueError, TypeError):
            pass
        return hits
