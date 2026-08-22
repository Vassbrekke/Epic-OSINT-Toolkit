"""Cloud storage bucket / blob enumeration (public exposure checks)."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import requests

from modules.net_util import DEFAULT_HEADERS

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$")


class BucketIntel:
    """Probe common public cloud bucket naming patterns."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)

    def hunt(self, name: str, threads: int = 20) -> Dict[str, Any]:
        base = self._normalize(name)
        if not base:
            return {"error": "Invalid name", "name": name}

        candidates = self._candidates(base)
        found: List[Dict[str, Any]] = []

        def check(item: Dict[str, str]) -> Optional[Dict[str, Any]]:
            url = item["url"]
            provider = item["provider"]
            try:
                r = self.session.get(url, timeout=6, allow_redirects=True, stream=True)
                status = r.status_code
                # read a small body sample for provider error XML/JSON
                try:
                    chunk = next(r.iter_content(chunk_size=4096), b"")
                    body = chunk.decode("utf-8", errors="ignore") if chunk else ""
                except Exception:
                    body = ""
                finally:
                    r.close()

                low = body.lower()
                # Definite non-existence signals
                no_bucket = any(s in low for s in (
                    "nosuchbucket",
                    "the specified bucket does not exist",
                    "no such bucket",
                    "bucket does not exist",
                    "notfound",
                    "nosuchkey",
                    "no such host",
                    "dns_probe",
                ))
                if status in (404, 410) or no_bucket:
                    return None

                # Azure / DO often return 400/404 for missing; generic 403 on
                # virtual-hosted endpoints can be platform noise (not proof of bucket).
                if provider in ("azure", "digitalocean") and status in (400, 404):
                    return None
                if provider == "azure" and status == 403 and "blob.core.windows.net" in url:
                    # Account may not exist or auth required — weak signal only
                    conf = "low"
                    return {
                        "provider": provider,
                        "bucket": item["bucket"],
                        "url": url,
                        "status": status,
                        "public_list": False,
                        "exists_hint": False,
                        "confidence": conf,
                        "note": "Weak 403 — may be platform default, not a real container",
                    }

                if status == 200:
                    # listing XML / HTML directory
                    public = ("listbucketresult" in low) or ("<html" not in low and len(body) > 0) or ("contents" in low)
                    return {
                        "provider": provider,
                        "bucket": item["bucket"],
                        "url": url,
                        "status": status,
                        "public_list": public or True,
                        "exists_hint": True,
                        "confidence": "high" if "listbucketresult" in low else "medium",
                    }
                if status == 403:
                    # S3 403 AccessDenied usually means the bucket exists
                    if provider.startswith("aws") or provider == "gcs":
                        if "invalidbucketname" in low or "nosuchbucket" in low:
                            return None
                        return {
                            "provider": provider,
                            "bucket": item["bucket"],
                            "url": url,
                            "status": status,
                            "public_list": False,
                            "exists_hint": True,
                            "confidence": "high" if "accessdenied" in low or "access denied" in low else "medium",
                        }
                    return None
                if status in (301, 302):
                    return {
                        "provider": provider,
                        "bucket": item["bucket"],
                        "url": url,
                        "status": status,
                        "public_list": False,
                        "exists_hint": True,
                        "confidence": "low",
                        "note": "Redirect only — verify manually",
                    }
            except requests.RequestException:
                return None
            return None

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futs = [pool.submit(check, c) for c in candidates]
            for fut in as_completed(futs):
                res = fut.result()
                if res:
                    found.append(res)

        found.sort(key=lambda x: (
            0 if x.get("confidence") == "high" else 1 if x.get("confidence") == "medium" else 2,
            not x.get("public_list"),
            x.get("provider"),
            x.get("bucket"),
        ))
        reliable = [f for f in found if f.get("confidence") in ("high", "medium") and f.get("exists_hint")]
        public = [f for f in reliable if f.get("public_list")]
        return {
            "name": base,
            "probed": len(candidates),
            "hits": len(reliable),
            "public": public,
            "exists": reliable,
            "low_confidence": [f for f in found if f.get("confidence") == "low"],
            "note": "Only medium/high confidence bucket signals counted as hits. 403 on S3/GCS usually means exists-but-private.",
        }

    def _normalize(self, name: str) -> str:
        n = (name or "").strip().lower()
        n = n.removeprefix("http://").removeprefix("https://").split("/")[0]
        n = n.replace("_", "-")
        # domain → slug
        if "." in n:
            n = n.split(".")[0] if n.count(".") >= 1 else n.replace(".", "-")
        n = re.sub(r"[^a-z0-9.\-]", "", n)
        if len(n) < 3 or len(n) > 63:
            return ""
        return n

    def _candidates(self, base: str) -> List[Dict[str, str]]:
        suffixes = (
            "", "-backup", "-backups", "-bak", "-dev", "-prod", "-staging",
            "-assets", "-static", "-media", "-uploads", "-data", "-logs",
            "-public", "-private", "-files", "-img", "-images", "-cdn",
        )
        names = []
        for s in suffixes:
            b = f"{base}{s}"
            if _NAME_RE.match(b) or (b.replace(".", "").isalnum() and 3 <= len(b) <= 63):
                names.append(b)
        out: List[Dict[str, str]] = []
        for b in names:
            out.append({
                "provider": "aws_s3",
                "bucket": b,
                "url": f"https://{b}.s3.amazonaws.com",
            })
            out.append({
                "provider": "aws_s3_path",
                "bucket": b,
                "url": f"https://s3.amazonaws.com/{quote(b)}",
            })
            out.append({
                "provider": "gcs",
                "bucket": b,
                "url": f"https://storage.googleapis.com/{quote(b)}",
            })
            out.append({
                "provider": "azure",
                "bucket": b,
                "url": f"https://{b}.blob.core.windows.net",
            })
            out.append({
                "provider": "digitalocean",
                "bucket": b,
                "url": f"https://{b}.digitaloceanspaces.com",
            })
        return out
