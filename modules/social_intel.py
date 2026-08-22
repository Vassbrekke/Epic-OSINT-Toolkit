"""Social Media Intelligence — username search with confidence-scored hits."""

from __future__ import annotations

import hashlib
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Sequence, Tuple
from urllib.parse import quote, urlparse

import requests
from bs4 import BeautifulSoup

from modules.net_util import DEFAULT_HEADERS
from modules.result_quality import (
    CONF_CONFIRMED,
    CONF_HIGH,
    CONF_LOW,
    CONF_MEDIUM,
    CONF_UNKNOWN,
    body_has_soft_404,
    extract_title,
    score_http_probe,
    title_looks_missing,
    url_looks_generic,
    username_still_in_url,
)

# platform -> url template with {} for username
PLATFORMS: Dict[str, str] = {
    # Dev / code
    "github": "https://github.com/{}",
    "gitlab": "https://gitlab.com/{}",
    "bitbucket": "https://bitbucket.org/{}",
    "codeberg": "https://codeberg.org/{}",
    "sourceforge": "https://sourceforge.net/u/{}/",
    "replit": "https://replit.com/@{}",
    "codepen": "https://codepen.io/{}",
    "jsfiddle": "https://jsfiddle.net/user/{}/",
    "leetcode": "https://leetcode.com/{}",
    "hackerrank": "https://www.hackerrank.com/{}",
    "kaggle": "https://www.kaggle.com/{}",
    "npm": "https://www.npmjs.com/~{}",
    "pypi": "https://pypi.org/user/{}",
    "dockerhub": "https://hub.docker.com/u/{}",
    "devto": "https://dev.to/{}",
    "hashnode": "https://hashnode.com/@{}",
    "stackoverflow": "https://stackoverflow.com/users/{}",
    "keybase": "https://keybase.io/{}",
    # Social
    "twitter": "https://x.com/{}",
    "instagram": "https://www.instagram.com/{}/",
    "facebook": "https://www.facebook.com/{}",
    "linkedin": "https://www.linkedin.com/in/{}",
    "reddit": "https://www.reddit.com/user/{}",
    "tiktok": "https://www.tiktok.com/@{}",
    "youtube": "https://www.youtube.com/@{}",
    "pinterest": "https://www.pinterest.com/{}/",
    "tumblr": "https://{}.tumblr.com",
    "threads": "https://www.threads.net/@{}",
    "mastodon_social": "https://mastodon.social/@{}",
    "bluesky": "https://bsky.app/profile/{}.bsky.social",
    "snapchat": "https://www.snapchat.com/add/{}",
    "vk": "https://vk.com/{}",
    "okru": "https://ok.ru/{}",
    # Creative / media
    "behance": "https://www.behance.net/{}",
    "dribbble": "https://dribbble.com/{}",
    "flickr": "https://www.flickr.com/people/{}",
    "vimeo": "https://vimeo.com/{}",
    "soundcloud": "https://soundcloud.com/{}",
    "spotify": "https://open.spotify.com/user/{}",
    "bandcamp": "https://bandcamp.com/{}",
    "lastfm": "https://www.last.fm/user/{}",
    "deviantart": "https://www.deviantart.com/{}",
    "artstation": "https://www.artstation.com/{}",
    "medium": "https://medium.com/@{}",
    "substack": "https://substack.com/@{}",
    "aboutme": "https://about.me/{}",
    "linktree": "https://linktr.ee/{}",
    "carrd": "https://{}.carrd.co",
    # Gaming
    "steam": "https://steamcommunity.com/id/{}",
    "xbox": "https://xboxgamertag.com/search/{}",
    "playstation": "https://psnprofiles.com/{}",
    "twitch": "https://www.twitch.tv/{}",
    "roblox": "https://www.roblox.com/users/profile?username={}",
    "minecraft": "https://namemc.com/profile/{}",
    "chess": "https://www.chess.com/member/{}",
    "lichess": "https://lichess.org/@/{}",
    # Community / forums
    "hackernews": "https://news.ycombinator.com/user?id={}",
    "producthunt": "https://www.producthunt.com/@{}",
    "telegram": "https://t.me/{}",
    "quora": "https://www.quora.com/profile/{}",
    "wikipedia": "https://en.wikipedia.org/wiki/User:{}",
    "imgur": "https://imgur.com/user/{}",
    "giphy": "https://giphy.com/channel/{}",
    "patreon": "https://www.patreon.com/{}",
    "ko_fi": "https://ko-fi.com/{}",
    "buymeacoffee": "https://www.buymeacoffee.com/{}",
    "cashapp": "https://cash.app/${}",
    "venmo": "https://venmo.com/{}",
    # Professional / misc
    "angel": "https://angel.co/u/{}",
    "crunchbase": "https://www.crunchbase.com/person/{}",
    "researchgate": "https://www.researchgate.net/profile/{}",
    "orcid": "https://orcid.org/{}",
    "academia": "https://independent.academia.edu/{}",
    "gravatar": "https://en.gravatar.com/{}",
    "wordpress": "https://{}.wordpress.com",
    "blogger": "https://www.blogger.com/profile/{}",
    "ghost": "https://{}.ghost.io",
    "notion": "https://www.notion.so/{}",
    "trello": "https://trello.com/{}",
    "fandom": "https://www.fandom.com/u/{}",
    "goodreads": "https://www.goodreads.com/{}",
    "letterboxd": "https://letterboxd.com/{}",
    "myanimelist": "https://myanimelist.net/profile/{}",
    "duolingo": "https://www.duolingo.com/profile/{}",
    "strava": "https://www.strava.com/athletes/{}",
    "vsco": "https://vsco.co/{}",
    "reddit_old": "https://old.reddit.com/user/{}",
    "gitee": "https://gitee.com/{}",
    "launchpad": "https://launchpad.net/~{}",
    "slashdot": "https://slashdot.org/~{}",
    "weebly": "https://{}.weebly.com",
}

# Platforms that commonly soft-404 or redirect; need stricter checks
# (platform, extra soft-404 body needles, require username in final URL)
_PLATFORM_RULES: Dict[str, Dict] = {
    "github": {
        "extra": ("not found", "404"),
        "api": True,
        "ok_title_has": (),
    },
    "gitlab": {"extra": ("page not found", "sign in · gitlab")},
    "reddit": {"extra": ("nobody on reddit goes by that name", "page not found", "failed to load user profile")},
    "reddit_old": {"extra": ("nobody on reddit goes by that name", "page not found")},
    "twitter": {"extra": ("this account doesn’t exist", "this account doesn't exist", "account suspended", "try searching for another")},
    "instagram": {"extra": ("sorry, this page isn't available", "the link you followed may be broken", "page not found")},
    "tiktok": {"extra": ("couldn't find this account", "page not available", "video currently unavailable")},
    "youtube": {"extra": ("this page isn't available", "404 not found", "channel does not exist")},
    "twitch": {"extra": ("sorry. unless you've got a time machine", "this channel is unavailable")},
    "telegram": {"extra": ("if you have telegram, you can contact", "tgme_page_description")},  # empty channels still show invite page
    "medium": {"extra": ("out of nothing, something", "page not found", "410")},
    "substack": {"extra": ("page not found", "we couldn't find that page", "no results")},
    "pinterest": {"extra": ("sorry! we couldn't find", "page not found")},
    "facebook": {"extra": ("this content isn't available", "page isn't available", "content not found")},
    "linkedin": {"extra": ("this page doesn’t exist", "this page doesn't exist", "page not found")},
    "snapchat": {"extra": ("page could not be found", "sorry")},
    "steam": {"extra": ("the specified profile could not be found", "failed to load")},
    "roblox": {"extra": ("page cannot be found or is no longer available", "user not found")},
    "keybase": {"extra": ("user not found", "sorry, the user")},
    "npm": {"extra": ("not found", "couldn't find")},
    "pypi": {"extra": ("not found", "we looked everywhere")},
    "dockerhub": {"extra": ("not found", "page not found")},
    "hackernews": {"extra": ("no such user",)},
    "wordpress": {"extra": ("doesn't exist", "doesn’t exist", "typo", "coming soon")},
    "ko_fi": {"extra": ("page not found", "404")},
    "patreon": {"extra": ("page not found", "sorry, we couldn't find that")},
    "orcid": {"extra": ("page not found", "404")},
    "trello": {"extra": ("page not found", "board not found", "log in")},
    "notion": {"extra": ("page not found", "couldn't find")},
    "giphy": {"extra": ("page not found", "explore")},
    "bluesky": {"extra": ("page not found", "unable to load", "profile not found")},
    "threads": {"extra": ("page isn't available", "log in", "sorry")},
    "duolingo": {"extra": ("page not found", "user not found")},
    "artstation": {"extra": ("page not found", "404")},
    "imgur": {"extra": ("page not found", "whoops")},
    "hackerrank": {"extra": ("page not found", "something went wrong")},
    "leetcode": {"extra": ("page not found", "user does not exist")},
    "replit": {"extra": ("not found", "log in", "404")},
    "xbox": {"extra": ("not found", "no gamertag")},
    "discord_invite": {"skip": True, "reason": "discord user ids are snowflakes, not usernames"},
}

# Platforms disabled because probes are inherently unreliable without auth/API
_SKIP_PLATFORMS = {
    "discord_invite",  # needs numeric snowflake
    "stackoverflow",  # URL needs numeric user id
    "askubuntu",
    "superuser",
    "serverfault",
    "spotify_artist",  # needs artist id
    "apple_music",
    "fitbit",
    "onlyfans",  # heavy soft-404 / geo blocks
    "pornhub",
    "slack_community",  # subdomain tenant, not username
    "blogger",  # profile ids not usernames
    "strava",  # athlete ids
}


class SocialIntel:
    """Social media intelligence gathering with confidence scoring."""

    def __init__(self):
        self.platforms = {k: v for k, v in PLATFORMS.items() if k not in _SKIP_PLATFORMS}
        self.headers = dict(DEFAULT_HEADERS)
        self.headers.setdefault(
            "Accept-Language",
            "en-US,en;q=0.9",
        )

    def search_username(self, username: str, threads: int = 40) -> Dict:
        username = (username or "").strip()
        if not re.match(r"^[\w.\-]{1,39}$", username):
            return {}
        results: Dict = {}

        def check(platform: str, template: str) -> tuple:
            rules = _PLATFORM_RULES.get(platform, {})
            if rules.get("skip"):
                return platform, {
                    "url": template.format(quote(username, safe="")),
                    "exists": None,
                    "confidence": CONF_UNKNOWN,
                    "reason": rules.get("reason", "skipped"),
                }
            url = template.format(quote(username, safe=""))
            try:
                # Platform-specific API first where available
                if platform == "github":
                    return platform, self._check_github(username, url)
                if platform == "gitlab":
                    return platform, self._check_gitlab(username, url)
                if platform == "reddit" or platform == "reddit_old":
                    return platform, self._check_reddit(username, url)
                if platform == "hackernews":
                    return platform, self._check_hn(username, url)
                if platform == "keybase":
                    return platform, self._check_keybase(username, url)
                if platform == "dockerhub":
                    return platform, self._check_dockerhub(username, url)
                if platform == "npm":
                    return platform, self._check_npm(username, url)
                if platform == "pypi":
                    return platform, self._check_pypi(username, url)

                r = requests.get(
                    url,
                    headers=self.headers,
                    timeout=8,
                    allow_redirects=True,
                )
                exists, confidence, reason = self._decide_exists(
                    platform, username, url, r
                )
                return platform, {
                    "url": url,
                    "exists": exists,
                    "confidence": confidence,
                    "reason": reason,
                    "status_code": r.status_code,
                    "final_url": r.url,
                }
            except requests.RequestException as exc:
                return platform, {
                    "url": url,
                    "exists": None,
                    "confidence": CONF_UNKNOWN,
                    "reason": "connection_failed",
                    "error": str(exc)[:120],
                }

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futs = [pool.submit(check, p, t) for p, t in self.platforms.items()]
            for fut in as_completed(futs):
                platform, data = fut.result()
                results[platform] = data
        return results

    def _decide_exists(
        self,
        platform: str,
        username: str,
        request_url: str,
        response: requests.Response,
    ) -> Tuple[Optional[bool], str, str]:
        rules = _PLATFORM_RULES.get(platform, {})
        extra: Sequence[str] = tuple(rules.get("extra") or ())
        body = response.text or ""
        final = response.url or request_url
        status = response.status_code

        # Hard negatives
        if status in (404, 410):
            return False, CONF_HIGH, f"http_{status}"
        if status in (401, 403, 429):
            return None, CONF_UNKNOWN, f"blocked_{status}"
        if status >= 400:
            return False, CONF_MEDIUM, f"http_{status}"

        title = extract_title(body)
        try:
            soup = BeautifulSoup(body[:50000], "html.parser")
            if soup.title and soup.title.string:
                title = soup.title.string.strip()[:200]
        except Exception:
            pass

        # Soft-404 body / title
        if body_has_soft_404(body, extra) or title_looks_missing(title):
            return False, CONF_HIGH, "soft_404"

        # Login / consent / search redirects
        if url_looks_generic(final, username):
            return False, CONF_HIGH, "generic_or_login_page"

        # Subdomain platforms: username must appear in host
        host = (urlparse(final).netloc or "").lower()
        if platform in ("tumblr", "wordpress", "carrd", "ghost", "weebly"):
            if username.lower() not in host:
                return False, CONF_HIGH, "subdomain_mismatch"
            # wordpress typo / parking
            if "typo" in final.lower() or "wordpress.com/typo" in final.lower():
                return False, CONF_HIGH, "registration_park"

        # Username must still appear unless numeric id path (roblox etc.)
        path = urlparse(final).path or ""
        if not username_still_in_url(final, username) and not re.search(r"/\d{4,}", path):
            return False, CONF_MEDIUM, "username_lost_in_redirect"

        # Platform-specific weak positives
        if platform == "telegram":
            # t.me always 200; require real channel signals
            low = body.lower()
            if "tgme_page_title" in low or "tgme_page_photo" in low:
                if "if you have telegram, you can contact" in low and "tgme_page_extra" not in low:
                    # bare user stub without subscribers often still exists — medium
                    return True, CONF_MEDIUM, "telegram_stub"
                return True, CONF_HIGH, "telegram_channel"
            return False, CONF_MEDIUM, "telegram_no_markers"

        if platform == "youtube":
            if "consent.youtube" in final or "accounts.google" in final:
                return None, CONF_UNKNOWN, "consent_wall"
            low = body.lower()
            if '"channelid"' in low or "subscribercounttext" in low or "@" + username.lower() in low:
                return True, CONF_HIGH, "youtube_channel_markers"
            return False, CONF_MEDIUM, "youtube_no_markers"

        if platform == "steam":
            low = body.lower()
            if "the specified profile could not be found" in low or "error_ctn" in low:
                return False, CONF_HIGH, "steam_missing"
            # real profiles usually include steamid or g_rgProfileData
            if "g_rgprofiledata" in low or "steamid" in low or "profile_header" in low:
                return True, CONF_HIGH, "steam_profile_markers"
            return True, CONF_LOW, "steam_weak_200"

        if platform == "twitch":
            low = body.lower()
            if "sorry. unless you've got a time machine" in low or "this channel is unavailable" in low:
                return False, CONF_HIGH, "twitch_missing"
            # Twitch returns SPA shells often — keep medium unless clear 404
            return True, CONF_MEDIUM, "twitch_200"

        if platform == "instagram":
            low = body.lower()
            if '"profilepage_"' in low or f'"username":"{username.lower()}"' in low:
                return True, CONF_HIGH, "instagram_profile_json"
            if "login" in final.lower() and username.lower() not in (urlparse(final).path or "").lower():
                return None, CONF_UNKNOWN, "login_wall"
            # Instagram often returns shell HTML for both — low confidence only
            return True, CONF_LOW, "instagram_weak_200"

        if platform in ("twitter",):
            low = body.lower()
            if "screen_name" in low or f"@{username.lower()}" in low:
                return True, CONF_MEDIUM, "x_markers"
            return True, CONF_LOW, "x_weak_200"

        if platform == "linkedin":
            if "/authwall" in final or "/login" in final:
                return None, CONF_UNKNOWN, "authwall"
            return True, CONF_LOW, "linkedin_weak_200"

        if platform == "facebook":
            if "login" in final.lower() and username.lower() not in final.lower():
                return None, CONF_UNKNOWN, "login_wall"
            return True, CONF_LOW, "facebook_weak_200"

        if status == 200:
            # default: medium when username retained and no soft-404
            conf = CONF_MEDIUM
            if username_still_in_url(final, username):
                conf = CONF_HIGH
            return True, conf, "http_200"

        exists, conf, reason = score_http_probe(
            status_code=status,
            final_url=final,
            request_url=request_url,
            body=body,
            username=username,
            soft_404_extra=extra,
        )
        return exists, conf, reason

    # --- high-accuracy platform APIs ---

    def _check_github(self, username: str, url: str) -> Dict:
        try:
            r = requests.get(
                f"https://api.github.com/users/{quote(username)}",
                headers=self.headers,
                timeout=8,
            )
            if r.status_code == 200:
                data = r.json()
                return {
                    "url": data.get("html_url") or url,
                    "exists": True,
                    "confidence": CONF_CONFIRMED,
                    "reason": "github_api",
                    "status_code": 200,
                    "final_url": data.get("html_url") or url,
                    "display_name": data.get("name"),
                    "bio": (data.get("bio") or "")[:160] or None,
                }
            if r.status_code == 404:
                return {
                    "url": url,
                    "exists": False,
                    "confidence": CONF_CONFIRMED,
                    "reason": "github_api_404",
                    "status_code": 404,
                }
            return {
                "url": url,
                "exists": None,
                "confidence": CONF_UNKNOWN,
                "reason": f"github_api_{r.status_code}",
                "status_code": r.status_code,
            }
        except requests.RequestException as exc:
            return {
                "url": url,
                "exists": None,
                "confidence": CONF_UNKNOWN,
                "reason": "connection_failed",
                "error": str(exc)[:120],
            }

    def _check_gitlab(self, username: str, url: str) -> Dict:
        try:
            r = requests.get(
                "https://gitlab.com/api/v4/users",
                params={"username": username},
                headers=self.headers,
                timeout=8,
            )
            if r.status_code == 200:
                arr = r.json()
                if isinstance(arr, list) and arr:
                    u = arr[0]
                    return {
                        "url": u.get("web_url") or url,
                        "exists": True,
                        "confidence": CONF_CONFIRMED,
                        "reason": "gitlab_api",
                        "status_code": 200,
                        "final_url": u.get("web_url") or url,
                        "display_name": u.get("name"),
                    }
                return {
                    "url": url,
                    "exists": False,
                    "confidence": CONF_HIGH,
                    "reason": "gitlab_api_empty",
                    "status_code": 200,
                }
            return {
                "url": url,
                "exists": None,
                "confidence": CONF_UNKNOWN,
                "reason": f"gitlab_api_{r.status_code}",
                "status_code": r.status_code,
            }
        except requests.RequestException as exc:
            return {
                "url": url,
                "exists": None,
                "confidence": CONF_UNKNOWN,
                "reason": "connection_failed",
                "error": str(exc)[:120],
            }

    def _check_reddit(self, username: str, url: str) -> Dict:
        try:
            r = requests.get(
                f"https://www.reddit.com/user/{quote(username)}/about.json",
                headers={**self.headers, "Accept": "application/json"},
                timeout=8,
            )
            if r.status_code == 200:
                data = r.json()
                kind = data.get("kind")
                if kind == "t2" or (data.get("data") or {}).get("name"):
                    return {
                        "url": f"https://www.reddit.com/user/{username}",
                        "exists": True,
                        "confidence": CONF_CONFIRMED,
                        "reason": "reddit_api",
                        "status_code": 200,
                        "final_url": f"https://www.reddit.com/user/{username}",
                    }
            if r.status_code in (404, 400):
                return {
                    "url": url,
                    "exists": False,
                    "confidence": CONF_HIGH,
                    "reason": f"reddit_api_{r.status_code}",
                    "status_code": r.status_code,
                }
            # banned / shadow → 403 sometimes
            if r.status_code == 403:
                return {
                    "url": url,
                    "exists": None,
                    "confidence": CONF_UNKNOWN,
                    "reason": "reddit_blocked",
                    "status_code": 403,
                }
            return {
                "url": url,
                "exists": None,
                "confidence": CONF_UNKNOWN,
                "reason": f"reddit_api_{r.status_code}",
                "status_code": r.status_code,
            }
        except requests.RequestException as exc:
            return {
                "url": url,
                "exists": None,
                "confidence": CONF_UNKNOWN,
                "reason": "connection_failed",
                "error": str(exc)[:120],
            }

    def _check_hn(self, username: str, url: str) -> Dict:
        try:
            r = requests.get(
                f"https://hacker-news.firebaseio.com/v0/user/{quote(username)}.json",
                headers=self.headers,
                timeout=8,
            )
            if r.status_code == 200:
                if r.text and r.text.strip() not in ("null", ""):
                    return {
                        "url": url,
                        "exists": True,
                        "confidence": CONF_CONFIRMED,
                        "reason": "hn_api",
                        "status_code": 200,
                        "final_url": url,
                    }
                return {
                    "url": url,
                    "exists": False,
                    "confidence": CONF_CONFIRMED,
                    "reason": "hn_api_null",
                    "status_code": 200,
                }
            return {
                "url": url,
                "exists": None,
                "confidence": CONF_UNKNOWN,
                "reason": f"hn_api_{r.status_code}",
                "status_code": r.status_code,
            }
        except requests.RequestException as exc:
            return {
                "url": url,
                "exists": None,
                "confidence": CONF_UNKNOWN,
                "reason": "connection_failed",
                "error": str(exc)[:120],
            }

    def _check_keybase(self, username: str, url: str) -> Dict:
        try:
            r = requests.get(
                "https://keybase.io/_/api/1.0/user/lookup.json",
                params={"usernames": username},
                headers=self.headers,
                timeout=8,
            )
            if r.status_code == 200:
                data = r.json()
                them = data.get("them") or []
                if them and them[0] is not None:
                    return {
                        "url": url,
                        "exists": True,
                        "confidence": CONF_CONFIRMED,
                        "reason": "keybase_api",
                        "status_code": 200,
                        "final_url": url,
                    }
                return {
                    "url": url,
                    "exists": False,
                    "confidence": CONF_HIGH,
                    "reason": "keybase_empty",
                    "status_code": 200,
                }
            return {
                "url": url,
                "exists": None,
                "confidence": CONF_UNKNOWN,
                "reason": f"keybase_{r.status_code}",
                "status_code": r.status_code,
            }
        except requests.RequestException as exc:
            return {
                "url": url,
                "exists": None,
                "confidence": CONF_UNKNOWN,
                "reason": "connection_failed",
                "error": str(exc)[:120],
            }

    def _check_dockerhub(self, username: str, url: str) -> Dict:
        try:
            r = requests.get(
                f"https://hub.docker.com/v2/users/{quote(username)}/",
                headers=self.headers,
                timeout=8,
            )
            if r.status_code == 200:
                return {
                    "url": url,
                    "exists": True,
                    "confidence": CONF_CONFIRMED,
                    "reason": "dockerhub_api",
                    "status_code": 200,
                    "final_url": url,
                }
            if r.status_code == 404:
                return {
                    "url": url,
                    "exists": False,
                    "confidence": CONF_CONFIRMED,
                    "reason": "dockerhub_404",
                    "status_code": 404,
                }
            return {
                "url": url,
                "exists": None,
                "confidence": CONF_UNKNOWN,
                "reason": f"dockerhub_{r.status_code}",
                "status_code": r.status_code,
            }
        except requests.RequestException as exc:
            return {
                "url": url,
                "exists": None,
                "confidence": CONF_UNKNOWN,
                "reason": "connection_failed",
                "error": str(exc)[:120],
            }

    def _check_npm(self, username: str, url: str) -> Dict:
        try:
            r = requests.get(
                f"https://registry.npmjs.org/-/user/org.couchdb.user:{quote(username)}",
                headers=self.headers,
                timeout=8,
            )
            if r.status_code == 200:
                return {
                    "url": url,
                    "exists": True,
                    "confidence": CONF_HIGH,
                    "reason": "npm_registry",
                    "status_code": 200,
                    "final_url": url,
                }
            if r.status_code == 404:
                return {
                    "url": url,
                    "exists": False,
                    "confidence": CONF_HIGH,
                    "reason": "npm_404",
                    "status_code": 404,
                }
            return {
                "url": url,
                "exists": None,
                "confidence": CONF_UNKNOWN,
                "reason": f"npm_{r.status_code}",
                "status_code": r.status_code,
            }
        except requests.RequestException as exc:
            return {
                "url": url,
                "exists": None,
                "confidence": CONF_UNKNOWN,
                "reason": "connection_failed",
                "error": str(exc)[:120],
            }

    def _check_pypi(self, username: str, url: str) -> Dict:
        try:
            r = requests.get(url, headers=self.headers, timeout=8, allow_redirects=True)
            if r.status_code == 404:
                return {
                    "url": url,
                    "exists": False,
                    "confidence": CONF_HIGH,
                    "reason": "pypi_404",
                    "status_code": 404,
                }
            if r.status_code == 200 and username.lower() in (r.url or "").lower():
                if body_has_soft_404(r.text or "", ("not found", "we looked everywhere")):
                    return {
                        "url": url,
                        "exists": False,
                        "confidence": CONF_HIGH,
                        "reason": "pypi_soft_404",
                        "status_code": 200,
                        "final_url": r.url,
                    }
                return {
                    "url": url,
                    "exists": True,
                    "confidence": CONF_HIGH,
                    "reason": "pypi_200",
                    "status_code": 200,
                    "final_url": r.url,
                }
            return {
                "url": url,
                "exists": False if r.status_code >= 400 else None,
                "confidence": CONF_MEDIUM if r.status_code >= 400 else CONF_UNKNOWN,
                "reason": f"pypi_{r.status_code}",
                "status_code": r.status_code,
                "final_url": r.url,
            }
        except requests.RequestException as exc:
            return {
                "url": url,
                "exists": None,
                "confidence": CONF_UNKNOWN,
                "reason": "connection_failed",
                "error": str(exc)[:120],
            }

    def discover_emails(self, username: str) -> List[Dict]:
        """Harvest only verified / observed emails (no invented mailbox guesses)."""
        found: List[Dict] = []
        seen = set()

        def add(email: str, source: str, confidence: str) -> None:
            em = (email or "").strip().lower()
            if not em or "@" not in em or em in seen:
                return
            # skip pure placeholder noreply unless github id-linked
            seen.add(em)
            found.append({
                "email": em,
                "source": source,
                "confidence": confidence,
                "guessed": False,
            })

        try:
            r = requests.get(
                f"https://api.github.com/users/{quote(username)}",
                headers=self.headers,
                timeout=8,
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("email"):
                    add(data["email"], "github_profile", CONF_CONFIRMED)
                # public events
                er = requests.get(
                    f"https://api.github.com/users/{quote(username)}/events/public",
                    headers=self.headers,
                    timeout=10,
                )
                if er.status_code == 200:
                    for ev in er.json()[:40]:
                        commits = (ev.get("payload") or {}).get("commits") or []
                        for c in commits:
                            em = (c.get("author") or {}).get("email")
                            if not em:
                                continue
                            if em.endswith("@users.noreply.github.com"):
                                add(em, "github_noreply", CONF_MEDIUM)
                            else:
                                add(em, "github_commit", CONF_HIGH)
        except requests.RequestException:
            pass

        # Optional guessed pivots are NOT returned as emails — only as pivot URLs
        return found

    def email_guess_pivots(self, username: str) -> List[Dict]:
        """Search pivots for common mailbox patterns (not claimed as real emails)."""
        common = ["gmail.com", "proton.me", "protonmail.com", "outlook.com", "yahoo.com"]
        pivots = []
        for d in common:
            em = f"{username}@{d}"
            pivots.append({
                "pattern": em,
                "note": "unverified guess — search only",
                "google": f'https://www.google.com/search?q=%22{quote(em)}%22',
                "confidence": CONF_LOW,
            })
        return pivots

    def find_associated_accounts(self, username: str) -> List[Dict]:
        """Correlate high-confidence profiles + GitHub orgs / blog links."""
        associated: List[Dict] = []
        profiles = self.search_username(username)
        found = [
            {
                "platform": p,
                "url": i.get("url"),
                "confidence": i.get("confidence", CONF_UNKNOWN),
            }
            for p, i in profiles.items()
            if i.get("exists") is True
            and (i.get("confidence") or CONF_UNKNOWN) in (
                CONF_CONFIRMED, CONF_HIGH, CONF_MEDIUM,
            )
        ]
        if found:
            associated.append({"source": "platform_matrix", "accounts": found})
        try:
            r = requests.get(
                f"https://api.github.com/users/{quote(username)}",
                headers=self.headers,
                timeout=8,
            )
            if r.status_code == 200:
                data = r.json()
                extra = []
                for key in ("blog", "twitter_username", "html_url"):
                    val = data.get(key)
                    if val:
                        extra.append({
                            "platform": key,
                            "url": val if str(val).startswith("http") else f"https://{val}",
                            "confidence": CONF_HIGH,
                        })
                orgs = requests.get(
                    f"https://api.github.com/users/{quote(username)}/orgs",
                    headers=self.headers,
                    timeout=8,
                )
                if orgs.status_code == 200:
                    for o in orgs.json()[:20]:
                        extra.append({
                            "platform": "github_org",
                            "url": o.get("html_url"),
                            "name": o.get("login"),
                            "confidence": CONF_CONFIRMED,
                        })
                if extra:
                    associated.append({"source": "github_profile", "accounts": extra})
        except requests.RequestException:
            pass
        return associated

    def summarize_profiles(self, profiles: Dict) -> Dict:
        """Build confidence-tiered summary for reports."""
        confirmed, high, medium, low, missing, unknown = [], [], [], [], [], []
        for p, info in (profiles or {}).items():
            if not isinstance(info, dict):
                continue
            row = {
                "platform": p,
                "url": info.get("url"),
                "confidence": info.get("confidence", CONF_UNKNOWN),
                "reason": info.get("reason"),
                "status_code": info.get("status_code"),
            }
            ex = info.get("exists")
            conf = (info.get("confidence") or CONF_UNKNOWN).lower()
            if ex is True:
                if conf == CONF_CONFIRMED:
                    confirmed.append(row)
                elif conf == CONF_HIGH:
                    high.append(row)
                elif conf == CONF_MEDIUM:
                    medium.append(row)
                else:
                    low.append(row)
            elif ex is False:
                missing.append(p)
            else:
                unknown.append(p)
        reliable = confirmed + high + medium
        return {
            "reliable_count": len(reliable),
            "low_confidence_count": len(low),
            "not_found_count": len(missing),
            "unknown_count": len(unknown),
            "reliable": reliable,
            "low_confidence": low,
            "confirmed": confirmed,
            "high": high,
            "medium": medium,
            "note": (
                "Only reliable (confirmed/high/medium) hits are treated as real findings. "
                "Low-confidence 200-OK soft matches are listed separately."
            ),
        }

    def get_profile_info(self, platform: str, username: str) -> Dict:
        url = self.platforms.get(platform, "").format(quote(username, safe=""))
        info: Dict = {"platform": platform, "username": username, "profile_url": url, "info": {}}
        if not url:
            return info
        try:
            r = requests.get(url, headers=self.headers, timeout=8)
            info["info"]["status_code"] = r.status_code
            exists, conf, reason = self._decide_exists(platform, username, url, r)
            info["exists"] = exists
            info["confidence"] = conf
            info["reason"] = reason
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                title = soup.title.string.strip() if soup.title and soup.title.string else ""
                desc = ""
                tag = soup.find("meta", attrs={"name": "description"}) or soup.find(
                    "meta", attrs={"property": "og:description"}
                )
                if tag:
                    desc = tag.get("content") or ""
                info["info"]["title"] = title[:200]
                info["info"]["description"] = desc[:500]
        except requests.RequestException as exc:
            info["info"]["error"] = str(exc)
        if platform == "github":
            try:
                r = requests.get(
                    f"https://api.github.com/users/{quote(username)}",
                    headers=self.headers,
                    timeout=8,
                )
                if r.status_code == 200:
                    info["info"]["api"] = r.json()
                    info["exists"] = True
                    info["confidence"] = CONF_CONFIRMED
            except requests.RequestException:
                pass
        return info

    @staticmethod
    def gravatar_url(email: str) -> str:
        h = hashlib.md5(email.strip().lower().encode()).hexdigest()
        return f"https://www.gravatar.com/avatar/{h}?d=404"
