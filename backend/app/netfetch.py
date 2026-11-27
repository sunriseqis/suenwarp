"""HTTP helpers that survive a blocked GitHub raw endpoint.

Several default sources live on raw.githubusercontent.com, which is unreliable
from mainland China. Every fetch goes through :func:`fetch_text`, which retries
the same resource through public mirrors before giving up.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

# Ordered cheapest-first: direct, then DNS-level rewrite, then path-prefix proxies.
PREFIX_MIRRORS = (
    "https://ghfast.top/{url}",
    "https://ghproxy.net/{url}",
    "https://gh-proxy.com/{url}",
)

GITHUB_HOSTS = {
    "raw.githubusercontent.com",
    "gist.githubusercontent.com",
    "github.com",
    "objects.githubusercontent.com",
}


@dataclass
class FetchResult:
    ok: bool
    text: str = ""
    url: str = ""          # the URL that actually answered
    via: str = "direct"    # direct | mirror
    status: int = 0
    message: str = ""
    tried: list[str] = field(default_factory=list)

    def label(self) -> str:
        """Short 'how did we get this' text for the source log."""
        if not self.ok:
            return self.message or "失败"
        if self.via == "mirror":
            host = urlparse(self.url).netloc
            return f"HTTP 200 · 镜像 {host}"
        return "HTTP 200"


def mirror_candidates(url: str) -> list[str]:
    """Return the ordered list of URLs to try for one resource."""
    out = [url]
    host = (urlparse(url).netloc or "").lower()
    if host not in GITHUB_HOSTS:
        return out

    if "raw.githubusercontent.com" in host:
        # gitmirror serves the same path layout
        out.append(url.replace("raw.githubusercontent.com", "raw.gitmirror.com"))
    for tpl in PREFIX_MIRRORS:
        out.append(tpl.format(url=url))

    # de-duplicate while keeping order
    seen: set[str] = set()
    uniq: list[str] = []
    for u in out:
        if u not in seen:
            seen.add(u)
            uniq.append(u)
    return uniq


async def fetch_text(
    client: httpx.AsyncClient,
    url: str,
    headers: dict[str, str] | None = None,
    timeout: float | None = None,
) -> FetchResult:
    """GET ``url`` with mirror fallback. Never raises."""
    url = (url or "").strip()
    if not url:
        return FetchResult(ok=False, message="空地址")

    tried: list[str] = []
    last: str = ""
    for cand in mirror_candidates(url):
        tried.append(cand)
        try:
            resp = await client.get(cand, headers=headers, timeout=timeout)
        except Exception as exc:  # noqa: BLE001 - network errors are expected here
            last = type(exc).__name__
            continue
        if resp.status_code == 200 and resp.text.strip():
            return FetchResult(
                ok=True,
                text=resp.text,
                url=cand,
                via="direct" if cand == url else "mirror",
                status=200,
                tried=tried,
            )
        last = f"HTTP {resp.status_code}"

    return FetchResult(
        ok=False,
        status=0,
        message=f"{last}（已试 {len(tried)} 个地址）" if last else "无可用地址",
        tried=tried,
    )
