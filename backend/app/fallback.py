from __future__ import annotations

import asyncio
import base64
import json
import re
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

import httpx
import yaml

from .netfetch import fetch_text
from .vless_client import tcp_connect_ms

RESTRICTED_NAME_RE = re.compile(
    r"(?:^|[^a-z])(cn|hk|mo|ru|china|hong\s*kong|hongkong|macau|macao|russia)(?:[^a-z]|$)"
    r"|中国|香港|澳门|俄罗斯|回国|剩余流量|过期时间|官网|套餐",
    re.IGNORECASE,
)


def _b64_decode(s: str) -> str:
    s = s.strip().replace("-", "+").replace("_", "/")
    pad = (-len(s)) % 4
    if pad:
        s += "=" * pad
    return base64.b64decode(s).decode("utf-8", errors="ignore")


def _parse_uri_node(uri: str) -> dict[str, Any] | None:
    uri = uri.strip()
    if not uri:
        return None
    try:
        if uri.startswith("vmess://"):
            raw = json.loads(_b64_decode(uri[8:]))
            host = str(raw.get("add") or "").strip()
            port = int(raw.get("port") or 0)
            name = str(raw.get("ps") or f"vmess-{host}")
            if not host or not port:
                return None
            clash_proxy: dict[str, Any] = {
                "name": name,
                "type": "vmess",
                "server": host,
                "port": port,
                "uuid": raw.get("id", ""),
                "alterId": int(raw.get("aid") or 0),
                "cipher": raw.get("scy") or "auto",
                "tls": str(raw.get("tls") or "").lower() == "tls",
                "network": raw.get("net") or "tcp",
            }
            if clash_proxy["network"] == "ws":
                clash_proxy["ws-opts"] = {
                    "path": raw.get("path") or "/",
                    "headers": {"Host": raw.get("host") or host},
                }
            return {
                "class": "fallback",
                "proto": "vmess",
                "name": name,
                "server": host,
                "port": port,
                "raw_uri": uri,
                "clash_proxy": clash_proxy,
            }

        p = urlparse(uri)
        scheme = p.scheme.lower()
        if scheme not in ("vless", "trojan", "ss"):
            return None
        host = p.hostname or ""
        port = p.port or 443
        if not host:
            return None
        name = unquote(p.fragment or f"{scheme}-{host}:{port}")
        qs = {k: v[0] for k, v in parse_qs(p.query).items() if v}

        if scheme == "trojan":
            clash_proxy = {
                "name": name,
                "type": "trojan",
                "server": host,
                "port": port,
                "password": unquote(p.username or ""),
                "sni": qs.get("sni") or host,
                "skip-cert-verify": qs.get("allowInsecure") in ("1", "true"),
            }
            if qs.get("type") == "ws":
                clash_proxy["network"] = "ws"
                clash_proxy["ws-opts"] = {
                    "path": qs.get("path") or "/",
                    "headers": {"Host": qs.get("host") or qs.get("sni") or host},
                }
        elif scheme == "vless":
            clash_proxy = {
                "name": name,
                "type": "vless",
                "server": host,
                "port": port,
                "uuid": unquote(p.username or ""),
                "tls": qs.get("security", "tls") in ("tls", "reality"),
                "servername": qs.get("sni") or host,
                "network": qs.get("type") or "tcp",
                "client-fingerprint": qs.get("fp") or "chrome",
            }
            if clash_proxy["network"] == "ws":
                clash_proxy["ws-opts"] = {
                    "path": qs.get("path") or "/",
                    "headers": {"Host": qs.get("host") or qs.get("sni") or host},
                }
        else:  # ss
            userinfo = unquote(p.username or "")
            if ":" not in userinfo:
                userinfo = _b64_decode(userinfo)
            if ":" not in userinfo:
                return None
            cipher, password = userinfo.split(":", 1)
            clash_proxy = {
                "name": name,
                "type": "ss",
                "server": host,
                "port": port,
                "cipher": cipher,
                "password": password,
            }

        return {
            "class": "fallback",
            "proto": scheme,
            "name": name,
            "server": host,
            "port": port,
            "raw_uri": uri,
            "clash_proxy": clash_proxy,
        }
    except Exception:
        return None


def parse_subscription_text(text: str) -> list[dict[str, Any]]:
    text = text.strip()
    if not text:
        return []
    out: list[dict[str, Any]] = []

    # Try Clash YAML first if it looks like YAML
    if "proxies:" in text[:4096]:
        try:
            doc = yaml.safe_load(text)
            if isinstance(doc, dict) and isinstance(doc.get("proxies"), list):
                for item in doc["proxies"]:
                    if not isinstance(item, dict):
                        continue
                    host = str(item.get("server") or "").strip()
                    port = int(item.get("port") or 0)
                    name = str(item.get("name") or f"{item.get('type', 'proxy')}-{host}")
                    if not host or not port:
                        continue
                    out.append({
                        "class": "fallback",
                        "proto": str(item.get("type") or "proxy"),
                        "name": name,
                        "server": host,
                        "port": port,
                        "raw_uri": "",
                        "clash_proxy": item,
                    })
                if out:
                    return out
        except Exception:
            pass

    # Try Base64 decode if no scheme markers present
    if "://" not in text:
        try:
            decoded = _b64_decode(text)
            if "://" in decoded:
                text = decoded
        except Exception:
            pass

    for line in text.splitlines():
        node = _parse_uri_node(line)
        if node:
            out.append(node)
    return out


async def collect_and_probe_fallback(
    cfg: dict[str, Any],
    on_progress: Any = None,
    source_logs: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    fb = cfg.get("fallback") or {}
    sources = [str(u).strip() for u in (fb.get("sources") or []) if str(u).strip()]
    if not sources:
        return []

    max_cand = max(1, int(fb.get("max_candidates") or 40))
    top_n = max(1, int(fb.get("top") or 5))
    timeout_s = max(0.5, float(fb.get("timeout_ms") or 2500) / 1000.0)

    raw_nodes: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()

    async with httpx.AsyncClient(timeout=12.0, follow_redirects=True) as client:
        for url in sources:
            t0 = asyncio.get_event_loop().time()
            try:
                resp = await fetch_text(client, url, headers={"User-Agent": "clash-verge/v2.0"})
                ms = round((asyncio.get_event_loop().time() - t0) * 1000)
                if not resp.ok:
                    if source_logs is not None:
                        source_logs.append({
                            "kind": "兜底订阅",
                            "target": url,
                            "ok": False,
                            "count": 0,
                            "ms": ms,
                            "message": resp.message,
                        })
                    continue
                parsed = parse_subscription_text(resp.text)
                added = 0
                for n in parsed:
                    if RESTRICTED_NAME_RE.search(n.get("name") or ""):
                        continue
                    key = (n["server"], int(n["port"]))
                    if key in seen:
                        continue
                    seen.add(key)
                    raw_nodes.append(n)
                    added += 1
                    if len(raw_nodes) >= max_cand:
                        break
                if source_logs is not None:
                    source_logs.append({
                        "kind": "兜底订阅",
                        "target": url,
                        "ok": added > 0,
                        "count": added,
                        "ms": ms,
                        "message": f"解析 {len(parsed)} 条，过滤后 {added} 条",
                    })
            except Exception as e:
                ms = round((asyncio.get_event_loop().time() - t0) * 1000)
                if source_logs is not None:
                    source_logs.append({
                        "kind": "兜底订阅",
                        "target": url,
                        "ok": False,
                        "count": 0,
                        "ms": ms,
                        "message": str(e) or "请求失败",
                    })
                continue
            if len(raw_nodes) >= max_cand:
                break

    if not raw_nodes:
        return []

    sem = asyncio.Semaphore(24)
    alive: list[dict[str, Any]] = []
    done = 0
    total = len(raw_nodes)

    async def probe(n: dict[str, Any]) -> None:
        nonlocal done
        async with sem:
            rtt = await tcp_connect_ms(n["server"], int(n["port"]), timeout_s)
            done += 1
            if on_progress:
                on_progress("兜底节点测活", done, total)
            if rtt is not None:
                n["latency_ms"] = round(rtt, 1)
                n["jitter_ms"] = 0.0
                n["loss_pct"] = 0.0
                n["score"] = round(max(10.0, 100.0 - rtt / 20.0), 1)
                n["ok"] = True
                alive.append(n)

    await asyncio.gather(*(probe(n) for n in raw_nodes))
    alive.sort(key=lambda x: x["latency_ms"])
    return alive[:top_n]
