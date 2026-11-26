from __future__ import annotations

import base64
from typing import Any
from urllib.parse import quote

import yaml


def effective_ws_path(path: str, proxy_ip: str) -> str:
    p = (path or "/").strip() or "/"
    pip = (proxy_ip or "").strip()
    if not pip or "proxyip=" in p.lower():
        return p
    sep = "&" if "?" in p else "?"
    return f"{p}{sep}proxyip={pip}"


def node_label(n: dict[str, Any]) -> str:
    cls = n.get("class") or "vless"
    if cls == "fallback":
        base = n.get("name") or f"{n.get('server')}:{n.get('port')}"
        lat = f" · {round(float(n['latency_ms']))}ms" if n.get("latency_ms") else ""
        return f"备用 {base}{lat}"
    prefix = {"wg": "WG", "wg_domain": "WGD", "masque": "MQ", "vless": "VL"}.get(cls, cls.upper())
    parts = [f"{prefix} {n.get('server')}:{n.get('port')}"]
    if n.get("egress_country"):
        parts.append(str(n["egress_country"]))
    if n.get("latency_ms"):
        parts.append(f"{round(float(n['latency_ms']))}ms")
    if n.get("speed_mbps"):
        parts.append(f"{float(n['speed_mbps']):.1f}Mbps")
    return " · ".join(parts)


def render_clash(nodes: list[dict[str, Any]], cfg: dict[str, Any]) -> str:
    vless = cfg.get("vless", {})
    sub = cfg.get("subscription", {})
    ech = vless.get("ech") or {}
    worker_host = str(vless.get("worker_host") or "")
    user_uuid = str(vless.get("uuid") or "")
    base_path = str(vless.get("path") or "/")
    default_proxy_ip = str(vless.get("proxy_ip") or "")
    fp = str(vless.get("fingerprint") or "chrome")
    test_url = sub.get("test_url") or "http://cp.cloudflare.com/generate_204"
    blocked = {str(c).strip().upper() for c in (vless.get("blocked_countries") or []) if str(c).strip()}

    proxies: list[dict[str, Any]] = []
    vless_names: list[str] = []
    fallback_names: list[str] = []
    ai_names: list[str] = []
    seen_names: set[str] = set()

    def unique_name(raw: str) -> str:
        name = raw
        idx = 2
        while name in seen_names:
            name = f"{raw} #{idx}"
            idx += 1
        seen_names.add(name)
        return name

    for n in nodes:
        cls = n.get("class") or "vless"
        if cls == "fallback":
            cp = dict(n.get("clash_proxy") or {})
            if not cp:
                continue
            name = unique_name(node_label(n))
            cp["name"] = name
            proxies.append(cp)
            fallback_names.append(name)
            continue

        if cls != "vless":
            continue
        name = unique_name(node_label(n))
        vless_names.append(name)
        ws_path = effective_ws_path(base_path, str(n.get("proxy_ip") or default_proxy_ip))
        entry: dict[str, Any] = {
            "name": name,
            "type": "vless",
            "server": n["server"],
            "port": int(n.get("port") or 443),
            "uuid": user_uuid,
            "network": "ws",
            "tls": True,
            "udp": False,
            "servername": worker_host,
            "client-fingerprint": fp,
            "ws-opts": {
                "path": ws_path,
                "headers": {"Host": worker_host},
            },
        }
        if ech.get("enabled") and ech.get("clash_config"):
            entry["ech-opts"] = {
                "enable": True,
                "config": ech["clash_config"],
            }
        proxies.append(entry)

        dom_ok = n.get("domain_ok") or {}
        country = str(n.get("egress_country") or "").upper()
        if dom_ok and all(dom_ok.values()) and (not country or country not in blocked):
            ai_names.append(name)

    groups: list[dict[str, Any]] = [
        {
            "name": "节点-自动",
            "type": "url-test",
            "url": test_url,
            "interval": 300,
            "tolerance": 50,
            "proxies": vless_names or fallback_names or ["DIRECT"],
        },
    ]

    if fallback_names:
        groups.append({
            "name": "🛡️ 兜底备用",
            "type": "url-test",
            "url": test_url,
            "interval": 300,
            "tolerance": 80,
            "proxies": fallback_names,
        })
        groups.append({
            "name": "🚀 自动故障转移",
            "type": "fallback",
            "url": test_url,
            "interval": 180,
            "proxies": ["节点-自动", "🛡️ 兜底备用"] if vless_names else ["🛡️ 兜底备用"],
        })

    if ai_names:
        groups.append({
            "name": "🤖 AI-专用",
            "type": "url-test",
            "url": test_url,
            "interval": 300,
            "tolerance": 50,
            "proxies": ai_names,
        })

    manual_list = []
    if fallback_names:
        manual_list.append("🚀 自动故障转移")
    manual_list.append("节点-自动")
    if ai_names:
        manual_list.append("🤖 AI-专用")
    if fallback_names:
        manual_list.append("🛡️ 兜底备用")
    manual_list.extend(vless_names)
    manual_list.extend(fallback_names)

    groups.append({
        "name": "节点-手动",
        "type": "select",
        "proxies": manual_list,
    })

    for dom in vless.get("verify_domains") or []:
        dom = str(dom).strip()
        if not dom:
            continue
        matched = [
            node_label(n)
            for n in nodes
            if (n.get("class") or "vless") == "vless" and (n.get("domain_ok") or {}).get(dom)
        ]
        if matched:
            groups.append({
                "name": f"直达-{dom}",
                "type": "select",
                "proxies": matched,
            })

    doc = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "ipv6": True,
        "proxies": proxies,
        "proxy-groups": groups,
        "rules": [
            "GEOIP,CN,DIRECT",
            "MATCH,节点-手动",
        ],
    }
    return "# generated by warp-sub\n" + yaml.safe_dump(doc, allow_unicode=True, sort_keys=False)


def render_v2ray(nodes: list[dict[str, Any]], cfg: dict[str, Any]) -> str:
    vless = cfg.get("vless", {})
    worker_host = str(vless.get("worker_host") or "")
    user_uuid = str(vless.get("uuid") or "")
    base_path = str(vless.get("path") or "/")
    default_proxy_ip = str(vless.get("proxy_ip") or "")
    fp = quote(str(vless.get("fingerprint") or "chrome"), safe="")
    sni = quote(worker_host, safe="")

    links: list[str] = []
    for n in nodes:
        cls = n.get("class") or "vless"
        if cls == "fallback":
            if n.get("raw_uri"):
                links.append(str(n["raw_uri"]))
            continue
        if cls != "vless":
            continue
        ws_path = quote(effective_ws_path(base_path, str(n.get("proxy_ip") or default_proxy_ip)), safe="")
        label = quote(node_label(n), safe="")
        link = (
            f"vless://{user_uuid}@{n['server']}:{int(n.get('port') or 443)}"
            f"?encryption=none&security=tls&type=ws&host={sni}&sni={sni}&fp={fp}&path={ws_path}#{label}"
        )
        links.append(link)
    return base64.b64encode("\n".join(links).encode("utf-8")).decode("ascii")
