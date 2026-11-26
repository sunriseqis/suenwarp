from __future__ import annotations

import asyncio
import ipaddress
import json
import math
import random
import socket
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from .ech import fetch_ech_config_list
from .fallback import collect_and_probe_fallback
from .render import effective_ws_path
from .store import Store
from .vless_client import probe_target_via_vless, speed_test_vless, tcp_connect_ms, ws_probe

CF_CIDRS = [
    "104.16.0.0/16",
    "104.18.0.0/16",
    "172.64.0.0/16",
    "162.159.0.0/16",
]


def _parse_http_status(raw: bytes) -> tuple[int, bytes, bytes]:
    if not raw:
        return 0, b"", b""
    head, _, body = raw.partition(b"\r\n\r\n")
    first_line = head.split(b"\r\n", 1)[0].decode("latin1", errors="ignore")
    parts = first_line.split(" ", 2)
    code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
    return code, head, body


def _is_ai_response_ok(raw: bytes, allow_401: bool = False) -> bool:
    code, head, body = _parse_http_status(raw)
    if code == 0 or code in (403, 451, 530):
        return False
    if code == 401 and not allow_401:
        return False
    lower_all = (head + b"\n" + body[:4096]).lower()
    blocked_markers = (
        b"unsupported_country",
        b"not available in your country",
        b"region is not supported",
        b"cf-mitigated",
        b"error code: 1020",
    )
    return not any(m in lower_all for m in blocked_markers)


def _parse_host_port(raw: str, default_port: int) -> tuple[str, int]:
    raw = raw.strip()
    if not raw:
        return "", default_port
    if raw.startswith("[") and "]:" in raw:
        h, p = raw[1:].split("]:", 1)
        return h, int(p) if p.isdigit() else default_port
    if ":" in raw and raw.count(":") == 1:
        h, p = raw.split(":", 1)
        return h.strip(), int(p.strip()) if p.strip().isdigit() else default_port
    return raw, default_port


async def _collect_vless_candidates(
    cfg: dict[str, Any],
    store: Store,
    source_logs: list[dict[str, Any]] | None = None,
) -> list[tuple[str, int]]:
    vless = cfg.get("vless", {})
    default_port = int(vless.get("port") or 443)
    max_cand = int(vless.get("max_candidates") or 120)
    seen: set[tuple[str, int]] = set()
    anchors: list[tuple[str, int]] = []
    pool: list[tuple[str, int]] = []

    def add_to(target: list[tuple[str, int]], item: str) -> bool:
        line = item.split("#", 1)[0].strip()
        if not line:
            return False
        h, p = _parse_host_port(line, default_port)
        if h and (h, p) not in seen:
            seen.add((h, p))
            target.append((h, p))
            return True
        return False

    # 1. Keep previous scan's winning VLESS nodes as anchors for continuity
    prev_nodes = (store.report() or {}).get("nodes") or []
    for n in prev_nodes:
        if (n.get("class") or "vless") == "vless" and n.get("server"):
            add_to(anchors, f"{n['server']}:{int(n.get('port') or default_port)}")

    # 2. Manual candidates as anchors
    manual_added = 0
    for c in vless.get("candidates") or []:
        if add_to(anchors, str(c)):
            manual_added += 1
    if source_logs is not None and manual_added:
        source_logs.append({
            "kind": "手填节点",
            "target": "vless.candidates",
            "ok": True,
            "count": manual_added,
            "ms": 0,
            "message": f"加载 {manual_added} 条",
        })

    # 3. Fetch ALL online IP/domain sources without early truncation
    sources = vless.get("sources") or []
    if sources:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            for src in sources:
                src = str(src).strip()
                if not src:
                    continue
                t0 = time.perf_counter()
                try:
                    resp = await client.get(src)
                    ms = round((time.perf_counter() - t0) * 1000)
                    if resp.status_code == 200:
                        added = 0
                        total_lines = 0
                        for line in resp.text.splitlines():
                            if line.strip() and not line.strip().startswith("#"):
                                total_lines += 1
                            if add_to(pool, line):
                                added += 1
                        if source_logs is not None:
                            source_logs.append({
                                "kind": "优选源",
                                "target": src,
                                "ok": total_lines > 0,
                                "count": added,
                                "ms": ms,
                                "message": f"HTTP 200 · 共 {total_lines} 行，入池 {added} 条",
                            })
                    else:
                        if source_logs is not None:
                            source_logs.append({
                                "kind": "优选源",
                                "target": src,
                                "ok": False,
                                "count": 0,
                                "ms": ms,
                                "message": f"HTTP {resp.status_code}",
                            })
                except Exception as e:
                    ms = round((time.perf_counter() - t0) * 1000)
                    if source_logs is not None:
                        source_logs.append({
                            "kind": "优选源",
                            "target": src,
                            "ok": False,
                            "count": 0,
                            "ms": ms,
                            "message": str(e) or "请求失败",
                        })
                    continue

    # 4. Add fresh CF Anycast IP samples into the rotating pool
    cf_sample = int((cfg.get("scan") or {}).get("cf_sample_count") or 0)
    if cf_sample > 0:
        nets = [ipaddress.ip_network(c) for c in CF_CIDRS]
        attempts = 0
        sampled = 0
        while sampled < cf_sample and attempts < cf_sample * 4:
            attempts += 1
            net = random.choice(nets)
            host_int = random.randint(int(net.network_address) + 1, int(net.broadcast_address) - 1)
            ip_str = str(ipaddress.IPv4Address(host_int))
            if (ip_str, default_port) not in seen:
                seen.add((ip_str, default_port))
                pool.append((ip_str, default_port))
                sampled += 1
        if source_logs is not None and sampled:
            source_logs.append({
                "kind": "CF 网段抽样",
                "target": "Cloudflare Anycast",
                "ok": True,
                "count": sampled,
                "ms": 0,
                "message": f"随机抽样 {sampled} 个 IP",
            })

    # 5. Shuffle pool so every scan tests fresh domains/IPs alongside anchors
    random.shuffle(pool)
    combined = anchors + pool
    return combined[:max_cand]


async def _collect_proxy_ips(
    cfg: dict[str, Any],
    source_logs: list[dict[str, Any]] | None = None,
) -> list[str]:
    vless = cfg.get("vless", {})
    out: list[str] = []
    if str(vless.get("proxy_ip") or "").strip():
        out.append(str(vless["proxy_ip"]).strip())

    # Fetch online ProxyIP subscription sources
    proxy_sources = [str(u).strip() for u in (vless.get("proxy_sources") or []) if str(u).strip()]
    fetched: list[str] = []
    if proxy_sources:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
            for src in proxy_sources:
                t0 = time.perf_counter()
                try:
                    r = await client.get(src)
                    ms = round((time.perf_counter() - t0) * 1000)
                    if r.status_code == 200:
                        lines = [ln.split("#", 1)[0].strip() for ln in r.text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
                        fetched.extend(lines)
                        if source_logs is not None:
                            source_logs.append({
                                "kind": "反代订阅",
                                "target": src,
                                "ok": len(lines) > 0,
                                "count": len(lines),
                                "ms": ms,
                                "message": f"HTTP 200 · 解析 {len(lines)} 条",
                            })
                    elif source_logs is not None:
                        source_logs.append({"kind": "反代订阅", "target": src, "ok": False, "count": 0, "ms": ms, "message": f"HTTP {r.status_code}"})
                except Exception as e:
                    ms = round((time.perf_counter() - t0) * 1000)
                    if source_logs is not None:
                        source_logs.append({"kind": "反代订阅", "target": src, "ok": False, "count": 0, "ms": ms, "message": str(e) or "请求失败"})

    random.shuffle(fetched)
    builtin = [str(p).strip() for p in (vless.get("proxy_ips") or []) if str(p).strip()]
    for cand in builtin + fetched[:10]:
        if cand and cand not in out:
            out.append(cand)
    return out[:8] if out else [""]


def _score_node(n: dict[str, Any], thresh: dict[str, Any], require_verify: bool = True) -> float:
    max_lat = float(thresh.get("max_latency_ms") or 1500.0)
    max_jit = float(thresh.get("max_jitter_ms") or 400.0)
    max_loss = float(thresh.get("max_loss_pct") or 50.0)
    ref_speed = float(thresh.get("speed_ref_mbps") or 50.0)

    lat = float(n.get("latency_ms") or max_lat)
    jit = float(n.get("jitter_ms") or max_jit)
    loss = float(n.get("loss_pct") or 0.0)
    speed = float(n.get("speed_mbps") or 0.0)

    s_lat = max(0.0, 1.0 - lat / max_lat) * 35.0
    s_jit = max(0.0, 1.0 - jit / max_jit) * 20.0
    s_loss = max(0.0, 1.0 - loss / max(1.0, max_loss)) * 15.0
    s_spd = min(1.0, speed / max(1.0, ref_speed)) * 30.0
    total = s_lat + s_jit + s_loss + s_spd
    if require_verify and n.get("measured") and n.get("ai_ok") is False:
        total *= 0.5
    return round(total, 1)


async def _verify_single_domain(
    host: str,
    port: int,
    worker_host: str,
    ws_path: str,
    user_uuid: str,
    dom: str,
    blocked_countries: set[str],
) -> bool:
    d_lower = dom.lower()
    if "chatgpt.com" in d_lower or "openai.com" in d_lower:
        try:
            ok_tr, raw_tr = await probe_target_via_vless(
                host, port, worker_host, ws_path, user_uuid, "https://chatgpt.com/cdn-cgi/trace", 7.0
            )
            if ok_tr:
                body_str = raw_tr.partition(b"\r\n\r\n")[2].decode("utf-8", errors="ignore")
                for line in body_str.splitlines():
                    if line.startswith("loc="):
                        loc = line.split("=", 1)[1].strip().upper()
                        if loc and loc in blocked_countries:
                            return False
            ok_api, raw_api = await probe_target_via_vless(
                host, port, worker_host, ws_path, user_uuid, "https://api.openai.com/v1/models", 7.0
            )
            if ok_api and _is_ai_response_ok(raw_api, allow_401=True):
                return True
        except Exception:
            pass

    try:
        ok_d, raw_resp = await probe_target_via_vless(
            host, port, worker_host, ws_path, user_uuid, f"https://{dom}/", 8.0
        )
        return bool(ok_d and _is_ai_response_ok(raw_resp, allow_401=False))
    except Exception:
        return False


async def run_scan(cfg: dict[str, Any], store: Store) -> dict[str, Any]:
    t_start = time.perf_counter()
    vless = cfg.get("vless", {})
    thresh = cfg.get("thresholds", {})
    scan_cfg = cfg.get("scan", {})
    speed_cfg = cfg.get("speed_test", {})
    stab_cfg = cfg.get("stability", {})
    top_cfg = cfg.get("top", {})
    fb_cfg = cfg.get("fallback", {})

    blocked_countries = {str(c).strip().upper() for c in (vless.get("blocked_countries") or []) if str(c).strip()}
    allowed_countries = {str(c).strip().upper() for c in (vless.get("allowed_countries") or []) if str(c).strip()}

    passed_raw: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    candidates: list[tuple[str, int]] = []
    source_logs: list[dict[str, Any]] = []

    if vless.get("enabled", True) and vless.get("worker_host") and vless.get("uuid"):
        worker_host = str(vless["worker_host"]).strip()
        user_uuid = str(vless["uuid"]).strip()
        base_path = str(vless.get("path") or "/")

        proxy_candidates = await _collect_proxy_ips(cfg, source_logs)
        active_proxy_ip = proxy_candidates[0]
        ws_path = effective_ws_path(base_path, active_proxy_ip)

        ech_cfg = vless.get("ech") or {}
        if ech_cfg.get("enabled") and not ech_cfg.get("clash_config"):
            store.set_progress("获取 ECH 配置", 0, 1)
            try:
                ech_val = await fetch_ech_config_list(
                    str(ech_cfg.get("doh") or "https://dns.alidns.com/dns-query"),
                    worker_host,
                )
                if ech_val:
                    ech_cfg["clash_config"] = ech_val
            except Exception:
                pass

        store.set_progress("采集候选节点", 0, 0)
        candidates = await _collect_vless_candidates(cfg, store, source_logs)
        concurrency = max(1, int(scan_cfg.get("concurrency") or 32))
        rounds = max(1, int(scan_cfg.get("rounds") or 3))
        timeout_s = max(0.5, float(scan_cfg.get("timeout_ms") or 3000) / 1000.0)

        sem = asyncio.Semaphore(concurrency)
        probe_done = 0
        probe_total = len(candidates)
        store.set_progress("并发探测节点", 0, probe_total)

        async def probe_one(host: str, port: int) -> None:
            nonlocal probe_done
            async with sem:
                try:
                    resolved_ip = socket.gethostbyname(host)
                except Exception:
                    resolved_ip = host

                code, err_msg = await ws_probe(host, port, worker_host, ws_path, timeout_s)
                if code != 101:
                    rejected.append({
                        "class": "vless",
                        "server": host,
                        "port": port,
                        "latency_ms": 0,
                        "loss_pct": 100,
                        "reason": f"WS 握手失败: {err_msg}",
                    })
                    probe_done += 1
                    store.set_progress("并发探测节点", probe_done, probe_total)
                    return

                rtts: list[float] = []
                for _ in range(rounds):
                    d = await tcp_connect_ms(host, port, timeout_s)
                    if d is not None:
                        rtts.append(d)

                probe_done += 1
                store.set_progress("并发探测节点", probe_done, probe_total)

                loss_pct = ((rounds - len(rtts)) / rounds) * 100.0
                if not rtts:
                    rejected.append({
                        "class": "vless",
                        "server": host,
                        "port": port,
                        "latency_ms": 0,
                        "loss_pct": 100,
                        "reason": "TCP 握手无响应",
                    })
                    return

                avg_lat = sum(rtts) / len(rtts)
                var = sum((r - avg_lat) ** 2 for r in rtts) / len(rtts)
                jitter = math.sqrt(var)

                if avg_lat > float(thresh.get("max_latency_ms") or 1500):
                    rejected.append({
                        "class": "vless",
                        "server": host,
                        "port": port,
                        "latency_ms": round(avg_lat, 1),
                        "loss_pct": round(loss_pct, 1),
                        "reason": f"延迟过高 ({avg_lat:.0f}ms)",
                    })
                    return
                if jitter > float(thresh.get("max_jitter_ms") or 400):
                    rejected.append({
                        "class": "vless",
                        "server": host,
                        "port": port,
                        "latency_ms": round(avg_lat, 1),
                        "loss_pct": round(loss_pct, 1),
                        "reason": f"抖动过高 ({jitter:.0f}ms)",
                    })
                    return
                if loss_pct > float(thresh.get("max_loss_pct") or 50):
                    rejected.append({
                        "class": "vless",
                        "server": host,
                        "port": port,
                        "latency_ms": round(avg_lat, 1),
                        "loss_pct": round(loss_pct, 1),
                        "reason": f"丢包过高 ({loss_pct:.0f}%)",
                    })
                    return

                node = {
                    "class": "vless",
                    "name": "",
                    "server": host,
                    "port": port,
                    "resolved_ip": resolved_ip,
                    "proxy_ip": active_proxy_ip,
                    "latency_ms": round(avg_lat, 3),
                    "jitter_ms": round(jitter, 3),
                    "loss_pct": round(loss_pct, 1),
                    "speed_mbps": 0.0,
                    "speed_peak_mbps": 0.0,
                    "speed_tail_mbps": 0.0,
                    "stability": 0.0,
                    "measured": False,
                    "idle_ok": False,
                    "idle_detail": "",
                    "domain_ok": {},
                    "egress_ip": "",
                    "egress_country": "",
                    "egress_city": "",
                    "egress_org": "",
                    "speed_diag": "",
                    "score": 0.0,
                    "streak": 1,
                    "ok": True,
                }
                node["score"] = _score_node(node, thresh)
                passed_raw.append(node)

        await asyncio.gather(*(probe_one(h, p) for h, p in candidates))
        passed_raw.sort(key=lambda x: (-x["score"], x["latency_ms"]))

        # Deduplicate by resolved_ip before shortlist so we test diverse edge IPs
        deduped: list[dict[str, Any]] = []
        seen_ips: set[str] = set()
        for n in passed_raw:
            rip = n.get("resolved_ip") or n["server"]
            if rip not in seen_ips:
                seen_ips.add(rip)
                deduped.append(n)
        passed_raw = deduped

        shortlist_n = int(speed_cfg.get("shortlist") or 8)
        shortlist = passed_raw[:shortlist_n]

        # Auto-select best working ProxyIP if multiple are configured
        if len(proxy_candidates) > 1 and shortlist:
            store.set_progress("优选反代 ProxyIP", 0, len(proxy_candidates))
            probe_node = shortlist[0]
            selected_pip = ""
            for idx, cand_pip in enumerate(proxy_candidates):
                test_path = effective_ws_path(base_path, cand_pip)
                t_pip = time.perf_counter()
                ok_pip = await _verify_single_domain(
                    probe_node["server"], int(probe_node["port"]),
                    worker_host, test_path, user_uuid, "chatgpt.com", blocked_countries,
                )
                ms_pip = round((time.perf_counter() - t_pip) * 1000)
                source_logs.append({
                    "kind": "反代探测",
                    "target": cand_pip or "(直连无反代)",
                    "ok": ok_pip,
                    "count": 1 if ok_pip else 0,
                    "ms": ms_pip,
                    "message": "ChatGPT 连通验证通过（已选用）" if ok_pip else "ChatGPT 验证未通过",
                })
                store.set_progress("优选反代 ProxyIP", idx + 1, len(proxy_candidates))
                if ok_pip:
                    active_proxy_ip = cand_pip
                    ws_path = test_path
                    selected_pip = cand_pip
                    for n in passed_raw:
                        n["proxy_ip"] = active_proxy_ip
                    break

        if speed_cfg.get("enabled", True) and shortlist:
            speed_url = str(speed_cfg.get("url") or "https://proof.ovh.net/files/100Mb.dat")
            dur_s = int(speed_cfg.get("duration_s") or 10)
            max_mb = int(speed_cfg.get("max_bytes_mb") or 0)
            sp_timeout = max(3.0, float(speed_cfg.get("timeout_ms") or 12000) / 1000.0)
            egress_url = str(vless.get("egress_probe") or "").strip()
            verify_domains = [str(d).strip() for d in (vless.get("verify_domains") or []) if str(d).strip()]

            for idx, node in enumerate(shortlist):
                store.set_progress("测速与 AI 站点验证", idx + 1, len(shortlist))
                host, port = node["server"], int(node["port"])
                try:
                    sp = await speed_test_vless(
                        host, port, worker_host, ws_path, user_uuid,
                        speed_url, dur_s, max_mb, sp_timeout,
                    )
                    node["measured"] = True
                    node["speed_mbps"] = sp["speed_mbps"]
                    node["speed_peak_mbps"] = sp["speed_peak_mbps"]
                    node["speed_tail_mbps"] = sp["speed_tail_mbps"]
                    node["stability"] = sp["stability"]
                    node["speed_diag"] = sp["speed_diag"]
                except Exception as e:
                    node["measured"] = True
                    node["speed_diag"] = "error"
                    node["speed_error"] = str(e)

                async def check_egress() -> None:
                    if not egress_url:
                        return
                    try:
                        ok_eg, body = await probe_target_via_vless(
                            host, port, worker_host, ws_path, user_uuid, egress_url, 8.0
                        )
                        if ok_eg and b"{" in body:
                            raw_json = body[body.find(b"{"):body.rfind(b"}") + 1]
                            info = json.loads(raw_json.decode("utf-8", errors="ignore"))
                            node["egress_ip"] = info.get("ip", "")
                            node["egress_country"] = info.get("country", "")
                            node["egress_city"] = info.get("city", "")
                            node["egress_org"] = info.get("org", "")
                    except Exception:
                        pass

                async def check_dom(dom: str) -> None:
                    node["domain_ok"][dom] = await _verify_single_domain(
                        host, port, worker_host, ws_path, user_uuid, dom, blocked_countries
                    )

                await asyncio.gather(check_egress(), *(check_dom(d) for d in verify_domains))
                dom_map = node["domain_ok"] or {}
                if dom_map:
                    node["ai_ok"] = all(dom_map.values())
                    node["ai_detail"] = " · ".join(f"{k}: {'✓' if v else '✗'}" for k, v in dom_map.items())
                else:
                    node["ai_ok"] = True
                    node["ai_detail"] = "未配置验证站点"
                node["score"] = _score_node(node, thresh, bool(vless.get("require_verify_pass", True)))

            # Concurrent idle survival test across shortlist (single wait)
            if speed_cfg.get("idle_enabled"):
                idle_s = max(1, min(15, int(speed_cfg.get("idle_seconds") or 10)))
                store.set_progress(f"空闲存活测试 ({idle_s}s)", 0, len(shortlist))
                await asyncio.sleep(idle_s)

                async def check_idle(n: dict[str, Any]) -> None:
                    try:
                        ok_idle, _ = await probe_target_via_vless(
                            n["server"], int(n["port"]), worker_host, ws_path, user_uuid,
                            "http://cp.cloudflare.com/generate_204", 6.0,
                        )
                        n["idle_ok"] = ok_idle
                        n["idle_detail"] = f"空闲 {idle_s}s 后{'仍可用' if ok_idle else '已断开'}"
                    except Exception:
                        n["idle_ok"] = False
                        n["idle_detail"] = f"空闲 {idle_s}s 后失败"

                await asyncio.gather(*(check_idle(n) for n in shortlist))
                store.set_progress(f"空闲存活测试 ({idle_s}s)", len(shortlist), len(shortlist))

    # Secondary filters
    require_verify = bool(vless.get("require_verify_pass", True))
    min_speed = float(thresh.get("min_speed_mbps") or 0.0)
    speed_req = bool(speed_cfg.get("required", True)) and bool(speed_cfg.get("enabled", True))

    final_vless: list[dict[str, Any]] = []
    for node in passed_raw:
        if speed_req and (not node["measured"] or node["speed_mbps"] <= 0 or node["speed_mbps"] < min_speed):
            reason = (
                "未进入测速或未测出速率"
                if (not node["measured"] or node["speed_mbps"] <= 0)
                else f"速率低于门槛 ({node['speed_mbps']} Mbps)"
            )
            rejected.append({
                "class": "vless",
                "server": node["server"],
                "port": node["port"],
                "latency_ms": node["latency_ms"],
                "loss_pct": node["loss_pct"],
                "reason": reason,
            })
            continue
        country = (node.get("egress_country") or "").upper()
        if country and country in blocked_countries:
            rejected.append({
                "class": "vless",
                "server": node["server"],
                "port": node["port"],
                "latency_ms": node["latency_ms"],
                "loss_pct": node["loss_pct"],
                "reason": f"出口地区受限 ({country})",
            })
            continue
        if allowed_countries and country and country not in allowed_countries:
            rejected.append({
                "class": "vless",
                "server": node["server"],
                "port": node["port"],
                "latency_ms": node["latency_ms"],
                "loss_pct": node["loss_pct"],
                "reason": f"出口国家不在允许列表 ({country})",
            })
            continue
        if require_verify and node["measured"] and node.get("ai_ok") is False:
            failed_doms = [d for d, ok in (node.get("domain_ok") or {}).items() if not ok]
            rejected.append({
                "class": "vless",
                "server": node["server"],
                "port": node["port"],
                "latency_ms": node["latency_ms"],
                "loss_pct": node["loss_pct"],
                "reason": f"AI/地域验证一票否决: {', '.join(failed_doms) or '受限'}",
            })
            continue
        final_vless.append(node)

    stab_data = store.load_stability()
    new_stab: dict[str, int] = {}
    for node in final_vless:
        key = f"vless:{node['server']}:{node['port']}"
        streak = int(stab_data.get(key, 0)) + 1
        node["streak"] = streak
        new_stab[key] = streak
    store.save_stability(new_stab)

    min_hits = int(stab_cfg.get("min_hits") or 1)
    bootstrap = bool(stab_cfg.get("bootstrap", True))
    if min_hits > 1 and not (bootstrap and len(stab_data) == 0):
        final_vless = [n for n in final_vless if n["streak"] >= min_hits]

    final_vless.sort(key=lambda x: (-x["score"], x["latency_ms"]))
    top_n = int(top_cfg.get("vless") or 10)
    final_vless = final_vless[:top_n]

    # Fallback open-source free nodes when enabled
    fallback_nodes: list[dict[str, Any]] = []
    if fb_cfg.get("enabled"):
        trigger_min = int(fb_cfg.get("trigger_min") or 2)
        if fb_cfg.get("always_include") or len(final_vless) < trigger_min:
            fallback_nodes = await collect_and_probe_fallback(
                cfg,
                on_progress=lambda st, d, t: store.set_progress(st, d, t),
                source_logs=source_logs,
            )

    all_nodes = final_vless + fallback_nodes
    rep = {
        "generated_at": datetime.now(timezone.utc).astimezone().isoformat(),
        "duration_sec": round(time.perf_counter() - t_start, 2),
        "candidates": len(candidates),
        "passed": len(all_nodes),
        "nodes": all_nodes,
        "rejected": rejected,
        "sources": source_logs,
    }
    store.save_report(rep)
    store.append_history(rep)
    return rep
