from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
import httpx

from .config import SCHEMA, ConfigHolder, active_env
from .fallback import parse_subscription_text
from .integrations import WritebackSyncer
from .netfetch import fetch_text
from .render import render_clash, render_v2ray
from .scanner import run_scan
from .store import Store

logger = logging.getLogger("warp-sub")

# uvicorn 只给自己的 logger 装 handler，应用自己的 info/warning 默认无处可去
# （root 没有 handler 时只有 WARNING+ 会走 last-resort 打到 stderr）。
# 首次部署“已生成初始配置”“WARPSUB_TOKEN 未设置”这类提示必须能在
# `docker logs` 里看到，所以在这里装一次 root handler。
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

holder = ConfigHolder()
store = Store(holder.data_dir())
wb = WritebackSyncer(holder.data_dir())
scan_lock = asyncio.Lock()


def _authorized(request: Request) -> bool:
    token = str(holder.get().get("token") or "")
    if not token:
        return True
    if request.query_params.get("token") == token:
        return True
    return request.headers.get("X-Warp-Token") == token


def _require_auth(request: Request) -> None:
    if not _authorized(request):
        raise HTTPException(status_code=403, detail="forbidden")


def _parse_daily(expr: str) -> tuple[int, int]:
    expr = expr.strip()
    if expr in ("@daily", "@midnight"):
        return 4, 0
    parts = expr.split()
    if len(parts) < 2:
        return 4, 0
    try:
        minute = max(0, min(59, int(parts[0])))
        hour = max(0, min(23, int(parts[1])))
        return hour, minute
    except ValueError:
        return 4, 0


async def _execute_scan() -> dict[str, Any]:
    async with scan_lock:
        started = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        store.set_running(True, started)
        try:
            cfg = holder.get()
            rep = await run_scan(cfg, store)
            nodes = rep.get("nodes") or []
            worker_host = str((cfg.get("vless") or {}).get("worker_host") or "")
            if wb.view(worker_host).get("enabled") and wb.view(worker_host).get("auto") and nodes:
                await wb.sync(nodes, worker_host)
            return rep
        finally:
            store.set_running(False, "")


async def _scheduler_loop() -> None:
    while True:
        cfg = holder.get()
        hour, minute = _parse_daily(str(cfg.get("schedule") or "0 4 * * *"))
        tz = _get_tz(str(cfg.get("timezone") or "Asia/Shanghai"))
        now = datetime.now(tz)
        nxt = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if nxt <= now:
            nxt += timedelta(days=1)
        await asyncio.sleep(max(10.0, (nxt - now).total_seconds()))
        try:
            await _execute_scan()
        except Exception:
            pass
        await asyncio.sleep(60.0)


def _get_tz(name: str):
    for key in (name, "Asia/Shanghai"):
        if not key:
            continue
        try:
            return ZoneInfo(key)
        except (ZoneInfoNotFoundError, Exception):
            pass
    return datetime.now().astimezone().tzinfo or timezone(timedelta(hours=8))


def _next_scan_str(cfg: dict[str, Any]) -> str:
    hour, minute = _parse_daily(str(cfg.get("schedule") or "0 4 * * *"))
    tz = _get_tz(str(cfg.get("timezone") or "Asia/Shanghai"))
    now = datetime.now(tz)
    nxt = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if nxt <= now:
        nxt += timedelta(days=1)
    return nxt.strftime("%Y-%m-%d %H:%M")


def _infer_vless_kind(url: str, sample_lines: list[str]) -> str:
    if "domain" in url.lower():
        return "优选域名"
    host_like = 0
    for ln in sample_lines[:10]:
        host = ln.split("#", 1)[0].split(":", 1)[0].strip()
        if host and any(c.isalpha() for c in host):
            host_like += 1
    return "优选域名" if host_like > len(sample_lines[:10]) / 2 else "优选 IP"


async def _check_one_source(kind: str, url: str, mode: str = "vless") -> dict[str, Any]:
    t0 = asyncio.get_event_loop().time()
    checked_at = datetime.now().strftime("%H:%M:%S")
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            r = await fetch_text(client, url, headers={"User-Agent": "clash-verge/v2.0"})
        ms = round((asyncio.get_event_loop().time() - t0) * 1000)
        if not r.ok:
            return {
                "kind": kind, "mode": mode, "target": url, "ok": False, "count": 0, "ms": ms,
                "checked_at": checked_at, "message": r.message,
            }
        lines = [ln.strip() for ln in r.text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        if mode == "fallback":
            cnt = len(parse_subscription_text(r.text))
        else:
            cnt = len(lines)
            if kind == "优选源":
                kind = _infer_vless_kind(url, lines)
        return {
            "kind": kind, "mode": mode, "target": url, "ok": cnt > 0, "count": cnt, "ms": ms,
            "checked_at": checked_at,
            "message": f"有效 · 解析 {cnt} 条" if cnt > 0 else "内容为空",
        }
    except Exception as e:
        ms = round((asyncio.get_event_loop().time() - t0) * 1000)
        return {
            "kind": kind, "mode": mode, "target": url, "ok": False, "count": 0, "ms": ms,
            "checked_at": checked_at, "message": str(e) or "请求失败",
        }


async def _refresh_all_sources(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    vless = cfg.get("vless") or {}
    vless_sources = [str(u).strip() for u in (vless.get("sources") or []) if str(u).strip()]
    proxy_sources = [str(u).strip() for u in (vless.get("proxy_sources") or []) if str(u).strip()]
    fb_sources = [str(u).strip() for u in ((cfg.get("fallback") or {}).get("sources") or []) if str(u).strip()]
    tasks = (
        [_check_one_source("优选源", u, "vless") for u in vless_sources]
        + [_check_one_source("反代 ProxyIP", u, "proxy") for u in proxy_sources]
        + [_check_one_source("兜底订阅", u, "fallback") for u in fb_sources]
    )
    results = list(await asyncio.gather(*tasks)) if tasks else []
    store.save_source_status(results)
    return results


def _warn_if_open() -> None:
    """A service reachable on the LAN with no token is an open proxy panel."""
    if not str(holder.get().get("token") or "").strip():
        logger.warning(
            "WARPSUB_TOKEN 未设置：面板与订阅接口无任何鉴权，"
            "局域网内任何人都能读取配置并触发扫描。请在 .env 设置 WARPSUB_TOKEN。"
        )


def _check_data_dir() -> None:
    """A root-owned ./data is the most common fresh-deploy trap.

    Docker creates a bind-mount directory as root when it does not exist, while
    the image runs as uid 1000 — every state write then fails silently and the
    panel looks broken. Say it out loud, with the fix.
    """
    data_dir = holder.data_dir()
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        probe = data_dir / ".write-check"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
    except OSError as exc:
        logger.warning(
            "数据目录 %s 不可写（%s）：扫描结果、配置与历史都无法落盘。"
            "请在宿主机执行 sudo chown -R 1000:1000 <本服务挂载的 data 目录>",
            data_dir, exc,
        )


@asynccontextmanager
async def lifespan(_: FastAPI):
    _warn_if_open()
    _check_data_dir()
    task = asyncio.create_task(_scheduler_loop())
    if not store.source_status():
        asyncio.create_task(_refresh_all_sources(holder.get()))
    try:
        yield
    finally:
        task.cancel()


app = FastAPI(title="warp-sub", lifespan=lifespan)


@app.get("/api/state")
async def api_state(request: Request) -> dict[str, Any]:
    _require_auth(request)
    rep = store.report()
    running, started_at = store.running_state()
    nodes = rep.get("nodes") or []
    counts: dict[str, int] = {}
    for n in nodes:
        cls = n.get("class") or "vless"
        counts[cls] = counts.get(cls, 0) + 1
    cfg = holder.get()
    return {
        "generated_at": rep.get("generated_at", ""),
        "duration_sec": rep.get("duration_sec", 0),
        "candidates": rep.get("candidates", 0),
        "passed": rep.get("passed", 0),
        "running": running,
        "started_at": started_at,
        "progress": store.progress(),
        "counts": counts,
        "nodes": nodes,
        "rejected": rep.get("rejected") or [],
        "sources": store.source_status(),
        "next_scan_at": _next_scan_str(cfg),
        "schedule": str(cfg.get("schedule") or "0 4 * * *"),
        "vless_enabled": bool((cfg.get("vless") or {}).get("enabled", True)),
        "worker_host": (cfg.get("vless") or {}).get("worker_host", ""),
        "ech_enabled": bool(((cfg.get("vless") or {}).get("ech") or {}).get("enabled", False)),
        "ech_ready": bool(((cfg.get("vless") or {}).get("ech") or {}).get("clash_config", "")),
        "proxy_ip": (cfg.get("vless") or {}).get("proxy_ip", ""),
    }


@app.get("/api/report")
async def api_report(request: Request) -> dict[str, Any]:
    _require_auth(request)
    return store.report()


@app.post("/api/scan")
async def api_scan(request: Request) -> dict[str, Any]:
    _require_auth(request)
    running, _ = store.running_state()
    if running or scan_lock.locked():
        return {"ok": False, "error": "扫描正在进行中"}
    asyncio.create_task(_execute_scan())
    return {"ok": True}


@app.post("/api/sources")
async def api_manage_sources(request: Request) -> dict[str, Any]:
    _require_auth(request)
    body = await request.json()
    if not isinstance(body, dict):
        return {"ok": False, "error": "无效请求"}
    action = body.get("action")
    mode = body.get("mode") or body.get("kind") or "vless"
    url = str(body.get("url") or "").strip()
    cfg = holder.get()

    if mode == "fallback":
        key = "fallback.sources"
        cur_list = [str(u).strip() for u in ((cfg.get("fallback") or {}).get("sources") or []) if str(u).strip()]
        label = "兜底订阅"
    elif mode == "proxy":
        key = "vless.proxy_sources"
        cur_list = [str(u).strip() for u in ((cfg.get("vless") or {}).get("proxy_sources") or []) if str(u).strip()]
        label = "反代 ProxyIP"
    else:
        key = "vless.sources"
        cur_list = [str(u).strip() for u in ((cfg.get("vless") or {}).get("sources") or []) if str(u).strip()]
        label = "优选域名" if mode == "vless_domain" else ("优选 IP" if mode == "vless_ip" else "优选源")
        mode = "vless"

    if action == "add":
        if not url.startswith(("http://", "https://")):
            return {"ok": False, "error": "请输入有效的 http(s):// 订阅链接"}
        if url not in cur_list:
            cur_list.append(url)
            holder.update_overlay({key: cur_list})
        item = await _check_one_source(label, url, mode)
        existing = [s for s in store.source_status() if s.get("target") != url]
        existing.append(item)
        store.save_source_status(existing)
        return {"ok": True, "item": item, "sources": existing}

    if action == "remove":
        cur_list = [u for u in cur_list if u != url]
        holder.update_overlay({key: cur_list})
        existing = [s for s in store.source_status() if s.get("target") != url]
        store.save_source_status(existing)
        return {"ok": True, "sources": existing}

    if action == "refresh":
        if url:
            if not url.startswith(("http://", "https://")):
                return {"ok": False, "error": "该条目不是 HTTP 订阅链接，无法单独刷新"}
            item = await _check_one_source(label, url, mode)
            existing = [item if s.get("target") == url else s for s in store.source_status()]
            if not any(s.get("target") == url for s in existing):
                existing.append(item)
            store.save_source_status(existing)
            return {"ok": True, "item": item, "sources": existing}
        results = await _refresh_all_sources(cfg)
        return {"ok": True, "sources": results}

    return {"ok": False, "error": "未知操作"}


@app.post("/api/sources/test")
async def api_test_sources(request: Request) -> dict[str, Any]:
    _require_auth(request)
    results = await _refresh_all_sources(holder.get())
    return {"ok": True, "sources": results}


@app.get("/api/history")
async def api_history(request: Request) -> list[dict[str, Any]]:
    _require_auth(request)
    return store.history()


@app.get("/api/config")
async def api_get_config(request: Request) -> dict[str, Any]:
    _require_auth(request)
    return {
        "ok": True,
        "schema": SCHEMA,
        "config": holder.redacted(),
        "env": active_env(),
        "overlay": holder.load_overlay(),
    }


@app.post("/api/config")
async def api_post_config(request: Request) -> dict[str, Any]:
    _require_auth(request)
    body = await request.json()
    if isinstance(body, dict) and body.get("reset"):
        new_cfg = holder.reset_overlay()
        await _refresh_all_sources(new_cfg)
        return {"ok": True, "config": holder.redacted(), "sources": store.source_status()}
    values = body.get("values") if isinstance(body, dict) else None
    if not isinstance(values, dict):
        return {"ok": False, "error": "无效的请求体"}
    new_cfg = holder.update_overlay(values)
    await _refresh_all_sources(new_cfg)
    return {"ok": True, "config": holder.redacted(), "sources": store.source_status()}


@app.get("/api/writeback")
async def api_get_writeback(request: Request) -> dict[str, Any]:
    _require_auth(request)
    worker_host = str((holder.get().get("vless") or {}).get("worker_host") or "")
    return {"ok": True, "writeback": wb.view(worker_host)}


@app.post("/api/writeback")
async def api_post_writeback(request: Request) -> dict[str, Any]:
    _require_auth(request)
    body = await request.json()
    if isinstance(body, dict):
        wb.update(body)
    worker_host = str((holder.get().get("vless") or {}).get("worker_host") or "")
    return {"ok": True, "writeback": wb.view(worker_host)}


@app.post("/api/writeback/sync")
async def api_sync_writeback(request: Request) -> dict[str, Any]:
    _require_auth(request)
    nodes = (store.report() or {}).get("nodes") or []
    if not nodes:
        return {"ok": False, "error": "暂无可用节点"}
    worker_host = str((holder.get().get("vless") or {}).get("worker_host") or "")
    ok, res = await wb.sync(nodes, worker_host)
    return {"ok": ok, "result": res}


@app.get("/sub")
async def handle_sub(request: Request) -> Response:
    cfg = holder.get()
    token = str(cfg.get("token") or "")
    if token and request.query_params.get("token") != token:
        raise HTTPException(status_code=403, detail="forbidden")
    target = (request.query_params.get("target") or "clash").lower()
    nodes = (store.report() or {}).get("nodes") or []
    only = (request.query_params.get("only") or "").lower()
    if only:
        nodes = [n for n in nodes if only in str(n.get("class") or "")]

    sub_cfg = cfg.get("subscription") or {}
    headers = {
        "Profile-Update-Interval": str(max(1, int(sub_cfg.get("update_hours") or 24))),
        "Cache-Control": "no-store",
    }
    if target in ("v2ray", "v2rayn", "base64"):
        return PlainTextResponse(render_v2ray(nodes, cfg), headers=headers)
    return Response(render_clash(nodes, cfg), media_type="text/yaml; charset=utf-8", headers=headers)


# Static frontend serving
_static_candidates = [
    Path(os.environ["WARPSUB_STATIC_DIR"]) if os.environ.get("WARPSUB_STATIC_DIR") else None,
    Path(__file__).resolve().parent.parent / "static",
    Path(__file__).resolve().parent.parent.parent / "frontend" / "dist",
]
STATIC_DIR = next((p for p in _static_candidates if p and p.is_dir()), None)

if STATIC_DIR:
    assets_dir = STATIC_DIR / "assets"
    if assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    @app.get("/{full_path:path}")
    async def spa_fallback(full_path: str) -> Response:
        candidate = STATIC_DIR / full_path
        if full_path and candidate.is_file():
            return FileResponse(str(candidate))
        return FileResponse(str(STATIC_DIR / "index.html"))
