from __future__ import annotations

import copy
import json
import os
import threading
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG: dict[str, Any] = {
    "listen": ":8088",
    "token": "",
    "data_dir": "./data",
    "schedule": "0 4 * * *",
    "timezone": "Asia/Shanghai",
    "vless": {
        "enabled": True,
        "worker_host": "",
        "uuid": "",
        "path": "/",
        "proxy_ip": "",
        "proxy_ips": [
            "cdn-all.xn--b6gac.eu.org",
            "cdn.xn--b6gac.eu.org",
            "cdn-b100.xn--b6gac.eu.org",
            "edgetunnel.anycast.eu.org",
            "cdn.anycast.eu.org",
        ],
        "proxy_sources": [
            "https://raw.githubusercontent.com/ymyuuu/IPDB/main/BestProxy/proxy.txt",
        ],
        "fingerprint": "chrome",
        "port": 443,
        "sources": [
            "https://bestcf.tools12345.com/domain/mini.txt",
            "https://ips.gaoji.uk/best_ips.txt",
            "https://raw.githubusercontent.com/svip-s/cloudflare_ip/refs/heads/main/domain.txt",
        ],
        "max_candidates": 120,
        "candidates": [
            "cf.1o.ee",
            "saas.sin.fan",
            "www.visa.com.sg",
            "www.shopify.com",
            "time.is",
            "icook.hk",
        ],
        "verify_domains": ["chatgpt.com", "antigravity.google", "antigravity-pa.googleapis.com"],
        "require_verify_pass": True,
        "egress_probe": "https://ipinfo.io/json",
        "allowed_countries": [],
        "blocked_countries": ["CN", "HK", "MO", "RU"],
        "ech": {
            "enabled": True,
            "public_name": "cloudflare-ech.com",
            "doh": "https://dns.alidns.com/dns-query",
            "clash_config": "",
        },
    },
    "fallback": {
        "enabled": True,
        "always_include": False,
        "trigger_min": 2,
        "sources": [
            "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
            "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity",
        ],
        "max_candidates": 40,
        "top": 5,
        "timeout_ms": 2500,
    },
    "thresholds": {
        "max_latency_ms": 1500.0,
        "max_jitter_ms": 400.0,
        "max_loss_pct": 50.0,
        "min_speed_mbps": 0.05,
        "min_stability": 0.0,
        "speed_ref_mbps": 50.0,
    },
    "top": {
        "vless": 10,
    },
    "scan": {
        "concurrency": 48,
        "rounds": 3,
        "timeout_ms": 3000,
        "cf_sample_count": 16,
    },
    "speed_test": {
        "enabled": True,
        "url": "https://proof.ovh.net/files/100Mb.dat",
        "timeout_ms": 12000,
        "required": True,
        "cooldown_ms": 3000,
        "shortlist": 16,
        "duration_s": 8,
        "max_bytes_mb": 0,
        "idle_enabled": True,
        "idle_seconds": 8,
    },
    "stability": {
        "min_hits": 1,
        "bootstrap": True,
    },
    "subscription": {
        "name": "warp-sub",
        "update_hours": 24,
        "test_url": "http://cp.cloudflare.com/generate_204",
    },
    "writeback": {
        "enabled": False,
        "base_url": "",
        "password": "",
        "auto": False,
    },
}

# Minimal, high-signal schema: only what a user actually needs to adjust.
# Everything else runs with smart out-of-the-box defaults.
SCHEMA: list[dict[str, Any]] = [
    {
        "title": "运行与筛选策略",
        "fields": [
            {"key": "schedule", "label": "每日定时扫描", "type": "string", "help": "Cron 分 时 * * *，默认 0 4 * * *"},
            {"key": "vless.ech.enabled", "label": "启用 ECH 加密", "type": "bool"},
            {"key": "vless.require_verify_pass", "label": "AI 与地域检测（一票否决）", "type": "bool", "help": "开启后必须通过 ChatGPT / AGY 检测且出口不在屏蔽地区"},
            {"key": "speed_test.required", "label": "必须测出真实速率", "type": "bool", "help": "开启后未测出速率或 0 Mbps 的节点直接淘汰"},
            {"key": "vless.blocked_countries", "label": "屏蔽出口地区", "type": "list", "help": "默认 CN, HK, MO, RU"},
            {"key": "top.vless", "label": "保留最优节点数", "type": "int"},
        ],
    },
    {
        "title": "节点与反代补充",
        "fields": [
            {"key": "vless.proxy_ip", "label": "自定义反代 ProxyIP", "type": "string", "help": "留空则自动从反代订阅池中优选"},
            {"key": "vless.candidates", "label": "手填优选节点", "type": "list", "help": "单个优选域名或 IP，换行/逗号分隔"},
            {"key": "fallback.enabled", "label": "启用开源免费兜底", "type": "bool", "help": "主节点不足 2 个时自动拉取并测活"},
        ],
    },
]

ALLOWED_KEYS: set[str] = {
    f["key"] for g in SCHEMA for f in g["fields"]
} | {"vless.sources", "vless.proxy_sources", "fallback.sources"}

ENV_KEYS = [
    "WARPSUB_LISTEN", "WARPSUB_TOKEN", "WARPSUB_SCHEDULE", "WARPSUB_TZ",
    "WARPSUB_DATA_DIR", "WARPSUB_VLESS_ENABLED", "WARPSUB_VLESS_HOST",
    "WARPSUB_VLESS_UUID", "WARPSUB_VLESS_PATH", "WARPSUB_VLESS_SOURCES",
    "WARPSUB_VLESS_VERIFY_DOMAINS", "WARPSUB_ALLOWED_COUNTRIES",
    "WARPSUB_EGRESS_PROBE", "WARPSUB_SPEED_ENABLED", "WARPSUB_SPEED_URL",
    "WARPSUB_SHORTLIST", "WARPSUB_SCAN_CONCURRENCY",
]


def deep_merge(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in patch.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def set_path(root: dict[str, Any], dot_path: str, value: Any) -> None:
    parts = dot_path.split(".")
    cur = root
    for p in parts[:-1]:
        if not isinstance(cur.get(p), dict):
            cur[p] = {}
        cur = cur[p]
    cur[parts[-1]] = value


def _mask(s: str) -> str:
    if len(s) <= 6:
        return "**"
    return s[:3] + "******" + s[-2:]


def _parse_bool(val: str) -> bool:
    return val.strip().lower() in {"1", "true", "yes", "on"}


def _parse_list(val: str) -> list[str]:
    return [x.strip() for x in val.replace("\n", ",").split(",") if x.strip()]


def find_config_path() -> Path | None:
    env_cfg = os.environ.get("WARPSUB_CONFIG", "").strip()
    candidates = [
        Path(env_cfg) if env_cfg else None,
        Path("config.yaml"),
        Path("data/config.yaml"),
    ]
    for c in candidates:
        if c and c.is_file():
            return c
    return None


def load_raw_config() -> tuple[dict[str, Any], Path | None]:
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    cfg_path = find_config_path()
    if cfg_path:
        with cfg_path.open("r", encoding="utf-8") as f:
            loaded = yaml.safe_load(f) or {}
        if isinstance(loaded, dict):
            cfg = deep_merge(cfg, loaded)

    data_dir = Path(os.environ.get("WARPSUB_DATA_DIR") or cfg.get("data_dir") or "./data")
    cfg["data_dir"] = str(data_dir)
    overlay_path = data_dir / "override.json"
    if overlay_path.is_file():
        try:
            ov = json.loads(overlay_path.read_text(encoding="utf-8"))
            if isinstance(ov, dict):
                for k, v in ov.items():
                    if k in ALLOWED_KEYS:
                        set_path(cfg, k, v)
        except Exception:
            pass

    _apply_env(cfg)
    return cfg, cfg_path


def _apply_env(cfg: dict[str, Any]) -> None:
    env = os.environ
    str_map = {
        "WARPSUB_LISTEN": "listen",
        "WARPSUB_TOKEN": "token",
        "WARPSUB_SCHEDULE": "schedule",
        "WARPSUB_TZ": "timezone",
        "WARPSUB_DATA_DIR": "data_dir",
        "WARPSUB_VLESS_HOST": "vless.worker_host",
        "WARPSUB_VLESS_UUID": "vless.uuid",
        "WARPSUB_VLESS_PATH": "vless.path",
        "WARPSUB_EGRESS_PROBE": "vless.egress_probe",
        "WARPSUB_SPEED_URL": "speed_test.url",
    }
    for ek, path in str_map.items():
        if ek in env and env[ek].strip():
            set_path(cfg, path, env[ek].strip())

    if "WARPSUB_VLESS_ENABLED" in env and env["WARPSUB_VLESS_ENABLED"].strip():
        set_path(cfg, "vless.enabled", _parse_bool(env["WARPSUB_VLESS_ENABLED"]))
    if "WARPSUB_SPEED_ENABLED" in env and env["WARPSUB_SPEED_ENABLED"].strip():
        set_path(cfg, "speed_test.enabled", _parse_bool(env["WARPSUB_SPEED_ENABLED"]))

    int_map = {
        "WARPSUB_SHORTLIST": "speed_test.shortlist",
        "WARPSUB_SCAN_CONCURRENCY": "scan.concurrency",
    }
    for ek, path in int_map.items():
        if ek in env and env[ek].strip():
            try:
                set_path(cfg, path, int(env[ek].strip()))
            except ValueError:
                pass

    list_map = {
        "WARPSUB_VLESS_SOURCES": "vless.sources",
        "WARPSUB_VLESS_VERIFY_DOMAINS": "vless.verify_domains",
        "WARPSUB_ALLOWED_COUNTRIES": "vless.allowed_countries",
    }
    for ek, path in list_map.items():
        if ek in env and env[ek].strip():
            set_path(cfg, path, _parse_list(env[ek]))


def active_env() -> dict[str, str]:
    out: dict[str, str] = {}
    for k in ENV_KEYS:
        v = os.environ.get(k, "").strip()
        if not v:
            continue
        if "TOKEN" in k or "UUID" in k:
            out[k] = _mask(v)
        else:
            out[k] = v
    return out


class ConfigHolder:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._cfg, self._cfg_path = load_raw_config()

    def get(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._cfg)

    def data_dir(self) -> Path:
        with self._lock:
            return Path(self._cfg.get("data_dir") or "./data")

    def overlay_path(self) -> Path:
        return self.data_dir() / "override.json"

    def load_overlay(self) -> dict[str, Any]:
        p = self.overlay_path()
        if not p.is_file():
            return {}
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def update_overlay(self, patch: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            ov = self.load_overlay()
            for k, v in patch.items():
                if k in ALLOWED_KEYS:
                    ov[k] = v
            p = self.overlay_path()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(ov, ensure_ascii=False, indent=2), encoding="utf-8")
            self._cfg, self._cfg_path = load_raw_config()
            return copy.deepcopy(self._cfg)

    def reset_overlay(self) -> dict[str, Any]:
        with self._lock:
            p = self.overlay_path()
            if p.is_file():
                p.unlink()
            self._cfg, self._cfg_path = load_raw_config()
            return copy.deepcopy(self._cfg)

    def redacted(self) -> dict[str, Any]:
        cfg = self.get()
        if cfg.get("token"):
            cfg["token"] = _mask(str(cfg["token"]))
        vless = cfg.get("vless", {})
        if vless.get("uuid"):
            vless["uuid"] = _mask(str(vless["uuid"]))
        ech = vless.get("ech", {})
        if ech.get("clash_config"):
            ech["clash_config"] = _mask(str(ech["clash_config"]))
        return cfg
