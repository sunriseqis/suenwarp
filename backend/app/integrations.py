from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


def _now_str() -> str:
    return datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")


def _normalize_base(s: str) -> str:
    s = (s or "").strip().rstrip("/")
    if not s:
        return ""
    if not s.startswith("http://") and not s.startswith("https://"):
        s = "https://" + s
    return s


def _build_add_lines(nodes: list[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    for n in nodes:
        if (n.get("class") or "vless") != "vless":
            continue
        remark = f"VL {round(float(n.get('latency_ms') or 0))}ms"
        if n.get("egress_country"):
            remark += f" {n['egress_country']}"
        if n.get("speed_mbps"):
            remark += f" {float(n['speed_mbps']):.1f}M"
        host = str(n.get("server") or "").strip()
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = int(n.get("port") or 443)
        remark = remark.replace("\n", " ").replace("#", " ")
        lines.append(f"{host}:{port}#{remark}")
    return lines


class WritebackSyncer:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.path = data_dir / "writeback.json"
        self.data: dict[str, Any] = self._load()

    def _load(self) -> dict[str, Any]:
        if self.path.is_file():
            try:
                return json.loads(self.path.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {"enabled": False, "base_url": "", "password": "", "auto": False, "last": {}}

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, ensure_ascii=False, indent=2), encoding="utf-8")

    def view(self, default_worker_host: str = "") -> dict[str, Any]:
        return {
            "enabled": bool(self.data.get("enabled")),
            "base_url": self.data.get("base_url") or "",
            "effective_url": _normalize_base(self.data.get("base_url") or default_worker_host),
            "has_password": bool(self.data.get("password")),
            "auto": bool(self.data.get("auto")),
            "last": self.data.get("last") or {},
        }

    def update(self, patch: dict[str, Any]) -> None:
        if "enabled" in patch:
            self.data["enabled"] = bool(patch["enabled"])
        if "base_url" in patch:
            self.data["base_url"] = _normalize_base(str(patch["base_url"]))
        if patch.get("password"):
            self.data["password"] = str(patch["password"])
        if "auto" in patch:
            self.data["auto"] = bool(patch["auto"])
        self._save()

    async def sync(self, nodes: list[dict[str, Any]], default_worker_host: str = "") -> tuple[bool, dict[str, Any]]:
        base = _normalize_base(self.data.get("base_url") or default_worker_host)
        password = str(self.data.get("password") or "")
        if not base:
            res = {"at": _now_str(), "ok": False, "message": "未配置 Worker 地址"}
            self.data["last"] = res
            self._save()
            return False, res
        if not password:
            res = {"at": _now_str(), "ok": False, "message": "未填写 Worker 后台密码"}
            self.data["last"] = res
            self._save()
            return False, res

        lines = _build_add_lines(nodes)
        if not lines:
            res = {"at": _now_str(), "ok": False, "message": "没有可回写的 VLESS 节点"}
            self.data["last"] = res
            self._save()
            return False, res

        try:
            async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
                r_login = await client.post(
                    f"{base}/login",
                    data={"password": password},
                    headers={"User-Agent": USER_AGENT, "Referer": f"{base}/login"},
                )
                if r_login.status_code != 200 or "success" not in r_login.text:
                    raise RuntimeError(f"登录失败 (HTTP {r_login.status_code})")

                r_old = await client.get(f"{base}/admin/ADD.txt", headers={"User-Agent": USER_AGENT})
                if r_old.status_code == 200 and r_old.text.strip():
                    backup_name = f"add-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}.txt"
                    (self.data_dir / backup_name).write_text(r_old.text, encoding="utf-8")

                r_post = await client.post(
                    f"{base}/admin/ADD.txt",
                    content="\n".join(lines).encode("utf-8"),
                    headers={
                        "User-Agent": USER_AGENT,
                        "Content-Type": "text/plain;charset=utf-8",
                        "Referer": f"{base}/admin",
                    },
                )
                if r_post.status_code != 200 or '"success":true' not in r_post.text:
                    raise RuntimeError(f"写入失败 (HTTP {r_post.status_code})")

                res = {"at": _now_str(), "ok": True, "message": f"已推送 {len(lines)} 个节点到 {base}"}
        except Exception as e:
            res = {"at": _now_str(), "ok": False, "message": str(e)}

        self.data["last"] = res
        self._save()
        return bool(res["ok"]), res

