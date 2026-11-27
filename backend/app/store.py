from __future__ import annotations

import logging

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("warp-sub")


def _is_url(target: Any) -> bool:
    """订阅源必须是 http(s) 链接；其余都是扫描步骤日志。"""
    return isinstance(target, str) and target.strip().lower().startswith(("http://", "https://"))


class Store:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._running = False
        self._started_at = ""
        self._progress: dict[str, Any] = {"stage": "", "done": 0, "total": 0}
        self._report: dict[str, Any] = self._read_json(self.data_dir / "report.json", {})
        self._history: list[dict[str, Any]] = self._read_json(self.data_dir / "history.json", [])
        self._source_status: list[dict[str, Any]] = self._read_json(self.data_dir / "sources_status.json", [])

    @staticmethod
    def _read_json(path: Path, default: Any) -> Any:
        if not path.is_file():
            return default
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return default

    @staticmethod
    def _write_json(path: Path, data: Any) -> None:
        # Cache writes must never kill a scan: a read-only mount or a uid
        # mismatch would otherwise abort the whole run after the work is done.
        payload = json.dumps(data, ensure_ascii=False, indent=2)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text(payload, encoding="utf-8")
            tmp.replace(path)
            return
        except OSError as exc:
            reason = exc
        # 目标文件属主不是自己（例如 /data 曾被 root 跑过一次）时 replace 会被拒，
        # 但目录可写就能删掉重写接管它，否则这个状态文件会永远停在旧值上。
        try:
            path.unlink(missing_ok=True)
            path.write_text(payload, encoding="utf-8")
            logger.warning("%s 无法原子替换（%s），已删除旧文件后重写接管", path.name, reason)
        except OSError as exc:
            logger.warning(
                "写入 %s 失败（不影响扫描结果）: %s（replace 已试过: %s）", path.name, exc, reason
            )

    def set_running(self, running: bool, started_at: str = "") -> None:
        with self._lock:
            self._running = running
            self._started_at = started_at if running else ""
            if not running:
                self._progress = {"stage": "", "done": 0, "total": 0}

    def set_progress(self, stage: str, done: int = 0, total: int = 0) -> None:
        with self._lock:
            self._progress = {"stage": stage, "done": done, "total": total}

    def running_state(self) -> tuple[bool, str]:
        with self._lock:
            return self._running, self._started_at

    def progress(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._progress)

    def report(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._report)

    def save_report(self, rep: dict[str, Any]) -> None:
        with self._lock:
            self._report = rep
            self._write_json(self.data_dir / "report.json", rep)
            self._merge_scan_sources(rep.get("sources"))

    def _merge_scan_sources(self, logs: Any) -> None:
        """Fold the scan's per-source findings into the 订阅源 list.

        一次扫描的 ``sources`` 还包含「手填节点」「CF 网段抽样」「反代探测」
        这类步骤日志，它们属于报表，不是订阅源。以前整表覆盖，面板上的订阅源
        就只剩这次扫描恰好碰过的那几条；现在只按 URL 逐条更新，步骤日志一律不进列表。
        """
        if not isinstance(logs, list):
            return
        current = list(self._source_status) or self._url_entries(self._report.get("sources"))
        by_target: dict[str, dict[str, Any]] = {
            str(e.get("target")): e for e in current if e.get("target")
        }
        changed = False
        for log in logs:
            if not isinstance(log, dict):
                continue
            target = str(log.get("target") or "")
            if not _is_url(target):
                continue
            entry = dict(log)
            entry.setdefault("checked_at", datetime.now().strftime("%H:%M:%S"))
            prev = by_target.get(target)
            if prev:
                # 保留面板原有的分类（优选域名 / 优选 IP / 反代 ProxyIP / 兜底订阅）
                entry["kind"] = prev.get("kind") or entry.get("kind")
            by_target[target] = entry
            changed = True
        if not changed:
            return
        self._source_status = list(by_target.values())
        self._write_json(self.data_dir / "sources_status.json", self._source_status)

    @staticmethod
    def _url_entries(items: Any) -> list[dict[str, Any]]:
        """The 订阅源 view of a report: only real http(s) targets, no step logs."""
        if not isinstance(items, list):
            return []
        return [i for i in items if isinstance(i, dict) and _is_url(i.get("target"))]

    def source_status(self) -> list[dict[str, Any]]:
        with self._lock:
            if self._source_status:
                return list(self._source_status)
            return self._url_entries(self._report.get("sources"))

    def save_source_status(self, items: list[dict[str, Any]]) -> None:
        with self._lock:
            self._source_status = list(items)
            self._write_json(self.data_dir / "sources_status.json", self._source_status)

    def history(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._history)

    def append_history(self, rep: dict[str, Any]) -> None:
        nodes = rep.get("nodes") or []
        counts: dict[str, int] = {}
        lats: list[float] = []
        best_speed = 0.0
        for n in nodes:
            cls = n.get("class") or "vless"
            counts[cls] = counts.get(cls, 0) + 1
            if n.get("latency_ms"):
                lats.append(float(n["latency_ms"]))
            sp = float(n.get("speed_mbps") or 0)
            if sp > best_speed:
                best_speed = sp
        entry = {
            "at": datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M"),
            "candidates": rep.get("candidates", 0),
            "passed": rep.get("passed", 0),
            "counts": counts,
            "best_latency_ms": round(min(lats), 1) if lats else 0.0,
            "avg_latency_ms": round(sum(lats) / len(lats), 1) if lats else 0.0,
            "best_speed_mbps": round(best_speed, 1),
            "duration_sec": round(float(rep.get("duration_sec") or 0), 1),
        }
        with self._lock:
            self._history.append(entry)
            if len(self._history) > 90:
                self._history = self._history[-90:]
            self._write_json(self.data_dir / "history.json", self._history)

    def load_stability(self) -> dict[str, Any]:
        with self._lock:
            return self._read_json(self.data_dir / "stability.json", {})

    def save_stability(self, data: dict[str, Any]) -> None:
        with self._lock:
            self._write_json(self.data_dir / "stability.json", data)
