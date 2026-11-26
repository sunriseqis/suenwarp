from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


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
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)

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
            if isinstance(rep.get("sources"), list):
                self._source_status = list(rep["sources"])
                self._write_json(self.data_dir / "sources_status.json", self._source_status)

    def source_status(self) -> list[dict[str, Any]]:
        with self._lock:
            if self._source_status:
                return list(self._source_status)
            return list(self._report.get("sources") or [])

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
