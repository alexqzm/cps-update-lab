"""Журнал сервера агента: дописываемый JSONL с хеш-цепочкой.

Каждая запись содержит номер (seq), хеш предыдущей записи (prev) и свой хеш (hash) — SHA-256 от
prev и канонического JSON записи без поля hash. Правка любой прошлой записи меняет её хеш и рвёт
цепочку у всех следующих. Внешней привязки (журнала прозрачности, отметки времени) у цепочки нет:
тот, кто может переписать файл целиком, может пересчитать и цепочку. Это ограничение стенда.
"""
from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path

from .util import canonical_json, now_utc

SEED = "0" * 64


def _hash(prev: str, entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(prev.encode() + canonical_json(body)).hexdigest()


class Journal:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.lock = threading.Lock()

    def entries(self) -> list:
        if not self.path.exists():
            return []
        return [json.loads(x) for x in self.path.read_text(encoding="utf-8").splitlines() if x.strip()]

    def head(self) -> dict:
        e = self.entries()
        return {"seq": e[-1]["seq"], "hash": e[-1]["hash"]} if e else {"seq": 0, "hash": SEED}

    def append(self, entry: dict) -> dict:
        with self.lock:
            h = self.head()
            rec = {"seq": h["seq"] + 1, "prev": h["hash"], "time": now_utc(), **entry}
            rec["hash"] = _hash(rec["prev"], rec)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
            return rec

    def verify(self) -> dict:
        """Проверить цепочку: {'ok': bool, 'entries': n, 'broken_at': seq первой испорченной записи}."""
        prev, n = SEED, 0
        for n, rec in enumerate(self.entries(), 1):
            if rec.get("seq") != n or rec.get("prev") != prev or rec.get("hash") != _hash(prev, rec):
                return {"ok": False, "entries": n, "broken_at": rec.get("seq", n)}
            prev = rec["hash"]
        return {"ok": True, "entries": n, "broken_at": None}


__all__ = ["Journal", "SEED"]
