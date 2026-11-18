"""Хранилище рецептов сервера агента: agent/recipes/<папка>/<имя>-r<ревизия>.json и сопутствующие файлы.

Рядом с рецептом лежат: .authoring.json — аттестация авторства (сервер агента), .approval.json —
утверждение оператора, .safety.json — заключение проверки безопасности, .decision.json — решение
гейта, .scr — квитанция допуска SCII-R v1. Ревизия рецепта неизменна: загрузить другое содержимое
под той же ревизией нельзя.
"""
from __future__ import annotations

import re
from pathlib import Path

from .recipe import NAME, canonical
from .util import rjson, sha256_bytes

FOLDER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,39}$")
DEFAULT_FOLDER = "shared"
_FILE = re.compile(r"^([a-z][a-z0-9-]{0,39})-r(\d+)\.json$")


class StoreError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class RecipeStore:
    def __init__(self, root: Path):
        self.root = Path(root)

    def path(self, folder: str, name: str, revision: int) -> Path:
        if not FOLDER.match(folder or ""):
            raise StoreError("bad_request", f"недопустимая папка {folder!r}")
        if not NAME.match(name or ""):
            raise StoreError("bad_request", f"недопустимое имя рецепта {name!r}")
        return self.root / folder / f"{name}-r{int(revision)}.json"

    @staticmethod
    def sidecar(path: Path, kind: str) -> Path:
        path = Path(path)
        if kind == "receipt":
            return path.with_suffix(".scr")
        return path.with_name(f"{path.stem}.{kind}.json")

    def entries(self, folder: str = None) -> list:
        out = []
        if not self.root.exists():
            return out
        for d in sorted(self.root.iterdir()):
            if not d.is_dir() or (folder and d.name != folder):
                continue
            for p in sorted(d.iterdir()):
                m = _FILE.match(p.name)
                if not m:
                    continue
                out.append({"folder": d.name, "name": m.group(1), "revision": int(m.group(2)), "path": p,
                            "sha256": sha256_bytes(p.read_bytes()),
                            "approved": self.sidecar(p, "approval").exists(),
                            "receipt": self.sidecar(p, "receipt").exists(),
                            "decision": (rjson(self.sidecar(p, "decision")).get("decision")
                                         if self.sidecar(p, "decision").exists() else None)})
        return out

    def find(self, name: str, revision: int = None, folder: str = None):
        """Путь рецепта: заданная ревизия или наибольшая; None, если нет."""
        cand = [e for e in self.entries(folder) if e["name"] == name and (revision is None or e["revision"] == revision)]
        if not cand:
            return None
        return max(cand, key=lambda e: e["revision"])["path"]

    def save(self, folder: str, recipe: dict) -> Path:
        data = canonical(recipe)
        p = self.path(folder, recipe["name"], recipe["revision"])
        for e in self.entries():
            if e["name"] == recipe["name"] and e["revision"] == recipe["revision"] and e["folder"] != folder:
                raise StoreError("already_exists", f"рецепт {recipe['name']} r{recipe['revision']} уже есть в папке "
                                                   f"{e['folder']}")
        if p.exists():
            if p.read_bytes() == data:
                return p
            raise StoreError("revision_exists", f"ревизия {recipe['revision']} рецепта {recipe['name']} уже загружена "
                                                f"с другим содержимым; увеличьте revision")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p


__all__ = ["RecipeStore", "StoreError", "DEFAULT_FOLDER"]
