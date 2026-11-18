"""Контур реагирования: проверка подписанных отчётов устройства и сверка с журналом допусков гейта.

Монитор проверяет подпись каждого отчёта ключом устройства, а затем сверяет образ, который
работает на устройстве по последнему отчёту, с журналом допусков гейта: пара (класс устройства,
SHA-256 образа) должна быть допущена. Отказы устройства в установке монитор считает попытками
атаки и выводит предупреждениями.

Сверка по журналу не замечает отката на старый, но когда-то допущенный образ: такой образ есть в
журнале. Это ограничение показывает сценарий A4.

Рецепты партии монитор сверяет с журналом допусков гейта рецептов: каждый рецепт, который начал
исполняться на устройстве, должен быть допущен для этого класса устройства. Повтор старой, но
допущенной ревизии рецепта (сценарий RA4) сверка не замечает по той же причине, что и откат образа.
Ручные команды сервера агента и отказы в исполнении рецептов выводятся предупреждениями.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .util import canonical_json, rjson


def check(device_root: Path, admitted: set, admitted_recipes: set = None) -> dict:
    root = Path(device_root)
    pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex((root / "device.pk").read_text().strip()))
    reports = []
    p = root / "reports.jsonl"
    if p.exists():
        reports = [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]
    alerts, warnings, last = [], [], None
    for r in reports:
        ev = r["event"]
        try:
            pk.verify(base64.b64decode(r["sig"]), canonical_json(ev))
        except (InvalidSignature, ValueError):
            alerts.append({"kind": "bad_report", "seq": ev.get("seq"), "message": "подпись отчёта не проверяется"})
            continue
        last = ev
        if ev["event"] == "reject":
            warnings.append({"kind": "rejected", "seq": ev["seq"], "path": ev["path"], "reason": ev["reason"],
                             "message": f"устройство отвергло образ ({ev['path']}): {ev['reason']}"})
        if ev["event"] == "mgmt":
            warnings.append({"kind": "mgmt", "seq": ev["seq"], "accepted": ev["accepted"],
                             "message": f"команда управления {ev.get('command')}: {ev['reason']}"})
        if ev["event"] == "recipe-reject":
            warnings.append({"kind": "recipe_rejected", "seq": ev["seq"], "reason": ev["reason"],
                             "message": f"устройство отвергло рецепт {ev.get('recipe') or ''}: {ev['reason']}"})
        if ev["event"] == "command":
            warnings.append({"kind": "command", "seq": ev["seq"], "accepted": ev["accepted"],
                             "message": f"ручная команда {ev.get('command')} {ev.get('args') or ''}: {ev['reason']}"})
        if ev["event"] == "recipe-start" and admitted_recipes is not None and \
                (ev["device_class"], ev.get("recipe_sha256")) not in admitted_recipes:
            alerts.append({"kind": "recipe_not_admitted", "seq": ev["seq"], "sha256": ev.get("recipe_sha256"),
                           "message": f"на устройстве исполнялся рецепт {ev.get('recipe')} r{ev.get('revision')}, "
                                      f"не допущенный гейтом рецептов"})
    if last is not None:
        sha = last.get("installed_sha256")
        if sha and (last["device_class"], sha) not in admitted:
            alerts.append({"kind": "not_admitted", "seq": last["seq"], "sha256": sha,
                           "message": "на устройстве работает образ, не допущенный гейтом для этого класса устройства"})
    cfg = rjson(root / "config.json")
    return {"device": cfg["name"], "reports": len(reports), "alerts": alerts, "warnings": warnings}
