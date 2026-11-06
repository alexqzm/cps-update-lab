"""Контур реагирования: проверка подписанных отчётов устройства и сверка с журналом допусков гейта.

Монитор проверяет подпись каждого отчёта ключом устройства, а затем сверяет образ, который
работает на устройстве по последнему отчёту, с журналом допусков гейта: пара (класс устройства,
SHA-256 образа) должна быть допущена. Отказы устройства в установке монитор считает попытками
атаки и выводит предупреждениями.

Сверка по журналу не замечает отката на старый, но когда-то допущенный образ: такой образ есть в
журнале. Это ограничение показывает сценарий A4.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .util import canonical_json, rjson


def check(device_root: Path, admitted: set) -> dict:
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
    if last is not None:
        sha = last.get("installed_sha256")
        if sha and (last["device_class"], sha) not in admitted:
            alerts.append({"kind": "not_admitted", "seq": last["seq"], "sha256": sha,
                           "message": "на устройстве работает образ, не допущенный гейтом для этого класса устройства"})
    cfg = rjson(root / "config.json")
    return {"device": cfg["name"], "reports": len(reports), "alerts": alerts, "warnings": warnings}
