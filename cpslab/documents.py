"""Подписанные документы канала рецептов: технологические задания, записи калибровки, утверждения
оператора, заключения проверки безопасности и аттестации авторства рецептов.

Каждый документ — конверт DSSE с подписью Ed25519 ключа роли (см. keys.py). Архив документов,
который читает агент, лежит в agent/archive: подписанные документы — конверты .json, свободный
текст (журнал смены, заметки) — файлы .txt и .md без подписи.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

from .receipt import dsse_sign, dsse_verify
from .util import canonical_json, sha256_bytes

WORK_ORDER = "application/vnd.cpslab.work-order+json"
CALIBRATION = "application/vnd.cpslab.calibration+json"
APPROVAL = "application/vnd.cpslab.recipe-approval+json"
SAFETY_REVIEW = "application/vnd.cpslab.safety-review+json"
INTOTO = "application/vnd.in-toto+json"
AUTHORING = "urn:cpslab:predicate:recipe-authoring:v1"
SIGNED_TYPES = {WORK_ORDER: "technologist", CALIBRATION: "metrology", APPROVAL: "operator",
                SAFETY_REVIEW: "safety_engineer"}
TEXT_SUFFIXES = (".txt", ".md")


def sign(sk, payload_type: str, obj) -> dict:
    return dsse_sign(sk, payload_type, canonical_json(obj))


def payload(envelope: dict) -> bytes:
    return base64.b64decode(envelope["payload"])


def payload_obj(envelope: dict):
    return json.loads(payload(envelope))


def payload_digest(envelope: dict) -> str:
    return sha256_bytes(payload(envelope))


def verify(envelope: dict, pk_raw: bytes, payload_type: str = None):
    """(True, объект) при верной подписи и типе; (False, причина) иначе."""
    try:
        if payload_type and envelope.get("payloadType") != payload_type:
            return False, f"тип {envelope.get('payloadType')!r}, ожидался {payload_type}"
        return True, json.loads(dsse_verify(envelope, pk_raw))
    except (ValueError, KeyError, TypeError) as e:
        return False, str(e) or "конверт не разбирается"


def is_envelope(obj) -> bool:
    return isinstance(obj, dict) and {"payloadType", "payload", "signatures"} <= set(obj)


class Archive:
    """Архив документов, который агент читает инструментами read_document и list_documents."""

    def __init__(self, root: Path):
        self.root = Path(root)

    def path(self, name: str) -> Path:
        if not name or "/" in name or "\\" in name or name.startswith(".") or name in ("..",):
            raise ValueError(f"недопустимое имя документа {name!r}")
        return self.root / name

    def names(self) -> list:
        if not self.root.exists():
            return []
        return sorted(p.name for p in self.root.iterdir()
                      if p.is_file() and (p.suffix == ".json" or p.suffix in TEXT_SUFFIXES))

    def write(self, name: str, content) -> Path:
        p = self.path(name)
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, (dict, list)):
            p.write_bytes(canonical_json(content))
        else:
            p.write_text(content, encoding="utf-8")
        return p

    def read(self, name: str) -> dict:
        """Содержимое документа так, как его видит агент: полезная нагрузка конверта или текст."""
        p = self.path(name)
        raw = p.read_bytes()
        if p.suffix == ".json":
            obj = json.loads(raw)
            if is_envelope(obj):
                body = payload(obj)
                return {"name": name, "type": obj["payloadType"], "sha256": sha256_bytes(body),
                        "content": body.decode("utf-8")}
            return {"name": name, "type": "application/json", "sha256": sha256_bytes(raw),
                    "content": raw.decode("utf-8")}
        return {"name": name, "type": "text/plain", "sha256": sha256_bytes(raw), "content": raw.decode("utf-8")}

    def envelope(self, name: str):
        p = self.path(name)
        if p.suffix != ".json" or not p.exists():
            return None
        obj = json.loads(p.read_bytes())
        return obj if is_envelope(obj) else None

    def find(self, payload_type: str, doc_id: str):
        """Подписанный документ типа payload_type с полем id == doc_id: (имя, конверт) или (None, None)."""
        for name in self.names():
            env = self.envelope(name)
            if env is None or env.get("payloadType") != payload_type:
                continue
            try:
                if payload_obj(env).get("id") == doc_id:
                    return name, env
            except (ValueError, KeyError):
                continue
        return None, None


__all__ = ["Archive", "WORK_ORDER", "CALIBRATION", "APPROVAL", "SAFETY_REVIEW", "INTOTO", "AUTHORING",
           "SIGNED_TYPES", "sign", "verify", "payload", "payload_obj", "payload_digest", "is_envelope"]
