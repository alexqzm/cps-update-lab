"""Квитанция допуска SCII-R v1: выпуск на стороне гейта и разбор для отображения.

Раскладка — по docs/receipt-format.md репозитория scii-verify: заголовок 16 байт (подсказки),
полезная нагрузка 164 байта (подписана), подпись Ed25519 64 байта над DSSE-PAE нагрузки.
Проверку на устройстве выполняет scii-agent из scii-verify; функция verify здесь нужна только
для отображения и тестов.

Здесь же — подпись DSSE-конвертов (VSA гейта, отчёты устройства) ключами Ed25519.
"""
from __future__ import annotations

import base64
import hashlib
import json
import struct
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

MAGIC = b"SCR1"
FORMAT_VERSION = 1
SCHEMA_V1 = 1
SUITE_ED25519 = 1
HEADER_LEN, PAYLOAD_LEN, SIG_LEN = 16, 164, 64
RECEIPT_LEN = HEADER_LEN + PAYLOAD_LEN + SIG_LEN
PAYLOAD_TYPE = b"application/vnd.scii.receipt.v1+bin"
_PAYLOAD = struct.Struct("<HBBHHI16sQI32sI32sHHHHQQ32s")
assert _PAYLOAD.size == PAYLOAD_LEN

REASONS = {0: "ADMIT", 1: "NO_RECEIPT", 2: "FORMAT", 3: "KEY", 4: "SIGNATURE", 5: "DECISION", 6: "TARGET",
           7: "POLICY", 8: "ROLLBACK", 9: "SIZE", 10: "DIGEST", 11: "STATE"}
DECISION_CODES = (0, 10, 20, 30)


@dataclass
class Payload:
    decision: int
    device_class: int
    svn: int
    image_size: int
    image_digest: bytes
    policy_epoch: int
    policy_digest: bytes
    device_instance: bytes = bytes(16)
    info_flags: int = 0
    r_min: int = 0
    r_max: int = 0
    theta: int = 0
    serial: int = 0
    issued_at: int = 0
    vsa_digest: bytes = bytes(32)
    suite: int = SUITE_ED25519
    schema: int = SCHEMA_V1
    critical: int = 0
    reserved: int = field(default=0, repr=False)

    def pack(self) -> bytes:
        if self.decision not in DECISION_CODES:
            raise ValueError(f"решение гейта {self.decision} не из {DECISION_CODES}")
        for name, n in (("device_instance", 16), ("image_digest", 32), ("policy_digest", 32), ("vsa_digest", 32)):
            if len(getattr(self, name)) != n:
                raise ValueError(f"{name}: нужно {n} байт")
        return _PAYLOAD.pack(self.schema, self.suite, self.decision, self.info_flags, self.critical,
                             self.device_class, self.device_instance, self.svn, self.image_size, self.image_digest,
                             self.policy_epoch, self.policy_digest, self.r_min, self.r_max, self.theta,
                             self.reserved, self.serial, self.issued_at, self.vsa_digest)

    @classmethod
    def unpack(cls, body: bytes) -> "Payload":
        (schema, suite, decision, info, critical, dclass, inst, svn, size, digest, epoch, pdigest, rmin, rmax,
         theta, reserved, serial, issued, vsa) = _PAYLOAD.unpack(body)
        return cls(decision=decision, device_class=dclass, svn=svn, image_size=size, image_digest=digest,
                   policy_epoch=epoch, policy_digest=pdigest, device_instance=inst, info_flags=info, r_min=rmin,
                   r_max=rmax, theta=theta, serial=serial, issued_at=issued, vsa_digest=vsa, suite=suite,
                   schema=schema, critical=critical, reserved=reserved)

    def describe(self) -> dict:
        return {"decision": self.decision, "device_class": self.device_class,
                "device_instance": self.device_instance.hex(), "svn": hex(self.svn), "image_size": self.image_size,
                "image_digest": self.image_digest.hex(), "policy_epoch": self.policy_epoch,
                "policy_digest": self.policy_digest.hex(), "r_min": self.r_min / 10000, "r_max": self.r_max / 10000,
                "theta": self.theta / 10000, "serial": self.serial, "issued_at": self.issued_at,
                "vsa_digest": self.vsa_digest.hex(), "info_flags": self.info_flags}


def raw_public(pk: Ed25519PublicKey) -> bytes:
    return pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def key_id(pk_raw: bytes, suite: int = SUITE_ED25519) -> bytes:
    return hashlib.sha256(bytes([suite]) + pk_raw).digest()[:8]


def pae(body: bytes, payload_type: bytes = PAYLOAD_TYPE) -> bytes:
    """DSSE Pre-Authentication Encoding."""
    return b"DSSEv1 %d %s %d %s" % (len(payload_type), payload_type, len(body), body)


def issue(sk: Ed25519PrivateKey, payload: Payload) -> bytes:
    body = payload.pack()
    pk = raw_public(sk.public_key())
    header = MAGIC + bytes([FORMAT_VERSION, payload.suite]) + struct.pack("<H", PAYLOAD_LEN) + key_id(pk, payload.suite)
    receipt = header + body + sk.sign(pae(body))
    assert len(receipt) == RECEIPT_LEN
    return receipt


def parse(receipt: bytes) -> Payload:
    if len(receipt) != RECEIPT_LEN or receipt[:4] != MAGIC or receipt[4] != FORMAT_VERSION:
        raise ValueError("не квитанция SCII-R v1")
    return Payload.unpack(receipt[HEADER_LEN:HEADER_LEN + PAYLOAD_LEN])


def verify(receipt: bytes, pk_raw: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pk_raw).verify(receipt[HEADER_LEN + PAYLOAD_LEN:],
                                                          pae(receipt[HEADER_LEN:HEADER_LEN + PAYLOAD_LEN]))
        return True
    except (InvalidSignature, ValueError):
        return False


# --- ключи Ed25519 ---
def new_key(path: Path) -> Ed25519PrivateKey:
    sk = Ed25519PrivateKey.generate()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(sk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
    path.chmod(0o600)
    return sk


def load_key(path: Path) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)


# --- конверты DSSE ---
def dsse_sign(sk: Ed25519PrivateKey, payload_type: str, body: bytes) -> dict:
    kid = key_id(raw_public(sk.public_key())).hex()
    sig = sk.sign(pae(body, payload_type.encode()))
    return {"payloadType": payload_type, "payload": base64.b64encode(body).decode(),
            "signatures": [{"keyid": kid, "sig": base64.b64encode(sig).decode()}]}


def dsse_verify(envelope: dict, pk_raw: bytes) -> bytes:
    """Проверить конверт и вернуть полезную нагрузку; ошибка — ValueError."""
    body = base64.b64decode(envelope["payload"])
    pt = envelope["payloadType"].encode()
    pk = Ed25519PublicKey.from_public_bytes(pk_raw)
    for s in envelope.get("signatures", []):
        try:
            pk.verify(base64.b64decode(s["sig"]), pae(body, pt))
            return body
        except (InvalidSignature, ValueError):
            continue
    raise ValueError("подпись конверта не проверяется")


def envelope_digest(envelope: dict) -> bytes:
    return hashlib.sha256(json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()).digest()


# --- подпись образа для загрузчика (аналог защищённой загрузки) ---
BOOTSIG_FORMAT = "cpslab-bootsig/1"


def boot_sign(sk: Ed25519PrivateKey, image: bytes) -> bytes:
    """Отделённая подпись Ed25519 над образом, которую проверяет загрузчик устройства."""
    sig = {"format": BOOTSIG_FORMAT, "alg": "ed25519", "keyid": key_id(raw_public(sk.public_key())).hex(),
           "sig": base64.b64encode(sk.sign(image)).decode()}
    return (json.dumps(sig, sort_keys=True, indent=1) + "\n").encode()


def boot_verify(sig_json: bytes, image: bytes, pk_raw: bytes) -> bool:
    try:
        sig = json.loads(sig_json)
        if sig.get("format") != BOOTSIG_FORMAT or sig.get("alg") != "ed25519":
            return False
        Ed25519PublicKey.from_public_bytes(pk_raw).verify(base64.b64decode(sig["sig"]), image)
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False
