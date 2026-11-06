import copy
import io
import json
import socket
import tarfile

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cpslab import image as img
from cpslab.attacks import malicious
from cpslab.modbus import ModbusClient, ModbusError, ModbusServer
from cpslab.plant import Tank, simulate
from cpslab.program import Controller, ProgramError, listing, validate
from cpslab.quality import functional_tests, lint
from cpslab.receipt import (PAYLOAD_LEN, RECEIPT_LEN, Payload, boot_sign, boot_verify, dsse_sign, dsse_verify, issue,
                            pae, parse, raw_public, verify)
from cpslab.util import DATA_DIR

HIST = DATA_DIR / "vendor-src" / "history"


def prog(product="tank-controller", version="1.1.0"):
    return json.loads((HIST / product / f"{version}.json").read_text(encoding="utf-8"))


# ---------------- программа ----------------
def test_vendor_programs_are_valid():
    for p in HIST.glob("*/*.json"):
        validate(json.loads(p.read_text(encoding="utf-8")))


@pytest.mark.parametrize("mutate, msg", [
    (lambda p: p.update(format="x"), "формат"),
    (lambda p: p["rules"].append({"when": ["level", "~", 1], "set": {"pump": True}}), "when"),
    (lambda p: p["rules"].append({"when": ["pressure", "<", 1], "set": {"pump": True}}), "операнд"),
    (lambda p: p["rules"].append({"when": ["level", "<", 1], "set": {"valve": True}}), "цель"),
    (lambda p: p["setpoints"]["hh"].update(default=95), "вне ограничений"),
    (lambda p: p["setpoints"]["hh"].update(register=0), "занят"),
    (lambda p: p.update(code="import os"), "неизвестные поля"),
])
def test_program_validation(mutate, msg):
    p = prog()
    mutate(p)
    with pytest.raises(ProgramError, match=msg):
        validate(p)


def test_controller_hysteresis_and_interlock():
    c = Controller(prog())
    assert c.scan(35) is True          # ниже low — включить
    assert c.scan(55) is True          # между low и high — держать
    assert c.scan(61) is False         # выше high — выключить
    c.write_register(1, 99)            # high ограничивается max = 80
    assert c.setpoints["high"] == 80
    c.write_register(2, 200)           # hh ограничивается max = 90
    assert c.setpoints["hh"] == 90


def test_unlimited_setpoints_in_1_0_0():
    c = Controller(prog(version="1.0.0"))
    c.write_register(1, 150)
    c.write_register(2, 150)
    assert c.setpoints["high"] == 150 and c.setpoints["hh"] == 150
    tank = simulate(c, Tank(level=50), 300)
    assert tank.overflowed


def test_backdoor_rule_in_1_2_0():
    c = Controller(prog(version="1.2.0"))
    assert simulate(c, Tank(level=50), 300).outcome() == "normal"
    c.write_register(100, 0xBEEF)
    assert simulate(c, Tank(level=50), 300).outcome() == "overflow"


def test_listing_shows_limits():
    text = listing(prog(version="1.0.0"))
    assert "без ограничений" in text and "ПАЗ" in text


# ---------------- статический анализ и испытания ----------------
def test_lint_findings():
    rules = lambda p: sorted({f["rule"] for f in lint(p)["findings"]})  # noqa: E731
    assert rules(prog()) == []
    assert rules(prog(version="1.0.0")) == ["CPS001"]
    assert rules(prog(version="1.2.0")) == ["CPS003", "CPS004"]
    assert "CPS002" in rules(malicious(prog()))
    assert lint(prog(version="1.2.0"))["status"] == "COMPLETED"


def suite(product="tank-controller"):
    return json.loads((DATA_DIR / "vendor-src" / "products" / product / "tests.json").read_text(encoding="utf-8"))


def test_functional_tests():
    for v in ("1.0.0", "1.1.0", "1.2.0"):
        assert functional_tests(prog(version=v), suite())["result"] == "PASSED"
    assert functional_tests(prog("pump-station"), suite("pump-station"))["result"] == "PASSED"
    res = functional_tests(malicious(prog()), suite())
    assert res["result"] == "FAILED" and "normal-demand" in res["failedTests"]
    # программа насосной станции на резервуаре держит уровень 2–4 % — резервуар опустошён (сценарий A5)
    res = functional_tests(prog("pump-station"), suite())
    assert res["result"] == "FAILED" and res["cases"][0]["max_level"] <= 50.0


# ---------------- образ ----------------
def build(tmp_path, version="1.1.0", product="tank-controller", **kw):
    src = tmp_path / "src"
    pdir = src / "products" / product
    pdir.mkdir(parents=True, exist_ok=True)
    meta = json.loads((DATA_DIR / "vendor-src" / "products" / product / "manifest.json").read_text())
    meta["version"] = version
    (pdir / "manifest.json").write_text(json.dumps(meta))
    (pdir / "program.json").write_text(json.dumps(prog(product, version)))
    return img.build_image(src, product, 1772434800, **kw)


def test_image_is_reproducible(tmp_path):
    a, b = build(tmp_path), build(tmp_path)
    assert a == b
    manifest, program = img.read_image(a)
    assert manifest["svn"] == img.svn("1.1.0") == (1 << 32) | (1 << 16) | 255
    assert program == prog()
    assert build(tmp_path, inject=malicious) != a


def _retar(data: bytes, change) -> bytes:
    members = {}
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        for m in t.getmembers():
            members[m.name] = t.extractfile(m).read()
    change(members)
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as t:
        for name, body in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(body)
            t.addfile(info, io.BytesIO(body))
    return out.getvalue()


@pytest.mark.parametrize("change, msg", [
    (lambda m: m.update({"program.json": m["program.json"].replace(b'"default": 85', b'"default": 86')}), "дайджест"),
    (lambda m: m.update({"extra.sh": b"echo"}), "только"),
    (lambda m: m.update({"manifest.json": m["manifest.json"].replace(b'"svn": ', b'"svn": 1')}), "svn"),
])
def test_image_rejects_tampering(tmp_path, change, msg):
    data = _retar(build(tmp_path), change)
    with pytest.raises(img.ImageError, match=msg):
        img.read_image(data)


def test_image_rejects_garbage():
    with pytest.raises(img.ImageError):
        img.read_image(b"\x00" * 1024 + b"not a tar")


# ---------------- квитанция и подписи ----------------
def test_receipt_roundtrip():
    sk = Ed25519PrivateKey.generate()
    p = Payload(decision=0, device_class=7001, svn=img.svn("1.1.0"), image_size=10240, image_digest=bytes(range(32)),
                policy_epoch=1, policy_digest=bytes(32), serial=7, issued_at=1, r_min=9000, r_max=9000, theta=9000)
    r = issue(sk, p)
    assert len(r) == RECEIPT_LEN == 244 and r[:4] == b"SCR1"
    assert parse(r).describe() == p.describe()
    assert verify(r, raw_public(sk.public_key()))
    bad = bytearray(r)
    bad[16 + 8] ^= 1                    # класс устройства в подписанной нагрузке
    assert not verify(bytes(bad), raw_public(sk.public_key()))
    assert pae(bytes(PAYLOAD_LEN)).startswith(b"DSSEv1 35 application/vnd.scii.receipt.v1+bin 164 ")
    assert len(pae(bytes(PAYLOAD_LEN))) == 214
    with pytest.raises(ValueError):
        Payload(**{**p.__dict__, "decision": 5}).pack()


def test_boot_signature_and_dsse():
    sk, other = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    sig = boot_sign(sk, b"image")
    assert boot_verify(sig, b"image", raw_public(sk.public_key()))
    assert not boot_verify(sig, b"image2", raw_public(sk.public_key()))
    assert not boot_verify(sig, b"image", raw_public(other.public_key()))
    env = dsse_sign(sk, "application/vnd.in-toto+json", b'{"a": 1}')
    assert dsse_verify(env, raw_public(sk.public_key())) == b'{"a": 1}'
    with pytest.raises(ValueError):
        dsse_verify(env, raw_public(other.public_key()))


# ---------------- Modbus ----------------
class FakeDevice:
    def __init__(self):
        self.regs = [0] * 10

    def mb_read(self, kind, addr, count):
        if kind != "holding" or addr + count > len(self.regs):
            raise ModbusError(2)
        return self.regs[addr:addr + count]

    def mb_write(self, addr, values):
        if addr + len(values) > len(self.regs):
            raise ModbusError(2)
        self.regs[addr:addr + len(values)] = values


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_modbus_roundtrip():
    dev = FakeDevice()
    port = free_port()
    srv = ModbusServer(dev, "127.0.0.1", port)
    srv.start()
    try:
        c = ModbusClient("127.0.0.1", port)
        c.write_register(1, 150)
        c.write_registers(2, [7, 8])
        assert c.read_holding(0, 4) == [0, 150, 7, 8]
        with pytest.raises(ModbusError) as e:
            c.read_holding(9, 5)
        assert e.value.code == 2
        with pytest.raises(ModbusError) as e:
            c.read(4, 0, 1)                 # входные регистры у FakeDevice не поддержаны
        assert e.value.code == 2
    finally:
        srv.shutdown()
        srv.server_close()


def test_malicious_keeps_program_valid():
    p = malicious(copy.deepcopy(prog()))
    validate(p)
    assert p["interlocks"] == [] and p["setpoints"]["high"]["default"] == 110
