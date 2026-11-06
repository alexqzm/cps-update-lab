"""Сценарии стенда: подготовка выпусков и решений гейта, прогон сценария на уровне защиты.

Lab собирает стенд в рабочем каталоге: ключи ролей, репозиторий поставщика, выпуски (подлинные
и варианты нарушителя), политику и решения гейта. Подготовка долгая (десятки подписей cosign),
поэтому выпуски и решения кэшируются. Каждый прогон сценария получает свой чистый канал сервера
обновлений и заново введённое в эксплуатацию устройство.
"""
from __future__ import annotations

import shutil
from dataclasses import asdict, dataclass, field
from pathlib import Path

import yaml

from . import monitor
from .attacks import ARCHIVE_DEFAULTS, BACKDOOR_REGISTER, BACKDOOR_VALUE, attacker_image, malicious, stolen_key_release
from .device import Device
from .ews import rogue_download
from .gate import Gate
from .image import svn
from .keys import Keys
from .server import UpdateStore
from .util import DATA_DIR, rjson, wjson
from .vendor import Vendor, package_files, release_info

CATALOG = DATA_DIR / "scenarios.yaml"
TANK, PUMP = 7001, 7002
PROCESS_SECONDS = 300.0

# выпуски стенда: ключ -> (изделие, версия, параметры варианта)
RELEASES = {
    "tank-1.0.0": ("tank-controller", "1.0.0", {}),
    "tank-1.1.0": ("tank-controller", "1.1.0", {}),
    "tank-1.2.0": ("tank-controller", "1.2.0", {}),
    "pump-1.1.0": ("pump-station", "1.1.0", {}),
    "tank-1.1.0-compromised-build": ("tank-controller", "1.1.0", {"inject": malicious}),
    "tank-1.1.0-compromised-build-norebuild": ("tank-controller", "1.1.0", {"inject": malicious, "independent": False}),
    "tank-1.1.0-from-archive": ("tank-controller", "1.1.0", {"from_archive": ARCHIVE_DEFAULTS}),
    "tank-1.1.0-stolen-key": None,
}
# решения гейта: ключ выпуска -> состояние парка на момент допуска
ADMISSIONS = {
    "tank-1.0.0": (TANK, "0.0.0"),
    "tank-1.1.0": (TANK, "1.0.0"),
    "tank-1.2.0": (TANK, "1.1.0"),
    "pump-1.1.0": (PUMP, "0.0.0"),
    "tank-1.1.0-compromised-build": (TANK, "1.0.0"),
    "tank-1.1.0-compromised-build-norebuild": (TANK, "1.0.0"),
    "tank-1.1.0-from-archive": (TANK, "1.0.0"),
    "tank-1.1.0-stolen-key": (TANK, "1.0.0"),
}


def catalog() -> dict:
    with open(CATALOG, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return {s["id"]: s for s in data["scenarios"]}


@dataclass
class Outcome:
    scenario: str
    level: int
    accepted: bool
    reason: str
    process: str
    alert: bool
    gate: int = None
    running: str = None
    max_level: float = None
    details: dict = field(default_factory=dict)

    def key(self) -> dict:
        return {"accepted": self.accepted, "reason": self.reason, "process": self.process, "alert": self.alert}


class Lab:
    def __init__(self, home: Path):
        self.home = Path(home).resolve()
        self.keys = Keys(self.home)
        self.vendor = Vendor(self.home, self.keys)
        self.gate = Gate(self.home, self.keys, self.vendor.src)
        self.state_path = self.home / "lab.json"

    # ---------------- подготовка ----------------
    def init(self, progress=print) -> "Lab":
        progress("ключи ролей")
        self.keys.init()
        progress("репозиторий поставщика")
        self.vendor.init_repo()
        if not self.gate.policy_path.exists():
            self.gate.init()
        for key in RELEASES:
            if not (self.vendor.releases / key / "bundle.json").exists():
                progress(f"выпуск {key}")
            self.release(key)
        state = rjson(self.state_path) if self.state_path.exists() else {"admissions": {}}
        for key, (dclass, installed) in ADMISSIONS.items():
            if key in state["admissions"]:
                continue
            progress(f"решение гейта: {key}")
            fleet = {"device_class": dclass, "installed_svn": svn(installed) if installed != "0.0.0" else 0}
            res = self.gate.admit(self.release(key), fleet)
            run_dir = res.get("run")
            state["admissions"][key] = {"code": res["code"], "decision": res["decision"], "R_min": res.get("R_min"),
                                        "R_max": res.get("R_max"),
                                        "run": str(run_dir.relative_to(self.home)) if run_dir else None,
                                        "error": res.get("error"), "receipt": bool(res["receipt"])}
            wjson(self.state_path, state)
        return self

    def release(self, key: str) -> Path:
        spec = RELEASES[key]
        if spec is None:
            return stolen_key_release(self.vendor, name=key)
        product, version, kw = spec
        return self.vendor.release(product, version, name=key, **kw)

    def admission(self, key: str) -> dict:
        return rjson(self.state_path)["admissions"][key]

    def receipt(self, key: str):
        a = self.admission(key)
        p = self.home / a["run"] / "receipt.scr"
        return p.read_bytes() if a["receipt"] and p.exists() else None

    def image(self, key: str) -> bytes:
        return package_files(self.release(key))["image"]

    # ---------------- прогон ----------------
    def store(self, run_id: str) -> UpdateStore:
        root = self.home / "runs" / run_id / "server"
        shutil.rmtree(root, ignore_errors=True)
        return UpdateStore(root)

    def publish(self, store: UpdateStore, key: str, channel: int = None, receipt: bool = True) -> None:
        """Поставщик публикует пакет; гейт прикладывает квитанцию, если допустил выпуск."""
        files = package_files(self.release(key))
        store.publish(files, channel)
        r = self.receipt(key) if receipt else None
        if r is not None:
            store.write(channel or files["release"]["device_class"], "receipt.scr", r)

    def device(self, run_id: str, level: int, initial: str, device_class: int = TANK) -> Device:
        root = self.home / "runs" / run_id / "device"
        shutil.rmtree(root, ignore_errors=True)
        return Device.provision(root, name=f"plc-{run_id}", device_class=device_class, level=level,
                                gate_pk=self.keys.gate_pk(), policy_digest=self.gate.policy_digest,
                                epoch=self.gate.epoch, vendor_boot_pk=self.keys.ed25519_pk("vendor_boot"),
                                image=self.image(initial))

    def outcome(self, sid: str, level: int, dev: Device, res: dict, gate_key: str = None, **details) -> Outcome:
        mon = monitor.check(dev.root, self.gate.admitted())
        st = dev.status()
        inst = st["installed"]
        return Outcome(scenario=sid, level=level, accepted=bool(res.get("accepted")), reason=res.get("reason"),
                       process=dev.tank.outcome(), alert=bool(mon["alerts"]),
                       gate=self.admission(gate_key)["code"] if gate_key else None,
                       running=f"{inst['product']} {inst['version']}" if inst["version"] else "нет программы",
                       max_level=round(dev.tank.max_level, 1),
                       details={"monitor": mon, **details})

    def run(self, sid: str, level: int) -> Outcome:
        fn = SCENARIOS[sid]
        return fn(self, f"{sid}-L{level}", level, catalog()[sid]["initial"])


# ---------------- сценарии ----------------
def _update(lab, rid, level, initial, publish_key, gate_key=None, tamper=None, channel=None, events=None):
    dev = lab.device(rid, level, initial)
    store = lab.store(rid)
    lab.publish(store, publish_key, channel=channel)
    if tamper:
        tamper(store)
    res = dev.check_update(store)
    dev.reset_process()
    dev.run_for(PROCESS_SECONDS, events=events(dev) if events else None)
    return dev, res


def n1(lab, rid, level, initial):
    dev, res = _update(lab, rid, level, initial, "tank-1.1.0")
    return lab.outcome("N1", level, dev, res, "tank-1.1.0")


def a1(lab, rid, level, initial):
    evil = attacker_image(lab.vendor)
    dev, res = _update(lab, rid, level, initial, "tank-1.1.0",
                       tamper=lambda store: store.write(TANK, "image.bin", evil))
    return lab.outcome("A1", level, dev, res, "tank-1.1.0", same_size=len(evil) == len(lab.image("tank-1.1.0")))


def a2(lab, rid, level, initial):
    dev, res = _update(lab, rid, level, initial, "tank-1.1.0-stolen-key")
    return lab.outcome("A2", level, dev, res, "tank-1.1.0-stolen-key")


def a3(lab, rid, level, initial):
    dev, res = _update(lab, rid, level, initial, "tank-1.1.0-compromised-build")
    return lab.outcome("A3", level, dev, res, "tank-1.1.0-compromised-build")


def a3b(lab, rid, level, initial):
    dev, res = _update(lab, rid, level, initial, "tank-1.1.0-compromised-build-norebuild")
    return lab.outcome("A3b", level, dev, res, "tank-1.1.0-compromised-build-norebuild")


def _raise_setpoints(dev):
    def write():
        try:
            dev.mb_write(1, [150, 150])         # high и hh
        except Exception:                       # контроллер без программы отвечает исключением Modbus
            pass
    return [(5.0, write)]


def a4(lab, rid, level, initial):
    dev, res = _update(lab, rid, level, initial, "tank-1.0.0", events=_raise_setpoints)
    return lab.outcome("A4", level, dev, res, "tank-1.0.0")


def a5(lab, rid, level, initial):
    dev, res = _update(lab, rid, level, initial, "pump-1.1.0", channel=TANK)
    return lab.outcome("A5", level, dev, res, "pump-1.1.0")


def a6(lab, rid, level, initial):
    dev = lab.device(rid, level, initial)
    shown, res = rogue_download(dev, lab.image("tank-1.1.0"), attacker_image(lab.vendor))
    dev.reset_process()
    dev.run_for(PROCESS_SECONDS)
    return lab.outcome("A6", level, dev, res, None, shown=shown)


def a7(lab, rid, level, initial):
    dev, res = _update(lab, rid, level, initial, "tank-1.1.0-from-archive")
    return lab.outcome("A7", level, dev, res, "tank-1.1.0-from-archive")


def _backdoor(dev):
    def write():
        try:
            dev.mb_write(BACKDOOR_REGISTER, [BACKDOOR_VALUE])
        except Exception:
            pass
    return [(5.0, write)]


def m1(lab, rid, level, initial):
    dev, res = _update(lab, rid, level, initial, "tank-1.2.0", events=_backdoor)
    return lab.outcome("M1", level, dev, res, "tank-1.2.0")


def m2(lab, rid, level, initial):
    dev = lab.device(rid, level, initial)
    res = dev.mgmt("factory-reset", "admin")
    dev.reset_process()
    dev.run_for(PROCESS_SECONDS)
    return lab.outcome("M2", level, dev, res, None)


SCENARIOS = {"N1": n1, "A1": a1, "A2": a2, "A3": a3, "A3b": a3b, "A4": a4, "A5": a5, "A6": a6, "A7": a7,
             "M1": m1, "M2": m2}
LEVELS = (0, 1, 2)


def run_matrix(lab: Lab, ids=None, levels=LEVELS) -> list:
    out = []
    for sid in ids or SCENARIOS:
        for level in levels:
            out.append(lab.run(sid, level))
    return out


def compare(outcomes: list) -> list:
    """Расхождения фактических исходов с ожидаемыми из каталога."""
    cat, diffs = catalog(), []
    for o in outcomes:
        exp = cat[o.scenario]["expected"][f"L{o.level}"]
        if o.key() != exp:
            diffs.append({"scenario": o.scenario, "level": o.level, "expected": exp, "actual": o.key()})
        if cat[o.scenario]["gate"] != o.gate:
            diffs.append({"scenario": o.scenario, "level": o.level, "expected_gate": cat[o.scenario]["gate"],
                          "actual_gate": o.gate})
    return diffs


def as_dict(o: Outcome) -> dict:
    d = asdict(o)
    d["details"] = {k: v for k, v in d["details"].items() if k != "monitor"} | {
        "alerts": [a["message"] for a in o.details["monitor"]["alerts"]],
        "warnings": [w["message"] for w in o.details["monitor"]["warnings"]]}
    return d


__all__ = ["Lab", "Outcome", "SCENARIOS", "LEVELS", "run_matrix", "compare", "catalog", "release_info"]
