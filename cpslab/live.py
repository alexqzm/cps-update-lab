"""Живой стенд: те же сценарии против работающих сервисов (сервер обновлений, контроллер, HMI).

Подготовка сценария (prepare) очищает каналы сервера обновлений и заново вводит контроллер в
эксплуатацию с исходным выпуском сценария; после неё контроллер нужно перезапустить. Прогон (run)
выполняет действия поставщика, гейта и нарушителя: пишет в каталог сервера обновлений, вызывает
API контроллера и отправляет запросы Modbus.
"""
from __future__ import annotations

import shutil
import time

from . import monitor
from .attacks import BACKDOOR_REGISTER, BACKDOOR_VALUE, attacker_image
from .device import Device
from .ews import DeviceApi, show
from .modbus import ModbusClient, ModbusError
from .scenarios import PUMP, TANK, Lab, catalog
from .server import UpdateStore

DEVICE_NAME = "plc-1"


def device_root(lab: Lab, name: str = DEVICE_NAME):
    return lab.home / "devices" / name


def provision(lab: Lab, name: str = DEVICE_NAME, level: int = 2, initial: str = "tank-1.0.0") -> Device:
    root = device_root(lab, name)
    shutil.rmtree(root, ignore_errors=True)
    return Device.provision(root, name=name, device_class=TANK, level=level, gate_pk=lab.keys.gate_pk(),
                            policy_digest=lab.gate.policy_digest, epoch=lab.gate.epoch,
                            vendor_boot_pk=lab.keys.ed25519_pk("vendor_boot"), image=lab.image(initial),
                            recipe_policy_digest=lab.recipe_gate.policy_digest, recipe_epoch=lab.recipe_gate.epoch)


def prepare(lab: Lab, sid: str, level: int, name: str = DEVICE_NAME) -> dict:
    sc = catalog()[sid]
    shutil.rmtree(lab.home / "server", ignore_errors=True)
    (lab.home / "server").mkdir(parents=True)
    provision(lab, name, level, sc["initial"])
    return {"scenario": sid, "level": level, "initial": sc["initial"]}


def run(lab: Lab, sid: str, device_url: str, modbus: tuple, log=print) -> list:
    api = DeviceApi(device_url)
    store = UpdateStore(lab.home / "server")
    mb = ModbusClient(*modbus)
    steps = []

    def step(title, fn):
        log(f"→ {title}")
        try:
            res = fn()
        except (ModbusError, ConnectionError, OSError) as e:
            res = {"error": str(e)}
        if isinstance(res, dict) and res:
            brief = {k: res[k] for k in ("accepted", "reason", "error") if k in res}
            log(f"  {brief}")
        steps.append({"step": title, "result": res})
        return res

    def publish(key, channel=None):
        return step(f"поставщик публикует {key}" + (f" в канал {channel}" if channel else "") +
                    (", гейт прикладывает квитанцию" if lab.receipt(key) else ", квитанции нет"),
                    lambda: lab.publish(store, key, channel=channel) or {})

    def update():
        return step("контроллер проверяет обновления", api.check_update)

    if sid == "N1":
        publish("tank-1.1.0")
        update()
    elif sid == "A1":
        publish("tank-1.1.0")
        evil = attacker_image(lab.vendor)
        step("нарушитель заменяет образ на сервере обновлений", lambda: store.write(TANK, "image.bin", evil) or {})
        update()
    elif sid in ("A2", "A3", "A3b", "A7"):
        key = {"A2": "tank-1.1.0-stolen-key", "A3": "tank-1.1.0-compromised-build",
               "A3b": "tank-1.1.0-compromised-build-norebuild", "A7": "tank-1.1.0-from-archive"}[sid]
        publish(key)
        update()
    elif sid == "A4":
        publish("tank-1.0.0")
        update()
        step("нарушитель записывает по Modbus high = 150 и hh = 150", lambda: mb.write_registers(1, [150, 150]) or {})
    elif sid == "A5":
        publish("pump-1.1.0", channel=TANK)
        update()
    elif sid == "A6":
        log(show(lab.image("tank-1.1.0")).replace("\n", "\n  "))
        step("подложная инженерная станция загружает в контроллер другую программу",
             lambda: api.program_download(attacker_image(lab.vendor)))
    elif sid == "M1":
        publish("tank-1.2.0")
        update()
        step(f"нарушитель записывает {BACKDOOR_VALUE:#x} в регистр {BACKDOOR_REGISTER}",
             lambda: mb.write_register(BACKDOOR_REGISTER, BACKDOOR_VALUE) or {})
    elif sid == "M2":
        step("нарушитель сбрасывает контроллер командой управления с паролем по умолчанию",
             lambda: api.mgmt("factory-reset", "admin"))
    else:
        raise ValueError(f"нет сценария {sid}")
    return steps


def observe(lab: Lab, device_url: str, seconds: float, name: str = DEVICE_NAME) -> dict:
    api = DeviceApi(device_url)
    time.sleep(seconds)
    st = api.status()
    mon = monitor.check(device_root(lab, name), lab.gate.admitted(), lab.recipe_gate.admitted())
    return {"status": st, "monitor": mon}


__all__ = ["prepare", "run", "observe", "provision", "PUMP"]


# ---------------- сервер агента живого стенда ----------------
AGENT_KEYS = {"agent": "Recipe", "observer": "Read"}


def agent_root(lab: Lab):
    return lab.home / "agent"


def setup_agent(lab: Lab, name: str = DEVICE_NAME) -> dict:
    """Каталог сервера агента: конфигурация, ключи agent (Recipe) и observer (Read), архив документов."""
    from . import documents as docs
    from .agent_server import AgentServer
    from .recipe_lab import NOTES_PLAIN, calibration, work_order_batch, work_order_drain
    root = agent_root(lab)
    srv = AgentServer(root, None).init()
    kd = root / "keys"
    kd.mkdir(parents=True, exist_ok=True)
    for kname, tier in AGENT_KEYS.items():
        kf = kd / f"{kname}.key"
        if not kf.exists():
            kf.write_text(srv.add_key(kname, tier, "shared") + "\n")
    a, keys = srv.archive, lab.keys
    if not a.names():
        a.write("WO-2026-014.json", docs.sign(keys.ed25519("technologist"), docs.WORK_ORDER,
                                              work_order_batch("WO-2026-014", name)))
        a.write("WO-2026-015.json", docs.sign(keys.ed25519("technologist"), docs.WORK_ORDER,
                                              work_order_drain("WO-2026-015", name, "drain-wash")))
        a.write("CAL-2026-07.json", docs.sign(keys.ed25519("metrology"), docs.CALIBRATION, calibration("CAL-2026-07", name)))
        a.write("shift-notes.txt", NOTES_PLAIN)
    return {"root": str(root), "keys": {k: str(kd / f"{k}.key") for k in AGENT_KEYS}, "mode": srv.mode()}


def recipe_demo(lab: Lab, agent_url: str, device_url: str, observe: float = 45.0, log=print) -> dict:
    """Живой канал рецептов: агент (детерминированный) через HTTP API сервера агента, утверждение
    оператора, решение гейта рецептов, запуск на контроллере и наблюдение за партией."""
    import uuid
    from .agent_server import AgentServer, HttpAgentClient, HttpDevice
    from .recipe_lab import RecipeLab, ScriptedAgent
    from .recipe import version_tuple
    root = agent_root(lab)
    api = DeviceApi(device_url)
    ver = api.status()["installed"].get("version") or "0.0.0"
    if version_tuple(ver) < (1, 1, 0):                # рецепты рассчитаны на программу 1.1.0 и выше
        lab.publish(UpdateStore(lab.home / "server"), "tank-1.1.0")
        res = api.check_update()
        log(f"→ контроллер обновляется {ver} → 1.1.0 (как в N1): {res.get('reason')}")
    AgentServer(root, None).set_mode("remote", "оператор (демонстрация)")
    log("→ оператор переводит сервер агента в режим remote")
    key = (root / "keys" / "agent.key").read_text().strip()
    agent = ScriptedAgent(HttpAgentClient(agent_url), key, f"demo-{uuid.uuid4().hex[:8]}")
    s = agent.prepare("WO-2026-014.json", "CAL-2026-07.json", notes=["shift-notes.txt"])
    log(f"→ агент: {' → '.join(agent.trace)}")
    log(f"  проверка: {'ошибок нет' if s['validate']['valid'] else 'ошибки'}; пробный прогон: "
        f"{'в норме' if s['dry_run']['ok'] else '; '.join(s['dry_run']['problems'])}")
    if not s["uploaded"]:
        return {"uploaded": False}
    path = root / s["uploaded"]["path"]
    log(f"  загружен {path.name}, SHA-256 {s['uploaded']['sha256'][:16]}…")
    dev = HttpDevice(device_url)
    st, pi = dev.status(), dev.program()
    fleet = {"device": st["name"], "device_class": st["device_class"], "instance": st.get("instance"),
             "product": (pi.get("manifest") or {}).get("product"),
             "program_version": (pi.get("manifest") or {}).get("version"), "program": pi.get("program"),
             "level": st["process"]["level"]}

    class _Dev:
        config = {"name": st["name"]}
    RecipeLab(lab).approve(root, path, _Dev)
    res = lab.recipe_gate.admit(lab.recipe_gate.assemble(root, path, fleet))
    log(f"→ оператор утверждает; гейт рецептов: {res['decision']} (R_min {res['R_min']:.3f}), квитанция: "
        f"{'выдана' if res['receipt'] else 'нет'}")
    start = agent.call("start_recipe", name=s["recipe"]["name"])
    log(f"→ агент запускает рецепт: {'принято' if start.get('accepted') else 'отказ'} {start.get('reason')}")
    time.sleep(observe)
    st = dev.status()
    rs, p = st.get("recipe") or {}, st["process"]
    log(f"через {observe:g} с: рецепт {rs.get('status')}, партия {rs.get('quality')}; уровень {p['level']} %, "
        f"аварии: {', '.join(p['alarms']) or 'нет'}")
    mon = monitor.check(device_root(lab), lab.gate.admitted(), lab.recipe_gate.admitted())
    for a in mon["alerts"]:
        log(f"монитор: {a['message']}")
    return {"uploaded": True, "gate": res["code"], "start": start, "recipe": rs, "process": p, "monitor": mon}
