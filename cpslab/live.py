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
                            vendor_boot_pk=lab.keys.ed25519_pk("vendor_boot"), image=lab.image(initial))


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
    mon = monitor.check(device_root(lab, name), lab.gate.admitted())
    return {"status": st, "monitor": mon}


__all__ = ["prepare", "run", "observe", "provision", "PUMP"]
