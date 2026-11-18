"""Эмулятор контроллера: установка образов на трёх уровнях защиты, процесс, Modbus, отчёты.

Уровни защиты:
  0 — без проверки: принимается любой образ правильного формата;
  1 — подпись поставщика: загрузчик проверяет подпись образа ключом поставщика (Ed25519). Загрузка
      логики с инженерной станции идёт мимо загрузчика и подписью не проверяется: логику
      пользователя поставщик не подписывает;
  2 — квитанция гейта SCII: и обновление, и загрузка логики допускаются только после проверки
      квитанции SCII-R v1 агентом scii-agent (11 проверок: подпись гейта, решение, класс и
      экземпляр устройства, политика, антиоткат, длина и дайджест образа); затем загрузчик
      проверяет подпись образа.

Каждая попытка установки и каждая команда управления записываются в отчёт, подписанный ключом
устройства (заготовка свидетельства s54 и вход контура реагирования, см. monitor.py).

Рецепты партии (recipe.py) приходят от сервера агента. На уровнях 0 и 1 контроллер исполняет любой
разбираемый рецепт (на уровне 1 статическую проверку выполняет сервер агента), на уровне 2 — только
с квитанцией допуска SCII-R v1, которую выдал гейт рецептов: scii-agent проверяет её против
дайджеста рецепта, класса и экземпляра устройства, политики допуска рецептов и наибольшей ревизии
этого рецепта, уже исполненной на устройстве (антиповтор). Начало и конец каждого рецепта
записываются в подписанный отчёт вместе с образом программы, на которой он исполнялся.
"""
from __future__ import annotations

import base64
import json
import re
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .image import ImageError, read_image
from .modbus import DEVICE_FAILURE, ILLEGAL_ADDRESS, ModbusError
from .plant import Tank
from .program import Controller, REGISTERS
from .receipt import boot_verify, load_key, new_key, parse as parse_receipt, raw_public
from .recipe import PUMP_MODES, RecipeError, RecipeRun, parse as parse_recipe
from .util import ToolError, canonical_json, now_utc, rjson, run, scii_agent, sha256_bytes, wjson

LEVELS = {0: "без проверки", 1: "подпись поставщика", 2: "квитанция гейта SCII"}
REASON_RU = {
    "OK": "принято", "NO_UPDATE": "новых обновлений нет", "IMAGE_FORMAT": "образ не разбирается",
    "BOOT_SIG": "подпись образа не принимается загрузчиком", "DENIED": "неверный пароль управления",
    "NO_RECEIPT": "нет квитанции допуска", "FORMAT": "квитанция не разбирается", "KEY": "неизвестный ключ гейта",
    "SIGNATURE": "подпись квитанции неверна", "DECISION": "квитанция не о допуске", "TARGET": "квитанция для другого устройства",
    "POLICY": "квитанция по другой политике", "ROLLBACK": "откат версии (для рецепта — повтор старой ревизии)",
    "SIZE": "длина образа или рецепта не совпадает с квитанцией",
    "DIGEST": "дайджест образа или рецепта не совпадает с квитанцией", "STATE": "нет состояния устройства",
    "INVALID": "статическая проверка на сервере агента отклонила рецепт", "RECIPE_FORMAT": "рецепт не разбирается",
    "NO_PROGRAM": "в контроллере нет программы", "BUSY": "исполняется другой рецепт",
    "BAD_COMMAND": "неизвестная команда или аргументы",
}
_AGENT_LINE = re.compile(r"^([A-Z_]+) \((\d+)\)$")


class Device:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.config = rjson(self.root / "config.json")
        self.state = rjson(self.root / "state.json")
        self.key = load_key(self.root / "device.pem")
        self.lock = threading.RLock()
        self.tank = Tank()
        self.controller = None
        self.recipe_run = None
        self.recipe_meta = None
        self.stopped = False
        self.last = None
        img = self.root / "flash" / "image.bin"
        if img.exists():
            self.controller = Controller(read_image(img.read_bytes())[1])

    # ---------------- ввод в эксплуатацию ----------------
    @classmethod
    def provision(cls, root: Path, *, name: str, device_class: int, level: int, gate_pk: bytes, policy_digest: bytes,
                  epoch: int, vendor_boot_pk: bytes, image: bytes, instance: bytes = bytes(16),
                  mgmt_password: str = "admin", recipe_policy_digest: bytes = None,
                  recipe_epoch: int = 1) -> "Device":
        """Завод: записать конфигурацию, ключ устройства и исходный образ без проверок."""
        root = Path(root)
        (root / "flash").mkdir(parents=True, exist_ok=True)
        manifest, _ = read_image(image)
        wjson(root / "config.json", {
            "name": name, "device_class": int(device_class), "instance": instance.hex(), "level": int(level),
            "gate_pk": gate_pk.hex(), "key_epoch_lo": 1, "key_epoch_hi": 0xFFFFFFFF,
            "policy_digest": policy_digest.hex(), "vendor_boot_pk": vendor_boot_pk.hex(),
            "mgmt_password": mgmt_password,
            "recipe_policy_digest": recipe_policy_digest.hex() if recipe_policy_digest else None})
        sk = new_key(root / "device.pem")
        (root / "device.pk").write_text(raw_public(sk.public_key()).hex() + "\n")
        (root / "flash" / "image.bin").write_bytes(image)
        (root / "flash" / "receipt.scr").unlink(missing_ok=True)
        (root / "reports.jsonl").unlink(missing_ok=True)
        wjson(root / "state.json", {"generation": 1, "installed_svn": manifest["svn"],
                                    "installed_digest": sha256_bytes(image), "installed_version": manifest["version"],
                                    "product": manifest["product"], "min_policy_epoch": int(epoch), "seq": 0,
                                    "recipe_min_epoch": int(recipe_epoch), "recipe_svn": {}})
        dev = cls(root)
        dev._report("factory", "factory", True, "OK", sha256_bytes(image))
        return dev

    @property
    def level(self) -> int:
        return int(self.config["level"])

    def set_level(self, level: int) -> None:
        if level not in LEVELS:
            raise ValueError(f"уровень защиты {level} не из {sorted(LEVELS)}")
        self.config["level"] = int(level)
        wjson(self.root / "config.json", self.config)

    # ---------------- отчёты ----------------
    def _report(self, event: str, path: str, accepted: bool, reason: str, digest: str = None, extra: dict = None):
        self.state["seq"] += 1
        wjson(self.root / "state.json", self.state)
        ev = {"device": self.config["name"], "device_class": self.config["device_class"],
              "instance": self.config["instance"], "seq": self.state["seq"], "time": now_utc(), "event": event,
              "path": path, "accepted": accepted, "reason": reason, "candidate_sha256": digest,
              "installed_sha256": self.state.get("installed_digest"), "installed_version": self.state.get("installed_version"),
              "installed_svn": self.state.get("installed_svn"), "level": self.level}
        if extra:
            ev.update(extra)
        sig = base64.b64encode(self.key.sign(canonical_json(ev))).decode()
        with open(self.root / "reports.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps({"event": ev, "sig": sig}, ensure_ascii=False) + "\n")
        self.last = ev
        return ev

    def reports(self) -> list:
        p = self.root / "reports.jsonl"
        return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()] if p.exists() else []

    # ---------------- установка ----------------
    def _agent(self, image: bytes, receipt: bytes, policy_digest: str = None, min_epoch: int = None,
               installed_svn: int = None) -> str:
        c = self.config
        policy_digest = policy_digest or c["policy_digest"]
        min_epoch = self.state["min_policy_epoch"] if min_epoch is None else min_epoch
        installed_svn = self.state["installed_svn"] if installed_svn is None else installed_svn
        with tempfile.TemporaryDirectory(prefix="cpslab-agent-") as d:
            ip, rp = Path(d) / "image.bin", Path(d) / "receipt.scr"
            ip.write_bytes(image)
            rp.write_bytes(receipt)
            r = run([scii_agent(), "--image", ip, "--receipt", rp, "--pk", c["gate_pk"], "--suite", "1",
                     "--epoch-lo", c["key_epoch_lo"], "--epoch-hi", c["key_epoch_hi"], "--board-id", c["device_class"],
                     "--policy-digest", policy_digest, "--min-epoch", min_epoch,
                     "--installed-svn", hex(installed_svn), "--instance", c["instance"]], check=False)
        m = _AGENT_LINE.match((r.stdout.strip().splitlines() or [""])[0])
        if not m:
            raise ToolError(f"scii-agent: {(r.stderr or r.stdout).strip()[-300:]}")
        return m.group(1)

    def install(self, image: bytes, bootsig: bytes = None, receipt: bytes = None, path: str = "update") -> dict:
        """Попытка установить образ; path — update (канал обновления) или ews (инженерная станция)."""
        with self.lock:
            digest = sha256_bytes(image)
            level = self.level
            if level >= 2:
                reason = "NO_RECEIPT" if receipt is None else self._agent(image, receipt)
                if reason != "ADMIT":
                    return self._reject(path, reason, digest)
            if path == "update" and level >= 1:
                pk = bytes.fromhex(self.config["vendor_boot_pk"])
                if bootsig is None or not boot_verify(bootsig, image, pk):
                    return self._reject(path, "BOOT_SIG", digest)
            try:
                manifest, program = read_image(image)
            except ImageError:
                return self._reject(path, "IMAGE_FORMAT", digest)
            controller = Controller(program)
            if self.recipe_run is not None and self.recipe_run.status == "running":
                self.recipe_run.abort("установлена новая программа")
                self._recipe_end()
            st = self.state
            if level >= 2:
                rp = parse_receipt(receipt)
                st["installed_svn"] = rp.svn
                st["min_policy_epoch"] = max(st["min_policy_epoch"], rp.policy_epoch)
            else:
                st["installed_svn"] = manifest["svn"]
            st.update({"installed_digest": digest, "installed_version": manifest["version"],
                       "product": manifest["product"], "generation": st["generation"] + 1})
            (self.root / "flash" / "image.bin").write_bytes(image)
            rf = self.root / "flash" / "receipt.scr"
            if receipt is not None and level >= 2:
                rf.write_bytes(receipt)
            else:
                rf.unlink(missing_ok=True)
            wjson(self.root / "state.json", st)
            self.controller, self.stopped = controller, False
            ev = self._report("install", path, True, "OK", digest,
                              {"version": manifest["version"], "product": manifest["product"]})
            return {"accepted": True, "reason": "OK", "event": ev}

    def _reject(self, path: str, reason: str, digest: str) -> dict:
        ev = self._report("reject", path, False, reason, digest)
        return {"accepted": False, "reason": reason, "event": ev}

    def check_update(self, transport) -> dict:
        """Канал обновления: забрать пакет своего класса устройства и попытаться установить."""
        pkg = transport.fetch(self.config["device_class"])
        if not pkg or not pkg.get("image"):
            return {"accepted": False, "reason": "NO_UPDATE"}
        if sha256_bytes(pkg["image"]) == self.state.get("installed_digest"):
            return {"accepted": False, "reason": "NO_UPDATE"}
        return self.install(pkg["image"], pkg.get("bootsig"), pkg.get("receipt"), path="update")

    def program_download(self, image: bytes, receipt: bytes = None) -> dict:
        """Инженерная станция: загрузка программы в контроллер в обход загрузчика."""
        return self.install(image, None, receipt, path="ews")

    def mgmt(self, command: str, password: str) -> dict:
        """Канал управления: команды оператора с паролем (по умолчанию слабым)."""
        with self.lock:
            if password != self.config["mgmt_password"]:
                self._report("mgmt", "mgmt", False, "DENIED", extra={"command": command})
                return {"accepted": False, "reason": "DENIED"}
            if command == "factory-reset":
                if self.recipe_run is not None and self.recipe_run.status == "running":
                    self.recipe_run.abort("сброс к заводским настройкам")
                    self._recipe_end()
                self.controller = None
                (self.root / "flash" / "image.bin").unlink(missing_ok=True)
                (self.root / "flash" / "receipt.scr").unlink(missing_ok=True)
                self.state.update({"installed_digest": None, "installed_version": None, "product": None})
                wjson(self.root / "state.json", self.state)
            elif command == "stop":
                self.stopped = True
            elif command == "start":
                self.stopped = False
            else:
                return {"accepted": False, "reason": "UNKNOWN_COMMAND"}
            self._report("mgmt", "mgmt", True, "OK", extra={"command": command})
            return {"accepted": True, "reason": "OK"}

    # ---------------- рецепты ----------------
    def program_info(self) -> dict:
        """Манифест и программа установленного образа (для сервера агента и гейта рецептов)."""
        img = self.root / "flash" / "image.bin"
        if not img.exists():
            return {"manifest": None, "program": None, "sha256": None}
        data = img.read_bytes()
        manifest, program = read_image(data)
        return {"manifest": manifest, "program": program, "sha256": sha256_bytes(data)}

    def run_recipe(self, data: bytes, receipt: bytes = None, source: str = "agent") -> dict:
        """Запустить рецепт партии; на уровне 2 — только с квитанцией гейта рецептов."""
        with self.lock:
            digest = sha256_bytes(data)
            if self.controller is None or self.stopped:
                return self._recipe_reject("NO_PROGRAM", digest, source)
            if self.recipe_run is not None and self.recipe_run.status == "running":
                return self._recipe_reject("BUSY", digest, source)
            try:
                recipe = parse_recipe(data)
            except RecipeError:
                return self._recipe_reject("RECIPE_FORMAT", digest, source)
            name, rev = recipe["name"], recipe["revision"]
            svns = self.state.setdefault("recipe_svn", {})
            serial = None
            if self.level >= 2:
                if receipt is None:
                    return self._recipe_reject("NO_RECEIPT", digest, source, recipe)
                if not self.config.get("recipe_policy_digest"):
                    return self._recipe_reject("STATE", digest, source, recipe)
                reason = self._agent(data, receipt, policy_digest=self.config["recipe_policy_digest"],
                                     min_epoch=self.state.get("recipe_min_epoch", 1),
                                     installed_svn=int(svns.get(name, 0)))
                if reason != "ADMIT":
                    return self._recipe_reject(reason, digest, source, recipe)
                rp = parse_receipt(receipt)
                rev_svn, serial = rp.svn, rp.serial
                self.state["recipe_min_epoch"] = max(self.state.get("recipe_min_epoch", 1), rp.policy_epoch)
            else:
                rev_svn = rev
            svns[name] = max(int(svns.get(name, 0)), int(rev_svn))
            wjson(self.root / "state.json", self.state)
            self.recipe_run = RecipeRun(recipe, self.controller)
            self.recipe_meta = {"recipe": name, "revision": rev, "recipe_sha256": digest, "receipt_serial": serial,
                                "source": source}
            ev = self._report("recipe-start", "recipe", True, "OK", digest, dict(self.recipe_meta))
            return {"accepted": True, "reason": "OK", "event": ev}

    def _recipe_reject(self, reason: str, digest: str, source: str, recipe: dict = None) -> dict:
        extra = {"source": source, "recipe_sha256": digest}
        if recipe:
            extra.update({"recipe": recipe["name"], "revision": recipe["revision"]})
        ev = self._report("recipe-reject", "recipe", False, reason, digest, extra)
        return {"accepted": False, "reason": reason, "event": ev}

    def _recipe_end(self) -> None:
        st = self.recipe_run.state()
        self._report("recipe-end", "recipe", st["status"] == "completed", st["status"].upper(),
                     (self.recipe_meta or {}).get("recipe_sha256"),
                     {**(self.recipe_meta or {}), "status": st["status"], "quality": st["quality"],
                      "detail": st["reason"], "max_level": round(self.tank.max_level, 1),
                      "min_level": round(self.tank.min_level, 1), "alarms": self.tank.alarms()})

    def abort_recipe(self, reason: str = "прервано оператором") -> dict:
        with self.lock:
            if self.recipe_run is None or self.recipe_run.status != "running":
                return {"accepted": False, "reason": "NO_RECIPE"}
            self.recipe_run.abort(reason)
            self._recipe_end()
            return {"accepted": True, "reason": "OK"}

    def recipe_state(self):
        with self.lock:
            if self.recipe_run is None:
                return None
            return {**self.recipe_run.state(), **(self.recipe_meta or {})}

    def command(self, command: str, args: dict) -> dict:
        """Ручная команда (уровень доступа Manual сервера агента): режим насоса или запись уставки."""
        with self.lock:
            if self.controller is None:
                return {"accepted": False, "reason": "NO_PROGRAM"}
            args = args or {}
            try:
                if command == "pump" and args.get("mode") in PUMP_MODES:
                    self.controller.manual = PUMP_MODES[args["mode"]]
                    value = args["mode"]
                elif command == "set" and isinstance(args.get("setpoint"), str):
                    sp = self.controller.sp_defs.get(args["setpoint"])
                    if sp is None or "register" not in sp:
                        raise ValueError("нет такой уставки")
                    value = self.controller.write_register(sp["register"], int(round(float(args["value"]))))
                else:
                    raise ValueError("команды: pump {mode: on|off|auto}, set {setpoint, value}")
            except (ValueError, TypeError, KeyError) as e:
                self._report("command", "command", False, "BAD_COMMAND", extra={"command": command, "detail": str(e)})
                return {"accepted": False, "reason": "BAD_COMMAND", "detail": str(e)}
            self._report("command", "command", True, "OK", extra={"command": command, "args": args, "value": value})
            return {"accepted": True, "reason": "OK", "value": value}

    # ---------------- процесс ----------------
    def reset_process(self, level: float = 50.0) -> None:
        with self.lock:
            self.tank = Tank(level=level)
            if self.controller is not None:
                self.controller.pump = False

    def step(self, dt: float) -> None:
        with self.lock:
            active = self.controller is not None and not self.stopped
            if active and self.recipe_run is not None and self.recipe_run.status == "running":
                self.recipe_run.tick(self.tank.level, dt)
                if self.recipe_run.status != "running":
                    self._recipe_end()
            pump = self.controller.scan(self.tank.level) if active else False
            self.tank.step(pump, dt)

    def run_for(self, seconds: float, dt: float = 0.5, events=None) -> Tank:
        """Модельное время: прогнать процесс; events — список (секунда, функция)."""
        pending = sorted(events or [], key=lambda e: e[0])
        t = 0.0
        for _ in range(int(round(seconds / dt))):
            while pending and pending[0][0] <= t:
                pending.pop(0)[1]()
            self.step(dt)
            t += dt
        return self.tank

    @property
    def pump(self) -> bool:
        return bool(self.controller and not self.stopped and self.controller.pump)

    # ---------------- Modbus ----------------
    def mb_read(self, kind: str, addr: int, count: int) -> list:
        with self.lock:
            if kind == "input":
                v = self.state.get("installed_version") or "0.0.0"
                regs = [int(round(self.tank.level * 10)), self.level, *[int(x) for x in v.split(".")]]
                src = regs
            elif kind == "coils":
                src = [self.pump]
            elif kind == "discrete":
                src = [self.tank.overflowed, self.tank.high_alarm, self.tank.emptied,
                       bool(self.controller and self.controller.active_interlocks), self.controller is not None]
            else:
                if self.controller is None:
                    raise ModbusError(DEVICE_FAILURE)
                if addr + count > REGISTERS:
                    raise ModbusError(ILLEGAL_ADDRESS)
                return [self.controller.read_register(addr + i) for i in range(count)]
            if addr + count > len(src):
                raise ModbusError(ILLEGAL_ADDRESS)
            return list(src[addr:addr + count])

    def mb_write(self, addr: int, values: list) -> None:
        with self.lock:
            if self.controller is None:
                raise ModbusError(DEVICE_FAILURE)
            if addr + len(values) > REGISTERS:
                raise ModbusError(ILLEGAL_ADDRESS)
            for i, v in enumerate(values):
                self.controller.write_register(addr + i, v)

    # ---------------- состояние ----------------
    def status(self) -> dict:
        with self.lock:
            c = self.controller
            return {
                "name": self.config["name"], "device_class": self.config["device_class"], "level": self.level,
                "level_title": LEVELS[self.level],
                "installed": {"product": self.state.get("product"), "version": self.state.get("installed_version"),
                              "sha256": self.state.get("installed_digest"),
                              "svn": hex(self.state["installed_svn"]) if self.state.get("installed_svn") is not None else None,
                              "min_policy_epoch": self.state.get("min_policy_epoch")},
                "controller": "нет программы" if c is None else ("остановлен" if self.stopped else "работает"),
                "process": {"level": round(self.tank.level, 1), "pump": self.pump, "alarms": self.tank.alarms(),
                            "outcome": self.tank.outcome(), "max_level": round(self.tank.max_level, 1),
                            "interlocks": list(c.active_interlocks) if c else [],
                            "setpoints": dict(c.setpoints) if c else {},
                            "manual": None if c is None or c.manual is None else ("on" if c.manual else "off")},
                "recipe": None if self.recipe_run is None else {**self.recipe_run.state(), **(self.recipe_meta or {})},
                "instance": self.config["instance"],
                "last_event": self.last,
            }


# ---------------- живой стенд: HTTP API, Modbus, процесс в реальном времени ----------------
class _Api(BaseHTTPRequestHandler):
    server_version = "cpslab-device/0.1"

    def _send(self, code: int, obj) -> None:
        data = json.dumps(obj, ensure_ascii=False, indent=1).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if n > 4 << 20:
            raise ValueError("слишком большой запрос")
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):  # noqa: N802
        dev = self.server.device
        if self.path == "/api/status":
            return self._send(200, dev.status())
        if self.path == "/api/reports":
            return self._send(200, dev.reports()[-50:])
        if self.path == "/api/program":
            return self._send(200, dev.program_info())
        if self.path == "/api/recipe":
            return self._send(200, {"recipe": dev.recipe_state()})
        self._send(404, {"error": "нет такого ресурса"})

    def do_POST(self):  # noqa: N802
        dev, srv = self.server.device, self.server
        try:
            body = self._body()
            if self.path == "/api/update":
                return self._send(200, dev.check_update(srv.transport))
            if self.path == "/api/program":
                image = base64.b64decode(body["image"])
                receipt = base64.b64decode(body["receipt"]) if body.get("receipt") else None
                return self._send(200, dev.program_download(image, receipt))
            if self.path == "/api/mgmt":
                return self._send(200, dev.mgmt(str(body.get("command")), str(body.get("password"))))
            if self.path == "/api/process/reset":
                dev.reset_process(float(body.get("level", 50.0)))
                return self._send(200, {"ok": True})
            if self.path == "/api/recipe/run":
                data = base64.b64decode(body["recipe"])
                receipt = base64.b64decode(body["receipt"]) if body.get("receipt") else None
                return self._send(200, dev.run_recipe(data, receipt, str(body.get("source") or "agent")))
            if self.path == "/api/recipe/abort":
                return self._send(200, dev.abort_recipe(str(body.get("reason") or "прервано")))
            if self.path == "/api/command":
                return self._send(200, dev.command(str(body.get("command")), body.get("args") or {}))
        except (ValueError, KeyError, TypeError) as e:
            return self._send(400, {"error": str(e)})
        except ToolError as e:
            return self._send(500, {"error": str(e)})
        self._send(404, {"error": "нет такого ресурса"})

    def log_message(self, fmt, *args):
        pass


def serve(root: Path, *, transport, http_port: int = 8080, modbus_port: int = 5020, speed: float = 5.0,
          dt: float = 0.5, host: str = "0.0.0.0", background: bool = False):
    """Контроллер с HTTP API, Modbus/TCP и процессом в реальном времени (ускорение speed).
    background=True — запустить в фоновых потоках и вернуть (HTTP-сервер, Modbus-сервер, событие остановки)."""
    from .modbus import ModbusServer
    dev = Device(root)
    mb = ModbusServer(dev, host, modbus_port)
    mb.start()
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            dev.step(dt * speed)
            time.sleep(dt)

    threading.Thread(target=loop, name="process", daemon=True).start()
    srv = ThreadingHTTPServer((host, http_port), _Api)
    srv.device, srv.transport = dev, transport
    if background:
        threading.Thread(target=srv.serve_forever, name="device-http", daemon=True).start()
        return srv, mb, stop
    try:
        srv.serve_forever()
    finally:
        stop.set()
