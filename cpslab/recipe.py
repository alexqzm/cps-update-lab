"""Рецепты партии: формат cpslab-recipe/1, статическая проверка, исполнение и пробный прогон.

Рецепт — последовательность шагов поверх программы контроллера, как рецепт партии в АСУ ТП (ISA-88)
или рецепт напыления в системе управления установкой. Программа контроллера (образ) задаёт правила и
блокировки ПАЗ, рецепт меняет уставки, переводит насос в ручной режим и ждёт условий процесса.
Блокировки ПАЗ программы действуют и при ручном режиме.

Шаги:
  {"op": "set",   "setpoint": "high", "value": 78}           записать уставку (как запись регистра Modbus)
  {"op": "pump",  "mode": "on" | "off" | "auto"}              ручной режим насоса или возврат к правилам
  {"op": "wait",  "until": ["level", ">=", 75], "timeout": 60}  ждать условия, по истечении — отказ партии
  {"op": "hold",  "seconds": 120}                            выдержка
  {"op": "check", "that": ["level", "<=", 80], "name": "…"}  проверка качества: не выполнена — отказ партии

Операнды условий: level (уровень, %), имена уставок программы и числа. По окончании рецепта или при
отказе насос возвращается к правилам программы.

Исполнитель на контроллере разбирает рецепт минимально (формат и список шагов): запись в
неописанный регистр hrN он выполняет, как запись регистра по Modbus. Статическая проверка
(validate) запрещает всё, что не описано программой: неизвестные уставки, регистры hrN, значения вне
ограничений, — и работает по принципу «запрещено всё, что не разрешено».

Пробный прогон (dry_run) исполняет рецепт на модели объекта — двойнике — и проверяет условия
безопасности объекта и условия приёмки из технологического задания.
"""
from __future__ import annotations

import json
import re

from .plant import HIGH_ALARM, LOW_LIMIT, Tank
from .program import OPS, Controller, ProgramError
from .util import canonical_json, sha256_bytes

FORMAT = "cpslab-recipe/1"
NAME = re.compile(r"^[a-z][a-z0-9-]{0,39}$")
_HR = re.compile(r"^hr(\d{1,3})$")
STEP_OPS = ("set", "pump", "wait", "hold", "check")
PUMP_MODES = {"on": True, "off": False, "auto": None}
MAX_STEPS = 100
MAX_SECONDS = 3600.0
TOP_FIELDS = {"format", "name", "revision", "title", "target", "work_order", "steps"}
DEFAULT_PLANT = {"q_in": 2.0, "q_out": 1.0, "capacity": 100.0, "low_limit": LOW_LIMIT, "alarm_high": HIGH_ALARM}


class RecipeError(ValueError):
    """Рецепт не разбирается исполнителем."""


def _number(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def canonical(recipe: dict) -> bytes:
    """Байты рецепта для дайджеста и квитанции: JSON с упорядоченными ключами."""
    return canonical_json(recipe)


def digest(recipe: dict) -> str:
    return sha256_bytes(canonical(recipe))


def parse(data: bytes) -> dict:
    """Минимальный разбор на исполнителе: JSON, формат, имя, ревизия и список шагов."""
    try:
        r = json.loads(data.decode("utf-8") if isinstance(data, (bytes, bytearray)) else data)
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise RecipeError(f"рецепт не разбирается: {e}") from e
    if not isinstance(r, dict) or r.get("format") != FORMAT:
        raise RecipeError(f"ожидался формат {FORMAT}")
    if not isinstance(r.get("name"), str) or not NAME.match(r["name"]):
        raise RecipeError("недопустимое имя рецепта")
    if not isinstance(r.get("revision"), int) or isinstance(r.get("revision"), bool) or not 1 <= r["revision"] < 2 ** 32:
        raise RecipeError("ревизия рецепта должна быть целым числом от 1")
    if not isinstance(r.get("steps"), list) or not r["steps"] or len(r["steps"]) > MAX_STEPS:
        raise RecipeError(f"рецепт должен содержать от 1 до {MAX_STEPS} шагов")
    if not all(isinstance(s, dict) and s.get("op") in STEP_OPS for s in r["steps"]):
        raise RecipeError(f"шаг рецепта должен быть объектом с op из {', '.join(STEP_OPS)}")
    return r


# ---------------- статическая проверка ----------------
def _cond_errors(cond, program, where) -> list:
    if not isinstance(cond, list) or len(cond) != 3 or cond[1] not in OPS:
        return [f"{where}: условие должно иметь вид [операнд, сравнение, операнд]"]
    out = []
    sps = (program or {}).get("setpoints", {})
    for x in (cond[0], cond[2]):
        if _number(x) or x == "level" or (isinstance(x, str) and x in sps):
            continue
        out.append(f"{where}: неизвестный операнд {x!r}")
    return out


def validate(recipe, program: dict = None) -> dict:
    """Проверка рецепта против программы контроллера. Любая ошибка делает рецепт недопустимым."""
    errors, warnings = [], []

    def err(step, msg):
        errors.append({"severity": "error", "step": step, "message": msg})

    def warn(step, msg):
        warnings.append({"severity": "warning", "step": step, "message": msg})

    if not isinstance(recipe, dict):
        err(None, "рецепт должен быть объектом JSON")
        return {"valid": False, "findings": errors, "summary": {}}
    extra = set(recipe) - TOP_FIELDS
    if extra:
        err(None, f"неизвестные поля рецепта: {', '.join(sorted(extra))}")
    if recipe.get("format") != FORMAT:
        err(None, f"формат {recipe.get('format')!r}, ожидался {FORMAT}")
    if not isinstance(recipe.get("name"), str) or not NAME.match(recipe.get("name") or ""):
        err(None, "имя рецепта: строчные латинские буквы, цифры и дефис, до 40 символов")
    rev = recipe.get("revision")
    if not isinstance(rev, int) or isinstance(rev, bool) or not 1 <= rev < 2 ** 32:
        err(None, "ревизия: целое число от 1")
    tgt = recipe.get("target")
    if not isinstance(tgt, dict) or not isinstance(tgt.get("product"), str) or not isinstance(tgt.get("device_class"), int):
        err(None, "target: нужны product и device_class")
    elif "program_min" in tgt and not re.match(r"^\d+\.\d+\.\d+$", str(tgt["program_min"])):
        err(None, "target.program_min: версия вида 1.1.0")
    if "work_order" in recipe and not isinstance(recipe["work_order"], str):
        err(None, "work_order: идентификатор технологического задания строкой")
    steps = recipe.get("steps")
    if not isinstance(steps, list) or not steps or len(steps) > MAX_STEPS:
        err(None, f"steps: от 1 до {MAX_STEPS} шагов")
        steps = []
    sps = (program or {}).get("setpoints", {})
    hold = timeouts = 0.0
    manual, setpoints, checks = False, {}, 0
    pump_state = None
    for i, st in enumerate(steps, 1):
        w = f"шаг {i}"
        if not isinstance(st, dict) or st.get("op") not in STEP_OPS:
            err(i, f"{w}: op из {', '.join(STEP_OPS)}")
            continue
        op = st["op"]
        allowed = {"set": {"op", "setpoint", "value"}, "pump": {"op", "mode"}, "wait": {"op", "until", "timeout"},
                   "hold": {"op", "seconds"}, "check": {"op", "that", "name"}}[op]
        if set(st) - allowed:
            err(i, f"{w}: неизвестные поля {', '.join(sorted(set(st) - allowed))}")
        if op == "set":
            name, val = st.get("setpoint"), st.get("value")
            if not _number(val):
                err(i, f"{w}: значение уставки — число")
            if not isinstance(name, str):
                err(i, f"{w}: нет имени уставки")
            elif _HR.match(name):
                err(i, f"{w}: запись в регистр {name} не описана программой (запрещено)")
            elif program is not None and name not in sps:
                err(i, f"{w}: в программе нет уставки {name!r}")
            elif program is not None and "register" not in sps[name]:
                err(i, f"{w}: уставка {name} не доступна для записи")
            elif program is not None and _number(val):
                sp = sps[name]
                if ("min" in sp and val < sp["min"]) or ("max" in sp and val > sp["max"]):
                    err(i, f"{w}: {name} = {val} вне ограничений программы {sp.get('min', '—')}…{sp.get('max', '—')}")
                setpoints[name] = val
            elif _number(val):
                setpoints[name] = val
        elif op == "pump":
            if st.get("mode") not in PUMP_MODES:
                err(i, f"{w}: mode из on, off, auto")
            else:
                pump_state = PUMP_MODES[st["mode"]]
                manual = manual or pump_state is not None
        elif op == "wait":
            errors.extend({"severity": "error", "step": i, "message": m}
                          for m in _cond_errors(st.get("until"), program, w))
            t = st.get("timeout")
            if not _number(t) or not 0 < t <= MAX_SECONDS:
                err(i, f"{w}: timeout от 0 до {MAX_SECONDS:g} с")
            else:
                timeouts += t
        elif op == "hold":
            s = st.get("seconds")
            if not _number(s) or not 0 < s <= MAX_SECONDS:
                err(i, f"{w}: seconds от 0 до {MAX_SECONDS:g} с")
            else:
                hold += s
        elif op == "check":
            checks += 1
            errors.extend({"severity": "error", "step": i, "message": m}
                          for m in _cond_errors(st.get("that"), program, w))
    if hold + timeouts > MAX_SECONDS:
        err(None, f"наибольшая длительность {hold + timeouts:g} с больше {MAX_SECONDS:g} с")
    if manual:
        warn(None, "ручной режим насоса: правила программы не действуют, действуют только блокировки ПАЗ")
    if pump_state is not None:
        warn(None, "рецепт заканчивается в ручном режиме насоса; исполнитель вернёт насос к правилам")
    if program is None:
        warn(None, "программа контроллера не задана: уставки и ограничения не проверены")
    summary = {"steps": len(steps), "hold_seconds": hold, "max_duration_seconds": hold + timeouts,
               "setpoints": setpoints, "manual_pump": manual, "checks": checks}
    return {"valid": not errors, "findings": errors + warnings, "summary": summary}


# ---------------- исполнение ----------------
class RecipeRun:
    """Исполнение рецепта на контроллере: вызывается перед каждым циклом сканирования."""

    def __init__(self, recipe: dict, controller: Controller):
        self.recipe = recipe
        self.ctl = controller
        self.steps = recipe["steps"]
        self.i = 0
        self.elapsed = 0.0
        self.t = 0.0
        self.status = "running"
        self.reason = None
        self.quality = None
        self.writes = []

    def _value(self, x, level):
        if _number(x):
            return float(x)
        if x == "level":
            return level
        if isinstance(x, str) and x in self.ctl.setpoints:
            return self.ctl.setpoints[x]
        raise RecipeError(f"неизвестный операнд {x!r}")

    def _cond(self, cond, level) -> bool:
        a, op, b = cond
        return OPS[op](self._value(a, level), self._value(b, level))

    def _set(self, st) -> None:
        name, val = st.get("setpoint"), st.get("value")
        defs = self.ctl.sp_defs
        if isinstance(name, str) and name in defs and "register" in defs[name]:
            self.writes.append((name, self.ctl.write_register(defs[name]["register"], int(round(float(val))))))
        elif isinstance(name, str) and _HR.match(name) and int(_HR.match(name).group(1)) < 200:
            self.writes.append((name, self.ctl.write_register(int(_HR.match(name).group(1)), int(round(float(val))))))
        else:
            raise RecipeError(f"нет уставки {name!r}")

    def _finish(self, status: str, reason: str = None) -> None:
        self.status, self.reason = status, reason
        self.quality = "ok" if status == "completed" else "out_of_spec"
        self.ctl.manual = None

    def abort(self, reason: str = "прервано") -> None:
        if self.status == "running":
            self._finish("aborted", reason)

    def tick(self, level: float, dt: float) -> None:
        if self.status != "running":
            return
        try:
            while self.i < len(self.steps):
                st = self.steps[self.i]
                op = st["op"]
                if op == "set":
                    self._set(st)
                elif op == "pump":
                    if st.get("mode") not in PUMP_MODES:
                        raise RecipeError("неизвестный режим насоса")
                    self.ctl.manual = PUMP_MODES[st["mode"]]
                elif op == "check":
                    if not self._cond(st["that"], level):
                        self._finish("failed", f"шаг {self.i + 1}: не выполнена проверка «{st.get('name') or st['that']}»")
                        return
                elif op == "wait":
                    if not self._cond(st["until"], level):
                        self.elapsed += dt
                        if self.elapsed > float(st["timeout"]) + 1e-9:
                            self._finish("failed", f"шаг {self.i + 1}: условие {st['until']} не выполнено за "
                                                   f"{float(st['timeout']):g} с")
                        self.t += dt
                        return
                elif op == "hold":
                    self.elapsed += dt
                    self.t += dt
                    if self.elapsed >= float(st["seconds"]) - 1e-9:
                        self.i += 1
                        self.elapsed = 0.0
                    return
                self.i += 1
                self.elapsed = 0.0
            self._finish("completed")
        except (RecipeError, KeyError, TypeError, ValueError, ProgramError) as e:
            self._finish("failed", f"шаг {self.i + 1}: {e}")

    def state(self) -> dict:
        return {"name": self.recipe.get("name"), "revision": self.recipe.get("revision"), "status": self.status,
                "step": min(self.i + 1, len(self.steps)), "steps": len(self.steps), "reason": self.reason,
                "quality": self.quality, "time": round(self.t, 1)}


# ---------------- пробный прогон на двойнике ----------------
def _acceptance(cond: dict, trace: list, dt: float, end_t: float) -> dict:
    kind = cond.get("kind")
    if kind == "reach":
        lo, hi = cond["band"]
        ok = any(t <= cond["within"] + 1e-9 and lo <= lv <= hi for t, lv in trace)
        return {"kind": kind, "ok": ok, "text": f"уровень {lo}…{hi} % не позже {cond['within']:g} с"}
    if kind == "hold":
        lo, hi = cond["band"]
        best = run = 0.0
        for _t, lv in trace:
            run = run + dt if lo <= lv <= hi else 0.0
            best = max(best, run)
        ok = best + 1e-9 >= cond["seconds"]
        return {"kind": kind, "ok": ok, "text": f"уровень {lo}…{hi} % не менее {cond['seconds']:g} с подряд",
                "observed_seconds": round(best, 1)}
    if kind == "range":
        within = [lv for t, lv in trace if t <= end_t + 1e-9] or [lv for _t, lv in trace]
        ok = min(within) >= cond.get("min", float("-inf")) and max(within) <= cond.get("max", float("inf"))
        return {"kind": kind, "ok": ok, "text": f"уровень в пределах {cond.get('min', '—')}…{cond.get('max', '—')} % "
                                              f"до конца рецепта", "observed": [round(min(within), 1),
                                                                                 round(max(within), 1)]}
    if kind == "final":
        lo, hi = cond["band"]
        lv = next((lv for t, lv in reversed(trace) if t <= end_t + 1e-9), trace[-1][1])
        return {"kind": kind, "ok": lo <= lv <= hi, "text": f"уровень в конце рецепта {lo}…{hi} %",
                "observed": round(lv, 1)}
    return {"kind": kind, "ok": False, "text": f"неизвестное условие приёмки {kind!r}"}


def dry_run(recipe: dict, program: dict, start_level: float, plant: dict = None, acceptance: list = None,
            tail: float = 60.0, dt: float = 0.5) -> dict:
    """Исполнить рецепт на двойнике: модель резервуара с параметрами plant и программа контроллера.

    ok — рецепт завершился, безопасность объекта не нарушена (нет перелива, опустошения, аварийно
    высокого уровня) и выполнены все условия приёмки. После окончания рецепта процесс моделируется
    ещё tail секунд в автоматическом режиме."""
    plant = dict(DEFAULT_PLANT, **(plant or {}))
    tank = Tank(level=float(start_level), q_in=plant["q_in"], q_out=plant["q_out"], capacity=plant["capacity"],
                low_limit=plant["low_limit"], alarm_high=plant["alarm_high"])
    ctl = Controller(program)
    rr = RecipeRun(recipe, ctl)
    trace, t, end_t = [(0.0, tank.level)], 0.0, None
    limit = MAX_SECONDS + tail
    while t < limit:
        if rr.status == "running":
            rr.tick(tank.level, dt)
        if rr.status != "running" and end_t is None:
            end_t = t
        tank.step(ctl.scan(tank.level), dt)
        t += dt
        trace.append((t, tank.level))
        if end_t is not None and t >= end_t + tail - 1e-9:
            break
    end_t = t if end_t is None else end_t
    safe = tank.outcome() == "normal" and tank.max_level < plant["alarm_high"]
    acc = [_acceptance(c, trace, dt, end_t) for c in (acceptance or [])]
    completed = rr.status == "completed"
    problems = []
    if not completed:
        problems.append(f"рецепт не завершён: {rr.reason}")
    if tank.overflowed:
        problems.append("перелив")
    if tank.emptied:
        problems.append("резервуар опустошён")
    if tank.max_level >= plant["alarm_high"] and not tank.overflowed:
        problems.append("аварийно высокий уровень")
    problems += [f"не выполнено условие приёмки: {a['text']}" for a in acc if not a["ok"]]
    return {"ok": completed and safe and all(a["ok"] for a in acc), "completed": completed, "safe": safe,
            "outcome": tank.outcome(), "recipe": rr.state(), "duration_s": round(end_t, 1),
            "max_level": round(tank.max_level, 1), "min_level": round(tank.min_level, 1),
            "acceptance": acc, "problems": problems, "plant": plant, "start_level": float(start_level)}


def version_tuple(v: str) -> tuple:
    return tuple(int(x) for x in str(v).split("."))


__all__ = ["FORMAT", "RecipeError", "RecipeRun", "canonical", "digest", "parse", "validate", "dry_run",
           "DEFAULT_PLANT", "version_tuple"]
