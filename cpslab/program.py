"""Программа контроллера: описание логики, проверка формата и исполнение цикла сканирования.

Программа — JSON-документ формата cpslab-program/1. Логика задаётся правилами вида
«если <операнд> <сравнение> <операнд>, то установить <выход или уставку>»; блокировки (ПАЗ)
выполняются после правил и имеют приоритет. Интерпретатор не исполняет произвольный код:
допустимы только переменные, числа и шесть операций сравнения.

Переменные: level — уровень в резервуаре, %; имена уставок; hrN — значение регистра хранения N,
не описанного как уставка. Цели установки: pump (насос, true/false) и уставки.

Карта Modbus задаётся средой исполнения (см. device.py): уставка с полем register доступна для
чтения и записи как регистр хранения с этим номером. Если у уставки заданы min и max, записанное
значение ограничивается ими; без них принимается любое значение.
"""
from __future__ import annotations

import operator
import re

FORMAT = "cpslab-program/1"
OPS = {"<": operator.lt, "<=": operator.le, ">": operator.gt, ">=": operator.ge, "==": operator.eq,
       "!=": operator.ne}
OUTPUTS = ("pump",)
SENSORS = ("level",)
REGISTERS = 200                      # регистры хранения 0..199
_NAME = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_HR = re.compile(r"^hr(\d{1,3})$")


class ProgramError(ValueError):
    """Программа не соответствует формату."""


def _number(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def validate(prog) -> dict:
    """Проверить программу и вернуть её без изменений. Любое отклонение — ProgramError."""
    if not isinstance(prog, dict):
        raise ProgramError("программа должна быть объектом JSON")
    allowed = {"format", "name", "title", "setpoints", "rules", "interlocks"}
    extra = set(prog) - allowed
    if extra:
        raise ProgramError(f"неизвестные поля программы: {', '.join(sorted(extra))}")
    if prog.get("format") != FORMAT:
        raise ProgramError(f"формат программы {prog.get('format')!r}, ожидался {FORMAT}")
    if not isinstance(prog.get("name"), str) or not prog["name"]:
        raise ProgramError("нет имени программы")
    sps = prog.get("setpoints", {})
    if not isinstance(sps, dict):
        raise ProgramError("setpoints должен быть объектом")
    regs = set()
    for name, sp in sps.items():
        if not _NAME.match(name) or name in OUTPUTS or name in SENSORS or _HR.match(name):
            raise ProgramError(f"недопустимое имя уставки {name!r}")
        if not isinstance(sp, dict) or set(sp) - {"default", "register", "min", "max", "title"}:
            raise ProgramError(f"уставка {name}: неизвестные поля")
        if not _number(sp.get("default")):
            raise ProgramError(f"уставка {name}: нет значения по умолчанию")
        for k in ("min", "max"):
            if k in sp and not _number(sp[k]):
                raise ProgramError(f"уставка {name}: {k} должно быть числом")
        if "min" in sp and "max" in sp and sp["min"] > sp["max"]:
            raise ProgramError(f"уставка {name}: min больше max")
        if ("min" in sp and sp["default"] < sp["min"]) or ("max" in sp and sp["default"] > sp["max"]):
            raise ProgramError(f"уставка {name}: значение по умолчанию вне ограничений")
        if "register" in sp:
            reg = sp["register"]
            if not isinstance(reg, int) or isinstance(reg, bool) or not 0 <= reg < REGISTERS:
                raise ProgramError(f"уставка {name}: номер регистра вне 0..{REGISTERS - 1}")
            if reg in regs:
                raise ProgramError(f"уставка {name}: регистр {reg} занят другой уставкой")
            regs.add(reg)
    for section in ("rules", "interlocks"):
        items = prog.get(section, [])
        if not isinstance(items, list):
            raise ProgramError(f"{section} должен быть списком")
        for i, rule in enumerate(items, 1):
            _validate_rule(rule, sps, f"{section}[{i}]")
    return prog


def _validate_operand(x, sps, where):
    if _number(x):
        return
    if isinstance(x, str) and (x in SENSORS or x in sps):
        return
    if isinstance(x, str) and _HR.match(x) and int(_HR.match(x).group(1)) < REGISTERS:
        return
    raise ProgramError(f"{where}: неизвестный операнд {x!r}")


def _validate_rule(rule, sps, where):
    if not isinstance(rule, dict) or set(rule) - {"when", "set", "name"}:
        raise ProgramError(f"{where}: правило должно содержать when и set")
    when = rule.get("when")
    if not isinstance(when, list) or len(when) != 3 or when[1] not in OPS:
        raise ProgramError(f"{where}: when должен иметь вид [операнд, сравнение, операнд]")
    _validate_operand(when[0], sps, where)
    _validate_operand(when[2], sps, where)
    sets = rule.get("set")
    if not isinstance(sets, dict) or not sets:
        raise ProgramError(f"{where}: пустое set")
    for target, value in sets.items():
        if target in OUTPUTS:
            if not isinstance(value, bool):
                raise ProgramError(f"{where}: выход {target} принимает true или false")
        elif target in sps:
            if not _number(value):
                raise ProgramError(f"{where}: уставке {target} можно присвоить только число")
        else:
            raise ProgramError(f"{where}: неизвестная цель {target!r}")


class Controller:
    """Исполнение программы: уставки, регистры хранения, выход насоса и активные блокировки."""

    def __init__(self, program: dict):
        self.program = validate(program)
        self.sp_defs = program.get("setpoints", {})
        self.setpoints = {n: float(sp["default"]) for n, sp in self.sp_defs.items()}
        self.reg_to_sp = {sp["register"]: n for n, sp in self.sp_defs.items() if "register" in sp}
        self.raw = {}
        self.pump = False
        self.manual = None                  # ручной режим насоса: True/False от рецепта или команды, None — правила
        self.active_interlocks: list = []

    # --- регистры хранения (Modbus) ---
    def read_register(self, reg: int) -> int:
        name = self.reg_to_sp.get(reg)
        if name is not None:
            return int(round(self.setpoints[name])) & 0xFFFF
        return self.raw.get(reg, 0)

    def write_register(self, reg: int, value: int) -> int:
        """Записать регистр; для уставки значение ограничивается min/max, если они заданы."""
        name = self.reg_to_sp.get(reg)
        if name is None:
            self.raw[reg] = value & 0xFFFF
            return self.raw[reg]
        sp = self.sp_defs[name]
        v = float(value)
        if "min" in sp:
            v = max(v, float(sp["min"]))
        if "max" in sp:
            v = min(v, float(sp["max"]))
        self.setpoints[name] = v
        return int(round(v))

    # --- цикл сканирования ---
    def _value(self, x, level):
        if _number(x):
            return float(x)
        if x == "level":
            return level
        if x in self.setpoints:
            return self.setpoints[x]
        return float(self.raw.get(int(_HR.match(x).group(1)), 0))

    def _apply(self, sets):
        for target, value in sets.items():
            if target == "pump":
                self.pump = value
            else:
                self.setpoints[target] = float(value)

    def scan(self, level: float) -> bool:
        """Цикл сканирования: правила (или ручной режим насоса), затем блокировки ПАЗ с приоритетом."""
        if self.manual is None:
            for rule in self.program.get("rules", []):
                a, op, b = rule["when"]
                if OPS[op](self._value(a, level), self._value(b, level)):
                    self._apply(rule["set"])
        else:
            self.pump = bool(self.manual)
        self.active_interlocks = []
        for rule in self.program.get("interlocks", []):
            a, op, b = rule["when"]
            if OPS[op](self._value(a, level), self._value(b, level)):
                self._apply(rule["set"])
                self.active_interlocks.append(rule.get("name", "блокировка"))
        return self.pump


def listing(prog: dict) -> str:
    """Человекочитаемое представление программы — так её показывает инженерная станция."""
    title = prog.get("title")
    L = [f"Программа {prog.get('name')}" + (f" ({title})" if title else "")]
    sps = prog.get("setpoints", {})
    if sps:
        L.append("Уставки:")
        for n, sp in sps.items():
            lim = (f", ограничения {sp.get('min', '—')}…{sp.get('max', '—')}"
                   if "min" in sp or "max" in sp else ", без ограничений")
            reg = f", регистр {sp['register']}" if "register" in sp else ""
            L.append(f"  {n} = {sp['default']}{reg}{lim}")
    for title, section in (("Правила:", "rules"), ("Блокировки:", "interlocks")):
        items = prog.get(section, [])
        if items:
            L.append(title)
            for r in items:
                a, op, b = r["when"]
                sets = ", ".join(f"{k} := {str(v).lower() if isinstance(v, bool) else v}"
                                 for k, v in r["set"].items())
                name = f"[{r['name']}] " if r.get("name") else ""
                L.append(f"  {name}если {a} {op} {b} то {sets}")
    return "\n".join(L)
