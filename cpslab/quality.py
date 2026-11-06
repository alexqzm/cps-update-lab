"""Проверки поставщика до выпуска: статический анализ программы и функциональные испытания.

Статический анализ (свидетельство s13) ищет в программе опасные конструкции. Его аттестация
подтверждает, что анализ выполнен (status = COMPLETED), а не что находок нет: так же устроено
свидетельство s13 в профиле SCII. Функциональные испытания (s43) прогоняют программу на модели
процесса изделия по набору случаев из исходного кода поставщика и дают PASSED или FAILED.
"""
from __future__ import annotations

from .plant import Tank, simulate
from .program import Controller, _HR, validate

TOOL = {"name": "cpslab-lint", "version": "0.1.0"}


def lint(prog: dict) -> dict:
    validate(prog)
    findings = []

    def add(severity, rule, message):
        findings.append({"severity": severity, "rule": rule, "message": message})

    for name, sp in prog.get("setpoints", {}).items():
        if "register" in sp and ("min" not in sp or "max" not in sp):
            add("high", "CPS001", f"уставка «{name}» записывается по Modbus без ограничений min/max")
    level_interlocks = [r for r in prog.get("interlocks", [])
                        if "level" in (r["when"][0], r["when"][2]) and r["set"].get("pump") is False]
    if not level_interlocks:
        add("high", "CPS002", "нет блокировки насоса по верхнему уровню")
    for section in ("rules", "interlocks"):
        for i, r in enumerate(prog.get(section, []), 1):
            for x in (r["when"][0], r["when"][2]):
                if isinstance(x, str) and _HR.match(x):
                    add("high", "CPS003", f"{section}[{i}]: условие зависит от регистра {x}, не описанного как уставка")
            for target in r["set"]:
                if target in prog.get("setpoints", {}):
                    add("medium", "CPS004", f"{section}[{i}]: логика меняет уставку «{target}» во время работы")
    by = {}
    for f in findings:
        by[f["severity"]] = by.get(f["severity"], 0) + 1
    return {"tool": TOOL, "status": "COMPLETED", "findings_total": len(findings), "findings_by_severity": by,
            "findings": findings}


TESTS_FORMAT = "cpslab-tests/1"


def functional_tests(prog: dict, suite: dict) -> dict:
    """Прогнать программу на модели процесса изделия по набору случаев поставщика (products/<изделие>/tests.json)."""
    if suite.get("format") != TESTS_FORMAT:
        raise ValueError(f"набор испытаний: формат {suite.get('format')!r}, ожидался {TESTS_FORMAT}")
    proc = suite["process"]
    results = []
    for c in suite["cases"]:
        ctl = Controller(prog)
        if c.get("write"):
            ctl.write_register(*c["write"])
        tank = simulate(ctl, Tank(level=c["start"], q_in=proc["q_in"], q_out=c["q_out"], capacity=proc["capacity"],
                                  low_limit=proc["low_limit"], alarm_high=proc["alarm_high"]), suite["seconds"])
        ok = not tank.overflowed and not tank.emptied
        if "max_below" in c:
            ok = ok and tank.max_level < c["max_below"]
        results.append({"case": c["case"], "title": c["title"], "ok": ok, "max_level": round(tank.max_level, 2),
                        "min_level": round(tank.min_level, 2)})
    return {"result": "PASSED" if all(r["ok"] for r in results) else "FAILED", "cases": results,
            "passedTests": [r["case"] for r in results if r["ok"]],
            "failedTests": [r["case"] for r in results if not r["ok"]]}
