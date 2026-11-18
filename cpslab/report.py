"""Таблица результатов стенда (docs/results.md): исходы сценариев на трёх уровнях защиты,
решения гейта по выпускам и сопоставление сценариев с атласом, ATT&CK и мерами ОПО."""
from __future__ import annotations

import json

from . import __version__
from .device import LEVELS, REASON_RU
from .scenarios import RELEASES, catalog
from .vendor import release_info

PROCESS_RU = {"normal": "норма", "overflow": "перелив", "empty": "опустошение"}
ATLAS = "https://github.com/alexqzm/cps-supply-chain-atlas/blob/main/data/records/{}.yaml"


def _f3(x: float) -> str:
    return f"{x:.3f}".replace(".", ",")


def _cell(o) -> str:
    act = "принято" if o.accepted else f"отказ: {o.reason}"
    proc = PROCESS_RU[o.process]
    alert = ", тревога монитора" if o.alert else ""
    return f"{act}; {proc}{alert}"


README_BEGIN, README_END = "<!-- results:begin -->", "<!-- results:end -->"
GATE_NOTE = ("Столбец «Гейт» — решение гейта по выпуску, который участвует в сценарии. В A1, A4 и A5 в канале "
             "обновления лежат подпись и квитанция допущенного подлинного выпуска; «—» — гейт не участвует.")


def outcomes_table(outs) -> list:
    """Таблица исходов: сценарий × уровень защиты контроллера, плюс решение гейта."""
    by = {(o.scenario, o.level): o for o in outs}
    L = ["| Сценарий | " + " | ".join(f"L{lv}: {t}" for lv, t in LEVELS.items()) + " | Гейт |",
         "|---|---|---|---|---|"]
    for sid, sc in catalog().items():
        cells = [_cell(by[(sid, lv)]) for lv in LEVELS]
        gate = by[(sid, 0)].gate
        g = "—" if gate is None else {0: "допуск", 10: "рассмотрение", 20: "запрос", 30: "отказ"}[gate]
        L.append(f"| {sid} {sc['title']} | " + " | ".join(cells) + f" | {g} |")
    return L


def readme_with_table(readme: str, outs) -> str:
    """Заменить таблицу исходов между метками README_BEGIN и README_END."""
    head, sep, rest = readme.partition(README_BEGIN)
    _old, sep2, tail = rest.partition(README_END)
    if not sep or not sep2:
        raise ValueError(f"в README нет меток {README_BEGIN} … {README_END}")
    return head + README_BEGIN + "\n" + "\n".join(outcomes_table(outs)) + "\n" + README_END + tail


def matrix_markdown(lab, outs) -> str:
    cat = catalog()
    L = ["# Результаты сценариев", "",
         "Файл и таблица исходов в README создаются командой "
         f"`cpslab scenario matrix --md docs/results.md --readme README.md` (cpslab {__version__}); "
         "CI проверяет, что они совпадают с прогоном. Процесс — 300 с модельного времени после действия нарушителя.",
         "",
         "## Исходы на трёх уровнях защиты контроллера", "", *outcomes_table(outs), "", GATE_NOTE]
    seen = {o.reason for o in outs if not o.accepted}
    L += ["", "Коды отказа: " + "; ".join(f"`{k}` — {v}" for k, v in REASON_RU.items() if k in seen) + ".", ""]
    L += ["## Решения гейта по выпускам", "",
          "| Выпуск | SHA-256 образа | Решение | R_P^min | R_P^max | Не подтверждены |", "|---|---|---|---|---|---|"]
    for key in RELEASES:
        a = lab.admission(key)
        rel = release_info(lab.release(key))
        if a["run"] is None:                    # гейт не дошёл до расчёта (например, тег не проверился)
            L.append(f"| {key} | `{rel['sha256'][:16]}` | {a['decision']} | — | — | {a.get('error') or '—'} |")
            continue
        rep = json.loads((lab.home / a["run"] / "report.json").read_text(encoding="utf-8"))
        bad = ", ".join(f"{s} {st}" for s, st in rep["states"].items() if st != "P")
        L.append(f"| {key} | `{rel['sha256'][:16]}` | {a['decision']} | {_f3(a['R_min'])} | {_f3(a['R_max'])} | {bad} |")
    L += ["", "## Сопоставление сценариев", "",
          "Сопоставления с ATT&CK (v20) и мерами ОПО приказа ФСТЭК России № 239 — оценка автора стенда.", "",
          "| Сценарий | ЛР | Записи атласа | ATT&CK | ОПО | Что останавливает |", "|---|---|---|---|---|---|"]
    for sid, sc in cat.items():
        atlas = ", ".join(f"[{r}]({ATLAS.format(r)})" for r in sc["atlas"]) or "—"
        L.append(f"| {sid} | {sc['lab']} | {atlas} | {', '.join(sc['attack']) or '—'} | {', '.join(sc['opo']) or '—'} "
                 f"| {sc['stopped_by']} |")
    return "\n".join(L) + "\n"


# ---------------- канал рецептов ----------------
RECIPES_BEGIN, RECIPES_END = "<!-- recipes:begin -->", "<!-- recipes:end -->"
QUALITY_RU = {"ok": "партия в норме", "out_of_spec": "брак партии", None: None}
RECIPE_LEVELS = {0: "без проверки", 1: "проверка на сервере агента", 2: "квитанция гейта рецептов"}
GATE_RU = {0: "допуск", 10: "рассмотрение", 20: "запрос", 30: "отказ", None: "—"}


def _recipe_cell(o) -> str:
    act = "принято" if o.accepted else f"отказ: {o.reason}"
    parts = [act, PROCESS_RU[o.process]]
    if QUALITY_RU.get(o.quality):
        parts.append(QUALITY_RU[o.quality])
    return "; ".join(parts) + (", тревога монитора" if o.alert else "")


def recipe_outcomes_table(outs) -> list:
    from .recipe_lab import catalog as rcat
    by = {(o.scenario, o.level): o for o in outs}
    L = ["| Сценарий | " + " | ".join(f"L{lv}: {t}" for lv, t in RECIPE_LEVELS.items()) + " | Гейт |",
         "|---|---|---|---|---|"]
    for sid, sc in rcat().items():
        cells = [_recipe_cell(by[(sid, lv)]) for lv in RECIPE_LEVELS]
        L.append(f"| {sid} {sc['title']} | " + " | ".join(cells) + f" | {GATE_RU[by[(sid, 0)].gate]} |")
    return L


def readme_with_recipe_table(readme: str, outs) -> str:
    head, sep, rest = readme.partition(RECIPES_BEGIN)
    _old, sep2, tail = rest.partition(RECIPES_END)
    if not sep or not sep2:
        raise ValueError(f"в README нет меток {RECIPES_BEGIN} … {RECIPES_END}")
    return head + RECIPES_BEGIN + "\n" + "\n".join(recipe_outcomes_table(outs)) + "\n" + RECIPES_END + tail


def recipe_matrix_markdown(rl, outs) -> str:
    from .recipe_lab import catalog as rcat
    cat = rcat()
    L = ["# Результаты сценариев канала рецептов", "",
         "Файл и таблица в README создаются командой "
         f"`cpslab recipes matrix --md docs/results-recipes.md --readme README.md` (cpslab {__version__}); CI "
         "проверяет, что они совпадают с прогоном. Агент в сценариях детерминированный (cpslab/recipe_lab.py), "
         "процесс — 300 с модельного времени после действия.", "",
         "## Исходы на трёх уровнях защиты канала рецептов", "", *recipe_outcomes_table(outs), "",
         "Столбец «Гейт» — решение гейта рецептов по рецепту сценария (в RA4 — по подложенной старой ревизии, в RA5 "
         "— по рецепту до подмены); «—» — гейт не участвует."]
    seen = {o.reason for o in outs if not o.accepted}
    L += ["", "Коды отказа: " + "; ".join(f"`{k}` — {v}" for k, v in REASON_RU.items() if k in seen) + ".", ""]
    L += ["## Решения гейта рецептов", "",
          "| Сценарий | Рецепт | SHA-256 | Решение | R_P^min | R_P^max | Не подтверждены |", "|---|---|---|---|---|---|---|"]
    st = rl.state()["scenarios"]
    for sid in cat:
        for label, a in st[sid]["admissions"].items():
            rep = json.loads((rl.home / a["run"] / "report.json").read_text(encoding="utf-8"))
            bad = ", ".join(f"{s} {x}" for s, x in rep["states"].items() if x != "P")
            name = a["path"].split("/")[-1].removesuffix(".json")
            tag = " (история)" if label == "history" else ""
            L.append(f"| {sid}{tag} | {name} | `{rep['recipe']['sha256'][:16]}` | {a['decision']} | {_f3(a['R_min'])} "
                     f"| {_f3(a['R_max'])} | {bad} |")
    L += ["", "Причины по свидетельствам — в отчёте гейта: `cpslab recipe report СЦЕНАРИЙ`.", "",
          "## Сопоставление сценариев", "",
          "Сопоставления с MITRE ATT&CK for ICS и MITRE ATLAS — оценка автора стенда.", "",
          "| Сценарий | ATT&CK for ICS | ATLAS | Что останавливает |", "|---|---|---|---|"]
    for sid, sc in cat.items():
        L.append(f"| {sid} | {', '.join(sc['attack']) or '—'} | {', '.join(sc['atlas']) or '—'} | {sc['stopped_by']} |")
    return "\n".join(L) + "\n"
