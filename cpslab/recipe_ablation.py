"""Э5 и Э7: абляция элементов защиты канала рецептов и чувствительность решений гейта.

Программа — experiments/agents/PROGRAM.md, разделы 4 и 6. Расчёт детерминированный: состояния
свидетельств берутся у гейта рецептов (RecipeGate.evidence) без записи в журнал допусков, решения
считает scii-gate (scii.model) для изменённого профиля или правила.

Варианты абляции:
  A0 полная схема;
  A1 без пробного прогона гейта: свидетельство q32 убрано из профиля, вес вершины r3 перенормирован;
  A2 без журнала сеанса сервера агента: q22 убрано из профиля;
  A3 условия приёмки из проверок самого рецепта: q32 по пробному прогону без условий задания;
  A4 без утверждения оператора: q41 считается подтверждённым всегда;
  A5 квитанция без дайджеста и длины рецепта: на контроллере проходит подменённый после допуска рецепт;
  A6 квитанция без защиты от повтора: на контроллере проходит старая допущенная ревизия;
  A7 правило допуска заменено двоичным контролем, аддитивным индексом или графовым индексом без
     блокирующего условия.
Порог каждого варианта назначается той же процедурой, что у стенда: R_P^min эталонного рецепта RN1.
Сочетание A1+A2 считается поисково и так помечается в отчёте.
"""
from __future__ import annotations

import copy
import itertools
import json
import math
import shutil
from fractions import Fraction
from pathlib import Path

from scii import model as sm

from .recipe import DEFAULT_PLANT, dry_run
from .recipe_gate import PROFILE
from .recipe_lab import RecipeLab, catalog

VARIANTS = ("A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7-binary", "A7-additive", "A7-nogate", "A1+A2")
EXPLORATORY = {"A1+A2"}
DECISION = {sm.ADMIT: "admit", sm.REVIEW: "review", sm.REQUEST: "request", sm.REJECT: "reject"}
REFERENCE = "RN1"


# ---------------- профиль и правила ----------------
def base_profile_data() -> dict:
    return json.loads(Path(PROFILE).read_text(encoding="utf-8"))


def without(data: dict, evidence: str) -> dict:
    """Профиль без типа свидетельства: веса остальных свидетельств вершины перенормированы."""
    d = copy.deepcopy(data)
    for v, items in d["catalog"].items():
        if any(x["id"] == evidence for x in items):
            rest = [x for x in items if x["id"] != evidence]
            total = sum(Fraction(str(x["alpha"])) for x in rest)
            for x in rest:
                x["alpha"] = float(Fraction(str(x["alpha"])) / total)
            d["catalog"][v] = rest
    return d


def additive(profile: sm.Profile, states: dict) -> float:
    """Аддитивный индекс: среднее меток l_A(v) по вершинам (как вариант табл. 3 статьи ВАК-2)."""
    lab = sm.labels(profile, states)
    return sum(x["l"] for x in lab.values()) / len(lab)


def decide(profile: sm.Profile, states: dict, rule: str, theta: float) -> str:
    if rule == "binary":
        return "admit" if sm.binary(profile, states) == 1 else "reject"
    if rule == "additive":
        g = sm.gate(profile, states)
        if g == sm.BOTTOM:
            return "request"
        m = additive(profile, states)
        if g == 0 or m < theta - sm.THETA_TOL:
            return "reject"
        return "admit" if sm.binary(profile, states) == 1 else "review"
    if rule == "nogate":
        rmin, rmax = sm.bounds(profile, states)
        if rmax < theta - sm.THETA_TOL:
            return "reject"
        return "admit" if rmin >= theta - sm.THETA_TOL else "review"
    return DECISION[sm.decide(profile, states, theta)]


def reference_theta(profile: sm.Profile, ref_states: dict, rule: str) -> float:
    """Порог по эталону: R_P^min (аддитивный — значение индекса) эталонного рецепта, вниз до 0,001."""
    if rule == "additive":
        x = additive(profile, ref_states)
    else:
        x = sm.bounds(profile, ref_states)[0]
    return math.floor(x * 1000 + 1e-9) / 1000


def variant_setup(variant: str) -> tuple:
    """(данные профиля, правило, функция изменения состояний)."""
    data = base_profile_data()
    rule, mod = "full", (lambda st, case: st)
    if variant == "A1":
        data = without(data, "q32")
    elif variant == "A2":
        data = without(data, "q22")
    elif variant == "A1+A2":
        data = without(without(data, "q32"), "q22")
    elif variant == "A3":
        mod = (lambda st, case: dict(st, q32=case["q32_recipe_checks"]))
    elif variant == "A4":
        mod = (lambda st, case: dict(st, q41=sm.P))
    elif variant.startswith("A7-"):
        rule = variant[3:]
    return data, rule, mod


# ---------------- случаи каталога ----------------
def _truth(recipe: dict, program: dict, level: float, acceptance: list, plant: dict = None) -> dict:
    dr = dry_run(recipe, program, level, dict(DEFAULT_PLANT, **(plant or {})), acceptance, tail=60.0)
    cls = "UNSAFE" if not dr["safe"] else ("SAFE_OK" if dr["ok"] else "SAFE_FAIL")
    return {"class": cls, "outcome": dr["outcome"], "completed": dr["completed"]}


def case_from_bundle(rlab: RecipeLab, case_id: str, bundle: dict, recipe: dict, start_level: float,
                     acceptance: list, plant: dict = None, attack: str = None) -> dict:
    """Случай абляции: состояния свидетельств, q32 без условий задания, истина на объекте."""
    states, reasons = rlab.gate.evidence(bundle)
    program = bundle["fleet"]["program"]
    dr = dry_run(recipe, program, bundle["fleet"]["level"], rlab.gate.policy.get("plant"), [],
                 tail=float(rlab.gate.policy.get("tail_seconds", 60.0)))
    return {"id": case_id, "states": states, "q32_recipe_checks": sm.P if dr["ok"] else sm.F,
            "truth": _truth(recipe, program, start_level, acceptance, plant), "attack": attack}


def catalog_cases(rlab: RecipeLab, work: Path) -> list:
    """Рецепты сценариев каталога (подготовленные RecipeLab.init) как случаи абляции."""
    st = rlab.state()["scenarios"]
    cat = catalog()
    cases = []
    for sid in ("RN1", "RA1", "RA2", "RA3", "RA4", "RA5", "RA6", "RA7", "RM1"):
        adm = st[sid]["admissions"].get("recipe")
        if not adm:
            continue
        agent_root = rlab.root / sid / "agent"
        path = agent_root / adm["path"]
        recipe = json.loads(path.read_bytes())
        dev = rlab.device(sid, work / sid, 2)
        dev.reset_process(float(cat[sid]["start_level"]))
        bundle = rlab.gate.assemble(agent_root, path, RecipeLab.fleet(dev))
        acceptance = _acceptance(agent_root, recipe)
        plant = {"q_out": float(cat[sid]["plant_q_out"])} if cat[sid].get("plant_q_out") else None
        attack = {"RA4": "replay", "RA5": "toctou"}.get(sid)
        case = case_from_bundle(rlab, sid, bundle, recipe, float(cat[sid]["start_level"]), acceptance, plant, attack)
        if sid == "RA4":       # подложенная старая ревизия: допущена раньше, опасна при текущем уровне
            hist = agent_root / st[sid]["admissions"]["history"]["path"]
            case["truth"] = _truth(json.loads(hist.read_bytes()), bundle["fleet"]["program"],
                                   float(cat[sid]["start_level"]), [])
        if sid == "RA5":       # рецепт после подмены в хранилище: слив перед партией
            from .recipe_lab import DRAIN_PREFIX
            evil = dict(recipe, steps=[dict(s) for s in DRAIN_PREFIX] + recipe["steps"])
            case["truth"] = _truth(evil, bundle["fleet"]["program"], float(cat[sid]["start_level"]), acceptance)
        cases.append(case)
        shutil.rmtree(work / sid, ignore_errors=True)
    return cases


def _acceptance(agent_root: Path, recipe: dict) -> list:
    from . import documents as docs
    from .documents import Archive
    name, env = Archive(Path(agent_root) / "archive").find(docs.WORK_ORDER, recipe.get("work_order"))
    return docs.payload_obj(env).get("acceptance", []) if env else []


# ---------------- абляция ----------------
def ablate(cases: list, variants=VARIANTS) -> dict:
    ref = next(c for c in cases if c["id"] == REFERENCE)
    rows, summary = [], {}
    for var in variants:
        data, rule, mod = variant_setup(var)
        prof = sm.Profile(data)
        theta = reference_theta(prof, mod(ref["states"], ref), rule)
        executed_bad = []
        for c in cases:
            st = {k: v for k, v in mod(c["states"], c).items() if k in prof.evidence}
            dec = decide(prof, st, rule, theta)
            admitted = dec == "admit"
            if c.get("attack") == "replay":
                executes = var == "A6"           # подлинная квитанция старой ревизии, антиповтор снят
            elif c.get("attack") == "toctou":
                executes = var == "A5"           # квитанция подлинного рецепта, дайджест и длина не проверяются
            else:
                executes = admitted
            bad = c["truth"]["class"] in ("UNSAFE", "SAFE_FAIL")
            if executes and bad:
                executed_bad.append(c["id"])
            rows.append({"variant": var, "case": c["id"], "decision": dec, "theta": theta, "executes": executes,
                         "truth": c["truth"]["class"], "outcome": c["truth"]["outcome"]})
        summary[var] = {"theta": theta, "executed_bad": executed_bad, "exploratory": var in EXPLORATORY}
    return {"variants": list(variants), "rows": rows, "summary": summary}


# ---------------- чувствительность ----------------
def _alpha_variants(items: list) -> list:
    """Исходные, равные и сдвинутые на 0,1 веса свидетельств вершины (сдвиг: к наибольшему от наименьшего)."""
    base = [Fraction(str(x["alpha"])) for x in items]
    n = len(base)
    out = [base, [Fraction(1, n)] * n]
    if n > 1:
        hi, lo = base.index(max(base)), base.index(min(base))
        if hi == lo:
            hi, lo = 0, n - 1
        s = list(base)
        s[hi] += Fraction(1, 10)
        s[lo] -= Fraction(1, 10)
        if all(x > 0 for x in s):
            out.append(s)
    uniq = []
    for v in out:
        if v not in uniq:
            uniq.append(v)
    return uniq


def weight_variants(data: dict) -> list:
    vert = [v for v in ("r1", "r2", "r3", "r5") if len(data["catalog"][v]) > 1]
    av = {v: _alpha_variants(data["catalog"][v]) for v in vert}
    codes = sorted(data["class_codes"], key=data["class_codes"].get)
    ev = []
    for e in data["edges"]:
        i = codes.index(e["class"])
        ev.append(sorted({codes[j] for j in (i - 1, i, i + 1) if 0 <= j < len(codes)}, key=codes.index))
    out = []
    for combo in itertools.product(*[av[v] for v in vert]):
        for classes in itertools.product(*ev):
            d = copy.deepcopy(data)
            for v, alphas in zip(vert, combo):
                for x, a in zip(d["catalog"][v], alphas):
                    x["alpha"] = float(a)
            for e, c in zip(d["edges"], classes):
                e["class"] = c
            out.append(d)
    return out


def sensitivity(cases: list) -> dict:
    data = base_profile_data()
    base = sm.Profile(data)
    ref = next(c for c in cases if c["id"] == REFERENCE)
    gated = [c for c in cases if not c.get("attack")]
    base_theta = reference_theta(base, ref["states"], "full")
    base_dec = {c["id"]: decide(base, c["states"], "full", base_theta) for c in gated}
    sweep = []
    for k in range(70, 91):
        th = k / 100
        dec = {c["id"]: decide(base, c["states"], "full", th) for c in gated}
        sweep.append({"theta": th, "changed": sorted(i for i in dec if dec[i] != base_dec[i]), "decisions": dec})
    variants = weight_variants(data)
    by_ref, fixed = [], []
    for d in variants:
        prof = sm.Profile(d)
        th = reference_theta(prof, ref["states"], "full")
        for th_used, sink in ((th, by_ref), (base.theta, fixed)):
            dec = {c["id"]: decide(prof, c["states"], "full", th_used) for c in gated}
            sink.append(sorted(i for i in dec if dec[i] != base_dec[i]))
    return {"theta_base": base_theta, "decisions_base": base_dec, "theta_sweep": sweep,
            "weight_variants": len(variants),
            "reference_theta": {"variants_with_change": sum(1 for x in by_ref if x),
                                "changed_cases": sorted({i for x in by_ref for i in x})},
            "fixed_theta": {"variants_with_change": sum(1 for x in fixed if x),
                            "changed_cases": sorted({i for x in fixed for i in x})}}


def report_md(abl: dict, sens: dict = None) -> str:
    cases = sorted({r["case"] for r in abl["rows"]}, key=lambda c: [r["case"] for r in abl["rows"]].index(c))
    lines = ["# Э5: абляция элементов защиты канала рецептов (каталог)", "",
             "| Вариант | θ | " + " | ".join(cases) + " | Исполнено опасных |", "|---|---|" + "---|" * len(cases) + "---|"]
    for var in abl["variants"]:
        cells = []
        for c in cases:
            r = next(x for x in abl["rows"] if x["variant"] == var and x["case"] == c)
            mark = ("✔ " if r["executes"] else "") + r["decision"]
            cells.append(mark)
        s = abl["summary"][var]
        name = var + (" (поисковый)" if s["exploratory"] else "")
        lines.append(f"| {name} | {s['theta']:.3f} | " + " | ".join(cells) + f" | {', '.join(s['executed_bad']) or '—'} |")
    truth = {r["case"]: f"{r['truth']} ({r['outcome']})" for r in abl["rows"] if r["variant"] == "A0"}
    lines += ["", "Истина на объекте: " + "; ".join(f"{c} {truth[c]}" for c in cases) + ".",
              "✔ — рецепт исполняется на уровне L2."]
    if sens:
        lines += ["", "# Э7: чувствительность решений гейта (каталог)", "",
                  f"Порог по эталону RN1: {sens['theta_base']:.3f}.", "",
                  "| θ | изменились решения |", "|---|---|"]
        for s in sens["theta_sweep"]:
            lines.append(f"| {s['theta']:.2f} | {', '.join(s['changed']) or '—'} |")
        lines += ["", f"Варианты весов: {sens['weight_variants']}. С порогом по эталону изменения в "
                  f"{sens['reference_theta']['variants_with_change']} вариантах "
                  f"({', '.join(sens['reference_theta']['changed_cases']) or 'нет'}); с постоянным порогом 0,8 — в "
                  f"{sens['fixed_theta']['variants_with_change']} "
                  f"({', '.join(sens['fixed_theta']['changed_cases']) or 'нет'})."]
    return "\n".join(lines) + "\n"


__all__ = ["VARIANTS", "ablate", "sensitivity", "catalog_cases", "case_from_bundle", "decide", "without",
           "weight_variants", "report_md"]
