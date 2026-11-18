"""Гейт рецептов: решение SCII по свидетельствам рецепта, квитанция SCII-R v1, журнал допусков.

Модель индекса и правило решения берутся из scii-gate без изменений (scii.model.evaluate) с профилем
cpslab/data/recipe-profile.json. Состояния свидетельств q11–q52 вычисляет этот модуль:

  q11 технологическое задание, на которое ссылается рецепт, подписано технологом;
  q12 записи калибровки, которые прочитал агент (материалы аттестации авторства), подписаны метрологом;
  q21 аттестация авторства от сервера агента: подпись и дайджест рецепта;
  q22 журнал сеанса: цепочка цела, до загрузки этот рецепт прошёл статическую проверку и пробный прогон;
  q31 статическая проверка против программы, установленной на устройстве;
  q32 пробный прогон на двойнике: безопасность объекта по модели из политики и условия приёмки из
      подписанного технологического задания;
  q33 заключение независимой проверки безопасности;
  q41 утверждение оператора для этого рецепта и устройства;
  q51 изделие, класс устройства и версия программы подходят рецепту;
  q52 ревизия рецепта не ниже уже допущенной для этого устройства.

Квитанция связывает решение с дайджестом и длиной канонического рецепта, классом и экземпляром
устройства, политикой допуска рецептов (дайджест и эпоха) и ревизией (поле svn): устройство
проверяет её тем же scii-agent, что и квитанции обновлений.
"""
from __future__ import annotations

import json
import math
import shutil
import time
from pathlib import Path

from scii import __version__ as SCII_VERSION
from scii.gate import to_markdown
from scii.model import ADMIT, BOTTOM, F, N, P, REJECT, REQUEST, REVIEW, Profile, evaluate

from . import __version__, documents as docs
from .journal import Journal
from .receipt import Payload, dsse_sign, envelope_digest, issue
from .recipe import DEFAULT_PLANT, RecipeError, canonical, dry_run, parse, validate, version_tuple
from .recipestore import RecipeStore
from .util import DATA_DIR, canonical_json, now_utc, rjson, sha256_bytes, wjson

PROFILE = DATA_DIR / "recipe-profile.json"
EXIT = {ADMIT: 0, REVIEW: 10, REQUEST: 20, REJECT: 30}
DECISION_RU = {0: "допуск", 10: "ручное рассмотрение", 20: "запрос свидетельств", 30: "отказ"}
ROLES = ("technologist", "metrology", "operator", "safety_engineer", "agent_server")


def _q(x: float, rnd) -> int:
    return max(0, min(10000, rnd(round(x * 10000, 6))))


class RecipeGate:
    def __init__(self, home: Path, keys):
        self.home = Path(home)
        self.keys = keys
        self.dir = self.home / "gate"
        self.policy_path = self.dir / "recipe-policy.json"
        self.ledger_path = self.dir / "recipe-ledger.jsonl"
        self.state_path = self.dir / "recipe-state.json"

    # ---------------- политика ----------------
    def init(self) -> "RecipeGate":
        kd = self.dir / "keys"
        kd.mkdir(parents=True, exist_ok=True)
        for role in ROLES:
            shutil.copy(self.keys.public / f"{role}.pk", kd / f"{role}.pk")
        wjson(self.policy_path, {
            "name": "Политика допуска рецептов учебного стенда cps-update-lab",
            "comment": "Якоря доверия ролей канала рецептов и модель объекта для пробного прогона. Пути к ключам — "
                       "относительно этого файла.",
            "epoch": 1,
            "keys": {role: f"keys/{role}.pk" for role in ROLES},
            "plant": dict(DEFAULT_PLANT),
            "tail_seconds": 60.0,
        })
        if not self.state_path.exists():
            wjson(self.state_path, {"serial": 0})
        return self

    @property
    def policy(self) -> dict:
        return rjson(self.policy_path)

    @property
    def policy_digest(self) -> bytes:
        return bytes.fromhex(sha256_bytes(self.policy_path.read_bytes()))

    @property
    def epoch(self) -> int:
        return int(self.policy["epoch"])

    def pk(self, role: str) -> bytes:
        return bytes.fromhex((self.dir / self.policy["keys"][role]).read_text().strip())

    # ---------------- свидетельства ----------------
    def _verify(self, envelope, role: str, payload_type: str):
        if envelope is None:
            return None, "не предъявлено"
        ok, obj = docs.verify(envelope, self.pk(role), payload_type)
        return (obj, None) if ok else (None, f"подпись ({role}) не проверяется: {obj}")

    def evidence(self, bundle: dict) -> tuple:
        """Состояния и причины q11–q52 для комплекта рецепта (см. assemble)."""
        data, fleet, archive = bundle["recipe"], bundle["fleet"], bundle["archive"]
        D = sha256_bytes(data)
        st, why = {}, {}

        def put(k, state, reason):
            st[k], why[k] = state, reason

        try:
            recipe = parse(data)
        except RecipeError as e:
            recipe = None
            for k in ("q31", "q32", "q51", "q52"):
                put(k, F, f"рецепт не разбирается: {e}")
        # --- аттестация авторства и материалы ---
        auth_env, materials, auth = bundle.get("authoring"), [], None
        if auth_env is None:
            put("q21", N, "аттестации авторства нет")
        else:
            obj, err = self._verify(auth_env, "agent_server", docs.INTOTO)
            if obj is None:
                put("q21", F, err)
            elif obj.get("predicateType") != docs.AUTHORING or \
                    {s["digest"].get("sha256") for s in obj.get("subject", [])} != {D}:
                put("q21", F, "аттестация авторства относится к другому содержимому рецепта")
            else:
                auth = obj["predicate"]
                materials = auth.get("materials", [])
                put("q21", P, f"рецепт загружен ключом {auth.get('key')} ({auth.get('tier')}), сеанс {auth.get('session')}")
        # --- q11 технологическое задание ---
        wo_obj = None
        wo_id = recipe.get("work_order") if recipe else None
        if not wo_id:
            put("q11", N, "рецепт не ссылается на технологическое задание")
        else:
            name, env = archive.find(docs.WORK_ORDER, wo_id)
            if env is None:
                put("q11", N, f"технологического задания {wo_id} нет в архиве")
            else:
                obj, err = self._verify(env, "technologist", docs.WORK_ORDER)
                used = [m for m in materials if m.get("name") == name]
                if obj is None:
                    put("q11", F, f"{name}: {err}")
                elif used and any(m.get("sha256") != docs.payload_digest(env) for m in used):
                    put("q11", F, f"агент читал {name} с другим содержимым, чем подписал технолог")
                else:
                    wo_obj = obj
                    put("q11", P, f"{wo_id} подписано технологом")
        # --- q12 калибровка ---
        cal = []
        for m in materials:
            env = archive.envelope(m.get("name", "")) if m.get("name", "").endswith(".json") else None
            if env is not None and env.get("payloadType") == docs.CALIBRATION:
                cal.append((m, env))
        if auth is None:
            put("q12", N, "неизвестно, какие записи калибровки использованы (нет аттестации авторства)")
        elif not cal:
            put("q12", N, "агент не читал записей калибровки")
        else:
            bad = []
            for m, env in cal:
                obj, err = self._verify(env, "metrology", docs.CALIBRATION)
                if obj is None:
                    bad.append(f"{m['name']}: {err}")
                elif docs.payload_digest(env) != m.get("sha256"):
                    bad.append(f"{m['name']}: агент читал другое содержимое")
            if bad:
                put("q12", F, "; ".join(bad))
            else:
                put("q12", P, ", ".join(m["name"] for m, _ in cal) +
                    (" подписаны метрологом" if len(cal) > 1 else " подписана метрологом"))
        # --- q22 журнал сеанса ---
        jp = bundle.get("journal")
        if jp is None or not Path(jp).exists():
            put("q22", N, "журнала сервера агента нет")
        else:
            j = Journal(jp)
            chk = j.verify()
            if not chk["ok"]:
                put("q22", F, f"цепочка журнала нарушена на записи {chk['broken_at']}")
            else:
                put("q22", *self._journal_state(j.entries(), D, recipe, auth))
        # --- q31, q32 проверка ---
        program = fleet.get("program")
        if recipe is not None:
            v = validate(recipe, program)
            errs = [f["message"] for f in v["findings"] if f["severity"] == "error"]
            put("q31", P if v["valid"] else F, "ошибок нет" if v["valid"] else "; ".join(errs[:3]))
            acceptance = (wo_obj or {}).get("acceptance", [])
            dr = dry_run(recipe, program, fleet["level"], self.policy.get("plant"), acceptance,
                         tail=float(self.policy.get("tail_seconds", 60.0)))
            bundle["dry_run"] = dr
            put("q32", P if dr["ok"] else F,
                ("на двойнике: " + ("рецепт завершён, объект в норме" +
                                    (", условия приёмки выполнены" if acceptance else ", условий приёмки нет"))
                 if dr["ok"] else "на двойнике: " + "; ".join(dr["problems"])))
        # --- q33 проверка безопасности ---
        obj, err = self._verify(bundle.get("safety"), "safety_engineer", docs.SAFETY_REVIEW)
        if bundle.get("safety") is None:
            put("q33", N, "заключения проверки безопасности нет")
        elif obj is None:
            put("q33", F, err)
        elif obj.get("recipe", {}).get("sha256") != D:
            put("q33", F, "заключение относится к другому содержимому рецепта")
        else:
            put("q33", P if obj.get("result") == "APPROVED" else F, f"заключение: {obj.get('result')}")
        # --- q41 утверждение оператора ---
        obj, err = self._verify(bundle.get("approval"), "operator", docs.APPROVAL)
        if bundle.get("approval") is None:
            put("q41", N, "утверждения оператора нет")
        elif obj is None:
            put("q41", F, err)
        elif obj.get("recipe", {}).get("sha256") != D:
            put("q41", F, "оператор утвердил другое содержимое рецепта")
        elif obj.get("device") != fleet.get("device"):
            put("q41", F, f"утверждено для устройства {obj.get('device')}, а не {fleet.get('device')}")
        elif obj.get("decision") != "APPROVED":
            put("q41", F, f"решение оператора: {obj.get('decision')}")
        else:
            put("q41", P, f"утвердил {obj.get('by', 'оператор')} для {obj.get('device')}")
        # --- q51, q52 устройство ---
        if recipe is not None:
            tgt = recipe.get("target") or {}
            pv = fleet.get("program_version") or "0.0.0"
            problems = []
            if tgt.get("product") != fleet.get("product"):
                problems.append(f"изделие {tgt.get('product')} ≠ {fleet.get('product')}")
            if tgt.get("device_class") != fleet.get("device_class"):
                problems.append(f"класс {tgt.get('device_class')} ≠ {fleet.get('device_class')}")
            try:
                if version_tuple(pv) < version_tuple(tgt.get("program_min", "0.0.0")):
                    problems.append(f"программа {pv} ниже {tgt.get('program_min')}")
            except ValueError:
                problems.append("версия программы не разбирается")
            put("q51", F if problems else P, "; ".join(problems) or f"{fleet.get('product')} {pv}, класс "
                                                                    f"{fleet.get('device_class')}")
            last = self.last_revision(recipe["name"], fleet)
            put("q52", P if recipe["revision"] >= last else F,
                f"ревизия {recipe['revision']}, наибольшая допущенная {last or '—'}")
        return st, why

    @staticmethod
    def _journal_state(entries: list, D: str, recipe, auth) -> tuple:
        uploads = [e for e in entries if e.get("tool") == "upload_recipe" and e.get("recipe_sha256") == D
                   and e.get("ok")]
        if not uploads:
            return N, "в журнале нет загрузки этого рецепта"
        up = uploads[-1]
        sess = up.get("session")
        before = [e for e in entries if e.get("session") == sess and e["seq"] < up["seq"]]
        mine = [e for e in before if e.get("recipe_sha256") == D]
        val = [e for e in mine if e.get("tool") == "validate_recipe"]
        dry = [e for e in mine if e.get("tool") == "dry_run"]
        if any(not e.get("ok") for e in val):
            return F, "рецепт загружен, хотя статическая проверка в сеансе его отклонила"
        if any(not e.get("ok") for e in dry):
            return F, "рецепт загружен, хотя пробный прогон в сеансе дал отрицательный результат"
        last_dry = next((e for e in reversed(before) if e.get("tool") == "dry_run"), None)
        if recipe and last_dry and last_dry.get("recipe_sha256") != D and last_dry.get("recipe") == \
                f"{recipe['name']} r{recipe['revision']}":
            return F, "пробный прогон в сеансе выполнен для другого содержимого этой ревизии рецепта"
        if val and dry:
            return P, f"сеанс {sess}: проверка и пробный прогон до загрузки (записи {val[-1]['seq']}, {dry[-1]['seq']})"
        missing = [x for x, ok in (("статической проверки", val), ("пробного прогона", dry)) if not ok]
        return N, "в сеансе нет " + " и ".join(missing) + " этого рецепта"

    # ---------------- комплект ----------------
    def assemble(self, agent_root: Path, recipe_path: Path, fleet: dict) -> dict:
        """Комплект рецепта из хранилища сервера агента для решения гейта."""
        rp = Path(recipe_path)

        def opt(kind):
            p = RecipeStore.sidecar(rp, kind)
            return json.loads(p.read_bytes()) if p.exists() else None
        return {"recipe": rp.read_bytes(), "authoring": opt("authoring"), "approval": opt("approval"),
                "safety": opt("safety"), "journal": Path(agent_root) / "journal.jsonl",
                "archive": docs.Archive(Path(agent_root) / "archive"), "fleet": fleet, "path": rp}

    # ---------------- решение ----------------
    def evaluate(self, bundle: dict) -> tuple:
        profile = Profile.load(str(PROFILE))
        t0 = time.perf_counter()
        states, reasons = self.evidence(bundle)
        rep = evaluate(profile, states)
        rep.update({"reasons": reasons, "elapsed_s": time.perf_counter() - t0,
                    "tool": f"scii-gate {SCII_VERSION}, cpslab {__version__}", "time_utc": now_utc(),
                    "recipe": {"sha256": sha256_bytes(bundle["recipe"]), "size": len(bundle["recipe"])},
                    "fleet": {k: v for k, v in bundle["fleet"].items() if k != "program"},
                    "dry_run": bundle.get("dry_run")})
        return profile, rep

    def admit(self, bundle: dict) -> dict:
        profile, rep = self.evaluate(bundle)
        code = EXIT[rep["decision"]]
        data, fleet = bundle["recipe"], bundle["fleet"]
        try:
            recipe = parse(data)
            label = f"{recipe['name']}-r{recipe['revision']}"
        except RecipeError:
            recipe, label = None, "unparsed"
        state = rjson(self.state_path)
        state["serial"] += 1
        serial = state["serial"]
        wjson(self.state_path, state)
        run_dir = self.dir / "recipe-runs" / f"{serial:04d}-{label}"
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "report.md").write_text(to_markdown(profile, rep), encoding="utf-8")
        wjson(run_dir / "report.json", rep)
        vsa = {"_type": "https://in-toto.io/Statement/v1",
               "subject": [{"name": f"recipe:{label}", "digest": {"sha256": sha256_bytes(data)}}],
               "predicateType": "https://slsa.dev/verification_summary/v1",
               "predicate": {"verifier": {"id": "urn:cpslab:recipe-gate",
                                          "version": {"scii-gate": SCII_VERSION, "cpslab": __version__}},
                             "timeVerified": rep["time_utc"], "resourceUri": f"cpslab:{fleet.get('device')}",
                             "policy": {"uri": "gate/recipe-policy.json",
                                        "digest": {"sha256": self.policy_digest.hex()}},
                             "verificationResult": "PASSED" if code == 0 else "FAILED", "verifiedLevels": [],
                             "scii": {"decision": code, "R_min": rep["R_min"], "R_max": rep["R_max"],
                                      "theta": rep["theta"], "G": rep["G"], "states": rep["states"]}}}
        envelope = dsse_sign(self.keys.gate_key(), docs.INTOTO, canonical_json(vsa))
        wjson(run_dir / "vsa.dsse.json", envelope)
        receipt = None
        if code == 0 and recipe is not None:
            flags = (1 if rep["G"] == 0 else 0) | (2 if rep["G"] == BOTTOM else 0) | (4 if rep["B"] == 1 else 0)
            payload = Payload(decision=0, device_class=int(fleet["device_class"]), svn=int(recipe["revision"]),
                              image_size=len(data), image_digest=bytes.fromhex(sha256_bytes(data)),
                              policy_epoch=self.epoch, policy_digest=self.policy_digest,
                              device_instance=bytes.fromhex(fleet.get("instance") or "00" * 16), info_flags=flags,
                              r_min=_q(rep["R_min"], math.floor), r_max=_q(rep["R_max"], math.ceil),
                              theta=round(rep["theta"] * 10000), serial=serial, issued_at=int(time.time()),
                              vsa_digest=envelope_digest(envelope))
            receipt = issue(self.keys.gate_key(), payload)
            (run_dir / "receipt.scr").write_bytes(receipt)
        entry = {"serial": serial, "time": rep["time_utc"], "recipe": recipe["name"] if recipe else None,
                 "revision": recipe["revision"] if recipe else None, "device": fleet.get("device"),
                 "device_class": fleet.get("device_class"), "instance": fleet.get("instance") or "00" * 16,
                 "sha256": sha256_bytes(data), "code": code, "decision": DECISION_RU[code], "R_min": rep["R_min"],
                 "R_max": rep["R_max"], "run": str(run_dir.relative_to(self.home))}
        with open(self.ledger_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        out = {"code": code, "decision": DECISION_RU[code], "detail": rep["decision_detail"], "R_min": rep["R_min"],
               "R_max": rep["R_max"], "states": rep["states"], "reasons": rep["reasons"], "receipt": receipt,
               "run": run_dir, "serial": serial, "dry_run": rep.get("dry_run")}
        if bundle.get("path") is not None:
            rp = Path(bundle["path"])
            wjson(RecipeStore.sidecar(rp, "decision"),
                  {k: (str(v) if isinstance(v, Path) else v) for k, v in out.items() if k not in ("receipt", "dry_run")})
            rs = RecipeStore.sidecar(rp, "receipt")
            if receipt is not None:
                rs.write_bytes(receipt)
            else:
                rs.unlink(missing_ok=True)
        return out

    # ---------------- журнал допусков ----------------
    def ledger(self) -> list:
        if not self.ledger_path.exists():
            return []
        return [json.loads(x) for x in self.ledger_path.read_text(encoding="utf-8").splitlines() if x.strip()]

    def admitted(self) -> set:
        """Пары (класс устройства, SHA-256 рецепта), допущенные гейтом."""
        return {(e["device_class"], e["sha256"]) for e in self.ledger() if e["code"] == 0}

    def last_revision(self, name: str, fleet: dict) -> int:
        inst = fleet.get("instance") or "00" * 16
        revs = [e["revision"] for e in self.ledger() if e["code"] == 0 and e["recipe"] == name
                and e.get("device_class") == fleet.get("device_class") and e.get("instance") == inst]
        return max(revs, default=0)


__all__ = ["RecipeGate", "EXIT", "DECISION_RU", "PROFILE", "canonical", "REJECT", "REQUEST", "REVIEW"]
