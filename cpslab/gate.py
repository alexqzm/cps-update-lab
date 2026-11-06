"""Гейт SCII получателя: решение по комплекту свидетельств, квитанция SCII-R v1, журнал допусков.

Проверки свидетельств стадий v1–v4 и модель решения берутся из scii-gate без изменений
(scii.checks.run_checks, scii.model.evaluate). Свидетельства стадии устройства s51–s53 для образа
контроллера проверяет стенд: подпись образа ключом загрузчика, номер версии и класс устройства из
манифеста образа против данных о парке устройств.

Политика получателя делится на две части. Постоянная часть (gate/policy.json: якоря доверия,
ожидаемый сборщик, тулчейн, зависимости, эпоха) входит в policy_digest квитанции, и её дайджест
записан в устройство при вводе в эксплуатацию. Ожидаемые значения выпуска (коммит и тег) и
состояние парка (класс устройства, установленная версия) гейт получает при каждом допуске:
коммит — из подписанного тега поставщика, парк — от оператора. Они в policy_digest не входят,
иначе устройству пришлось бы получать новый дайджест к каждому выпуску.
"""
from __future__ import annotations

import json
import math
import os
import shutil
import tempfile
import time
from pathlib import Path

from scii import __version__ as SCII_VERSION
from scii.checks import Context, Result, run_checks
from scii.gate import to_markdown
from scii.model import ADMIT, BOTTOM, F, N, P, REJECT, REQUEST, REVIEW, Profile, evaluate

from . import __version__
from .image import ImageError, read_image, toolchain_sha256
from .receipt import Payload, boot_verify, dsse_sign, envelope_digest, issue
from .util import DATA_DIR, canonical_json, cosign, gpg, now_utc, rjson, run, sha256_bytes, wjson
from .vendor import BUILDER_ID, REPO_URI, SBOM_DEPENDENCIES, tag_name

PROFILE = DATA_DIR / "profile.json"
EXIT = {ADMIT: 0, REVIEW: 10, REQUEST: 20, REJECT: 30}
DECISION_RU = {0: "допуск", 10: "ручное рассмотрение", 20: "запрос свидетельств", 30: "отказ"}
POLICY_KEYS = {"builder": "builder.pub", "independent_builder": "independent_builder.pub", "vendor": ["vendor.pub"],
               "repository": "repository.pub", "reviewer": "reviewer.pub", "sast": "sast.pub", "tester": "tester.pub",
               "tag_signers": "tag_signers.asc", "commit_signers": "tag_signers.asc", "vendor_boot": "vendor_boot.pk"}


def _q(x: float, rnd) -> int:
    """Индекс в квитанции — в десятитысячных: min округляется вниз, max вверх, без артефактов плавающей точки."""
    return max(0, min(10000, rnd(round(x * 10000, 6))))


class GateError(RuntimeError):
    """Гейт не может принять решение (нет подписанного тега выпуска и т. п.)."""


class Gate:
    def __init__(self, home: Path, keys, vendor_src: Path):
        self.home = Path(home)
        self.keys = keys
        self.vendor_src = Path(vendor_src)
        self.dir = self.home / "gate"
        self.policy_path = self.dir / "policy.json"
        self.ledger_path = self.dir / "ledger.jsonl"
        self.state_path = self.dir / "state.json"

    # ---------------- политика ----------------
    def init(self) -> "Gate":
        kd = self.dir / "keys"
        kd.mkdir(parents=True, exist_ok=True)
        for f in {x for v in POLICY_KEYS.values() for x in (v if isinstance(v, list) else [v])}:
            shutil.copy(self.keys.public / f, kd / f)
        fpr = self.keys.fpr("vendor")
        policy = {
            "name": "Политика получателя учебного стенда cps-update-lab",
            "comment": "Якоря доверия и ожидаемые значения задаёт получатель. Пути к ключам — относительно этого файла.",
            "epoch": 1,
            "keys": {role: ([f"keys/{x}" for x in f] if isinstance(f, list) else f"keys/{f}")
                     for role, f in POLICY_KEYS.items()},
            "expect": {"source_repository": REPO_URI, "builder_id": BUILDER_ID,
                       "toolchain_sha256": toolchain_sha256(), "dependencies": SBOM_DEPENDENCIES,
                       "repository_writers": ["builder"], "tag_signer_fingerprints": [fpr],
                       "commit_signer_fingerprints": [fpr]},
        }
        wjson(self.policy_path, policy)
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

    def expectations(self, product: str, version: str) -> dict:
        """Коммит выпуска из тега поставщика; подпись тега проверяется ключом из политики."""
        tag = tag_name(product, version)
        home = tempfile.mkdtemp(prefix="cpslab-gate-gpg-")
        try:
            env = dict(os.environ, GNUPGHOME=home)
            run([gpg(), "--batch", "--import", self.dir / "keys" / "tag_signers.asc"], env=env)
            r = run(["git", "-C", self.vendor_src, "verify-tag", "--raw", tag], env=env, check=False)
            if r.returncode != 0 or "VALIDSIG" not in (r.stderr + r.stdout):
                raise GateError(f"тег {tag} не найден или не подписан ключом поставщика из политики")
            commit = run(["git", "-C", self.vendor_src, "rev-parse", f"{tag}^{{commit}}"]).stdout.strip()
        finally:
            run(["gpgconf", "--homedir", home, "--kill", "all"], check=False)
            shutil.rmtree(home, ignore_errors=True)
        return {"source_commit": commit, "tag": tag}

    # ---------------- решение ----------------
    def _device_checks(self, bundle_dir: Path, bundle: dict, fleet: dict) -> dict:
        ev, out = bundle.get("evidence", {}), {}
        image = (bundle_dir / bundle["artifact"]).read_bytes()
        if "s51" in ev:
            sig = bundle_dir / ev["s51"]["signature"]
            if not sig.exists():
                out["s51"] = Result(N, "не предъявлено")
            else:
                pk = bytes.fromhex((self.dir / self.policy["keys"]["vendor_boot"]).read_text().strip())
                out["s51"] = (Result(P, "подпись образа принимается ключом загрузчика поставщика")
                              if boot_verify(sig.read_bytes(), image, pk)
                              else Result(F, "подпись образа не принимается ключом загрузчика"))
        try:
            manifest, _ = read_image(image)
        except ImageError as e:
            manifest, err = None, str(e)
        if "s52" in ev:
            if manifest is None:
                out["s52"] = Result(F, f"образ не разбирается: {err}")
            elif manifest["svn"] > fleet["installed_svn"]:
                out["s52"] = Result(P, f"версия {manifest['version']} выше установленной на парке ({fleet['installed_svn']:#x})")
            else:
                out["s52"] = Result(F, f"версия {manifest['version']} не выше установленной на парке (откат)")
        if "s53" in ev:
            if manifest is None:
                out["s53"] = Result(F, f"образ не разбирается: {err}")
            elif manifest["device_class"] == fleet["device_class"]:
                out["s53"] = Result(P, f"класс устройства {manifest['device_class']} совпадает с парком")
            else:
                out["s53"] = Result(F, f"образ для класса {manifest['device_class']}, парк — {fleet['device_class']}")
        return out

    def evaluate(self, release_dir: Path, fleet: dict) -> tuple:
        release_dir = Path(release_dir).resolve()
        profile = Profile.load(str(PROFILE))
        bundle = rjson(release_dir / "bundle.json")
        rel = bundle["release"]
        t0 = time.perf_counter()
        policy = self.policy
        policy["expect"].update(self.expectations(rel["product"], rel["version"]))
        policy["tools"] = {"cosign": cosign()}
        ctx = Context(str(release_dir), policy, str(self.dir))
        artifact = {"path": bundle["artifact"], "sha256": ctx.artifact_sha256}
        res = run_checks(profile, ctx)
        res.update(self._device_checks(release_dir, bundle, fleet))
        states = {k: r.state for k, r in res.items()}
        rep = evaluate(profile, states)
        rep.update({"reasons": {k: r.reason for k, r in res.items()}, "artifact": artifact,
                    "elapsed_s": time.perf_counter() - t0, "tool": f"scii-gate {SCII_VERSION}, cpslab {__version__}",
                    "time_utc": now_utc(), "release": rel, "fleet": fleet,
                    "expect": {k: policy["expect"][k] for k in ("source_commit", "tag")}})
        return profile, rep

    def admit(self, release_dir: Path, fleet: dict, instance: bytes = bytes(16)) -> dict:
        """Решение гейта; при допуске — квитанция для класса устройства парка (и экземпляра, если задан)."""
        release_dir = Path(release_dir).resolve()
        try:
            profile, rep = self.evaluate(release_dir, fleet)
        except GateError as e:
            code = 20
            return {"code": code, "decision": DECISION_RU[code], "error": str(e), "receipt": None}
        code = EXIT[rep["decision"]]
        state = rjson(self.state_path)
        state["serial"] += 1
        serial = state["serial"]
        wjson(self.state_path, state)
        run_dir = self.dir / "runs" / f"{serial:04d}-{release_dir.name}"
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "report.md").write_text(to_markdown(profile, rep), encoding="utf-8")
        wjson(run_dir / "report.json", rep)
        rel = rep["release"]
        image = (release_dir / rjson(release_dir / "bundle.json")["artifact"]).read_bytes()
        vsa = {"_type": "https://in-toto.io/Statement/v1",
               "subject": [{"name": rel["image"], "digest": {"sha256": sha256_bytes(image)}}],
               "predicateType": "https://slsa.dev/verification_summary/v1",
               "predicate": {"verifier": {"id": "urn:cpslab:gate", "version": {"scii-gate": SCII_VERSION,
                                                                                "cpslab": __version__}},
                             "timeVerified": rep["time_utc"], "resourceUri": f"cpslab:{rel['product']}@{rel['version']}",
                             "policy": {"uri": "gate/policy.json",
                                        "digest": {"sha256": self.policy_digest.hex()}},
                             "verificationResult": "PASSED" if code == 0 else "FAILED",
                             "verifiedLevels": [],
                             "scii": {"decision": code, "R_min": rep["R_min"], "R_max": rep["R_max"],
                                      "theta": rep["theta"], "G": rep["G"], "states": rep["states"]}}}
        envelope = dsse_sign(self.keys.gate_key(), "application/vnd.in-toto+json", canonical_json(vsa))
        wjson(run_dir / "vsa.dsse.json", envelope)
        receipt = None
        if code == 0:
            manifest, _ = read_image(image)
            flags = (1 if rep["G"] == 0 else 0) | (2 if rep["G"] == BOTTOM else 0) | (4 if rep["B"] == 1 else 0)
            payload = Payload(decision=0, device_class=manifest["device_class"], svn=manifest["svn"],
                              image_size=len(image), image_digest=bytes.fromhex(sha256_bytes(image)),
                              policy_epoch=self.epoch, policy_digest=self.policy_digest, device_instance=instance,
                              info_flags=flags, r_min=_q(rep["R_min"], math.floor),
                              r_max=_q(rep["R_max"], math.ceil),
                              theta=round(rep["theta"] * 10000), serial=serial, issued_at=int(time.time()),
                              vsa_digest=envelope_digest(envelope))
            receipt = issue(self.keys.gate_key(), payload)
            (run_dir / "receipt.scr").write_bytes(receipt)
        entry = {"serial": serial, "time": rep["time_utc"], "product": rel["product"], "version": rel["version"],
                 "variant": rel.get("variant"), "device_class": fleet["device_class"],
                 "sha256": sha256_bytes(image), "code": code, "decision": DECISION_RU[code],
                 "R_min": rep["R_min"], "R_max": rep["R_max"], "run": str(run_dir.relative_to(self.home))}
        with open(self.ledger_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return {"code": code, "decision": DECISION_RU[code], "detail": rep["decision_detail"], "R_min": rep["R_min"],
                "R_max": rep["R_max"], "states": rep["states"], "reasons": rep["reasons"], "receipt": receipt,
                "run": run_dir, "serial": serial}

    def ledger(self) -> list:
        if not self.ledger_path.exists():
            return []
        return [json.loads(x) for x in self.ledger_path.read_text(encoding="utf-8").splitlines() if x.strip()]

    def admitted(self) -> set:
        """Пары (класс устройства, SHA-256 образа), допущенные гейтом."""
        return {(e["device_class"], e["sha256"]) for e in self.ledger() if e["code"] == 0}


__all__ = ["Gate", "GateError", "EXIT", "DECISION_RU", "REJECT", "REQUEST", "REVIEW"]
