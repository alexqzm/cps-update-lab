"""Поставщик ПО контроллеров: git-репозиторий, сборка образов и комплект свидетельств для гейта.

Конвейер выпуска повторяет конвейер стенда ArduPilot из scii-gate (testbed/pipeline.py) для
образа контроллера: подписанные коммит и тег, рецензирование, статический анализ и испытания,
привязанные к коммиту; ссылка шага in-toto, SLSA provenance, SBOM и пересборка, привязанные к
образу; подписанный журнал хранилища; подпись пакета cosign и подпись образа для загрузчика.

Варианты выпуска для сценариев нарушителя:
  compromised_build — сборочный агент меняет программу во время сборки (схема SolarWinds);
  independent=False — без контрольной пересборки независимым сборщиком;
  from_archive      — сборка из выпускного архива с файлом, которого нет в теге (схема xz).
"""
from __future__ import annotations

import io
import json
import shutil
import tarfile
import uuid
from pathlib import Path

from . import __version__
from .image import FORMAT as IMAGE_FORMAT, build_image, load_product, read_image, toolchain_sha256
from .program import FORMAT as PROGRAM_FORMAT
from .quality import functional_tests, lint
from .receipt import boot_sign
from .util import DATA_DIR, cosign, cosign_env, now_utc, rjson, run, sha256_bytes, wjson

VENDOR_NAME, VENDOR_EMAIL = "Учебный поставщик", "vendor@cpslab.invalid"
REPO_URI = "https://vendor.cpslab.invalid/controllers.git"
ARCHIVE_URI = "https://vendor.cpslab.invalid/releases/"
BUILDER_ID = "urn:cpslab:builder:v1"
INDEP_ID = "urn:cpslab:independent-rebuilder:v1"
T_LINK = "https://in-toto.io/attestation/link/v0.3"
T_SLSA = "https://slsa.dev/provenance/v1"
T_CDX = "https://cyclonedx.org/bom"
T_TEST = "https://in-toto.io/attestation/test-result/v0.1"
T_SAST = "urn:scii:predicate:sast:v1"
T_REVIEW = "urn:scii:predicate:review:v1"
T_REBUILD = "urn:scii:predicate:rebuild:v1"
SBOM_DEPENDENCIES = {"cpslab-image-format": IMAGE_FORMAT, "cpslab-program-format": PROGRAM_FORMAT}

HISTORY = (
    {"date": "2026-01-15T10:00:00+03:00", "message": "ТК-1 1.0.0: первый выпуск",
     "products": {"tank-controller": "1.0.0"}},
    {"date": "2026-03-02T10:00:00+03:00",
     "message": "ТК-1 1.1.0: ограничены уставки high и hh, записываемые по Modbus; НС-2 1.1.0: первый выпуск",
     "products": {"tank-controller": "1.1.0", "pump-station": "1.1.0"}},
    {"date": "2026-05-20T10:00:00+03:00", "message": "ТК-1 1.2.0: сервисный режим поставщика",
     "products": {"tank-controller": "1.2.0"}},
)
TEMPLATE = DATA_DIR / "vendor-src"


def tag_name(product: str, version: str) -> str:
    return f"{product}/v{version}"


def image_name(product: str, version: str) -> str:
    return f"{product}-{version}.img"


def git(repo, *args, env=None, raw=False):
    r = run(["git", "-C", repo, *args], env=env, text=not raw)
    return r.stdout if raw else r.stdout.strip()


def attest(keys, role: str, ptype: str, predicate: dict, blob: Path, out: Path) -> Path:
    """DSSE-аттестация in-toto с подписью ключом роли (cosign attest-blob, без журнала прозрачности)."""
    out.parent.mkdir(parents=True, exist_ok=True)
    pfile = out.with_name(out.name + ".predicate.json")
    wjson(pfile, predicate)
    run([cosign(), "attest-blob", "--key", keys.cosign_key(role), "--predicate", pfile, "--type", ptype,
         "--tlog-upload=false", "--yes", "--output-signature", out, blob], env=cosign_env())
    pfile.unlink()
    return out


def sign_blob(keys, role: str, blob: Path, out: Path) -> Path:
    run([cosign(), "sign-blob", "--key", keys.cosign_key(role), "--tlog-upload=false", "--yes", "--bundle", out,
         blob], env=cosign_env())
    return out


def export_tree(repo: Path, commit: str, dst: Path) -> Path:
    """Дерево коммита без рабочей копии (git archive)."""
    data = git(repo, "archive", "--format=tar", commit, raw=True)
    dst.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        t.extractall(dst, filter="data")
    return dst


class Vendor:
    def __init__(self, home: Path, keys):
        self.home = Path(home)
        self.keys = keys
        self.src = self.home / "vendor" / "src"
        self.releases = self.home / "vendor" / "releases"
        self.work = self.home / "vendor" / "work"

    # ---------------- репозиторий ----------------
    def _git_identity(self, date: str = None) -> dict:
        env = self.keys.gpg_env()
        env.update({"GIT_AUTHOR_NAME": VENDOR_NAME, "GIT_AUTHOR_EMAIL": VENDOR_EMAIL,
                    "GIT_COMMITTER_NAME": VENDOR_NAME, "GIT_COMMITTER_EMAIL": VENDOR_EMAIL,
                    "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"})
        if date:
            env.update({"GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date})
        return env

    def _signing(self) -> list:
        return ["-c", f"user.signingkey={self.keys.fpr('vendor')}", "-c", "gpg.format=openpgp",
                "-c", "gpg.program=gpg"]

    def init_repo(self) -> Path:
        if (self.src / ".git").exists():
            return self.src
        self.src.mkdir(parents=True, exist_ok=True)
        env = self._git_identity()
        git(self.src, "init", "-q", "-b", "main", env=env)
        shutil.copy(TEMPLATE / "README.md", self.src / "README.md")
        for step in HISTORY:
            for product, version in step["products"].items():
                pdir = self.src / "products" / product
                pdir.mkdir(parents=True, exist_ok=True)
                meta = rjson(TEMPLATE / "products" / product / "manifest.json")
                meta["version"] = version
                wjson(pdir / "manifest.json", meta)
                shutil.copy(TEMPLATE / "history" / product / f"{version}.json", pdir / "program.json")
                shutil.copy(TEMPLATE / "products" / product / "tests.json", pdir / "tests.json")
            env = self._git_identity(step["date"])
            git(self.src, "add", "-A", env=env)
            git(self.src, *self._signing(), "commit", "-q", "-S", "-m", step["message"], env=env)
            for product, version in step["products"].items():
                git(self.src, *self._signing(), "tag", "-s", "-m", f"Выпуск {product} {version}",
                    tag_name(product, version), env=env)
        return self.src

    def commit_of(self, product: str, version: str, repo: Path = None) -> str:
        return git(repo or self.src, "rev-parse", f"{tag_name(product, version)}^{{commit}}")

    def commit_time(self, commit: str, repo: Path = None) -> int:
        return int(git(repo or self.src, "log", "-1", "--format=%ct", commit))

    # ---------------- выпуск ----------------
    def release(self, product: str, version: str, *, name: str = None, inject=None, independent: bool = True,
                from_archive: dict = None) -> Path:
        """Собрать выпуск и комплект свидетельств. Результат кэшируется в vendor/releases/<name>."""
        name = name or f"{product}-{version}"
        out = self.releases / name
        if (out / "bundle.json").exists():
            return out
        tmp = self.releases / f".{name}.tmp"
        shutil.rmtree(tmp, ignore_errors=True)
        work = self.work / name
        shutil.rmtree(work, ignore_errors=True)
        commit = self.commit_of(product, version)
        epoch = self.commit_time(commit)
        tag = tag_name(product, version)
        img_name = image_name(product, version)
        ev = {}

        # --- стадия источника: коммит, тег, рецензирование, анализ, испытания ---
        sd = tmp / "source"
        sd.mkdir(parents=True)
        (sd / "commit.txt").write_text(commit + "\n")
        (sd / "commit_object").write_bytes(git(self.src, "cat-file", "commit", commit, raw=True))
        (sd / "tag_object").write_bytes(git(self.src, "cat-file", "tag", f"refs/tags/{tag}", raw=True))
        ev["s11"] = {"commit_object": "source/commit_object"}
        ev["s14"] = {"tag_object": "source/tag_object"}
        tree = export_tree(self.src, commit, work / "tree")
        _meta, prog = load_product(tree, product)
        src_ref = {"uri": f"git+{REPO_URI}@refs/tags/{tag}", "commit": commit}
        blob = sd / "commit.txt"
        review = {"result": "APPROVED", "change": {"uri": REPO_URI, "commit": commit, "tag": tag},
                  "reviewers": ["Учебный поставщик: ведущий инженер"], "reviewedOn": now_utc()}
        attest(self.keys, "reviewer", T_REVIEW, review, blob, sd / "review.intoto.json")
        rep = lint(prog)
        rep["source"] = src_ref
        attest(self.keys, "sast", T_SAST, rep, blob, sd / "sast.intoto.json")
        suite_path = tree / "products" / product / "tests.json"
        tests = functional_tests(prog, rjson(suite_path))
        test_pred = {"result": tests["result"], "configuration": [
            {"name": "cpslab.quality.functional_tests", "digest": {"sha256": sha256_bytes(
                (Path(__file__).parent / "quality.py").read_bytes())}},
            {"name": f"products/{product}/tests.json", "digest": {"sha256": sha256_bytes(suite_path.read_bytes())}}],
            "passedTests": tests["passedTests"], "warnedTests": [], "failedTests": tests["failedTests"],
            "cases": tests["cases"], "source": src_ref}
        attest(self.keys, "tester", T_TEST, test_pred, blob, sd / "tests.intoto.json")
        for sid, f in (("s12", "review"), ("s13", "sast"), ("s43", "tests")):
            ev[sid] = {"subject": "source/commit.txt", "attestation": f"source/{f}.intoto.json"}

        # --- стадия сборки ---
        bd = tmp / "build"
        bd.mkdir()
        if from_archive is not None:
            archive = self._release_archive(commit, product, version, from_archive)
            (sd / archive["name"]).write_bytes(archive["data"])
            input_ref = {"uri": ARCHIVE_URI + archive["name"], "digest": {"sha256": sha256_bytes(archive["data"])}}
            material = input_ref
            build_src = lambda d: self._extract_archive(archive, d)  # noqa: E731
        else:
            input_ref = src_ref
            material = {"uri": src_ref["uri"], "digest": {"gitCommit": commit}}
            build_src = lambda d: export_tree(self.src, commit, d)  # noqa: E731
        started = now_utc()
        image = build_image(build_src(work / "build1"), product, epoch, inject=inject)
        finished = now_utc()
        digest = sha256_bytes(image)
        (bd / img_name).write_bytes(image)
        manifest, _ = read_image(image)
        toolchain = {"name": "toolchain", "uri": "cpslab/image.py", "digest": {"sha256": toolchain_sha256()}}
        link = {"name": "build", "command": ["cpslab", "build", product],
                "materials": [material], "byproducts": {},
                "environment": {"builder": BUILDER_ID, "cpslab": __version__}}
        prov = {"buildDefinition": {
                    "buildType": "urn:cpslab:buildtype:image:v1",
                    "externalParameters": {"source": input_ref, "product": product},
                    "internalParameters": {"SOURCE_DATE_EPOCH": epoch},
                    "resolvedDependencies": [toolchain]},
                "runDetails": {"builder": {"id": BUILDER_ID},
                               "metadata": {"invocationId": f"{name}-{uuid.uuid4()}", "startedOn": started,
                                            "finishedOn": finished}}}
        bom = {"bomFormat": "CycloneDX", "specVersion": "1.5",
               "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, 'cpslab:' + digest)}", "version": 1,
               "metadata": {"timestamp": now_utc(),
                            "tools": {"components": [{"type": "application", "name": "cpslab", "version": __version__}]},
                            "component": {"type": "firmware", "name": product, "version": version,
                                          "hashes": [{"alg": "SHA-256", "content": digest}]}},
               "components": [{"type": "library", "name": k, "version": v} for k, v in SBOM_DEPENDENCIES.items()]
               + [{"type": "application", "name": "cpslab-build", "version": __version__,
                   "hashes": [{"alg": "SHA-256", "content": toolchain_sha256()}]}]}
        wjson(bd / "sbom.cdx.json", bom)
        attest(self.keys, "builder", T_LINK, link, bd / img_name, bd / "link.intoto.json")
        attest(self.keys, "builder", T_SLSA, prov, bd / img_name, bd / "provenance.intoto.json")
        attest(self.keys, "builder", T_CDX, bom, bd / img_name, bd / "sbom.intoto.json")
        ev["s21"] = {"attestation": "build/link.intoto.json"}
        ev["s22"] = {"attestation": "build/provenance.intoto.json"}
        ev["s41"] = {"attestation": "build/sbom.intoto.json"}
        # воспроизводимость: сборочный агент собирает второй раз в чистом каталоге тем же процессом
        again = build_image(build_src(work / "build2"), product, epoch, inject=inject)
        attest(self.keys, "builder", T_REBUILD, self._rebuild_pred(input_ref, again, digest, BUILDER_ID),
               bd / img_name, bd / "repro.intoto.json")
        ev["s23"] = {"attestation": "build/repro.intoto.json"}
        if independent:
            # контрольная пересборка: свой клон, проверка подписи тега, сборка из тега без изменений
            clone = work / "indep"
            run(["git", "clone", "-q", "--no-checkout", self.src, clone], env=self._git_identity())
            git(clone, "verify-tag", tag, env=self.keys.gpg_env())
            rebuilt = build_image(export_tree(clone, commit, work / "indep-tree"), product, epoch)
            attest(self.keys, "independent_builder", T_REBUILD,
                   self._rebuild_pred(src_ref, rebuilt, digest, INDEP_ID), bd / img_name,
                   bd / "rebuild-independent.intoto.json")
            ev["s24"] = {"attestation": "build/rebuild-independent.intoto.json"}

        # --- хранилище артефактов ---
        rd = tmp / "repository"
        rd.mkdir()
        entry = {"seq": 1, "name": img_name, "sha256": digest, "uploader": "builder", "time": now_utc()}
        (rd / "log.jsonl").write_text(json.dumps(entry, ensure_ascii=False) + "\n")
        sign_blob(self.keys, "repository", rd / "log.jsonl", rd / "log.sigstore.json")
        ev["s31"] = ev["s32"] = {"log": "repository/log.jsonl", "signature": "repository/log.sigstore.json"}

        # --- пакет: подпись поставщика и подпись образа для загрузчика ---
        pd = tmp / "package"
        pd.mkdir()
        shutil.copy(bd / img_name, pd / img_name)
        sign_blob(self.keys, "vendor", pd / img_name, pd / f"{img_name}.sigstore.json")
        (pd / f"{img_name}.bootsig").write_bytes(boot_sign(self.keys.ed25519("vendor_boot"), image))
        ev["s42"] = {"signature": f"package/{img_name}.sigstore.json"}
        ev["s51"] = {"signature": f"package/{img_name}.bootsig"}
        ev["s52"] = {"embedded": True}
        ev["s53"] = {"embedded": True}

        release = {"product": product, "version": version, "device_class": manifest["device_class"],
                   "svn": manifest["svn"], "tag": tag, "commit": commit, "image": img_name, "sha256": digest,
                   "variant": name}
        wjson(tmp / "bundle.json", {"artifact": f"package/{img_name}", "build_product_name": img_name,
                                    "release": release, "evidence": ev})
        shutil.rmtree(out, ignore_errors=True)
        tmp.rename(out)
        shutil.rmtree(work, ignore_errors=True)
        return out

    @staticmethod
    def _rebuild_pred(source: dict, rebuilt: bytes, candidate: str, builder_id: str) -> dict:
        rd = sha256_bytes(rebuilt)
        return {"source": source, "toolchain": {"uri": "cpslab/image.py", "sha256": toolchain_sha256()},
                "builder": {"id": builder_id}, "rebuilt": {"sha256": rd}, "candidate": {"sha256": candidate},
                "result": "MATCH" if rd == candidate else "MISMATCH", "finishedOn": now_utc()}

    def _release_archive(self, commit: str, product: str, version: str, defaults: dict) -> dict:
        """Выпускной архив: дерево тега плюс build-aux/<изделие>.defaults.json, которого в git нет."""
        prefix = f"{product}-{version}/"
        data = git(self.src, "archive", "--format=tar", f"--prefix={prefix}", commit, raw=True)
        out = io.BytesIO()
        with tarfile.open(fileobj=io.BytesIO(data)) as tin, tarfile.open(fileobj=out, mode="w:gz") as tout:
            for m in tin.getmembers():
                tout.addfile(m, tin.extractfile(m) if m.isreg() else None)
            extra = (json.dumps(defaults, ensure_ascii=False, indent=1) + "\n").encode()
            info = tarfile.TarInfo(f"{prefix}build-aux/{product}.defaults.json")
            info.size, info.mode, info.mtime = len(extra), 0o644, self.commit_time(commit)
            tout.addfile(info, io.BytesIO(extra))
        return {"name": f"{product}-{version}.tar.gz", "data": out.getvalue(), "prefix": prefix}

    @staticmethod
    def _extract_archive(archive: dict, dst: Path) -> Path:
        dst.mkdir(parents=True, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(archive["data"]), mode="r:gz") as t:
            t.extractall(dst, filter="data")
        return dst / archive["prefix"].rstrip("/")


def release_info(release_dir: Path) -> dict:
    return rjson(Path(release_dir) / "bundle.json")["release"]


def package_files(release_dir: Path) -> dict:
    """Файлы пакета обновления, которые поставщик публикует на сервере обновлений."""
    rel = release_info(release_dir)
    pd = Path(release_dir) / "package"
    return {"release": rel, "image": (pd / rel["image"]).read_bytes(),
            "bootsig": (pd / f"{rel['image']}.bootsig").read_bytes(),
            "sigstore": (pd / f"{rel['image']}.sigstore.json").read_bytes()}


