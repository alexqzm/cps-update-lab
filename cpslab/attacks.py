"""Действия нарушителя в сценариях стенда.

Вредоносная программа снимает блокировку по верхнему уровню и поднимает уставку отключения
насоса выше объёма резервуара: насос не выключается, и резервуар переливается. Изменения
сделаны в пределах формата программы, поэтому такой образ проходит разбор на устройстве.
"""
from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path

from .image import build_image, load_product, read_image
from .receipt import boot_sign
from .util import now_utc, sha256_bytes, wjson
from .vendor import (BUILDER_ID, REPO_URI, T_CDX, T_LINK, T_SLSA, Vendor, attest, export_tree, git, image_name,
                     sign_blob, tag_name)

ARCHIVE_DEFAULTS = {"setpoints": {"high": {"default": 110, "max": 150}, "hh": {"default": 120, "max": 150}}}
BACKDOOR_REGISTER, BACKDOOR_VALUE = 100, 0xBEEF


def malicious(prog: dict) -> dict:
    """Снять блокировку ПАЗ и поднять уставку отключения насоса выше объёма резервуара."""
    p = copy.deepcopy(prog)
    p["interlocks"] = []
    sp = p["setpoints"]["high"]
    sp["default"] = 110
    if "max" in sp:
        sp["max"] = 150
    return p


def attacker_image(vendor: Vendor, product: str = "tank-controller", version: str = "1.1.0") -> bytes:
    """Образ нарушителя: исходный код выпуска поставщика с вредоносной программой, та же метка версии."""
    commit = vendor.commit_of(product, version)
    work = vendor.home / "attacker" / "work" / f"{product}-{version}"
    shutil.rmtree(work, ignore_errors=True)
    tree = export_tree(vendor.src, commit, work)
    return build_image(tree, product, vendor.commit_time(commit), inject=malicious)


def stolen_key_release(vendor: Vendor, product: str = "tank-controller", version: str = "1.1.0",
                       name: str = None) -> Path:
    """Выпуск нарушителя с похищенными ключами подписи поставщика (схемы Stuxnet и ShadowHammer).

    Нарушитель собирает образ сам, подписывает пакет и образ похищенными ключами поставщика, а
    тег — своим ключом OpenPGP. Ключей сборочного агента, хранилища, рецензента, анализа и
    испытаний у него нет: аттестации сборки он подписывает своим ключом.
    """
    keys = vendor.keys
    name = name or f"{product}-{version}-stolen-key"
    out = vendor.releases / name
    if (out / "bundle.json").exists():
        return out
    fork = vendor.home / "attacker" / "fork"
    if not (fork / ".git").exists():
        shutil.rmtree(fork, ignore_errors=True)
        git(vendor.home, "clone", "-q", str(vendor.src), str(fork))
    env = keys.gpg_env()
    env.update({"GIT_AUTHOR_NAME": "Нарушитель", "GIT_AUTHOR_EMAIL": "attacker@cpslab.invalid",
                "GIT_COMMITTER_NAME": "Нарушитель", "GIT_COMMITTER_EMAIL": "attacker@cpslab.invalid",
                "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"})
    tag = tag_name(product, version)
    git(fork, "checkout", "-q", "-B", "evil", tag, env=env)
    image = attacker_image(vendor, product, version)
    tmp = vendor.releases / f".{name}.tmp"
    shutil.rmtree(tmp, ignore_errors=True)
    sd, bd, pd = tmp / "source", tmp / "build", tmp / "package"
    for d in (sd, bd, pd):
        d.mkdir(parents=True)
    # «исправление» в форке: в коммит попадает вредоносная программа
    _meta, prog = load_product(fork, product)
    (fork / "products" / product / "program.json").write_text(
        json.dumps(malicious(prog), ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    git(fork, "commit", "-q", "-am", f"{product} {version}", env=env)
    commit = git(fork, "rev-parse", "HEAD")
    git(fork, "-c", f"user.signingkey={keys.fpr('attacker')}", "-c", "gpg.program=gpg", "tag", "-s", "-f",
        "-m", f"Выпуск {product} {version}", f"evil-{version}", commit, env=env)
    (sd / "commit.txt").write_text(commit + "\n")
    (sd / "commit_object").write_bytes(git(fork, "cat-file", "commit", commit, raw=True))
    (sd / "tag_object").write_bytes(git(fork, "cat-file", "tag", f"refs/tags/evil-{version}", raw=True))
    img = image_name(product, version)
    (bd / img).write_bytes(image)
    src = {"uri": f"git+{REPO_URI}@refs/tags/{tag}", "commit": commit}
    attest(keys, "attacker", T_LINK, {"name": "build", "command": ["cpslab", "build", product],
                                      "materials": [{"uri": src["uri"], "digest": {"gitCommit": commit}}]},
           bd / img, bd / "link.intoto.json")
    attest(keys, "attacker", T_SLSA, {"buildDefinition": {"buildType": "urn:cpslab:buildtype:image:v1",
                                                          "externalParameters": {"source": src}},
                                      "runDetails": {"builder": {"id": BUILDER_ID}}}, bd / img,
           bd / "provenance.intoto.json")
    attest(keys, "attacker", T_CDX, {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}, bd / img,
           bd / "sbom.intoto.json")
    shutil.copy(bd / img, pd / img)
    sign_blob(keys, "vendor", pd / img, pd / f"{img}.sigstore.json")          # похищенный ключ поставщика
    (pd / f"{img}.bootsig").write_bytes(boot_sign(keys.ed25519("vendor_boot"), image))
    ev = {"s11": {"commit_object": "source/commit_object"}, "s14": {"tag_object": "source/tag_object"},
          "s21": {"attestation": "build/link.intoto.json"}, "s22": {"attestation": "build/provenance.intoto.json"},
          "s41": {"attestation": "build/sbom.intoto.json"}, "s42": {"signature": f"package/{img}.sigstore.json"},
          "s51": {"signature": f"package/{img}.bootsig"}, "s52": {"embedded": True}, "s53": {"embedded": True}}
    manifest, _ = read_image(image)
    release = {"product": product, "version": version, "device_class": manifest["device_class"],
               "svn": manifest["svn"], "tag": tag, "commit": commit, "image": img, "sha256": sha256_bytes(image),
               "variant": name, "built": now_utc()}
    wjson(tmp / "bundle.json", {"artifact": f"package/{img}", "build_product_name": img, "release": release,
                                "evidence": ev})
    shutil.rmtree(out, ignore_errors=True)
    tmp.rename(out)
    return out
