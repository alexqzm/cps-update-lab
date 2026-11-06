"""Образ ПО контроллера: детерминированная сборка и разбор.

Образ — архив tar (USTAR) из двух файлов: manifest.json (изделие, класс устройства, версия,
номер версии svn, дайджест программы) и program.json (программа). Метаданные архива
фиксированы (время — SOURCE_DATE_EPOCH коммита, владелец 0, права 0644), JSON записывается с
упорядоченными ключами, поэтому одна и та же ревизия исходного кода даёт побитово одинаковый
образ на любой машине. Это условие свидетельств s23 и s24 (воспроизводимая и независимая сборка).

Этот файл — «тулчейн» стенда: его SHA-256 закрепляет политика получателя (toolchain_sha256),
и он входит в аттестацию происхождения как зависимость сборки.
"""
from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

from .program import validate
from .util import canonical_json, rjson, sha256_bytes

FORMAT = "cpslab-image/1"
FW_OFFICIAL = 255
MEMBERS = ("manifest.json", "program.json")
MAX_IMAGE = 1 << 20


class ImageError(ValueError):
    """Образ не разбирается или не соответствует формату."""


def svn(version: str, fw_type: int = FW_OFFICIAL) -> int:
    """Номер версии для антиотката, как в квитанции SCII-R v1: major·2^32 + minor·2^16 + patch·2^8 + тип."""
    parts = version.split(".")
    if len(parts) != 3 or not all(x.isdigit() for x in parts):
        raise ValueError(f"версия {version!r} не в виде major.minor.patch")
    major, minor, patch = (int(x) for x in parts)
    if not (0 <= minor < 1 << 16 and 0 <= patch < 1 << 8 and 0 <= major < 1 << 32 and 0 <= fw_type < 1 << 8):
        raise ValueError(f"версия {version} вне допустимых границ")
    return (major << 32) | (minor << 16) | (patch << 8) | fw_type


def _tar(members, mtime: int) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(data), int(mtime), 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def load_product(src: Path, product: str) -> tuple:
    """Описание изделия и программа из дерева исходного кода поставщика."""
    base = Path(src) / "products" / product
    meta, prog = rjson(base / "manifest.json"), rjson(base / "program.json")
    path = Path(src) / "build-aux" / f"{product}.defaults.json"
    if path.exists():
        # «заводские значения», которые процесс выпуска кладёт в архив; в git их нет
        defaults = rjson(path)
        for name, sp in defaults.get("setpoints", {}).items():
            prog.setdefault("setpoints", {}).setdefault(name, {}).update(sp)
        for section in ("rules", "interlocks"):
            if section in defaults:
                prog[section] = defaults[section]
    return meta, prog


def build_image(src: Path, product: str, epoch: int, inject=None) -> bytes:
    """Собрать образ изделия product из дерева src. inject — изменение программы при сборке (атака A3)."""
    meta, prog = load_product(src, product)
    if inject is not None:
        prog = inject(prog)
    validate(prog)
    program = canonical_json(prog)
    manifest = {"format": FORMAT, "product": meta["product"], "title": meta.get("title", ""),
                "device_class": int(meta["device_class"]), "version": meta["version"], "fw_type": FW_OFFICIAL,
                "svn": svn(meta["version"]), "program_sha256": sha256_bytes(program)}
    return _tar([("manifest.json", canonical_json(manifest)), ("program.json", program)], epoch)


def read_image(data: bytes) -> tuple:
    """Разобрать образ: (manifest, program). Любое отклонение от формата — ImageError."""
    if len(data) > MAX_IMAGE:
        raise ImageError("образ больше 1 МиБ")
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tar:
            members = tar.getmembers()
            names = [m.name for m in members]
            if sorted(names) != sorted(MEMBERS) or not all(m.isreg() for m in members):
                raise ImageError(f"в образе должны быть только {', '.join(MEMBERS)}")
            files = {m.name: tar.extractfile(m).read() for m in members}
    except tarfile.TarError as e:
        raise ImageError(f"образ не разбирается: {e}") from e
    try:
        manifest = json.loads(files["manifest.json"])
        program = json.loads(files["program.json"])
    except ValueError as e:
        raise ImageError(f"JSON образа не разбирается: {e}") from e
    if not isinstance(manifest, dict) or not isinstance(program, dict):
        raise ImageError("манифест и программа должны быть объектами JSON")
    if manifest.get("format") != FORMAT:
        raise ImageError(f"формат образа {manifest.get('format')!r}, ожидался {FORMAT}")
    if manifest.get("program_sha256") != sha256_bytes(files["program.json"]):
        raise ImageError("дайджест программы не совпадает с манифестом")
    if not all(isinstance(manifest.get(k), int) for k in ("device_class", "fw_type", "svn")):
        raise ImageError("класс устройства, тип прошивки и svn должны быть целыми")
    try:
        expected_svn = svn(str(manifest.get("version")), manifest["fw_type"])
    except ValueError as e:
        raise ImageError(f"версия образа: {e}") from e
    if manifest["svn"] != expected_svn:
        raise ImageError("номер версии svn не соответствует версии")
    try:
        validate(program)
    except ValueError as e:
        raise ImageError(f"программа: {e}") from e
    return manifest, program


def toolchain_sha256() -> str:
    return sha256_bytes(Path(__file__).read_bytes())
