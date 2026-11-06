"""Общие помощники стенда: дайджесты, JSON, запуск внешних инструментов, каталоги."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import urllib.request
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
DATA_DIR = PACKAGE_DIR / "data"


class ToolError(RuntimeError):
    """Внешний инструмент не найден или завершился с ошибкой."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical_json(obj) -> bytes:
    """JSON с упорядоченными ключами: одинаковое содержимое даёт одинаковые байты."""
    return (json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=1) + "\n").encode("utf-8")


def wjson(path, obj) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(obj))
    return path


def rjson(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def lab_home(explicit=None) -> Path:
    """Рабочий каталог стенда: ключи, репозиторий поставщика, выпуски, гейт, устройства."""
    return Path(explicit or os.environ.get("CPSLAB_HOME") or Path.cwd() / "work").resolve()


def tool(name: str, env_var: str) -> str:
    path = os.environ.get(env_var) or shutil.which(name)
    if not path:
        raise ToolError(f"не найден {name}: установите его или задайте путь в {env_var}")
    return path


def cosign() -> str:
    return tool("cosign", "CPSLAB_COSIGN")


def scii_agent() -> str:
    return tool("scii-agent", "CPSLAB_SCII_AGENT")


def gpg() -> str:
    return tool("gpg", "CPSLAB_GPG")


def run(cmd, *, env=None, cwd=None, check=True, timeout=180, input=None, text=True):
    try:
        r = subprocess.run([str(c) for c in cmd], capture_output=True, env=env, cwd=cwd, timeout=timeout,
                           input=input, text=text)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise ToolError(f"{Path(str(cmd[0])).name}: {e}") from e
    if check and r.returncode != 0:
        err = r.stderr if text else r.stderr.decode("utf-8", "replace")
        raise ToolError(f"{Path(str(cmd[0])).name} {' '.join(map(str, cmd[1:3]))}: {err.strip()[-600:]}")
    return r


def cosign_env() -> dict:
    env = dict(os.environ)
    env["COSIGN_PASSWORD"] = ""
    return env


_DIRECT = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def http_open(req, timeout: float):
    """HTTP между службами стенда: напрямую, без системного прокси."""
    return _DIRECT.open(req, timeout=timeout)
