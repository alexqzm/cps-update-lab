"""Сервер обновлений: каталог каналов по классам устройств и HTTP-доступ к нему.

Канал класса устройства — каталог <корень>/<класс>/ с файлами release.json, image.bin,
image.bootsig, image.sigstore.json и, если гейт допустил выпуск, receipt.scr. Поставщик публикует
пакет, гейт прикладывает квитанцию. Нарушитель в сценариях пишет в тот же каталог: это модель
скомпрометированного сервера обновлений.
"""
from __future__ import annotations

import json
import re
import threading
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .util import canonical_json, http_open, sha256_bytes

FILES = ("release.json", "image.bin", "image.bootsig", "image.sigstore.json", "receipt.scr")
_PATH = re.compile(r"^/updates/(\d{1,10})/([a-z.]+)$")


class UpdateStore:
    def __init__(self, root: Path):
        self.root = Path(root)

    def channel(self, device_class: int) -> Path:
        return self.root / str(int(device_class))

    def publish(self, files: dict, device_class: int = None) -> Path:
        """Опубликовать пакет поставщика; прежняя квитанция удаляется (она относилась к другому образу)."""
        rel = files["release"]
        ch = self.channel(device_class if device_class is not None else rel["device_class"])
        ch.mkdir(parents=True, exist_ok=True)
        (ch / "image.bin").write_bytes(files["image"])
        (ch / "image.bootsig").write_bytes(files["bootsig"])
        (ch / "image.sigstore.json").write_bytes(files["sigstore"])
        (ch / "release.json").write_bytes(canonical_json(rel))
        (ch / "receipt.scr").unlink(missing_ok=True)
        return ch

    def attach_receipt(self, device_class: int, receipt: bytes, image_sha256: str) -> bool:
        """Приложить квитанцию, если в канале лежит именно допущенный образ."""
        ch = self.channel(device_class)
        img = ch / "image.bin"
        if not img.exists() or sha256_bytes(img.read_bytes()) != image_sha256:
            return False
        (ch / "receipt.scr").write_bytes(receipt)
        return True

    def write(self, device_class: int, name: str, data: bytes) -> None:
        if name not in FILES:
            raise ValueError(f"недопустимое имя файла {name}")
        ch = self.channel(device_class)
        ch.mkdir(parents=True, exist_ok=True)
        (ch / name).write_bytes(data)

    def fetch(self, device_class: int) -> dict:
        ch = self.channel(device_class)
        if not (ch / "release.json").exists():
            return {}
        out = {"release": json.loads((ch / "release.json").read_text(encoding="utf-8"))}
        for key, name in (("image", "image.bin"), ("bootsig", "image.bootsig"), ("receipt", "receipt.scr")):
            out[key] = (ch / name).read_bytes() if (ch / name).exists() else None
        return out


class HttpTransport:
    """Клиент сервера обновлений для устройства в режиме живого стенда."""

    def __init__(self, base_url: str, timeout: float = 10.0):
        self.base, self.timeout = base_url.rstrip("/"), timeout

    def _get(self, device_class: int, name: str):
        try:
            with http_open(f"{self.base}/updates/{int(device_class)}/{name}", self.timeout) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise

    def fetch(self, device_class: int) -> dict:
        rel = self._get(device_class, "release.json")
        if rel is None:
            return {}
        return {"release": json.loads(rel), "image": self._get(device_class, "image.bin"),
                "bootsig": self._get(device_class, "image.bootsig"), "receipt": self._get(device_class, "receipt.scr")}


class _Handler(BaseHTTPRequestHandler):
    server_version = "cpslab-update-server/0.1"

    def do_GET(self):  # noqa: N802
        m = _PATH.match(self.path)
        if m and m.group(2) in FILES:
            f = self.server.store.channel(int(m.group(1))) / m.group(2)
            if f.is_file():
                data = f.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/json" if f.suffix == ".json" else "application/octet-stream")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
        self.send_error(404)

    def log_message(self, fmt, *args):
        pass


def serve(root: Path, host: str = "0.0.0.0", port: int = 8000, background: bool = False):
    srv = ThreadingHTTPServer((host, port), _Handler)
    srv.store = UpdateStore(root)
    if background:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv
    srv.serve_forever()
