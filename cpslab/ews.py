"""Инженерная станция: просмотр программы и загрузка в контроллер; подложная станция нарушителя.

Подложная станция (схема Rogue7) показывает инженеру одну программу, а в контроллер загружает
другую. Отличить их можно только по тому, что исполняет сам контроллер: по дайджесту образа в
его отчёте или по квитанции допуска, без которой контроллер уровня 2 логику не примет.
"""
from __future__ import annotations

import base64
import json
import urllib.request

from .image import read_image
from .program import listing
from .util import http_open, sha256_bytes


def show(image: bytes) -> str:
    manifest, program = read_image(image)
    head = (f"{manifest['title'] or manifest['product']} {manifest['version']} (класс {manifest['device_class']}), "
            f"SHA-256 {sha256_bytes(image)[:16]}…")
    return head + "\n" + listing(program)


class DeviceApi:
    """HTTP-клиент API живого контроллера (device.serve)."""

    def __init__(self, url: str, timeout: float = 30.0):
        self.url, self.timeout = url.rstrip("/"), timeout

    def _call(self, path: str, body: dict = None) -> dict:
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.url + path, data=data, method="GET" if body is None else "POST",
                                     headers={"Content-Type": "application/json"})
        with http_open(req, self.timeout) as r:
            return json.loads(r.read())

    def status(self) -> dict:
        return self._call("/api/status")

    def reports(self) -> list:
        return self._call("/api/reports")

    def check_update(self, _transport=None) -> dict:
        return self._call("/api/update", {})

    def program_download(self, image: bytes, receipt: bytes = None) -> dict:
        return self._call("/api/program", {"image": base64.b64encode(image).decode(),
                                           "receipt": base64.b64encode(receipt).decode() if receipt else None})

    def mgmt(self, command: str, password: str) -> dict:
        return self._call("/api/mgmt", {"command": command, "password": password})

    def reset_process(self, level: float = 50.0) -> dict:
        return self._call("/api/process/reset", {"level": level})


def rogue_download(device, shown: bytes, actual: bytes) -> tuple:
    """Подложная станция: инженер видит shown, в контроллер уходит actual."""
    return show(shown), device.program_download(actual)
