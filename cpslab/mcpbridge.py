"""Мост MCP: stdio-сервер Model Context Protocol для подключения ИИ-агента к серверу агента стенда.

Мост ничего не решает сам: он передаёт вызовы инструментов серверу агента (agent_server.py) с ключом
доступа из файла и номером сеанса, а уровни доступа, режим управления и журнал проверяет сервер.
Сообщения — JSON-RPC 2.0, по одному в строке, в stdin и stdout; журнал моста — в stderr.

Поддерживается рукопожатие initialize (версии протокола 2024-11-05 … 2025-11-25), инструменты
(tools/list, tools/call) и ping. Запрос server/discover новых клиентов мост отклоняет кодом
-32601, и клиент переходит к рукопожатию initialize.

Подключение к Claude Code (стенд в docker compose, см. README):
  claude mcp add cpslab -- docker compose -f /путь/к/cps-update-lab/compose.yaml run --rm -T --no-deps \\
      tools mcp --url http://agent-server:8026 --key-file /lab/agent/keys/agent.key
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
import uuid

from . import __version__, i18n
from .util import http_open

PROTOCOL_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
LATEST = PROTOCOL_VERSIONS[-1]
INSTRUCTIONS = i18n.instructions("ru", True)   # по умолчанию; сервер агента присылает свои указания
_MSG = {
    "ru": {"no_link": "нет связи с сервером агента {url}: {e}. Изменяющие команды повторно не отправлены: "
                      "проверьте recipe_status.",
           "error": "ошибка {code}: {message}",
           "limit": "достигнут предел вызовов инструментов в сеансе ({n}); сеанс завершён"},
    "en": {"no_link": "no connection to the agent server {url}: {e}. Mutating commands were not re-sent: "
                      "check recipe_status.",
           "error": "error {code}: {message}",
           "limit": "the session's limit of {n} tool calls is reached; the session is over"},
}


class Bridge:
    def __init__(self, url: str, key: str, session: str = None, timeout: float = 60.0, log=None,
                 max_calls: int = None):
        self.url = url.rstrip("/")
        self.key = key
        self.session = session or f"mcp-{uuid.uuid4().hex[:12]}"
        self.timeout = timeout
        self.log = log or (lambda m: print(f"cpslab-mcp: {m}", file=sys.stderr, flush=True))
        self.max_calls = max_calls
        self.calls = 0
        self._tools = None
        self._instructions = None
        self.lang = "ru"

    def _m(self, key: str, **kw) -> str:
        return _MSG.get(self.lang, _MSG["ru"])[key].format(**kw)

    def _http(self, path: str, body=None) -> dict:
        data = None if body is None else json.dumps(body, ensure_ascii=False).encode()
        req = urllib.request.Request(self.url + path, data=data, method="GET" if body is None else "POST",
                                     headers={"Authorization": f"Bearer {self.key}", "X-Cpslab-Session": self.session,
                                              "Content-Type": "application/json"})
        try:
            with http_open(req, self.timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            try:
                return json.loads(e.read())
            except ValueError:
                return {"ok": False, "error": {"code": f"http_{e.code}", "message": str(e)}}

    def tools(self) -> list:
        if self._tools is None:
            res = self._http("/api/tools")
            if not res.get("ok"):
                raise RuntimeError(f"сервер агента: {res.get('error')}")
            self._instructions = res.get("instructions")
            self.lang = res.get("lang") if res.get("lang") in i18n.LANGS else "ru"
            self._tools = [{"name": t["name"], "description": f"[{t['tier']}] {t['description']}",
                            "inputSchema": t["inputSchema"],
                            "annotations": {"readOnlyHint": not t["mutating"], "destructiveHint": t["mutating"],
                                            "openWorldHint": False}}
                           for t in res["tools"]]
        return self._tools

    def instructions(self) -> str:
        if self._instructions is None:
            try:
                self.tools()
            except (OSError, ValueError, RuntimeError):
                return INSTRUCTIONS
        return self._instructions or INSTRUCTIONS

    def call(self, name: str, args: dict) -> dict:
        if self.max_calls is not None and self.calls >= self.max_calls:
            return {"content": [{"type": "text", "text": self._m("limit", n=self.max_calls)}], "isError": True}
        self.calls += 1
        try:
            res = self._http("/api/call", {"tool": name, "args": args or {}})
        except (OSError, ValueError) as e:
            return {"content": [{"type": "text", "text": self._m("no_link", url=self.url, e=e)}], "isError": True}
        if res.get("ok"):
            return {"content": [{"type": "text", "text": json.dumps(res["result"], ensure_ascii=False, indent=1)}],
                    "isError": False}
        err = res.get("error") or {}
        return {"content": [{"type": "text", "text": self._m("error", code=err.get("code"),
                                                              message=err.get("message"))}],
                "isError": True}

    # ---------------- JSON-RPC ----------------
    def handle(self, msg: dict):
        """Ответ на сообщение (dict) или None для уведомлений."""
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or "method" not in msg:
            return _error(msg.get("id") if isinstance(msg, dict) else None, -32600, "неверный запрос")
        mid, method, params = msg.get("id"), msg["method"], msg.get("params") or {}
        if "id" not in msg:
            return None
        try:
            if method == "initialize":
                want = params.get("protocolVersion")
                return _result(mid, {"protocolVersion": want if want in PROTOCOL_VERSIONS else LATEST,
                                     "capabilities": {"tools": {"listChanged": False}},
                                     "serverInfo": {"name": "cpslab-agent-bridge", "title": "cps-update-lab",
                                                    "version": __version__},
                                     "instructions": self.instructions()})
            if method == "ping":
                return _result(mid, {})
            if method == "tools/list":
                return _result(mid, {"tools": self.tools()})
            if method == "tools/call":
                name = params.get("name")
                if name not in {t["name"] for t in self.tools()}:
                    return _error(mid, -32602, f"нет инструмента {name}")
                return _result(mid, self.call(name, params.get("arguments") or {}))
            return _error(mid, -32601, f"метод {method} не поддерживается")
        except RuntimeError as e:
            return _error(mid, -32603, str(e))


def _result(mid, result) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _error(mid, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def serve_stdio(bridge: Bridge, stdin=None, stdout=None) -> None:
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout.buffer
    bridge.log(f"сеанс {bridge.session}, сервер агента {bridge.url}")
    for raw in stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            out = _error(None, -32700, "сообщение не JSON")
        else:
            out = bridge.handle(msg) if not isinstance(msg, list) else _error(None, -32600, "пакеты не поддерживаются")
        if out is not None:
            stdout.write(json.dumps(out, ensure_ascii=False).encode() + b"\n")
            stdout.flush()


def load_key(key_file: str = None) -> str:
    if key_file:
        with open(key_file, encoding="utf-8") as f:
            return f.read().strip()
    key = os.environ.get("CPSLAB_AGENT_KEY")
    if not key:
        raise SystemExit("cpslab mcp: нужен --key-file или переменная CPSLAB_AGENT_KEY")
    return key


__all__ = ["Bridge", "serve_stdio", "load_key", "PROTOCOL_VERSIONS"]
