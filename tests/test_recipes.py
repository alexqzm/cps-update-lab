"""Канал рецептов: формат и проверка рецепта, исполнение, двойник, журнал, сервер агента, мост MCP,
гейт рецептов и матрица сценариев RN1–RM2."""
import importlib.util
import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from cpslab.agent_server import AgentError, AgentServer, serve
from cpslab.journal import Journal
from cpslab.plant import Tank
from cpslab.program import Controller
from cpslab.recipe import RecipeRun, digest, dry_run, parse, validate

from conftest import need_tools

ROOT = Path(__file__).resolve().parents[1]
PROG_110 = json.loads((ROOT / "cpslab/data/vendor-src/history/tank-controller/1.1.0.json").read_text(encoding="utf-8"))
PROG_120 = json.loads((ROOT / "cpslab/data/vendor-src/history/tank-controller/1.2.0.json").read_text(encoding="utf-8"))
ACCEPT = [{"kind": "reach", "band": [75, 80], "within": 90}, {"kind": "hold", "band": [40, 80], "seconds": 120},
          {"kind": "range", "min": 20, "max": 85}]


def batch(rev=1, prefix=()):
    return {"format": "cpslab-recipe/1", "name": "batch-prep", "revision": rev, "title": "Партия",
            "target": {"product": "tank-controller", "device_class": 7001, "program_min": "1.1.0"},
            "work_order": "WO-1",
            "steps": [*prefix, {"op": "set", "setpoint": "low", "value": 45}, {"op": "set", "setpoint": "high", "value": 78},
                      {"op": "wait", "until": ["level", ">=", 75], "timeout": 63}, {"op": "hold", "seconds": 120},
                      {"op": "check", "that": ["level", ">=", 40]}, {"op": "check", "that": ["level", "<=", 80]},
                      {"op": "set", "setpoint": "low", "value": 40}, {"op": "set", "setpoint": "high", "value": 60}]}


DRAIN = [{"op": "pump", "mode": "off"}, {"op": "hold", "seconds": 120}, {"op": "pump", "mode": "auto"}]


# ---------------- формат, проверка, исполнение ----------------
def test_validate_accepts_batch_and_denies_undescribed():
    assert validate(batch(), PROG_110)["valid"]
    bad = batch(prefix=[{"op": "set", "setpoint": "hr100", "value": 48879}])
    msgs = [f["message"] for f in validate(bad, PROG_110)["findings"] if f["severity"] == "error"]
    assert any("hr100" in m for m in msgs)
    r = batch()
    r["steps"][1]["value"] = 95                           # high вне 50…80
    assert not validate(r, PROG_110)["valid"]
    r = batch()
    r["steps"].append({"op": "jump", "to": 1})
    assert not validate(r, PROG_110)["valid"]
    assert not validate({"format": "cpslab-recipe/1", "name": "x", "revision": 0, "steps": []}, PROG_110)["valid"]


def test_parse_is_minimal_on_executor():
    data = json.dumps(batch(prefix=[{"op": "set", "setpoint": "hr100", "value": 48879}])).encode()
    assert parse(data)["name"] == "batch-prep"          # исполнитель L0 не проверяет уставки
    with pytest.raises(ValueError):
        parse(b'{"format": "other"}')


def _run(recipe, prog=PROG_110, level=40.0, q_out=1.0, seconds=300.0):
    tank, ctl = Tank(level=level, q_out=q_out), Controller(prog)
    rr = RecipeRun(recipe, ctl)
    for _ in range(int(seconds / 0.5)):
        rr.tick(tank.level, 0.5)
        tank.step(ctl.scan(tank.level), 0.5)
    return tank, rr, ctl


def test_recipe_run_completes_and_restores_auto():
    tank, rr, ctl = _run(batch())
    assert rr.status == "completed" and rr.quality == "ok"
    assert tank.outcome() == "normal" and ctl.manual is None
    assert ctl.setpoints["low"] == 40 and ctl.setpoints["high"] == 60


def test_manual_pump_off_drains_tank_and_wait_times_out():
    tank, rr, _ = _run(batch(prefix=DRAIN))
    assert tank.emptied and rr.status == "failed" and rr.quality == "out_of_spec"


def test_interlock_keeps_priority_in_manual_mode():
    tank, rr, ctl = _run({"format": "cpslab-recipe/1", "name": "fill", "revision": 1,
                          "steps": [{"op": "pump", "mode": "on"}, {"op": "hold", "seconds": 200}]}, level=50)
    assert tank.max_level < 90 and not tank.overflowed  # hh = 85 по умолчанию, ПАЗ сильнее ручного режима


def test_backdoor_register_through_recipe_on_120():
    tank, rr, _ = _run(batch(prefix=[{"op": "set", "setpoint": "hr100", "value": 48879}]), prog=PROG_120)
    assert tank.overflowed


def test_dry_run_checks_safety_and_acceptance():
    ok = dry_run(batch(), PROG_110, 40.0, acceptance=ACCEPT)
    assert ok["ok"] and all(a["ok"] for a in ok["acceptance"])
    bad = dry_run(batch(prefix=DRAIN), PROG_110, 40.0, acceptance=ACCEPT)
    assert not bad["ok"] and not bad["safe"] and "резервуар опустошён" in bad["problems"]
    drift = dry_run({"format": "cpslab-recipe/1", "name": "drain", "revision": 1,
                     "steps": [{"op": "pump", "mode": "off"}, {"op": "hold", "seconds": 40}, {"op": "pump", "mode": "auto"}]},
                    PROG_110, 75.0)
    assert drift["ok"]                                   # с номинальным расходом слив безопасен


def test_journal_chain_detects_edit(tmp_path):
    j = Journal(tmp_path / "j.jsonl")
    for i in range(3):
        j.append({"tool": "t", "n": i})
    assert j.verify()["ok"]
    lines = (tmp_path / "j.jsonl").read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[1])
    rec["n"] = 42
    lines[1] = json.dumps(rec, ensure_ascii=False, sort_keys=True)
    (tmp_path / "j.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert j.verify() == {"ok": False, "entries": 2, "broken_at": 2}


# ---------------- сервер агента ----------------
class FakeDevice:
    def __init__(self):
        self.runs, self.cmds, self.level = [], [], 2

    def status(self):
        return {"name": "plc-test", "device_class": 7001, "instance": "00" * 16, "level": self.level,
                "level_title": "квитанция гейта SCII", "controller": "работает",
                "installed": {"product": "tank-controller", "version": "1.1.0", "sha256": "ab" * 32},
                "process": {"level": 40.0, "pump": False, "alarms": []}, "recipe": None}

    def program(self):
        return {"manifest": {"product": "tank-controller", "version": "1.1.0"}, "program": PROG_110, "sha256": "ab" * 32}

    def run_recipe(self, data, receipt, source):
        self.runs.append((data, receipt, source))
        return {"accepted": receipt is not None or self.level < 2, "reason": "OK" if receipt or self.level < 2 else "NO_RECEIPT"}

    def abort_recipe(self):
        return {"accepted": False, "reason": "NO_RECIPE"}

    def recipe_state(self):
        return None

    def command(self, command, args):
        self.cmds.append((command, args))
        return {"accepted": True, "reason": "OK"}

    def reports(self, n):
        return []


@pytest.fixture()
def agent(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    srv = AgentServer(tmp_path / "agent", FakeDevice(), attest_key=Ed25519PrivateKey.generate()).init()
    srv.archive.write("notes.txt", "журнал смены\n")
    keys = {t: srv.add_key(t.lower(), t) for t in ("Read", "Recipe", "Manual")}
    return srv, keys


def test_tiers_mode_and_ceilings(agent):
    srv, k = agent
    assert srv.call(k["Read"], "describe_machine")["session_tier"] == "Read"
    with pytest.raises(AgentError) as e:
        srv.call(k["Read"], "upload_recipe", {"recipe": batch()})
    assert e.value.code == "tier_denied"
    with pytest.raises(AgentError) as e:
        srv.call(k["Recipe"], "upload_recipe", {"recipe": batch()})
    assert e.value.code == "control_mode"                # режим local: изменяющие команды недоступны
    srv.set_mode("remote")
    assert srv.call(k["Recipe"], "upload_recipe", {"recipe": batch()})["revision"] == 1
    with pytest.raises(AgentError) as e:                 # Manual срезан потолком allow_manual = false
        srv.call(k["Manual"], "device_command", {"command": "pump", "args": {"mode": "off"}})
    assert e.value.code == "tier_denied"
    srv.set_ceiling(allow_manual=True)
    assert srv.call(k["Manual"], "device_command", {"command": "pump", "args": {"mode": "off"}})["accepted"]
    with pytest.raises(AgentError) as e:
        srv.call("неверный ключ", "describe_machine")
    assert e.value.code == "unauthorized"


def test_revision_is_immutable_and_upload_is_attested(agent):
    srv, k = agent
    srv.set_mode("remote")
    s = "sess-1"
    srv.call(k["Recipe"], "read_document", {"name": "notes.txt"}, s)
    up = srv.call(k["Recipe"], "upload_recipe", {"recipe": batch()}, s)
    att = json.loads((srv.root / up["path"]).with_name("batch-prep-r1.authoring.json").read_text(encoding="utf-8"))
    from cpslab import documents as docs
    st = docs.payload_obj(att)
    assert st["subject"][0]["digest"]["sha256"] == digest(batch())
    assert [m["name"] for m in st["predicate"]["materials"]] == ["notes.txt"]
    with pytest.raises(AgentError) as e:
        srv.call(k["Recipe"], "upload_recipe", {"recipe": batch(prefix=DRAIN)}, s)
    assert e.value.code == "revision_exists"
    assert srv.journal.verify()["ok"]


def test_l1_server_validation_and_l2_receipt(agent):
    srv, k = agent
    srv.set_mode("remote")
    srv.call(k["Recipe"], "upload_recipe", {"recipe": batch(prefix=[{"op": "set", "setpoint": "hr100", "value": 1}])})
    srv.device.level = 1
    assert srv.call(k["Recipe"], "start_recipe", {"name": "batch-prep"})["reason"] == "INVALID"
    srv.device.level = 2
    assert srv.call(k["Recipe"], "start_recipe", {"name": "batch-prep"})["reason"] == "NO_RECEIPT"


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _rpc(proc, msg):
    proc.stdin.write((json.dumps(msg) + "\n").encode())
    proc.stdin.flush()
    if "id" not in msg:
        return None
    return json.loads(proc.stdout.readline())


def test_mcp_bridge_stdio_protocol(agent, tmp_path):
    srv, k = agent
    port = _free_port()
    http = serve(srv, port=port, background=True)
    kf = tmp_path / "key"
    kf.write_text(k["Read"])
    proc = subprocess.Popen([sys.executable, "-m", "cpslab", "mcp", "--url", f"http://127.0.0.1:{port}", "--key-file",
                             str(kf)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            cwd=ROOT)
    try:
        assert _rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "server/discover"})["error"]["code"] == -32601
        init = _rpc(proc, {"jsonrpc": "2.0", "id": 2, "method": "initialize",
                           "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                      "clientInfo": {"name": "test", "version": "0"}}})
        assert init["result"]["protocolVersion"] == "2025-06-18"
        assert init["result"]["capabilities"]["tools"] == {"listChanged": False}
        _rpc(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        tools = _rpc(proc, {"jsonrpc": "2.0", "id": 3, "method": "tools/list"})["result"]["tools"]
        names = {t["name"] for t in tools}
        assert {"describe_machine", "validate_recipe", "dry_run", "upload_recipe", "device_command"} <= names
        r = _rpc(proc, {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                        "params": {"name": "validate_recipe", "arguments": {"recipe": batch()}}})["result"]
        assert not r["isError"] and json.loads(r["content"][0]["text"])["valid"]
        r = _rpc(proc, {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                        "params": {"name": "upload_recipe", "arguments": {"recipe": batch()}}})["result"]
        assert r["isError"] and "tier_denied" in r["content"][0]["text"]
        assert _rpc(proc, {"jsonrpc": "2.0", "id": 6, "method": "ping"})["result"] == {}
        assert _rpc(proc, {"jsonrpc": "2.0", "id": 7, "method": "resources/list"})["error"]["code"] == -32601
    finally:
        proc.stdin.close()
        proc.wait(timeout=10)
        http.shutdown()
    sessions = {e["session"] for e in srv.journal.entries()}
    assert any(s.startswith("mcp-") for s in sessions)


@pytest.mark.skipif(importlib.util.find_spec("mcp") is None, reason="нужен пакет mcp (официальный SDK клиента)")
def test_mcp_bridge_with_official_client(agent, tmp_path):
    import anyio
    from mcp import Client, StdioServerParameters
    srv, k = agent
    port = _free_port()
    http = serve(srv, port=port, background=True)
    kf = tmp_path / "key"
    kf.write_text(k["Read"])

    async def go():
        params = StdioServerParameters(command=sys.executable, cwd=str(ROOT),
                                       args=["-m", "cpslab", "mcp", "--url", f"http://127.0.0.1:{port}",
                                             "--key-file", str(kf)])
        async with Client(params) as c:
            tools = await c.list_tools()
            names = {t.name for t in tools.tools}
            res = await c.call_tool("describe_machine", {})
            return names, res
    try:
        names, res = anyio.run(go)
    finally:
        http.shutdown()
    assert "dry_run" in names
    assert not res.is_error and json.loads(res.content[0].text)["session_tier"] == "Read"


# ---------------- гейт рецептов и сценарии ----------------
@pytest.fixture(scope="module")
def rlab(lab):
    from cpslab.recipe_lab import RecipeLab
    return RecipeLab(lab).init(progress=lambda m: None)


@need_tools
def test_reference_recipe_sets_theta(rlab):
    a = rlab.state()["scenarios"]["RN1"]["admissions"]["recipe"]
    assert a["decision"] == "допуск" and a["receipt"]
    assert abs(a["R_min"] - 0.8) < 1e-9 and {k for k, v in a["states"].items() if v != "P"} == {"q33"}
    from scii.model import Profile
    from cpslab.recipe_gate import PROFILE
    assert Profile.load(str(PROFILE)).theta == pytest.approx(a["R_min"])


@need_tools
def test_receipt_binds_recipe_device_and_revision(rlab):
    from cpslab.receipt import parse as parse_receipt
    from cpslab.recipe_lab import instance_of
    a = rlab.state()["scenarios"]["RA4"]["admissions"]
    rp = parse_receipt((rlab.home / a["recipe"]["run"] / "receipt.scr").read_bytes())
    old = parse_receipt((rlab.home / a["history"]["run"] / "receipt.scr").read_bytes())
    assert (rp.svn, old.svn) == (2, 1) and rp.device_class == 7001 and rp.device_instance == instance_of("RA4")
    assert rp.policy_digest == rlab.gate.policy_digest


@need_tools
def test_evidence_states_of_attacks(rlab):
    st = {sid: s["admissions"]["recipe"]["states"] for sid, s in rlab.state()["scenarios"].items()
          if "recipe" in s["admissions"]}
    assert st["RA1"]["q32"] == "F" and st["RA1"]["q22"] == "F"
    assert st["RA2"]["q12"] == "F" and st["RA2"]["q22"] == "N"
    assert st["RA3"]["q41"] == "N" and st["RA3"]["q21"] == "P"      # ключ подлинный: аутентификация ≠ утверждение
    assert st["RA6"]["q22"] == "F"
    assert st["RA7"]["q31"] == "F"


@need_tools
def test_recipe_matrix_matches_catalog(rlab):
    from cpslab.recipe_lab import compare, run_matrix
    outs = run_matrix(rlab)
    assert len(outs) == 30
    assert compare(outs) == []
