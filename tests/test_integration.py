"""Интеграционные проверки: полный стенд с cosign, gpg, git, scii-gate и scii-agent."""
import contextlib
import dataclasses
import json
import socket
import time
import urllib.request
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cpslab import cli, hmi, live, monitor, server
from cpslab import device as devmod
from cpslab.attacks import attacker_image
from cpslab.image import svn
from cpslab.receipt import dsse_verify, envelope_digest, issue, parse
from cpslab.report import matrix_markdown, readme_with_table
from cpslab.scenarios import RELEASES, compare, run_matrix

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_GATE = {"tank-1.0.0": 0, "tank-1.1.0": 0, "tank-1.2.0": 0, "pump-1.1.0": 0,
                 "tank-1.1.0-compromised-build": 30, "tank-1.1.0-compromised-build-norebuild": 30,
                 "tank-1.1.0-from-archive": 30, "tank-1.1.0-stolen-key": 30}


def report(lab, key):
    return json.loads((lab.home / lab.admission(key)["run"] / "report.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def outcomes(lab):
    return run_matrix(lab)


def test_matrix_matches_catalog(outcomes):
    assert len(outcomes) == 33
    assert compare(outcomes) == []


def test_results_docs_are_current(lab, outcomes):
    hint = "выполните cpslab scenario matrix --md docs/results.md --readme README.md"
    assert (ROOT / "docs" / "results.md").read_text(encoding="utf-8") == matrix_markdown(lab, outcomes), hint
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert readme == readme_with_table(readme, outcomes), hint


def test_gate_decisions(lab):
    assert set(EXPECTED_GATE) == set(RELEASES)
    for key, code in EXPECTED_GATE.items():
        assert lab.admission(key)["code"] == code, key
        assert (lab.receipt(key) is not None) == (code == 0), key
    st = report(lab, "tank-1.1.0-stolen-key")["states"]
    assert st["s11"] == "F" and st["s14"] == "F" and st["s42"] == "P"     # подпись пакета похищенным ключом верна
    st = report(lab, "tank-1.1.0-compromised-build")["states"]
    assert st["s22"] == "P" and st["s24"] == "F"                          # происхождение подписано, пересборка не сошлась
    rep = report(lab, "tank-1.1.0-compromised-build-norebuild")
    assert rep["states"]["s24"] == "N" and rep["R_max"] < rep["theta"]
    st = report(lab, "tank-1.1.0-from-archive")["states"]
    assert {st[s] for s in ("s21", "s22", "s23", "s24")} == {"F"}


def test_vsa_and_receipt_are_bound(lab):
    for key, code in EXPECTED_GATE.items():
        env = json.loads((lab.home / lab.admission(key)["run"] / "vsa.dsse.json").read_text(encoding="utf-8"))
        vsa = json.loads(dsse_verify(env, lab.keys.gate_pk()))
        assert vsa["predicate"]["verificationResult"] == ("PASSED" if code == 0 else "FAILED")
        assert vsa["predicate"]["policy"]["digest"]["sha256"] == lab.gate.policy_digest.hex()
        if code == 0:
            p = parse(lab.receipt(key))
            assert p.vsa_digest == envelope_digest(env)
            assert p.image_digest.hex() == vsa["subject"][0]["digest"]["sha256"]


def test_agent_reason_codes(lab):
    dev = lab.device("agent", 2, "tank-1.0.0")
    img, rcp = lab.image("tank-1.1.0"), lab.receipt("tank-1.1.0")
    assert dev._agent(img, rcp) == "ADMIT"
    evil = attacker_image(lab.vendor)
    assert len(evil) == len(img) and dev._agent(evil, rcp) == "DIGEST"
    assert dev._agent(img + bytes(512), rcp) == "SIZE"
    assert dev._agent(lab.image("pump-1.1.0"), lab.receipt("pump-1.1.0")) == "TARGET"
    bad = bytearray(rcp)
    bad[-1] ^= 1
    assert dev._agent(img, bytes(bad)) == "SIGNATURE"
    assert dev._agent(img, rcp[:100]) == "FORMAT"
    assert dev._agent(img, issue(Ed25519PrivateKey.generate(), parse(rcp))) == "KEY"
    review = issue(lab.keys.gate_key(), dataclasses.replace(parse(rcp), decision=10))
    assert dev._agent(img, review) == "DECISION"
    dev.config["policy_digest"] = "00" * 32
    assert dev._agent(img, rcp) == "POLICY"
    dev.config["policy_digest"] = lab.gate.policy_digest.hex()
    dev.state["min_policy_epoch"] = lab.gate.epoch + 1
    assert dev._agent(img, rcp) == "POLICY"                  # эпоха политики ниже минимальной
    dev.state["min_policy_epoch"] = lab.gate.epoch
    dev.state["installed_svn"] = svn("1.1.0")
    assert dev._agent(img, rcp) == "ADMIT"                   # scii-agent допускает повторную установку той же версии
    dev.state["installed_svn"] = svn("1.2.0")
    assert dev._agent(img, rcp) == "ROLLBACK"


def test_monitor_detects_tampered_report(lab):
    lab.run("N1", 2)
    root = lab.home / "runs" / "N1-L2" / "device"
    assert monitor.check(root, lab.gate.admitted())["alerts"] == []
    p = root / "reports.jsonl"
    lines = p.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[-1])
    rec["event"]["installed_version"] = "9.9.9"
    lines[-1] = json.dumps(rec, ensure_ascii=False)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert [a["kind"] for a in monitor.check(root, lab.gate.admitted())["alerts"]] == ["bad_report"]


# ---------------- живой стенд: службы на локальных портах ----------------
def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def get(url):
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(url, timeout=10) as r:
        return r.status, r.read()


@contextlib.contextmanager
def running(lab, sid, level):
    """Живой стенд для сценария sid: сервер обновлений, контроллер и HMI на свободных портах."""
    live.prepare(lab, sid, level)
    sport, hport, mport, iport = free_port(), free_port(), free_port(), free_port()
    upd = server.serve(lab.home / "server", host="127.0.0.1", port=sport, background=True)
    srv, mb, stop = devmod.serve(live.device_root(lab), transport=server.HttpTransport(f"http://127.0.0.1:{sport}"),
                                 http_port=hport, modbus_port=mport, host="127.0.0.1", speed=20.0, dt=0.05,
                                 background=True)
    ui = hmi.serve(f"http://127.0.0.1:{hport}", host="127.0.0.1", port=iport, background=True)
    try:
        yield {"url": f"http://127.0.0.1:{hport}", "modbus": ("127.0.0.1", mport), "hmi": f"http://127.0.0.1:{iport}"}
    finally:
        stop.set()
        for s in (srv, mb, upd, ui):
            s.shutdown()
            s.server_close()


@pytest.mark.parametrize("sid, level, expect, process", [
    ("N1", 2, (True, "OK"), "normal"),
    ("A1", 0, (True, "OK"), "overflow"),
    ("A1", 2, (False, "DIGEST"), "normal"),
])
def test_live(lab, sid, level, expect, process):
    with running(lab, sid, level) as st:
        steps = live.run(lab, sid, st["url"], st["modbus"], log=lambda m: None)
        res = steps[-1]["result"]
        assert (res["accepted"], res["reason"]) == expect
        time.sleep(4.0)                       # ≈ 80 с модельного времени: при переливе уровень дойдёт до 100 %
        obs = live.observe(lab, st["url"], 0)
        assert obs["status"]["process"]["outcome"] == process
        alerts = [a["kind"] for a in obs["monitor"]["alerts"]]
        assert alerts == (["not_admitted"] if sid == "A1" and level == 0 else [])
        if not expect[0]:
            assert [w["kind"] for w in obs["monitor"]["warnings"]] == ["rejected"]
        code, body = get(f"{st['hmi']}/")
        assert code == 200 and "<svg" in body.decode()
        code, body = get(f"{st['hmi']}/api/status")
        assert code == 200 and json.loads(body)["name"] == live.DEVICE_NAME


# ---------------- командная строка: команды из лабораторных работ ----------------
def cli_run(lab, capsys, *argv):
    capsys.readouterr()
    code = cli.main(["--home", str(lab.home), *argv])
    out = capsys.readouterr()
    return code, out.out, out.err


def test_cli_offline(lab, capsys):
    code, out, _ = cli_run(lab, capsys, "release", "list")
    assert code == 0 and out.count("квитанция: да") == 4
    code, out, _ = cli_run(lab, capsys, "release", "show", "tank-1.1.0")
    assert code == 0 and '"s22"' in out
    code, out, _ = cli_run(lab, capsys, "gate", "report", "tank-1.1.0-stolen-key")
    assert code == 0 and "отказ (вето)" in out
    code, out, _ = cli_run(lab, capsys, "receipt", "show", "tank-1.1.0")
    rc = json.loads(out)
    assert code == 0 and rc["r_min"] == rc["r_max"] == rc["theta"] == 0.9 and rc["device_class"] == 7001
    code, _, err = cli_run(lab, capsys, "receipt", "show", "tank-1.1.0-stolen-key")
    assert code == 2 and "не выдал квитанцию" in err
    code, out, _ = cli_run(lab, capsys, "image", "show", "tank-1.1.0-from-archive")
    assert code == 0 and "high = 110" in out and "hh = 120" in out
    code, out, _ = cli_run(lab, capsys, "lint", "tank-1.2.0")
    assert code == 0 and "CPS003" in out


def test_cli_live(lab, capsys):
    """ЛР-4, ЛР-5, ЛР-7: Modbus и загрузка логики с инженерной станции на контроллере L2 с ТК-1 1.1.0."""
    with running(lab, "A6", 2) as st:
        target = "%s:%d" % st["modbus"]
        mb = lambda *a: cli_run(lab, capsys, "modbus", "--target", target, *a)  # noqa: E731
        ews = lambda *a: cli_run(lab, capsys, "ews", "download", *a, "--device", st["url"])  # noqa: E731
        assert mb("write", "1", "150")[0] == 0
        assert mb("read", "holding", "0", "3")[1].split() == ["holding[0]", "=", "40", "holding[1]", "=", "80",
                                                              "holding[2]", "=", "85"]
        code, out, _ = ews("tank-1.1.0")
        assert code == 1 and json.loads(out)["reason"] == "NO_RECEIPT"
        code, out, _ = ews("tank-1.1.0", "--receipt", "tank-1.1.0")
        assert code == 0 and json.loads(out)["accepted"] is True
        code, out, _ = ews("tank-1.0.0", "--receipt", "tank-1.0.0")
        assert code == 1 and json.loads(out)["reason"] == "ROLLBACK"
        code, out, _ = ews("tank-1.2.0", "--receipt", "tank-1.2.0")
        assert code == 0 and json.loads(out)["accepted"] is True
        assert mb("write", "100", "48879")[0] == 0
        time.sleep(0.5)                       # правило срабатывает на следующем цикле контроллера
        assert mb("read", "holding", "1", "2")[1].split() == ["holding[1]", "=", "200", "holding[2]", "=", "200"]
        code, _, err = mb("read", "holding", "250", "1")
        assert code == 1 and "исключение Modbus 2" in err
