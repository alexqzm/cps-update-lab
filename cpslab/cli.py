"""Командная строка стенда: cpslab <команда>.

Подготовка и сценарии в модельном времени:
  cpslab init                         ключи, репозиторий поставщика, выпуски, решения гейта
  cpslab doctor                       проверить инструменты (cosign, gpg, git, scii-agent, scii-gate)
  cpslab scenario list
  cpslab scenario run A1 [--level 0|1|2]
  cpslab scenario matrix [--md FILE] [--json FILE] [--check]
  cpslab release list | show КЛЮЧ     выпуски стенда и решения гейта | комплект свидетельств выпуска
  cpslab gate report КЛЮЧ             отчёт гейта по выпуску
  cpslab image show | receipt show | lint  ФАЙЛ или КЛЮЧ выпуска

Живой стенд (сервисы docker compose):
  cpslab server serve | cpslab device serve | cpslab hmi serve
  cpslab live prepare A1 --level 2    очистить сервер обновлений, ввести контроллер с исходным выпуском
  cpslab live run A1                  действия поставщика, гейта и нарушителя против живого стенда
  cpslab live status | cpslab live monitor
  cpslab live recipe-demo --observe 45  канал рецептов на живом стенде: агент, оператор, гейт, контроллер
  cpslab modbus read holding 0 3 | cpslab modbus write 1 150     клиент Modbus/TCP (--target device:5020)
  cpslab ews download КЛЮЧ [--receipt КЛЮЧ]                     загрузка логики с инженерной станции

Канал рецептов ИИ-агента:
  cpslab recipes list | run RA1 [--level 0|1|2] | matrix [--md FILE] [--readme README.md] [--check]
  cpslab recipe validate ФАЙЛ [--program КЛЮЧ] | dry-run ФАЙЛ --start 40 [--work-order ФАЙЛ]
  cpslab recipe report RA1            отчёт гейта рецептов по рецепту сценария
  cpslab recipe approve ИМЯ [--revision N] --device URL   оператор: утвердить рецепт и получить решение гейта
  cpslab recipe safety ИМЯ --result APPROVED|REJECTED      инженер по безопасности: заключение q33
  cpslab agent serve --device URL     сервер агента (порт 8026)
  cpslab agent key ИМЯ --tier Read|Recipe|Manual | mode remote|local | journal [--verify]
  cpslab mcp --url URL --key-file ФАЙЛ   мост MCP (stdio) для ИИ-агента
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

from . import __version__
from .util import ToolError, lab_home


def _lab(args):
    from .scenarios import Lab
    return Lab(lab_home(args.home))


def cmd_init(args) -> int:
    from . import live
    lab = _lab(args)
    lab.init(progress=lambda m: print(f"· {m}", flush=True))
    ag = live.setup_agent(lab)
    print(f"· сервер агента: {ag['root']}, ключи {', '.join(ag['keys'])}, режим {ag['mode']}")
    st = json.loads((lab.home / "lab.json").read_text(encoding="utf-8"))
    print(f"стенд готов: {lab.home}")
    for k, v in st["admissions"].items():
        print(f"  {k:<42} гейт: {v['decision']} (R_min {v['R_min']:.3f})")
    return 0


def cmd_doctor(args) -> int:
    from .util import cosign, gpg, scii_agent
    ok = True
    for name, get, ver in (("cosign", cosign, ["version"]), ("gpg", gpg, ["--version"]),
                           ("git", lambda: shutil.which("git") or "git", ["--version"]),
                           ("scii-agent", scii_agent, None)):
        try:
            path = get()
            if ver is None:
                print(f"  {name:<11} {path}")
                continue
            r = subprocess.run([path, *ver], capture_output=True, text=True, timeout=30)
            line = next((ln for ln in (r.stdout + r.stderr).splitlines() if ln.strip()), "")
            if name == "cosign":
                line = next((ln for ln in (r.stdout + r.stderr).splitlines() if "GitVersion" in ln), line)
            print(f"  {name:<11} {path}  {line.strip()[:60]}")
        except (ToolError, OSError) as e:
            ok = False
            print(f"  {name:<11} НЕТ: {e}")
    try:
        import scii
        print(f"  {'scii-gate':<11} {scii.__file__}  {scii.__version__}")
    except ImportError as e:
        ok = False
        print(f"  {'scii-gate':<11} НЕТ: {e}")
    return 0 if ok else 1


def _fmt(o) -> str:
    gate = "—" if o.gate is None else str(o.gate)
    return (f"{o.scenario:<4} L{o.level}  {'принято' if o.accepted else 'отказ':<8} {o.reason:<12} "
            f"процесс: {o.process:<8} тревога: {'да' if o.alert else 'нет':<3} гейт: {gate:<3} работает: {o.running}")


def cmd_scenario(args) -> int:
    from .scenarios import LEVELS, as_dict, catalog, compare, run_matrix
    cat = catalog()
    if args.action == "list":
        for sid, s in cat.items():
            print(f"{sid:<4} ЛР-{s['lab']}  {s['title']}")
        return 0
    lab = _lab(args)
    lab.init(progress=lambda m: print(f"· {m}", flush=True))
    if args.action == "run":
        if args.id not in cat:
            print(f"нет сценария {args.id}", file=sys.stderr)
            return 2
        levels = LEVELS if args.level is None else (args.level,)
        outs = [lab.run(args.id, lv) for lv in levels]
        sc = cat[args.id]
        print(f"{args.id}: {sc['title']}\n{' '.join(sc['summary'].split())}\n")
        for o in outs:
            print(_fmt(o))
            for a in o.details["monitor"]["alerts"]:
                print(f"       монитор: {a['message']}")
        if args.json:
            print(json.dumps([as_dict(o) for o in outs], ensure_ascii=False, indent=1))
        diffs = compare(outs)
        if diffs:
            print("\nрасхождения с ожидаемым:", json.dumps(diffs, ensure_ascii=False))
        return 1 if diffs else 0
    # matrix
    outs = run_matrix(lab)
    for o in outs:
        print(_fmt(o))
    diffs = compare(outs)
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps([as_dict(o) for o in outs], ensure_ascii=False, indent=1) + "\n",
                                   encoding="utf-8")
    from .report import matrix_markdown, readme_with_table
    stale = []
    for path, make in ((args.md, lambda: matrix_markdown(lab, outs)),
                       (args.readme, lambda: readme_with_table(Path(args.readme).read_text(encoding="utf-8"), outs))):
        if not path:
            continue
        text = make()
        cur = Path(path).read_text(encoding="utf-8") if Path(path).exists() else ""
        if args.check and cur != text:
            stale.append(path)
        elif not args.check and cur != text:
            Path(path).write_text(text, encoding="utf-8")
    if stale:
        print(f"устарели: {', '.join(stale)}; выполните cpslab scenario matrix --md docs/results.md --readme README.md",
              file=sys.stderr)
        return 1
    if diffs:
        print("\nрасхождения с ожидаемым:\n" + json.dumps(diffs, ensure_ascii=False, indent=1))
        return 1
    print(f"\nсовпали с ожидаемыми: {len(outs)} из {len(outs)} исходов")
    return 0


def cmd_release(args) -> int:
    lab = _lab(args)
    if not (lab.home / "lab.json").exists():
        raise ToolError(f"стенд не подготовлен: cpslab init (рабочий каталог {lab.home})")
    st = json.loads((lab.home / "lab.json").read_text(encoding="utf-8"))
    from .vendor import release_info
    if args.action == "show":
        if args.key not in st["admissions"]:
            raise ToolError(f"нет выпуска {args.key}: cpslab release list")
        d = lab.release(args.key)
        b = json.loads((d / "bundle.json").read_text(encoding="utf-8"))
        print(f"каталог выпуска: {d}\nрешение гейта: {lab.home / st['admissions'][args.key]['run']}")
        print(json.dumps({"release": b["release"], "artifact": b["artifact"], "evidence": b["evidence"]},
                         ensure_ascii=False, indent=1))
        return 0
    for key, adm in st["admissions"].items():
        rel = release_info(lab.release(key))
        print(f"{key:<42} {rel['sha256'][:16]}…  гейт: {adm['decision']:<20} R_min {adm['R_min']:.3f}  "
              f"квитанция: {'да' if adm['receipt'] else 'нет'}")
    return 0


def cmd_gate(args) -> int:
    lab = _lab(args)
    if not (lab.home / "lab.json").exists():
        raise ToolError(f"стенд не подготовлен: cpslab init (рабочий каталог {lab.home})")
    adm = json.loads((lab.home / "lab.json").read_text(encoding="utf-8"))["admissions"]
    if args.key not in adm:
        raise ToolError(f"нет выпуска {args.key}: cpslab release list")
    if adm[args.key]["run"] is None:
        print(f"{adm[args.key]['decision']}: {adm[args.key].get('error')}")
        return 0
    print((lab.home / adm[args.key]["run"] / "report.md").read_text(encoding="utf-8"))
    return 0


def _artifact(args, kind: str) -> bytes:
    """Файл или ключ выпуска стенда (cpslab release list): образ или квитанция этого выпуска."""
    p = Path(args.file)
    if p.is_file():
        return p.read_bytes()
    from .scenarios import RELEASES
    if args.file not in RELEASES:
        raise ToolError(f"нет файла {args.file} и нет выпуска с таким ключом (cpslab release list)")
    lab = _lab(args)
    if not (lab.home / "lab.json").exists():
        raise ToolError(f"стенд не подготовлен: cpslab init (рабочий каталог {lab.home})")
    if kind == "image":
        return lab.image(args.file)
    r = lab.receipt(args.file)
    if r is None:
        raise ToolError(f"гейт не выдал квитанцию для выпуска {args.file}")
    return r


def cmd_image(args) -> int:
    from .ews import show
    print(show(_artifact(args, "image")))
    return 0


def cmd_receipt(args) -> int:
    from .receipt import parse
    print(json.dumps(parse(_artifact(args, "receipt")).describe(), ensure_ascii=False, indent=1))
    return 0


def cmd_lint(args) -> int:
    from .image import read_image
    from .quality import lint
    _m, prog = read_image(_artifact(args, "image"))
    print(json.dumps(lint(prog), ensure_ascii=False, indent=1))
    return 0


# ---------------- живой стенд ----------------
MODBUS_TABLES = {"coils": 1, "discrete": 2, "holding": 3, "input": 4}
MODBUS_ERRORS = {1: "недопустимая функция", 2: "недопустимый адрес", 3: "недопустимое значение",
                 4: "отказ устройства (нет программы)"}


def cmd_modbus(args) -> int:
    from .modbus import ModbusClient, ModbusError
    host, _, port = args.target.partition(":")
    c = ModbusClient(host, int(port or 5020))
    try:
        if args.action == "read":
            for i, v in enumerate(c.read(MODBUS_TABLES[args.table], args.addr, args.count)):
                print(f"{args.table}[{args.addr + i}] = {int(v)}")
        elif len(args.values) == 1:
            c.write_register(args.addr, args.values[0])
            print(f"holding[{args.addr}] ← {args.values[0]}")
        else:
            c.write_registers(args.addr, args.values)
            print(f"holding[{args.addr}…{args.addr + len(args.values) - 1}] ← {' '.join(map(str, args.values))}")
    except ModbusError as e:
        print(f"исключение Modbus {e.code}: {MODBUS_ERRORS.get(e.code, '')}", file=sys.stderr)
        return 1
    except OSError as e:
        raise ToolError(f"Modbus {args.target}: {e}") from e
    return 0


def cmd_ews(args) -> int:
    """Инженерная станция: показать программу или загрузить образ в контроллер мимо канала обновления."""
    from .ews import DeviceApi, show
    image = _artifact(argparse.Namespace(file=args.image, home=args.home), "image")
    if args.action == "show":
        print(show(image))
        return 0
    receipt = _artifact(argparse.Namespace(file=args.receipt, home=args.home), "receipt") if args.receipt else None
    res = DeviceApi(args.device).program_download(image, receipt)
    print(json.dumps(res, ensure_ascii=False, indent=1))
    return 0 if res.get("accepted") else 1


def cmd_server(args) -> int:
    from .server import serve
    root = lab_home(args.home) / "server"
    root.mkdir(parents=True, exist_ok=True)
    print(f"сервер обновлений: каталог {root}, порт {args.port}", flush=True)
    serve(root, port=args.port)
    return 0


def cmd_device(args) -> int:
    from . import live
    from .device import serve
    from .server import HttpTransport
    lab = _lab(args)
    root = live.device_root(lab, args.name)
    if not (root / "config.json").exists():
        lab.init(progress=lambda m: print(f"· {m}", flush=True))
        live.provision(lab, args.name, args.level if args.level is not None else 2)
    if args.level is not None:
        from .device import Device
        Device(root).set_level(args.level)
    print(f"контроллер {args.name}: HTTP {args.http_port}, Modbus {args.modbus_port}, обновления {args.update_url}",
          flush=True)
    serve(root, transport=HttpTransport(args.update_url), http_port=args.http_port, modbus_port=args.modbus_port,
          speed=args.speed)
    return 0


def cmd_hmi(args) -> int:
    from .hmi import serve
    print(f"HMI: порт {args.port}, контроллер {args.device}", flush=True)
    serve(args.device, port=args.port)
    return 0


def cmd_live(args) -> int:
    from . import live
    from .ews import DeviceApi
    lab = _lab(args)
    if args.action == "prepare":
        lab.init(progress=lambda m: print(f"· {m}", flush=True))
        print(json.dumps(live.prepare(lab, args.id, args.level, args.name), ensure_ascii=False))
        return 0
    if args.action == "run":
        host, _, port = args.modbus.partition(":")
        live.run(lab, args.id, args.device, (host, int(port or 5020)))
        if args.observe:
            res = live.observe(lab, args.device, args.observe, args.name)
            p = res["status"]["process"]
            print(f"\nчерез {args.observe:g} с: уровень {p['level']} %, насос {'вкл' if p['pump'] else 'выкл'}, "
                  f"аварии: {', '.join(p['alarms']) or 'нет'}; работает: {res['status']['installed']['version'] or '—'}")
            for a in res["monitor"]["alerts"]:
                print(f"монитор: {a['message']}")
        return 0
    if args.action == "status":
        print(json.dumps(DeviceApi(args.device).status(), ensure_ascii=False, indent=1))
        return 0
    if args.action == "monitor":
        from . import monitor
        print(json.dumps(monitor.check(live.device_root(lab, args.name), lab.gate.admitted(),
                                       lab.recipe_gate.admitted()), ensure_ascii=False, indent=1))
        return 0
    if args.action == "recipe-demo":
        res = live.recipe_demo(lab, args.agent, args.device, args.observe)
        ok = res.get("gate") == 0 and (res.get("recipe") or {}).get("quality") == "ok"
        return 0 if ok else 1
    return 2


# ---------------- канал рецептов ----------------
def _recipe_lab(args):
    from .recipe_lab import RecipeLab
    return RecipeLab(_lab(args))


def _rfmt(o) -> str:
    gate = "—" if o.gate is None else str(o.gate)
    q = {"ok": "в норме", "out_of_spec": "брак", None: "—"}[o.quality]
    return (f"{o.scenario:<4} L{o.level}  {'принято' if o.accepted else 'отказ':<8} {o.reason:<11} "
            f"процесс: {o.process:<8} партия: {q:<7} тревога: {'да' if o.alert else 'нет':<3} гейт: {gate}")


def cmd_recipes(args) -> int:
    from .recipe_lab import LEVELS, as_dict, catalog, compare, run_matrix
    cat = catalog()
    if args.action == "list":
        for sid, s in cat.items():
            print(f"{sid:<4} ЛР-{s['lab']}  {s['title']}")
        return 0
    rl = _recipe_lab(args)
    rl.init(progress=lambda m: print(f"· {m}", flush=True))
    if args.action == "run":
        if args.id not in cat:
            print(f"нет сценария {args.id}", file=sys.stderr)
            return 2
        outs = [rl.run(args.id, lv) for lv in (LEVELS if args.level is None else (args.level,))]
        sc = cat[args.id]
        print(f"{args.id}: {sc['title']}\n{' '.join(sc['summary'].split())}\n")
        for o in outs:
            print(_rfmt(o))
            rs = o.details.get("recipe") or {}
            if rs.get("reason"):
                print(f"       рецепт: {rs['reason']}")
            for a in o.details["monitor"]["alerts"]:
                print(f"       монитор: {a['message']}")
        if args.json:
            print(json.dumps([as_dict(o) for o in outs], ensure_ascii=False, indent=1))
        diffs = compare(outs)
        if diffs:
            print("\nрасхождения с ожидаемым:", json.dumps(diffs, ensure_ascii=False))
        return 1 if diffs else 0
    outs = run_matrix(rl)
    for o in outs:
        print(_rfmt(o))
    diffs = compare(outs)
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps([as_dict(o) for o in outs], ensure_ascii=False, indent=1) + "\n",
                                   encoding="utf-8")
    from .report import readme_with_recipe_table, recipe_matrix_markdown
    stale = []
    for path, make in ((args.md, lambda: recipe_matrix_markdown(rl, outs)),
                       (args.readme, lambda: readme_with_recipe_table(Path(args.readme).read_text(encoding="utf-8"),
                                                                      outs))):
        if not path:
            continue
        text = make()
        cur = Path(path).read_text(encoding="utf-8") if Path(path).exists() else ""
        if cur != text:
            if args.check:
                stale.append(path)
            else:
                Path(path).write_text(text, encoding="utf-8")
    if stale:
        print(f"устарели: {', '.join(stale)}; выполните cpslab recipes matrix --md docs/results-recipes.md "
              f"--readme README.md", file=sys.stderr)
        return 1
    if diffs:
        print("\nрасхождения с ожидаемым:\n" + json.dumps(diffs, ensure_ascii=False, indent=1))
        return 1
    print(f"\nсовпали с ожидаемыми: {len(outs)} из {len(outs)} исходов")
    return 0


def _program_for(args):
    if not args.program:
        return None
    from .image import read_image
    return read_image(_artifact(argparse.Namespace(file=args.program, home=args.home), "image"))[1]


def cmd_recipe(args) -> int:
    from .recipe import dry_run, validate
    if args.action == "validate":
        res = validate(json.loads(Path(args.target).read_text(encoding="utf-8")), _program_for(args))
        print(json.dumps(res, ensure_ascii=False, indent=1))
        return 0 if res["valid"] else 1
    if args.action == "dry-run":
        prog = _program_for(args)
        if prog is None:
            raise ToolError("для пробного прогона нужна программа контроллера: --program tank-1.1.0")
        acc = []
        if args.work_order:
            from . import documents as docs
            wo = json.loads(Path(args.work_order).read_text(encoding="utf-8"))
            acc = (docs.payload_obj(wo) if docs.is_envelope(wo) else wo).get("acceptance", [])
        res = dry_run(json.loads(Path(args.target).read_text(encoding="utf-8")), prog, args.start, acceptance=acc)
        print(json.dumps({k: v for k, v in res.items() if k != "plant"}, ensure_ascii=False, indent=1))
        return 0 if res["ok"] else 1
    lab = _lab(args)
    if args.action == "report":
        rl = _recipe_lab(args)
        st = rl.state()["scenarios"]
        if args.target not in st:
            raise ToolError(f"нет подготовленного сценария {args.target}: cpslab recipes matrix")
        for label, a in st[args.target]["admissions"].items():
            print(f"## {args.target}: {label}\n")
            print((lab.home / a["run"] / "report.md").read_text(encoding="utf-8"))
        return 0
    from . import live
    if args.action == "safety":
        from . import documents as docs
        from .recipestore import RecipeStore
        from .util import wjson
        path = RecipeStore(live.agent_root(lab) / "recipes").find(args.target, args.revision)
        if path is None:
            raise ToolError(f"нет рецепта {args.target}")
        r = json.loads(path.read_bytes())
        from .recipe import digest
        body = {"recipe": {"name": r["name"], "revision": r["revision"], "sha256": digest(r)},
                "result": args.result, "by": "инженер по безопасности", "comment": args.comment or ""}
        out = RecipeStore.sidecar(path, "safety")
        wjson(out, docs.sign(lab.keys.ed25519("safety_engineer"), docs.SAFETY_REVIEW, body))
        print(f"заключение {args.result} для {path.name}: {out}")
        return 0
    # approve: оператор утверждает рецепт живого стенда, гейт рецептов принимает решение
    from .agent_server import HttpDevice
    from .recipe_lab import RecipeLab
    from .recipestore import RecipeStore
    root = live.agent_root(lab)
    path = RecipeStore(root / "recipes").find(args.target, args.revision)
    if path is None:
        raise ToolError(f"нет рецепта {args.target} в {root / 'recipes'}")
    dev = HttpDevice(args.device)
    st, pi = dev.status(), dev.program()
    fleet = {"device": st["name"], "device_class": st["device_class"], "instance": st.get("instance"),
             "product": (pi.get("manifest") or {}).get("product"),
             "program_version": (pi.get("manifest") or {}).get("version"), "program": pi.get("program"),
             "level": st["process"]["level"]}

    class _Dev:                                   # утверждение привязано к имени устройства
        config = {"name": st["name"]}
    if not args.no_approve:
        RecipeLab(lab).approve(root, path, _Dev, args.work_order)
    res = lab.recipe_gate.admit(lab.recipe_gate.assemble(root, path, fleet))
    print(f"{path.name}: гейт рецептов — {res['decision']} (R_min {res['R_min']:.3f}, R_max {res['R_max']:.3f}), "
          f"квитанция: {'выдана' if res['receipt'] else 'нет'}")
    for k, v in res["states"].items():
        print(f"  {k} {v}  {res['reasons'].get(k, '')}")
    return 0 if res["code"] == 0 else 1


def cmd_agent(args) -> int:
    from . import live
    from .agent_server import AgentServer, HttpDevice, serve
    from .journal import Journal
    lab = _lab(args)
    root = live.agent_root(lab)
    if args.action == "serve":
        if not (root / "server.json").exists():
            lab.init(progress=lambda m: print(f"· {m}", flush=True))
            live.setup_agent(lab)
        srv = AgentServer(root, HttpDevice(args.device), attest_key=lab.keys.ed25519("agent_server"),
                          plant=lab.recipe_gate.policy.get("plant"))
        print(f"сервер агента: {args.host}:{args.port}, контроллер {args.device}, режим {srv.mode()}", flush=True)
        serve(srv, host=args.host, port=args.port)
        return 0
    srv = AgentServer(root, None)
    if args.action == "key":
        if not args.name:
            raise ToolError("укажите имя ключа: cpslab agent key ИМЯ --tier Recipe")
        key = srv.init().add_key(args.name, args.tier, args.folder)
        kf = root / "keys" / f"{args.name}.key"
        kf.parent.mkdir(parents=True, exist_ok=True)
        kf.write_text(key + "\n")
        print(f"ключ {args.name} ({args.tier}) записан в {kf}")
        return 0
    if args.action == "mode":
        if args.name not in ("remote", "local"):
            print(f"режим управления: {srv.mode()}")
            return 0
        srv.set_mode(args.name, "оператор (cpslab agent mode)")
        print(f"режим управления: {args.name}")
        return 0
    if args.action == "ceiling":
        srv.set_ceiling(allow_manual=args.name == "manual")
        print(json.dumps({k: v for k, v in srv.config().items() if k != "keys"}, ensure_ascii=False))
        return 0
    j = Journal(root / "journal.jsonl")
    if args.verify:
        res = j.verify()
        print(json.dumps(res, ensure_ascii=False))
        return 0 if res["ok"] else 1
    for e in j.entries()[-(args.count or 20):]:
        print(json.dumps(e, ensure_ascii=False))
    return 0


def cmd_mcp(args) -> int:
    from .mcpbridge import Bridge, load_key, serve_stdio
    serve_stdio(Bridge(args.url, load_key(args.key_file)))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="cpslab", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    ap.add_argument("--home", help="рабочий каталог стенда (по умолчанию $CPSLAB_HOME или ./work)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init", help="подготовить стенд").set_defaults(func=cmd_init)
    sub.add_parser("doctor", help="проверить инструменты").set_defaults(func=cmd_doctor)

    sc = sub.add_parser("scenario", help="сценарии в модельном времени")
    sc.add_argument("action", choices=["list", "run", "matrix"])
    sc.add_argument("id", nargs="?")
    sc.add_argument("--level", type=int, choices=[0, 1, 2])
    sc.add_argument("--json")
    sc.add_argument("--md")
    sc.add_argument("--readme", help="обновить таблицу исходов в README между метками results:begin/end")
    sc.add_argument("--check", action="store_true", help="с --md/--readme: проверить, что файлы актуальны, не перезаписывая")
    sc.set_defaults(func=cmd_scenario)

    p = sub.add_parser("release", help="выпуски и решения гейта")
    p.add_argument("action", choices=["list", "show"])
    p.add_argument("key", nargs="?")
    p.set_defaults(func=cmd_release)
    g = sub.add_parser("gate", help="отчёт гейта")
    g.add_argument("action", choices=["report"])
    g.add_argument("key")
    g.set_defaults(func=cmd_gate)
    for name, fn, helptext in (("image", cmd_image, "показать образ"), ("receipt", cmd_receipt, "разобрать квитанцию")):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("action", choices=["show"])
        p.add_argument("file", help="файл или ключ выпуска стенда")
        p.set_defaults(func=fn)
    p = sub.add_parser("lint", help="статический анализ программы образа")
    p.add_argument("file", help="файл образа или ключ выпуска стенда")
    p.set_defaults(func=cmd_lint)

    p = sub.add_parser("server", help="сервер обновлений")
    p.add_argument("action", choices=["serve"])
    p.add_argument("--port", type=int, default=8000)
    p.set_defaults(func=cmd_server)
    p = sub.add_parser("device", help="контроллер")
    p.add_argument("action", choices=["serve"])
    p.add_argument("--name", default="plc-1")
    p.add_argument("--level", type=int, choices=[0, 1, 2])
    p.add_argument("--update-url", default="http://update-server:8000")
    p.add_argument("--http-port", type=int, default=8080)
    p.add_argument("--modbus-port", type=int, default=5020, help="порт Modbus/TCP (на реальных ПЛК — 502)")
    p.add_argument("--speed", type=float, default=5.0, help="ускорение модельного времени процесса")
    p.set_defaults(func=cmd_device)
    p = sub.add_parser("hmi", help="веб-интерфейс оператора")
    p.add_argument("action", choices=["serve"])
    p.add_argument("--device", default="http://device:8080")
    p.add_argument("--port", type=int, default=8081)
    p.set_defaults(func=cmd_hmi)
    p = sub.add_parser("modbus", help="клиент Modbus/TCP: чтение и запись регистров контроллера")
    p.add_argument("--target", default="device:5020", help="хост:порт контроллера")
    ms = p.add_subparsers(dest="action", required=True)
    r = ms.add_parser("read", help="прочитать регистры")
    r.add_argument("table", choices=list(MODBUS_TABLES))
    r.add_argument("addr", type=int)
    r.add_argument("count", type=int, nargs="?", default=1)
    w = ms.add_parser("write", help="записать регистры хранения")
    w.add_argument("addr", type=int)
    w.add_argument("values", type=int, nargs="+")
    p.set_defaults(func=cmd_modbus)
    p = sub.add_parser("ews", help="инженерная станция: показать или загрузить программу в контроллер")
    p.add_argument("action", choices=["show", "download"])
    p.add_argument("image", help="файл образа или ключ выпуска стенда")
    p.add_argument("--receipt", help="квитанция: файл или ключ выпуска (по умолчанию без квитанции)")
    p.add_argument("--device", default="http://device:8080")
    p.set_defaults(func=cmd_ews)
    p = sub.add_parser("recipes", help="сценарии канала рецептов ИИ-агента в модельном времени")
    p.add_argument("action", choices=["list", "run", "matrix"])
    p.add_argument("id", nargs="?")
    p.add_argument("--level", type=int, choices=[0, 1, 2])
    p.add_argument("--json")
    p.add_argument("--md")
    p.add_argument("--readme", help="обновить таблицу рецептов в README между метками recipes:begin/end")
    p.add_argument("--check", action="store_true", help="проверить, что файлы актуальны, не перезаписывая")
    p.set_defaults(func=cmd_recipes)
    p = sub.add_parser("recipe", help="рецепт: проверка, пробный прогон, отчёт гейта, утверждение оператором")
    p.add_argument("action", choices=["validate", "dry-run", "report", "approve", "safety"])
    p.add_argument("target", help="файл рецепта, сценарий (report) или имя рецепта (approve)")
    p.add_argument("--program", help="программа контроллера: файл образа или ключ выпуска (tank-1.1.0)")
    p.add_argument("--start", type=float, default=40.0, help="уровень в начале пробного прогона, %%")
    p.add_argument("--work-order", help="dry-run: файл технологического задания; approve: идентификатор")
    p.add_argument("--revision", type=int)
    p.add_argument("--device", default="http://device:8080")
    p.add_argument("--no-approve", action="store_true", help="approve: только решение гейта, без подписи оператора")
    p.add_argument("--result", choices=["APPROVED", "REJECTED"], default="APPROVED", help="safety: заключение")
    p.add_argument("--comment")
    p.set_defaults(func=cmd_recipe)
    p = sub.add_parser("agent", help="сервер агента: запуск, ключи, режим управления, журнал")
    p.add_argument("action", choices=["serve", "key", "mode", "ceiling", "journal"])
    p.add_argument("name", nargs="?", help="key: имя ключа; mode: remote|local; ceiling: recipe|manual")
    p.add_argument("--tier", choices=["Read", "Recipe", "Manual"], default="Recipe")
    p.add_argument("--folder", default="shared")
    p.add_argument("--device", default="http://device:8080")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8026)
    p.add_argument("--verify", action="store_true")
    p.add_argument("--count", type=int)
    p.set_defaults(func=cmd_agent)
    p = sub.add_parser("mcp", help="мост MCP (stdio) к серверу агента")
    p.add_argument("--url", default="http://127.0.0.1:8026")
    p.add_argument("--key-file")
    p.set_defaults(func=cmd_mcp)
    p = sub.add_parser("live", help="сценарии на живом стенде")
    p.add_argument("action", choices=["prepare", "run", "status", "monitor", "recipe-demo"])
    p.add_argument("id", nargs="?")
    p.add_argument("--level", type=int, choices=[0, 1, 2], default=2)
    p.add_argument("--name", default="plc-1")
    p.add_argument("--device", default="http://device:8080")
    p.add_argument("--modbus", default="device:5020", help="адрес Modbus/TCP контроллера, хост:порт")
    p.add_argument("--observe", type=float, default=20.0, help="сколько секунд наблюдать процесс после действий")
    p.add_argument("--agent", default="http://agent-server:8026", help="recipe-demo: адрес сервера агента")
    p.set_defaults(func=cmd_live)

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except ToolError as e:
        print(f"ошибка: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
