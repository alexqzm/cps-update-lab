#!/usr/bin/env bash
# Управление живым стендом cps-update-lab.
#   ./lab.sh up                 подготовить стенд и запустить службы (образ собирается, если его нет)
#   ./lab.sh build              собрать образ заново (после обновления репозитория)
#   ./lab.sh scenario A1 [0|1|2]  подготовить сценарий, перезапустить контроллер и выполнить действия
#   ./lab.sh status | monitor   состояние контроллера | проверка отчётов и журнала допусков
#   ./lab.sh matrix             все сценарии на трёх уровнях в модельном времени
#   ./lab.sh cli ...            любая команда cpslab в контейнере инструментов
#   ./lab.sh shell              оболочка в контейнере инструментов: /lab, cosign, gpg, git, scii-agent
#   ./lab.sh logs | down | reset  журналы | остановить | остановить и удалить данные стенда
set -euo pipefail
cd "$(dirname "$0")"
compose() { docker compose "$@"; }
tools() { compose run --rm --no-deps tools "$@"; }

cmd="${1:-help}"
shift || true
case "$cmd" in
  up)
    docker image inspect cps-update-lab:local >/dev/null 2>&1 || compose build init
    compose up -d --wait
    echo "HMI: http://127.0.0.1:8081   API контроллера: http://127.0.0.1:8080/api/status   Modbus/TCP: 127.0.0.1:5020"
    ;;
  scenario)
    id="${1:?укажите сценарий: ./lab.sh scenario A1 [уровень]}"
    level="${2:-2}"
    tools live prepare "$id" --level "$level"
    compose up -d --force-recreate --no-deps --wait device
    tools live run "$id" --device http://device:8080 --modbus device:5020 --observe "${OBSERVE:-20}"
    ;;
  build) compose build init ;;
  status) tools live status --device http://device:8080 ;;
  monitor) tools live monitor ;;
  matrix) tools scenario matrix "$@" ;;
  cli) tools "$@" ;;
  shell) compose run --rm --no-deps --entrypoint bash tools ;;
  logs) compose logs -f "$@" ;;
  down) compose down ;;
  reset) compose down --volumes ;;
  *)
    sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
    ;;
esac
