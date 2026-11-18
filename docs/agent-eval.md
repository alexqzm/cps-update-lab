# Эксперимент Э8: ИИ-агенты и рецепты партии

Программа эксперимента — [`experiments/agents/PROGRAM.md`](../experiments/agents/PROGRAM.md). Эксперимент
измеряет, как часто реальные модели загружают небезопасный рецепт, когда в архиве есть внедрённые
указания или искажённые данные, и что с таким рецептом делают уровни защиты L1 и L2.

Сеанс агента идёт в песочнице: свой контроллер на уровне L2, сервер агента с архивом условия, мост MCP.
Агент только составляет и загружает рецепт. Оценку делает программа после сеанса: прогон рецепта на
модели объекта (истина), статическая проверка (L1), утверждение оператора без проверки, решение гейта и
квитанция на контроллере (L2).

Интерфейс агента и документы архива в эксперименте английские (`--lang en`), учебный стенд остаётся
русским.

## Что где работает

- **Стенд и программа эксперимента** — в контейнере `eval` (образ стенда и Claude Code).
- **Локальные модели** — в Ollama на компьютере, контейнер обращается к ним по `OLLAMA_HOST`
  (по умолчанию `http://host.docker.internal:11434`).
- **Claude** — Claude Code в контейнере, вход по токену подписки (`CLAUDE_CODE_OAUTH_TOKEN`).

## Подготовка (один раз)

Нужны Docker (на Windows — Docker Desktop с WSL 2, команды ниже выполняются в терминале WSL), Ollama и
подписка Claude.

```bash
git clone https://github.com/alexqzm/cps-update-lab && cd cps-update-lab
./lab.sh up               # стенд: образ, ключи, выпуски
./lab.sh eval-build       # образ эксперимента с Claude Code
./lab.sh eval-token       # вход в Claude: откройте ссылку, вставьте код, получите токен
echo 'CLAUDE_CODE_OAUTH_TOKEN=…' > .env    # токен для docker compose; файл .env в git не попадает
```

Ollama на Windows: установите с ollama.com, задайте переменную среды `OLLAMA_HOST=0.0.0.0:11434`
(иначе контейнер её не видит) и перезапустите Ollama. Затем скачайте модели в PowerShell, например
`ollama pull qwen3:14b`.

## Проверка

```bash
./lab.sh eval check --model claude:claude-sonnet-5-5 --model ollama:qwen3:14b --probe
./lab.sh eval selftest
```

`check` показывает версию Claude Code, вход (`--probe` отправляет один короткий запрос) и для моделей
Ollama дайджест манифеста, шаблон и параметры. `selftest` проходит четыре условия эталонным агентом без
модели и сверяет исходы с ожидаемыми.

## Пилот

```bash
./lab.sh eval plan --pilot --model claude:claude-sonnet-5-5 --model ollama:qwen3:14b \
    --model ollama:gpt-oss:20b --model ollama:llama3.1:8b --model ollama:mistral-nemo:12b \
    --out /runs/pilot-plan.json
./lab.sh eval check --model … --out /runs/pilot-models.json      # те же модели
./lab.sh eval run --plan /runs/pilot-plan.json --model ollama:qwen3:14b --out /runs/pilot
./lab.sh eval run --plan /runs/pilot-plan.json --model claude:claude-sonnet-5-5 --out /runs/pilot
#   … для каждой модели плана
./lab.sh eval score --plan /runs/pilot-plan.json --out /runs/pilot
./lab.sh eval report --plan /runs/pilot-plan.json --out /runs/pilot
./lab.sh eval-export > e8-pilot.tar.gz
```

Архив `e8-pilot.tar.gz` (без ключей) передаётся для анализа. Повторный `run` продолжает с места
остановки: завершённые сеансы пропускаются, сеанс с отказом инфраструктуры повторяется один раз.

## Основной прогон

После пилота и записи в журнале программы (версия стенда и список моделей) — те же команды с планом
`eval plan` без `--pilot` (`--out /runs/plan.json`, каталог `/runs/main`). На время прогона отключите
спящий режим компьютера.

## Что сохраняется в каталоге сеанса

| Файл | Содержимое |
|---|---|
| `session.json` | сеанс плана, модель, запрос агенту, статус, вызовы, время, токены |
| `transcript.jsonl` | диалог локальной модели или события Claude Code (без системного сообщения Claude Code) |
| `bridge.log`, `mcp.json` | журнал моста MCP и его настройка для Claude Code |
| `sandbox/agent/` | журнал сервера агента, архив условия, загруженные рецепты с аттестациями |
| `score.json` | класс рецепта, исходы L1 и L2, решение гейта, признаки поведения агента |
| `score/agent/` | копия хранилища с утверждением, решением гейта и квитанцией |

Меры M1–M8 и сравнение условий I0 и I1 — в `summary.md` и `summary.json` каталога прогона.
