# Результаты сценариев

Файл и таблица исходов в README создаются командой `cpslab scenario matrix --md docs/results.md --readme README.md` (cpslab 0.1.0); CI проверяет, что они совпадают с прогоном. Процесс — 300 с модельного времени после действия нарушителя.

## Исходы на трёх уровнях защиты контроллера

| Сценарий | L0: без проверки | L1: подпись поставщика | L2: квитанция гейта SCII | Гейт |
|---|---|---|---|---|
| N1 Штатное обновление 1.0.0 → 1.1.0 | принято; норма | принято; норма | принято; норма | допуск |
| A1 Подмена образа на сервере обновлений | принято; перелив, тревога монитора | отказ: BOOT_SIG; норма | отказ: DIGEST; норма | допуск |
| A2 Вредоносный образ, подписанный похищенными ключами поставщика | принято; перелив, тревога монитора | принято; перелив, тревога монитора | отказ: NO_RECEIPT; норма | отказ |
| A3 Компрометация сборочной среды | принято; перелив, тревога монитора | принято; перелив, тревога монитора | отказ: NO_RECEIPT; норма | отказ |
| A3b Компрометация сборочной среды без контрольной пересборки | принято; перелив, тревога монитора | принято; перелив, тревога монитора | отказ: NO_RECEIPT; норма | отказ |
| A4 Откат на подлинную версию с уязвимостью | принято; перелив | принято; перелив | отказ: ROLLBACK; норма | допуск |
| A5 Подлинный выпуск для другого класса устройства | принято; опустошение, тревога монитора | принято; опустошение, тревога монитора | отказ: TARGET; норма | допуск |
| A6 Загрузка логики с подложной инженерной станции | принято; перелив, тревога монитора | принято; перелив, тревога монитора | отказ: NO_RECEIPT; норма | — |
| A7 Выпускной архив не совпадает с тегом | принято; перелив, тревога монитора | принято; перелив, тревога монитора | отказ: NO_RECEIPT; норма | отказ |
| M1 Граница метода: скрытая функция производителя | принято; перелив | принято; перелив | принято; перелив | допуск |
| M2 Граница метода: команда по каналу управления | принято; опустошение | принято; опустошение | принято; опустошение | — |

Столбец «Гейт» — решение гейта по выпуску, который участвует в сценарии. В A1, A4 и A5 в канале обновления лежат подпись и квитанция допущенного подлинного выпуска; «—» — гейт не участвует.

Коды отказа: `BOOT_SIG` — подпись образа не принимается загрузчиком; `NO_RECEIPT` — нет квитанции допуска; `TARGET` — квитанция для другого устройства; `ROLLBACK` — откат версии; `DIGEST` — дайджест образа не совпадает с квитанцией.

## Решения гейта по выпускам

| Выпуск | SHA-256 образа | Решение | R_P^min | R_P^max | Не подтверждены |
|---|---|---|---|---|---|
| tank-1.0.0 | `c7fe7ab9317f02cd` | допуск | 0,900 | 0,900 | s54 N |
| tank-1.1.0 | `620be890a2a46214` | допуск | 0,900 | 0,900 | s54 N |
| tank-1.2.0 | `12a78cca1b1ca3d1` | допуск | 0,900 | 0,900 | s54 N |
| pump-1.1.0 | `4ac0f3a3029f6473` | допуск | 0,900 | 0,900 | s54 N |
| tank-1.1.0-compromised-build | `56abaccf8405cf25` | отказ | 0,180 | 0,540 | s24 F, s54 N |
| tank-1.1.0-compromised-build-norebuild | `56abaccf8405cf25` | отказ | 0,828 | 0,864 | s24 N, s54 N |
| tank-1.1.0-from-archive | `eea265f78714f9dc` | отказ | 0,180 | 0,540 | s21 F, s22 F, s23 F, s24 F, s54 N |
| tank-1.1.0-stolen-key | `56abaccf8405cf25` | отказ | 0,000 | 0,450 | s11 F, s12 N, s13 N, s14 F, s21 F, s22 F, s23 N, s24 N, s31 N, s32 N, s41 F, s43 N, s54 N |

## Сопоставление сценариев

Сопоставления с ATT&CK (v20) и мерами ОПО приказа ФСТЭК России № 239 — оценка автора стенда.

| Сценарий | ЛР | Записи атласа | ATT&CK | ОПО | Что останавливает |
|---|---|---|---|---|---|
| N1 | 1 | — | — | ОПО.1, ОПО.2, ОПО.3, ОПО.4 | — |
| A1 | 2 | [havex-2014](https://github.com/alexqzm/cps-supply-chain-atlas/blob/main/data/records/havex-2014.yaml), [notpetya-medoc-2017](https://github.com/alexqzm/cps-supply-chain-atlas/blob/main/data/records/notpetya-medoc-2017.yaml), [flame-2012](https://github.com/alexqzm/cps-supply-chain-atlas/blob/main/data/records/flame-2012.yaml), [medtronic-carelink-2018](https://github.com/alexqzm/cps-supply-chain-atlas/blob/main/data/records/medtronic-carelink-2018.yaml) | T0862, T1693.001 | ОПО.1, ОПО.2 | L1: подпись образа (BOOT_SIG); L2: дайджест образа в квитанции (DIGEST) |
| A2 | 3 | [stuxnet-2010](https://github.com/alexqzm/cps-supply-chain-atlas/blob/main/data/records/stuxnet-2010.yaml), [shadowhammer-2019](https://github.com/alexqzm/cps-supply-chain-atlas/blob/main/data/records/shadowhammer-2019.yaml) | T0862, T1693.001 | ОПО.1, ОПО.2 | гейт: s11, s14, s21, s22, s41 опровергнуты (вето); L2: нет квитанции (NO_RECEIPT) |
| A3 | 3 | [solarwinds-2020](https://github.com/alexqzm/cps-supply-chain-atlas/blob/main/data/records/solarwinds-2020.yaml), [tanstack-2026](https://github.com/alexqzm/cps-supply-chain-atlas/blob/main/data/records/tanstack-2026.yaml), [xtrader-3cx-2023](https://github.com/alexqzm/cps-supply-chain-atlas/blob/main/data/records/xtrader-3cx-2023.yaml) | T0862, T1195.002 | ОПО.2 | гейт: s24 опровергнуто (вето); L2: нет квитанции (NO_RECEIPT) |
| A3b | 3 | [solarwinds-2020](https://github.com/alexqzm/cps-supply-chain-atlas/blob/main/data/records/solarwinds-2020.yaml) | T0862, T1195.002 | ОПО.2 | гейт: верхняя граница индекса ниже порога (отказ без вето); L2: нет квитанции (NO_RECEIPT) |
| A4 | 4 | — | T1693.001, T0831 | ОПО.4 | L2: номер версии в квитанции ниже установленного (ROLLBACK) |
| A5 | 4 | — | T1693.001 | ОПО.4 | L2: класс устройства в квитанции (TARGET) |
| A6 | 5 | [stuxnet-2010](https://github.com/alexqzm/cps-supply-chain-atlas/blob/main/data/records/stuxnet-2010.yaml), [triton-2017](https://github.com/alexqzm/cps-supply-chain-atlas/blob/main/data/records/triton-2017.yaml), [plc-blaster-2016](https://github.com/alexqzm/cps-supply-chain-atlas/blob/main/data/records/plc-blaster-2016.yaml), [rogue7-2019](https://github.com/alexqzm/cps-supply-chain-atlas/blob/main/data/records/rogue7-2019.yaml) | T0843, T0889 | — | L2: квитанция требуется и для загрузки логики (NO_RECEIPT); L0–L1: монитор обнаруживает недопущенный образ |
| A7 | 6 | [xz-utils-2024](https://github.com/alexqzm/cps-supply-chain-atlas/blob/main/data/records/xz-utils-2024.yaml) | T0862, T1195.002 | ОПО.2 | гейт: s21, s22, s23, s24 опровергнуты (вето); L2: нет квитанции (NO_RECEIPT) |
| M1 | 7 | [contec-cms8000-2025](https://github.com/alexqzm/cps-supply-chain-atlas/blob/main/data/records/contec-cms8000-2025.yaml), [badbox2-2025](https://github.com/alexqzm/cps-supply-chain-atlas/blob/main/data/records/badbox2-2025.yaml) | T0862, T0831 | ОПО.3 | не останавливается: SCII подтверждает происхождение, а не намерения поставщика |
| M2 | 7 | [viasat-ka-sat-2022](https://github.com/alexqzm/cps-supply-chain-atlas/blob/main/data/records/viasat-ka-sat-2022.yaml), [li-auto-master-accounts-2025](https://github.com/alexqzm/cps-supply-chain-atlas/blob/main/data/records/li-auto-master-accounts-2025.yaml) | T0859, T0813 | — | не останавливается: канал управления защищается отдельно |
