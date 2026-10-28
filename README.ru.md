<p align="center">
  <img src="DayBookEvtxMacOS/Assets.xcassets/AppIcon.appiconset/icon_128x128@2x.png" width="128" alt="DayBookEvtxMacOS">
</p>

# DayBookEvtxMacOS

[English](README.md) · **Русский** · [Документация](https://thxstuck.github.io/DayBook/ru/) ·
[Скачать](https://github.com/thxStuck/DayBook/releases/latest)

Нативное приложение для macOS для просмотра и анализа журналов Windows (`.evtx`) в стиле SIEM:
выбираете папку с журналами (например, `C/Windows/System32/winevt/logs` из триажа) — все файлы
разбираются в кейс, дальше быстрый поиск, фильтры кликом, таймлайн, реестр хостов и пользователей,
сеансы, дерево процессов и Sigma-детекты. Поддержаны и Linux-системы: распакованный сбор
[UAC](https://github.com/tclahr/uac) становится таким же кейсом.

## Возможности

- **Собственный парсер EVTX** (Swift, без внешних библиотек): все физические чанки, а не только
  перечисленные в устаревшем заголовке; проверка CRC; восстановление удалённых записей из slack
  с флагом `carved`; объединение копий одной записи (живой журнал, VSS, slack) с указанием всех мест.
- **Linux (сбор UAC)**: syslog, journald (свой декодер zstd), auditd, wtmp / btmp / lastlog,
  веб-журналы, dpkg / apt, MySQL, истории оболочек и таймлайн файловой системы из bodyfile; сеансы по
  wtmp, дерево процессов по auditd, экран «Система» с выводом команд и файлами автозапуска. Время без
  года или пояса восстанавливается и помечается флагами.
- **Язык запросов DQL** в стиле PDQL/KQL: `EventID = 4624 and LogonType in (3, 10) | group by IpAddress`.
  Запрос не превращается в SQL — выполняется как операции над множествами.
- **Клик по значению** в таблице, деталях или сайдбаре добавляет фильтр `=` / `≠`.
- **Часовой пояс отображения** UTC±HH:MM или IANA — для отчётов заказчику; время хранится в UTC.
- **Таймлайн** выбранных журналов, гистограмма по времени, закладки и заметки.
- **Журналы** — просмотр отдельного журнала как в «Просмотре событий» Windows.
- **Реестр хостов, пользователей и IP** со связями, **сеансы входа и RDP**, **дерево процессов**
  (Sysmon по ProcessGuid, Security 4688 по PID — эвристика помечена).
- **Sigma-детекты**: 2 933 правила SigmaHQ и Hayabusa для Windows и Linux в поставке и своя папка
  правил; кнопка **«Обновить Sigma-правила»** проверяет на GitHub новый релиз SigmaHQ и коммит Hayabusa,
  скачивает их (со сверкой SHA-256) и ставит новый набор. Каждое правило превращается в DQL, который
  виден и выполняется вручную; неподдерживаемые правила перечислены с причиной.
- **Экспорт** в CSV, CSV для Excel (с защитой от формул), JSON Lines и XLSX — время в выбранном поясе
  и UTC, исходный файл, RecordID и SHA-256 файла.
- **Прозрачность**: эвристики, пропуски, лимиты и восстановленные данные всегда помечены.

Исходные файлы открываются только на чтение и никогда не изменяются.

## Требования

- macOS 14 или новее; собирается и проверялась на Apple Silicon (сборка под Intel не проверялась).
- Для сборки — Xcode с Swift 6 (проверялось на Xcode 27, macOS 26).

## Скачать

Готовая сборка для Apple Silicon — в [Releases](https://github.com/thxStuck/DayBook/releases/latest).
Распакуйте архив и перенесите `DayBookEvtxMacOS.app` в «Программы».

Приложение подписано локально (ad-hoc) и не нотаризовано Apple — для этого нужен платный
Developer ID. Поэтому при первом запуске macOS откажется его открывать: закройте окно
предупреждения, затем «Системные настройки» → «Конфиденциальность и безопасность» →
«Всё равно открыть» (понадобится пароль администратора). Или в Терминале:

```bash
xattr -dr com.apple.quarantine /Applications/DayBookEvtxMacOS.app
```

Язык интерфейса выбирается по системе; сменить его можно в самом приложении: DayBookEvtxMacOS →
«Язык интерфейса». «Справка» → «Справка DayBookEvtxMacOS» открывает полную документацию без интернета.

## Сборка и запуск

```bash
scripts/build.sh
open build/DayBookEvtxMacOS.app
```

Или откройте `DayBookEvtxMacOS.xcodeproj` в Xcode и нажмите ⌘R.
Если `xcode-select` указывает на Command Line Tools, скрипт сам использует
`DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer`.

## Документация

Полная документация на русском и английском — на сайте
[thxstuck.github.io/DayBook](https://thxstuck.github.io/DayBook/ru/): импорт и кейсы,
работа с событиями, полный справочник языка запросов DQL, сущности, сеансы и процессы, Sigma-детекты,
экспорт, устройство приложения, частые вопросы. Исходники страниц — в папке [`docs/`](docs/).

## Утилита командной строки

`Packages/DaybookKit/.build/release/evtxdump` (собирается тем же скриптом):

```bash
evtxdump ingest case.daybook /path/to/winevt/logs     # импорт в кейс
evtxdump ingest linux.daybook /path/to/uac-collection  # распакованный сбор UAC (Linux)
evtxdump dql case.daybook 'EventID = 4625 | group by IpAddress'
evtxdump sigma case.daybook --pack DayBookEvtxMacOS/Resources/Rules/rules.json
evtxdump export case.daybook out.xlsx 'EventID = 4688'
evtxdump stats /path/to/logs                           # состояние файлов и чанков
```

## Структура

```
DayBookEvtxMacOS/            приложение (SwiftUI + AppKit), локализация RU/EN
Packages/DaybookKit/
  Sources/EvtxCore/          парсер EVTX и BinXML
  Sources/DaybookStore/      хранилище кейса (SQLite), DQL, сущности, сеансы, процессы, экспорт
  Sources/DaybookSigma/      разбор и компиляция правил Sigma, проверка движка
  Sources/evtxdump/          CLI
scripts/                     сборка, упаковка правил, иконка, синхронизация строк, справка (make_help.py)
docs/                        сайт документации (GitHub Pages), RU и EN
```

## Лицензия

Все права на код приложения принадлежат автору — см. [LICENSE](LICENSE). Изменять и
распространять код без разрешения нельзя. **Issue приветствуются**: ошибки, идеи, вопросы.

Сторонние компоненты сохраняют свои лицензии:
- правила [SigmaHQ](https://github.com/SigmaHQ/sigma) и
  [Hayabusa](https://github.com/Yamato-Security/hayabusa-rules) —
  [Detection Rule License 1.1](DayBookEvtxMacOS/Resources/Rules/DRL-1.1.md);
  автор каждого правила указан в правиле и показывается в приложении рядом с каждым срабатыванием;
- [Yams](https://github.com/jpsim/Yams) — MIT.
