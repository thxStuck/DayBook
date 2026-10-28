---
title: Linux (сбор UAC)
parent: Русский
nav_order: 7
---

# Linux: сбор UAC
{: .no_toc }

[English version](../en/linux.html)

1. TOC
{:toc}

## Что это

[UAC](https://github.com/tclahr/uac) (Unix-like Artifacts Collector) собирает с Linux-системы журналы,
настройки, вывод команд и таймлайн файловой системы. DayBookEvtxMacOS разбирает **распакованный** сбор
UAC в кейс и даёт работать с ним так же, как с журналами Windows: поиск DQL, фильтры кликом, таймлайн,
журналы, сущности, сеансы и процессы.

Структура сбора:

| Путь | Что там |
|---|---|
| `uac.log` | журнал самого UAC: версия, командная строка, ОС, хост, **часовой пояс системы** |
| `[root]/…` | копии файлов системы под исходными путями (`/var/log`, `/etc`, домашние папки…) |
| `live_response/…` | вывод команд на момент сбора (процессы, сеть, пакеты, диски…) |
| `bodyfile/bodyfile.txt` | таймлайн файловой системы (формат Sleuth Kit) |
| `hash_executables/`, `system/`, `chkrootkit/`, `ssh/` | хеши исполняемых файлов, списки suid/скрытых/доступных на запись файлов и др. |

## Импорт

1. **Файл → Новый кейс из журналов…** (⌘N), выберите папку сбора (или папку, где лежат несколько сборов).
   Архив `uac-*.tar.gz` сначала распакуйте.
2. В окне параметров выберите систему **Linux — сбор UAC**. Тип подставляется сам: если в папках есть
   сбор UAC и нет файлов `.evtx`, выбран Linux. Там же видно, какие сборы найдены: хост, версия UAC,
   ОС, часовой пояс, время сбора.
3. Параметры: **таймлайн файловой системы (bodyfile)** — до четырёх событий на каждый файл системы
   (на больших серверах это миллионы событий); **SHA-256 исходных файлов**.

Исходные файлы открываются только для чтения. Символьные ссылки внутри сбора не разыменовываются:
они указывают в исследуемую систему, а не на этот Mac.

Из командной строки: `evtxdump ingest case.daybook <папка сбора> --linux` (без флага Linux выбирается,
если в папке есть сбор UAC и нет `.evtx`).

## Что разбирается

Каждый файл `/var/log` попадает в список источников («Сведения о кейсе»), даже если не разобран:
пустые, двоичные и файлы неизвестного формата видны с причиной.

| Источник | Формат | Что извлекается |
|---|---|---|
| `auth.log`, `syslog`, `kern.log`, `cron.log`, `messages`, `secure`… | syslog (RFC 3339 и классический BSD), ротации `.1`, `.gz`, `.xz` | программа и PID; для sshd, sudo, su, PAM, cron, systemd-logind, useradd/usermod/passwd, правил netfilter (UFW) — пользователь, адрес, порт, способ входа, команда, `Action` |
| `/var/log/journal/**/*.journal` | journald (обычный и компактный формат, сжатие XZ, LZ4, **zstd**) | все поля записи; `MESSAGE`, `PRIORITY`, `SYSLOG_IDENTIFIER`, `_PID`, `_HOSTNAME` — в колонки кейса |
| `audit/audit.log` | auditd | записи одного события (`msg=audit(время:номер)`) объединяются; hex-значения декодируются; расшифровка после 0x1D — поля `…Name` (`AuidName`); команда EXECVE — `CommandLine` |
| `wtmp`, `btmp`, `utmp`, `lastlog` | двоичные записи glibc | входы, выходы, загрузки, неудачные входы, последний вход (имя по `/etc/passwd`) |
| `nginx/*`, `apache2/*`, `httpd/*` | access (common/combined + хвост `key=value`), JSON lines, error | клиент, метод, URI, статус, размер, Referer, User-Agent |
| `*.jsonl` и строки-JSON | JSON lines | все ключи (вложенные — через точку), время по `ts`/`time`/`@timestamp`… |
| `dpkg.log`, `apt/history.log`, `apt/term.log` | dpkg / apt | установка, обновление, удаление пакетов; транзакции apt с командой и пользователем |
| `mysql/general.log` | общий журнал MySQL/MariaDB | подключения и запросы |
| журналы вида «время + текст» | время в начале строки (ISO, nginx error, PHP, Apache error, YYMMDD, epoch) | уровень, PID, пары `key=value`; строки без времени (стек вызовов) — продолжение сообщения |
| `.bash_history`, `.zsh_history`, `fish_history`, истории mysql/psql/python… | истории оболочек | команды; время из `#epoch` (bash), расширенного формата zsh, fish |
| `bodyfile/bodyfile.txt` | Sleuth Kit body | времена файлов: совпадающие времена — одно событие с меткой MACB, как в `mactime` |

## Время

В кейсе время хранится в UTC; отображается в выбранном поясе.

- Строка с поясом (`2026-09-27T01:31:03+03:00`) — время точное.
- Строка без пояса (классический syslog, dpkg, nginx error) — берётся **часовой пояс системы из
  `uac.log`**, событие помечается флагом `zoneAssumed`.
- В классическом syslog (`Sep 27 01:31:03`) нет года. Он восстанавливается по времени изменения
  файла (из bodyfile, иначе — копии): последняя строка относится к году изменения файла, переход
  «декабрь → январь» — к следующему году. Флаг `yearInferred`.
- Запись без своего времени (строка, которую не удалось разобрать; история bash до включения
  `HISTTIMEFORMAT`) получает время соседней записи (`timeCarried`) или время изменения файла
  (`timeFromFile`) и сохраняет своё место в порядке файла.

Пресет **Качество данных** в боковой панели показывает все такие события.

## Поля и `Action`

Имена полей — CamelCase и совпадают с полями Windows там, где смысл тот же: `TargetUserName`,
`SubjectUserName` (с доменом = имя хоста, чтобы `root` разных машин не сливался), `IpAddress`,
`WorkstationName`, `CommandLine`, `ProcessId`. Сырые поля auditd и journald сохраняют свои имена
(`exe`, `auid`, `_SYSTEMD_UNIT`). Поле, имя которого DQL считает псевдонимом (`host`, `user`,
`time`…), хранится с заглавной буквы или переименовано (`Host`, `UserName`, `TimeRaw`).

`Action` — нормализованное действие, одно для всех источников:

| Группа | Значения |
|---|---|
| Аутентификация | `auth_success`, `auth_failure`, `invalid_user`, `user_not_allowed`, `too_many_auth_failures`, `key_accepted`, `auth_postponed` |
| Входы и сеансы | `login`, `logout`, `login_failed`, `last_login`, `session_opened`, `session_closed`, `session_start`, `session_end`, `logind_session_new`, `logind_session_logout`, `logind_session_removed`, `boot`, `shutdown`, `runlevel` |
| SSH-соединения | `connection`, `connection_closed`, `connection_reset`, `disconnected`, `disconnect_received`, `preauth_timeout`, `no_identification`, `negotiation_failed`, `bad_banner`, `listening` |
| Привилегии | `sudo`, `sudo_denied`, `su`, `su_failed` |
| Учётные записи | `user_added`, `user_deleted`, `user_modified`, `group_added`, `group_deleted`, `group_member_added`, `group_member_removed`, `password_changed` |
| Выполнение | `process_exec` (auditd), `shell_command` (истории), `cron_command` |
| auditd | `audit_config_change`, `audit_daemon_start`, `audit_daemon_end`, `service_start`, `service_stop`, `kernel_module`, `promiscuous_mode`, `abnormal_end` |
| Веб, пакеты, БД | `http_request`, `package_install`, `package_upgrade`, `package_remove`, `package_purge`, `package_configure`, `package_status`, `apt_transaction`, `apt_output`, `db_connect`, `db_query`… |
| Прочее | `firewall` (netfilter), `file_time` (bodyfile) |

Примеры:

```
Action in (auth_failure, invalid_user) | group by IpAddress | sort count desc
Action = process_exec and CommandLine contains wget
Action = http_request and HttpStatus >= 500 | group by Uri
Action = file_time and FilePath startswith /etc/cron and MACB contains m
```

Имена пользователей Linux различаются регистром: `Root`, которого пробовал сканер, — не `root`.

## Разделы Linux-кейса

- **События** и **Таймлайн** — как для Windows; колонка «Программа» вместо Event ID.
- **Журналы** — дерево `/var/log`: журнал открывается целиком со всеми ротациями или по одному файлу.
- **Система** — сведения из `uac.log`, вывод команд `live_response` по группам, списки UAC, хеши и
  собранные файлы настроек и автозапуска (cron, systemd, sudoers, `authorized_keys`, profile, PAM,
  правила auditd). Файлы читаются из папки сбора по запросу.
- **Хосты, пользователи, IP** — реестр сущностей.
- **Сеансы** — входы из wtmp: вход → выход на том же терминале или перезагрузка, как в `last`.
- **Детекты** — правила SigmaHQ для Linux (auditd, auth, sshd, sudo, cron, запуски процессов);
  сопоставление полей описано на странице [Sigma-детекты](detections.html).
- **Процессы** — запуски программ из auditd. auditd пишет только PPID, поэтому связь «родитель →
  потомок» восстанавливается эвристически и помечена значком 🔗.
- В деталях события вкладка **Запись** показывает исходные строки (для события auditd и транзакции
  apt — все строки), для journald — поля `FIELD=value`, для wtmp — расшифровку записи; **Hex** —
  байты.

## Ограничения

- Нужен распакованный сбор: архивы `.tar.gz` и `.zip` не открываются.
- Двоичные журналы (`mysql-bin.*`, `faillog`, `tallylog`) только перечисляются в источниках.
- Записи auditd одного события объединяются, если идут подряд; при перемешивании записей разных
  событий получится несколько событий с одним `AuditId`.
- Время строк без пояса и года восстановлено по правилам выше и помечено флагами — проверяйте его
  по событиям с точным временем.
