---
title: Главная · Home
nav_order: 1
permalink: /
---

# DayBookEvtxMacOS
{: .fs-9 }

Нативное приложение для macOS для просмотра и анализа журналов Windows (`.evtx`) и сборов Linux (UAC) в стиле SIEM.
{: .fs-6 .fw-300 }

A native macOS app for viewing and analysing Windows event logs (`.evtx`) and Linux collections (UAC), SIEM-style.
{: .fs-6 .fw-300 }

[Русская документация](ru/){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 }
[English documentation](en/){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 }
[Скачать · Download](https://github.com/thxStuck/DayBookEvtxMacOS/releases/latest){: .btn .fs-5 .mb-4 .mb-md-0 }

---

## Коротко

Выбираете папку с журналами (например, `C/Windows/System32/winevt/logs` из триажа). Приложение разбирает
все файлы в кейс, после чего доступны:

- быстрый поиск на собственном языке запросов DQL;
- фильтры кликом по любому значению;
- гистограмма и единый таймлайн;
- просмотр отдельного журнала, как в «Просмотре событий» Windows;
- реестр хостов, пользователей и IP-адресов;
- сеансы входа и RDP, деревья процессов;
- Sigma-детекты по правилам SigmaHQ и Hayabusa;
- экспорт в CSV, JSON Lines и XLSX;
- Linux: распакованный сбор UAC — syslog, journald, auditd, wtmp, веб-журналы, истории оболочек, таймлайн файлов.

Исходные файлы только читаются. Всё, что приложение восстановило, предположило или пропустило, помечено.

## In short

Pick a folder with logs (for example `C/Windows/System32/winevt/logs` from a triage collection). The app parses
every file into a case, which gives you:

- fast search with its own DQL query language;
- click-to-filter on any value;
- a histogram and a merged timeline;
- a single-log viewer like Windows Event Viewer;
- a registry of hosts, users and IP addresses;
- logon and RDP sessions and process trees;
- Sigma detections with the SigmaHQ and Hayabusa rules;
- export to CSV, JSON Lines and XLSX;
- Linux: an extracted UAC collection — syslog, journald, auditd, wtmp, web logs, shell histories, file timeline.

Source files are only read. Everything the app recovered, guessed or skipped is marked.

macOS 14+ · Apple Silicon · Русский и English
