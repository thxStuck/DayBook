---
title: English
nav_order: 3
has_children: true
has_toc: false
permalink: /en/
---

# DayBookEvtxMacOS documentation

[Русская версия](../ru/)

DayBookEvtxMacOS is a native macOS app for incident response with Windows event logs (`.evtx`)
and UAC collections of Linux systems.
It parses a folder of logs (for example `C/Windows/System32/winevt/logs` from a triage collection)
into a case and lets you work with it like a SIEM: fast search, click-to-filter, a timeline,
entities, sessions, processes and detections.

## Features

- **Own EVTX parser** in Swift: every physical chunk, not only the ones listed in the stale file header;
  CRC checks; recovery of deleted records from slack space; copies of one record from the live log,
  shadow copies and slack merged into one event that lists every location.
- **Linux (UAC collections)**: syslog, journald (including zstd), auditd, wtmp/btmp/lastlog, web
  server logs, dpkg/apt, MySQL, shell histories and a file system timeline from the bodyfile — in one
  case with the same search, filters and timeline. See [Linux (UAC collections)](linux.html).
- **DQL query language** in the style of PDQL/KQL:
  `EventID = 4624 and LogonType in (3, 10) | group by IpAddress`. Queries run as set operations and
  never become SQL.
- **Click-to-filter** on any value in the table, the details and the sidebar.
- **Display time zone**: UTC, a fixed offset or an IANA zone; the case stores time in UTC.
- **Histogram and timeline** with day and gap separators.
- **Logs**: one log at a time, like Windows Event Viewer.
- **Registry of hosts, users and IP addresses** with links, **logon and RDP sessions**,
  **process trees**.
- **Sigma detections**: 2,748 bundled SigmaHQ and Hayabusa rules plus your own rules folder. Every rule
  becomes visible DQL; unsupported rules are listed with the reason.
- **Export** to CSV, CSV for Excel, JSON Lines and XLSX with the time zone, the source file and its
  SHA-256.
- **Transparency**: recovered records, heuristics, limits and skips are always marked.
- Russian and English user interface.

Source logs are only ever read, never modified.

## Quick start

1. Download the app from [Releases](https://github.com/thxStuck/DayBook/releases/latest)
   and allow it to open on first launch — see [Installation](install.html).
2. File → New Case from Logs… (⌘N), choose the logs folder and where to save the case.
3. Keep the default import options and click Start Import.
4. In Events, pick a preset in the sidebar or type a query, for example
   `EventID = 4625 | group by IpAddress, TargetUserName`.
5. Right-click a value to filter with = or ≠; click a row to see the event details.
6. Open Detections: the Sigma rules ran automatically after the import.

## Contents

| Page | Covers |
|---|---|
| [Installation](install.html) | Requirements, installing, first launch, folder access, interface language, building from source |
| [Cases and import](cases-import.html) | What a case is, import options, how files are parsed, slack recovery, copies, flags, Case Information |
| [Working with events](events.html) | Window sections, query and filters, table, grouping, histogram, timeline, logs, details, time zone, bookmarks |
| [DQL query language](dql.html) | Full reference: operators, time, fields, pipeline, limits, ready-made queries |
| [Entities, sessions, processes](entities.html) | Hosts, users and IP registry, logon sessions, RDP, process trees |
| [Sigma detections](detections.html) | Bundled rules, your own folder, how rules become DQL, modifiers, the Detections screen |
| [Export and command line](export-cli.html) | Export formats and columns, the `evtxdump` tool |
| [How it works](internals.html) | Parser, import, storage, query execution, performance, limitations |
| [FAQ and troubleshooting](faq.html) | Common questions and what to do when something does not work |
