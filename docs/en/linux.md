---
title: Linux (UAC collections)
parent: English
nav_order: 7
---

# Linux: UAC collections
{: .no_toc }

[Русская версия](../ru/linux.html)

1. TOC
{:toc}

## What it is

[UAC](https://github.com/tclahr/uac) (Unix-like Artifacts Collector) collects logs, configuration,
command output and a file system timeline from a Linux system. DayBookEvtxMacOS parses an **extracted**
UAC collection into a case and lets you work with it the way you work with Windows logs: DQL search,
click-to-filter, timeline, logs, entities, sessions and processes.

Layout of a collection:

| Path | Contents |
|---|---|
| `uac.log` | UAC's own log: version, command line, OS, host, **the system's time zone** |
| `[root]/…` | copies of the system's files under their original paths (`/var/log`, `/etc`, home folders…) |
| `live_response/…` | command output at collection time (processes, network, packages, disks…) |
| `bodyfile/bodyfile.txt` | file system timeline (Sleuth Kit format) |
| `hash_executables/`, `system/`, `chkrootkit/`, `ssh/` | hashes of executables, lists of suid / hidden / writable files and more |

## Import

1. **File → New Case from Logs…** (⌘N) and choose the collection folder (or a folder with several
   collections). Extract a `uac-*.tar.gz` archive first.
2. In the import options choose **Linux — UAC collection**. It is preselected when the folders hold a
   UAC collection and no `.evtx` files. The sheet lists the collections found: host, UAC version, OS,
   time zone and collection time.
3. Options: **file system timeline (bodyfile)** — up to four events per file of the system (millions on
   large servers); **SHA-256 of source files**.

Source files are opened read-only. Symbolic links inside a collection are not followed: they point
into the analysed system, not this Mac.

From the command line: `evtxdump ingest case.daybook <collection folder> --linux` (without the flag,
Linux is chosen when the folder holds a UAC collection and no `.evtx` files).

## What is parsed

Every file of `/var/log` is listed as a source ("Case Information"), parsed or not: empty files, binary
files and unknown formats are shown with the reason.

| Source | Format | What is extracted |
|---|---|---|
| `auth.log`, `syslog`, `kern.log`, `cron.log`, `messages`, `secure`… | syslog (RFC 3339 and classic BSD), rotations `.1`, `.gz`, `.xz` | program and PID; for sshd, sudo, su, PAM, cron, systemd-logind, useradd/usermod/passwd and netfilter (UFW) lines: user, address, port, auth method, command, `Action` |
| `/var/log/journal/**/*.journal` | journald (regular and compact format, XZ, LZ4, **zstd** compression) | every field of the entry; `MESSAGE`, `PRIORITY`, `SYSLOG_IDENTIFIER`, `_PID`, `_HOSTNAME` go to the case's columns |
| `audit/audit.log` | auditd | the records of one event (`msg=audit(time:serial)`) are merged; hex values decoded; the interpreted part after 0x1D becomes `…Name` fields (`AuidName`); the EXECVE command becomes `CommandLine` |
| `wtmp`, `btmp`, `utmp`, `lastlog` | glibc binary records | logins, logouts, boots, failed logins, last login (name from `/etc/passwd`) |
| `nginx/*`, `apache2/*`, `httpd/*` | access (common/combined + `key=value` tail), JSON lines, error | client, method, URI, status, size, Referer, User-Agent |
| `*.jsonl` and JSON lines | JSON lines | every key (nested ones with dots), time from `ts`/`time`/`@timestamp`… |
| `dpkg.log`, `apt/history.log`, `apt/term.log` | dpkg / apt | package installs, upgrades, removals; apt transactions with command and user |
| `mysql/general.log` | MySQL/MariaDB general log | connections and queries |
| "time + text" logs | a time stamp at the start of the line (ISO, nginx error, PHP, Apache error, YYMMDD, epoch) | level, PID, `key=value` pairs; lines without a time (stack traces) continue the message |
| `.bash_history`, `.zsh_history`, `fish_history`, mysql/psql/python histories… | shell histories | commands; time from `#epoch` (bash), zsh's extended format, fish |
| `bodyfile/bodyfile.txt` | Sleuth Kit body | file times: equal times are one event with a MACB mark, as in `mactime` |

## Time

The case stores time in UTC and shows it in the chosen zone.

- A line with an offset (`2026-09-27T01:31:03+03:00`) has an exact time.
- A line without one (classic syslog, dpkg, nginx error) is read in **the system's time zone from
  `uac.log`**; the event is flagged `zoneAssumed`.
- Classic syslog (`Sep 27 01:31:03`) has no year. It is inferred from the file's modification time
  (from the bodyfile, else from the copy): the last line belongs to the year of the modification, a
  "December → January" step starts the next year. Flag `yearInferred`.
- A record without a time of its own (a line that could not be parsed; bash history before
  `HISTTIMEFORMAT` was set) gets the time of a neighbouring record (`timeCarried`) or the file's
  modification time (`timeFromFile`) and keeps its place in the file's order.

The **Data quality** presets in the sidebar list all such events.

## Fields and `Action`

Field names are CamelCase and match Windows fields where the meaning is the same: `TargetUserName`,
`SubjectUserName` (with the host name as domain, so `root` of two machines stays two accounts),
`IpAddress`, `WorkstationName`, `CommandLine`, `ProcessId`. Raw auditd and journald fields keep their
names (`exe`, `auid`, `_SYSTEMD_UNIT`). A field whose name DQL treats as an alias (`host`, `user`,
`time`…) is stored capitalised or renamed (`Host`, `UserName`, `TimeRaw`).

`Action` is a normalised action, the same across sources:

| Group | Values |
|---|---|
| Authentication | `auth_success`, `auth_failure`, `invalid_user`, `user_not_allowed`, `too_many_auth_failures`, `key_accepted`, `auth_postponed` |
| Logins and sessions | `login`, `logout`, `login_failed`, `last_login`, `session_opened`, `session_closed`, `session_start`, `session_end`, `logind_session_new`, `logind_session_logout`, `logind_session_removed`, `boot`, `shutdown`, `runlevel` |
| SSH connections | `connection`, `connection_closed`, `connection_reset`, `disconnected`, `disconnect_received`, `preauth_timeout`, `no_identification`, `negotiation_failed`, `bad_banner`, `listening` |
| Privileges | `sudo`, `sudo_denied`, `su`, `su_failed` |
| Accounts | `user_added`, `user_deleted`, `user_modified`, `group_added`, `group_deleted`, `group_member_added`, `group_member_removed`, `password_changed` |
| Execution | `process_exec` (auditd), `shell_command` (histories), `cron_command` |
| auditd | `audit_config_change`, `audit_daemon_start`, `audit_daemon_end`, `service_start`, `service_stop`, `kernel_module`, `promiscuous_mode`, `abnormal_end` |
| Web, packages, databases | `http_request`, `package_install`, `package_upgrade`, `package_remove`, `package_purge`, `package_configure`, `package_status`, `apt_transaction`, `apt_output`, `db_connect`, `db_query`… |
| Other | `firewall` (netfilter), `file_time` (bodyfile) |

Examples:

```
Action in (auth_failure, invalid_user) | group by IpAddress | sort count desc
Action = process_exec and CommandLine contains wget
Action = http_request and HttpStatus >= 500 | group by Uri
Action = file_time and FilePath startswith /etc/cron and MACB contains m
```

Linux user names are case-sensitive: `Root` tried by a scanner is not `root`.

## Sections of a Linux case

- **Events** and **Timeline** — as for Windows; a "Program" column instead of the Event ID.
- **Logs** — the `/var/log` tree: a log opens whole with all its rotations, or one file at a time.
- **System** — details from `uac.log`, `live_response` command output by group, UAC's lists, hashes and
  the collected configuration and autostart files (cron, systemd, sudoers, `authorized_keys`, profile,
  PAM, audit rules). Files are read from the collection folder on demand.
- **Hosts, Users, IP addresses** — the entity registry.
- **Sessions** — wtmp logins: login → logout on the same terminal or a reboot, as `last` reads them.
- **Processes** — program launches from auditd. auditd writes only the PPID, so parent → child links
  are reconstructed heuristically and marked 🔗.
- In the event details the **Record** tab shows the original lines (all lines of an audit event or an
  apt transaction), `FIELD=value` lines of a journal entry, the decoded wtmp record; **Hex** shows the
  bytes.

## Limits

- The collection must be extracted: `.tar.gz` and `.zip` archives are not opened.
- Sigma detections for Linux are not bundled yet: the Detections section is hidden in Linux cases.
- Binary logs (`mysql-bin.*`, `faillog`, `tallylog`) are only listed as sources.
- The records of one audit event are merged when they follow each other; records of different events
  mixed together give several events with the same `AuditId`.
- The time of lines without a zone or a year is reconstructed by the rules above and flagged — check
  it against events with an exact time.
