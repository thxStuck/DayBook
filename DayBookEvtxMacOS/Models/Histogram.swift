import DaybookStore
import EvtxCore
import Foundation

struct HistogramBin: Identifiable, Sendable {
    let id: Int
    let start: Int64
    let end: Int64
    let count: Int
}

struct Histogram: Sendable {
    let bins: [HistogramBin]
    let binTicks: Int64
    /// Events left out of the axis (0.1–99.9 percentile window, e.g. dates like 1601),
    /// before and after it. Zero when the full range is shown.
    let outliersBefore: Int
    let outliersAfter: Int
    let fullRange: Bool
    var outliers: Int { outliersBefore + outliersAfter }
}

nonisolated enum HistogramBuilder {
    static let niceSeconds: [Int64] = [1, 5, 15, 30, 60, 300, 900, 1800, 3600, 3 * 3600, 6 * 3600, 12 * 3600,
                                       86_400, 7 * 86_400, 30 * 86_400, 365 * 86_400]

    /// Bins over a time-ordered result: each bin boundary is one binary search, so the
    /// cost is independent of the number of events.
    static func build(store: CaseStore, events: ResultSet, targetBins: Int = 160, fullRange: Bool = false) -> Histogram? {
        let n = events.count
        guard n > 0 else { return nil }
        func ts(_ i: Int) -> Int64 { store.timestamp(events.id(at: i)) }
        let loIndex = !fullRange && n > 1000 ? n / 1000 : 0
        let hiIndex = !fullRange && n > 1000 ? n - 1 - n / 1000 : n - 1
        let lo = ts(loIndex), hi = ts(hiIndex)
        let span = max(hi - lo, FileTime.ticksPerSecond)
        let raw = span / Int64(targetBins)
        let width = (niceSeconds.map { $0 * FileTime.ticksPerSecond }.first { $0 >= raw }) ?? raw
        let start = lo - ((lo % width) + width) % width
        let count = Int((hi - start) / width) + 1
        func position(_ t: Int64) -> Int {
            var a = 0, b = n
            while a < b {
                let m = (a + b) >> 1
                if ts(m) < t { a = m + 1 } else { b = m }
            }
            return a
        }
        var bins: [HistogramBin] = []
        bins.reserveCapacity(count)
        let first = position(start)
        var prev = first
        for i in 0..<count {
            let s = start + Int64(i) * width
            let next = position(s + width)
            bins.append(HistogramBin(id: i, start: s, end: s + width, count: next - prev))
            prev = next
        }
        return Histogram(bins: bins, binTicks: width, outliersBefore: first, outliersAfter: n - prev, fullRange: fullRange)
    }
}

struct Preset: Identifiable {
    let id = UUID()
    let title: String
    let query: String
}

/// Ready-made DFIR queries (shown in the sidebar).
enum Presets {
    /// Linux (UAC): queries over the normalised `Action` values of auth.log, wtmp/btmp and others.
    static let linux: [(group: String, items: [Preset])] = [
        (String(localized: "Входы и учётные записи"), [
            Preset(title: String(localized: "SSH: успешные входы"), query: "Action = auth_success | group by TargetUserName, IpAddress, AuthMethod"),
            Preset(title: String(localized: "SSH: неудачные попытки"), query: "Action in (auth_failure, invalid_user, user_not_allowed, too_many_auth_failures) | group by IpAddress, TargetUserName"),
            Preset(title: String(localized: "SSH: перебор по источнику"), query: "Action in (auth_failure, invalid_user, user_not_allowed) | group by IpAddress | sort count desc"),
            Preset(title: String(localized: "Неудачные входы (btmp, auditd)"), query: "Action = login_failed | group by IpAddress, TargetUserName | sort count desc"),
            Preset(title: String(localized: "Входы и выходы (wtmp)"), query: "Action in (login, logout) and channel = wtmp"),
            Preset(title: String(localized: "Загрузки и выключения"), query: "Action in (boot, shutdown, runlevel)"),
            Preset(title: String(localized: "Учётные записи и группы"), query: "Action in (user_added, user_deleted, user_modified, group_added, group_deleted, group_member_added, group_member_removed, password_changed)"),
        ]),
        (String(localized: "Повышение привилегий"), [
            Preset(title: String(localized: "sudo: команды"), query: "Action = sudo | group by SubjectUserName, TargetUserName, CommandLine"),
            Preset(title: String(localized: "sudo: отказы"), query: "Action = sudo_denied"),
            Preset(title: String(localized: "su"), query: "Action in (su, su_failed)"),
        ]),
        (String(localized: "Выполнение"), [
            Preset(title: String(localized: "Запуски программ (auditd)"), query: "Action = process_exec | group by SubjectUserName, exe | sort count desc"),
            Preset(title: String(localized: "Команды из историй оболочек"), query: "Action = shell_command | group by SubjectUserName, CommandLine"),
            Preset(title: String(localized: "Задания cron"), query: "Action = cron_command | group by SubjectUserName, CommandLine"),
            Preset(title: String(localized: "Скачивание и запуск из /tmp, /dev/shm"), query: "Action = process_exec and (CommandLine contains /tmp/ or CommandLine contains /dev/shm/ or CommandLine contains wget or CommandLine contains curl)"),
        ]),
        (String(localized: "Веб-серверы"), [
            Preset(title: String(localized: "Запросы по адресам"), query: "Action = http_request | group by IpAddress | sort count desc"),
            Preset(title: String(localized: "Ответы 4xx / 5xx"), query: "Action = http_request and HttpStatus >= 400 | group by HttpStatus, Uri | sort count desc"),
            Preset(title: String(localized: "POST-запросы"), query: "Action = http_request and HttpMethod = POST | group by Uri, IpAddress | sort count desc"),
            Preset(title: String(localized: "User-Agent клиентов"), query: "Action = http_request | group by UserAgent | sort count desc"),
        ]),
        (String(localized: "Пакеты и базы данных"), [
            Preset(title: String(localized: "Установка и удаление пакетов (dpkg)"), query: "Action in (package_install, package_upgrade, package_remove, package_purge) | group by Action, PackageName"),
            Preset(title: String(localized: "Транзакции apt"), query: "Action = apt_transaction"),
            Preset(title: String(localized: "MySQL: подключения и запросы"), query: "Action in (db_connect, db_query) | group by DbUser, DbCommand"),
        ]),
        (String(localized: "Сеть"), [
            Preset(title: String(localized: "Межсетевой экран (журнал ядра)"), query: "Action = firewall | group by SourceIp, DestinationPort, FirewallRule"),
        ]),
        (String(localized: "Качество данных"), [
            Preset(title: String(localized: "Строки, которые не удалось разобрать"), query: "flag = unparsed"),
            Preset(title: String(localized: "Время с восстановленным годом или поясом"), query: "flag in (yearInferred, zoneAssumed) | group by channel"),
            Preset(title: String(localized: "Записи без своего времени"), query: "flag in (timeCarried, timeFromFile) | group by channel"),
        ]),
    ]

    static let all: [(group: String, items: [Preset])] = [
        (String(localized: "Входы и учётные записи"), [
            Preset(title: String(localized: "Успешные входы (4624)"), query: "EventID = 4624 | group by LogonType, TargetUserName"),
            Preset(title: String(localized: "Неудачные входы (4625)"), query: "EventID = 4625 | group by TargetUserName, IpAddress, SubStatus"),
            Preset(title: String(localized: "Password spraying: неудачи по источнику"), query: "EventID = 4625 | group by IpAddress | sort count desc"),
            Preset(title: String(localized: "Сетевые входы (тип 3)"), query: "EventID = 4624 and LogonType = 3 and not TargetUserName endswith \"$\" | group by IpAddress, TargetUserName"),
            Preset(title: String(localized: "RDP-входы (тип 10)"), query: "EventID = 4624 and LogonType in (10, 7) | group by IpAddress, TargetUserName"),
            Preset(title: String(localized: "RDP: сессии (LSM / RCM)"), query: "channel in (\"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational\", \"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational\")"),
            Preset(title: String(localized: "Явные учётные данные (4648)"), query: "EventID = 4648 | group by SubjectUserName, TargetUserName, TargetServerName"),
            Preset(title: String(localized: "Привилегированные входы (4672)"), query: "EventID = 4672 and not SubjectUserName in (SYSTEM, \"LOCAL SERVICE\", \"NETWORK SERVICE\") and not SubjectUserName endswith \"$\""),
            Preset(title: String(localized: "Изменения учётных записей и групп"), query: "EventID in (4720, 4722, 4724, 4725, 4726, 4728, 4732, 4756, 4738) | group by EventID, TargetUserName"),
        ]),
        ("Kerberos / NTLM", [
            Preset(title: String(localized: "Kerberoasting (RC4 TGS, 4769)"), query: "EventID = 4769 and TicketEncryptionType = 0x17 and not ServiceName endswith \"$\""),
            Preset(title: String(localized: "AS-REP roasting (4768 без preauth)"), query: "EventID = 4768 and PreAuthType = 0"),
            Preset(title: String(localized: "NTLM-аутентификации (4776)"), query: "EventID = 4776 | group by TargetUserName, Workstation"),
        ]),
        (String(localized: "Выполнение и закрепление"), [
            Preset(title: String(localized: "Создание процессов (4688 / Sysmon 1)"), query: "EventID = 4688 or (provider = \"Microsoft-Windows-Sysmon\" and EventID = 1)"),
            Preset(title: String(localized: "Новые службы (7045 / 4697)"), query: "(EventID = 7045 and channel = System) or EventID = 4697"),
            Preset(title: String(localized: "Запланированные задачи (4698 / 106)"), query: "EventID = 4698 or (channel = \"Microsoft-Windows-TaskScheduler/Operational\" and EventID = 106)"),
            Preset(title: String(localized: "PowerShell ScriptBlock (4104)"), query: "EventID = 4104"),
            Preset(title: String(localized: "PowerShell: подозрительное"), query: "EventID = 4104 and (ScriptBlockText contains FromBase64String or ScriptBlockText contains \"Invoke-Expression\" or ScriptBlockText contains DownloadString or ScriptBlockText contains \"-enc\" or ScriptBlockText contains IEX)"),
            Preset(title: String(localized: "Sysmon: сетевые соединения (3)"), query: "provider = \"Microsoft-Windows-Sysmon\" and EventID = 3 | group by Image, DestinationIp, DestinationPort"),
            Preset(title: String(localized: "Sysmon: автозапуск в реестре (13)"), query: #"provider = "Microsoft-Windows-Sysmon" and EventID = 13 and TargetObject contains "\CurrentVersion\Run""#),
        ]),
        (String(localized: "Сокрытие следов"), [
            Preset(title: String(localized: "Очистка журналов (1102 / 104 / 1100)"), query: "(EventID = 1102 and channel = Security) or (EventID = 104 and channel = System) or (EventID = 1100 and channel = Security)"),
            Preset(title: String(localized: "Изменение системного времени (4616)"), query: "EventID = 4616 or (provider = \"Microsoft-Windows-Kernel-General\" and EventID = 1)"),
            Preset(title: String(localized: "Defender: обнаружения и действия"), query: "provider = \"Microsoft-Windows-Windows Defender\" and EventID in (1116, 1117, 5001, 5007)"),
        ]),
        (String(localized: "Доступ к ресурсам"), [
            Preset(title: String(localized: "Админ-шары (5140 / 5145)"), query: #"EventID in (5140, 5145) and ShareName in ("\\\\*\\ADMIN$", "\\\\*\\C$", "\\\\*\\IPC$") | group by IpAddress, ShareName, SubjectUserName"#),
        ]),
        (String(localized: "Особенности журналов"), [
            Preset(title: String(localized: "Восстановленные из slack"), query: "flag = carved"),
            Preset(title: String(localized: "Чанки за заголовком (новые данные)"), query: "flag = beyondHeader and not flag = stale"),
            Preset(title: String(localized: "Устаревшие чанки (остатки)"), query: "flag = stale"),
            Preset(title: String(localized: "TimeCreated ≠ время записи"), query: "flag = timeSkew"),
            Preset(title: String(localized: "Ошибки разбора"), query: "flag = parseError"),
        ]),
    ]
}
