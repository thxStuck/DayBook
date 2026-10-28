import DaybookStore
import Foundation

/// A rule translated to DQL. `query` is the exact DQL that is evaluated, so analysts can
/// read it, run it from the query bar and adjust it.
public struct CompiledSigmaRule: Sendable {
    public let rule: SigmaRule
    public let expr: DQLExpr?
    /// Why the rule cannot be evaluated (nil when supported).
    public let unsupported: String?
    /// Event families the rule is evaluated on, with the field renames that were applied.
    public let variants: [String]
    /// Fields the rule uses that never occur in the case (conditions on them are false,
    /// `field: null` is true) — shown so a silent rule is not mistaken for a clean result.
    public let absentFields: [String]
    public var query: String { expr?.dql ?? "" }
}

/// What the compiler needs to know about the case.
public struct SigmaFieldCatalog {
    /// True when a field with exactly this (case-sensitive) name occurs in the case.
    public let has: (String) -> Bool
    /// Hayabusa field aliases (alias → XML path).
    public let aliases: [String: String]
    /// The system the case comes from: Windows rules run on .evtx cases, Linux rules on UAC cases.
    public let platform: CasePlatform

    public init(has: @escaping (String) -> Bool, aliases: [String: String], platform: CasePlatform = .windows) {
        self.has = has
        self.aliases = aliases
        self.platform = platform
    }
}

struct SigmaUnsupported: Error { let reason: String }

public enum SigmaCompiler {
    // MARK: Logsource → event families

    /// One family of events a rule is evaluated on (e.g. Sysmon 1, Security 4688).
    struct Variant {
        let label: String
        let base: DQLExpr
        /// Sigma field → field of these events (only where values mean the same thing).
        var renames: [String: String] = [:]
        /// Value translation for renamed fields (e.g. IntegrityLevel names → mandatory label SIDs).
        var values: [String: [String: String]] = [:]
    }

    static let sysmonChannel = "Microsoft-Windows-Sysmon/Operational"

    static func channel(_ c: String) -> DQLExpr {
        c.contains("*") ? .compare(field: CaseSchema.SystemKey.channel, op: .like, value: c)
            : .compare(field: CaseSchema.SystemKey.channel, op: .eq, value: c)
    }

    static func channels(_ cs: [String]) -> DQLExpr { cs.count == 1 ? channel(cs[0]) : .or(cs.map(channel)) }

    static func ids(_ list: [Int]) -> DQLExpr {
        list.count == 1 ? .compare(field: CaseSchema.SystemKey.eventId, op: .eq, value: String(list[0]))
            : .inList(field: CaseSchema.SystemKey.eventId, values: list.map(String.init))
    }

    static func sysmon(_ list: [Int]) -> Variant {
        Variant(label: "Sysmon " + list.map(String.init).joined(separator: "/"), base: .and([channel(sysmonChannel), ids(list)]))
    }

    static func events(_ label: String, _ cs: [String], _ list: [Int]) -> Variant {
        Variant(label: label, base: .and([channels(cs), ids(list)]))
    }

    static let powershell = ["Microsoft-Windows-PowerShell/Operational", "PowerShellCore/Operational"]

    /// Mandatory label SIDs (MS-DTYP 2.4.2.4) for Sysmon's IntegrityLevel names.
    static let integrityLevels: [String: String] = [
        "untrusted": "S-1-16-0", "low": "S-1-16-4096", "medium": "S-1-16-8192", "mediumplus": "S-1-16-8448",
        "medium plus": "S-1-16-8448", "high": "S-1-16-12288", "system": "S-1-16-16384", "protected": "S-1-16-20480",
    ]

    /// Category mapping; channels and event ids follow Hayabusa's conversion of the same
    /// SigmaHQ rules. Security-log variants are added only where the fields carry the same
    /// values (4688 for process creation); 4657 (registry) and 5156 (network) are not used:
    /// their paths, value names and directions are encoded differently.
    static let categories: [String: [Variant]] = [
        "process_creation": [
            sysmon([1]),
            Variant(label: "Security 4688", base: .and([channel("Security"), ids([4688])]),
                    renames: ["Image": "NewProcessName", "ParentImage": "ParentProcessName", "IntegrityLevel": "MandatoryLabel"],
                    values: ["IntegrityLevel": integrityLevels]),
        ],
        "process_termination": [sysmon([5])],
        "network_connection": [sysmon([3])],
        "driver_load": [sysmon([6])],
        "image_load": [sysmon([7])],
        "create_remote_thread": [sysmon([8])],
        "raw_access_thread": [sysmon([9])],
        "process_access": [sysmon([10])],
        "file_event": [sysmon([11])],
        "file_change": [sysmon([2])],
        "registry_add": [sysmon([12])],
        "registry_delete": [sysmon([12])],
        "registry_set": [sysmon([13])],
        "registry_rename": [sysmon([14])],
        "registry_event": [sysmon([12, 13, 14])],
        "create_stream_hash": [sysmon([15])],
        "pipe_created": [sysmon([17, 18])],
        "wmi_event": [sysmon([19, 20, 21])],
        "dns_query": [sysmon([22])],
        "file_delete": [sysmon([23, 26])],
        "clipboard_change": [sysmon([24])],
        "process_tampering": [sysmon([25])],
        "file_block_executable": [sysmon([27])],
        "file_block_shredding": [sysmon([28])],
        "file_executable_detected": [sysmon([29])],
        "sysmon_status": [sysmon([4, 16])],
        "sysmon_error": [sysmon([255])],
        "ps_module": [events("PowerShell 4103", powershell, [4103])],
        "ps_script": [events("PowerShell 4104", powershell, [4104])],
        "ps_classic_start": [events("Windows PowerShell 400", ["Windows PowerShell"], [400])],
        "ps_classic_provider_start": [events("Windows PowerShell 600", ["Windows PowerShell"], [600])],
        "ps_classic_script": [events("Windows PowerShell 800", ["Windows PowerShell"], [800])],
    ]

    /// Service → channels (Hayabusa's conversion; names checked against real log file names where possible).
    static let services: [String: [String]] = [
        "security": ["Security"], "system": ["System"], "application": ["Application"],
        "sysmon": [sysmonChannel],
        "powershell": powershell, "powershell-classic": ["Windows PowerShell"],
        "taskscheduler": ["Microsoft-Windows-TaskScheduler/Operational"],
        "wmi": ["Microsoft-Windows-WMI-Activity/Operational"],
        "dns-server": ["DNS Server"],
        "dns-server-audit": ["Microsoft-Windows-DNSServer/Audit", "Microsoft-Windows-DNS-Server/Audit"],
        "dns-server-analytic": ["Microsoft-Windows-DNS-Server/Analytical", "Microsoft-Windows-DNSServer/Analytical"],
        "dns-client": ["Microsoft-Windows-DNS Client Events/Operational"],
        "driver-framework": ["Microsoft-Windows-DriverFrameworks-UserMode/Operational"],
        "ntlm": ["Microsoft-Windows-NTLM/Operational"],
        "windefend": ["Microsoft-Windows-Windows Defender/Operational"],
        "firewall-as": ["Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"],
        "bits-client": ["Microsoft-Windows-Bits-Client/Operational"],
        "codeintegrity-operational": ["Microsoft-Windows-CodeIntegrity/Operational"],
        "terminalservices-localsessionmanager": ["Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"],
        "msexchange-management": ["MSExchange Management"],
        "applocker": ["Microsoft-Windows-AppLocker/MSI and Script", "Microsoft-Windows-AppLocker/EXE and DLL",
                      "Microsoft-Windows-AppLocker/Packaged app-Deployment", "Microsoft-Windows-AppLocker/Packaged app-Execution"],
        "appmodel-runtime": ["Microsoft-Windows-AppModel-Runtime/Admin"],
        "appxdeployment-server": ["Microsoft-Windows-AppXDeploymentServer/Operational"],
        "appxpackaging-om": ["Microsoft-Windows-AppxPackaging/Operational"],
        "capi2": ["Microsoft-Windows-CAPI2/Operational"],
        "certificateservicesclient-lifecycle-system": ["Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational"],
        "diagnosis-scripted": ["Microsoft-Windows-Diagnosis-Scripted/Operational"],
        "lsa-server": ["Microsoft-Windows-LSA/Operational"],
        "microsoft-servicebus-client": ["Microsoft-ServiceBus-Client"],
        "openssh": ["OpenSSH/Operational"],
        "printservice-admin": ["Microsoft-Windows-PrintService/Admin"],
        "printservice-operational": ["Microsoft-Windows-PrintService/Operational"],
        "security-mitigations": ["Microsoft-Windows-Security-Mitigations*"],
        "shell-core": ["Microsoft-Windows-Shell-Core/Operational"],
        "smbclient-connectivity": ["Microsoft-Windows-SmbClient/Connectivity"],
        "smbclient-security": ["Microsoft-Windows-SmbClient/Security"],
        "smbserver-connectivity": ["Microsoft-Windows-SMBServer/Connectivity"],
        "ldap": ["Microsoft-Windows-LDAP-Client/Debug"],
        "dfsn-server": ["Microsoft-Windows-DFSN-Server/Admin"],
        "ntfs": ["Microsoft-Windows-Ntfs/Operational"],
        "vhdmp": ["Microsoft-Windows-VHDMP-Operational"],
        "iis-configuration": ["Microsoft-IIS-Configuration/Operational"],
    ]

    // MARK: Linux (UAC cases)

    static func providers(_ ps: [String]) -> DQLExpr {
        ps.count == 1 ? .compare(field: CaseSchema.SystemKey.provider, op: .eq, value: ps[0])
            : .inList(field: CaseSchema.SystemKey.provider, values: ps)
    }

    /// Linux services → the events of a UAC case that carry them.
    static func linuxServices(_ catalog: SigmaFieldCatalog) -> [String: Variant] {
        var auth: [DQLExpr] = [channels(["auth.log", "secure"])]
        if catalog.has("SYSLOG_FACILITY") {   // journald entries of the auth / authpriv facilities
            auth.append(.inList(field: "SYSLOG_FACILITY", values: ["4", "10"]))
        }
        return [
            "auditd": Variant(label: "auditd (audit/audit.log)", base: channel("audit/audit.log"),
                              renames: ["type": "Type", "SYSCALL": "SyscallName"]),
            "auth": Variant(label: "auth.log | secure", base: auth.count == 1 ? auth[0] : .or(auth)),
            "syslog": Variant(label: "syslog | messages", base: channels(["syslog", "messages"])),
            "sshd": Variant(label: "sshd", base: providers(["sshd", "sshd-session", "sshd-auth"])),
            "sudo": Variant(label: "sudo", base: providers(["sudo"]), renames: ["USER": "TargetUserName"]),
            "cron": Variant(label: "cron", base: providers(["CRON", "cron", "crond"])),
            "clamav": Variant(label: "clamav", base: providers(["clamd", "freshclam", "clamav"])),
            "vsftpd": Variant(label: "vsftpd", base: providers(["vsftpd"])),
            "guacamole": Variant(label: "guacamole", base: providers(["guacd"])),
        ]
    }

    /// Linux categories: process creation comes from auditd's execve records. Fields keep their
    /// meaning where renamed; ParentImage / ParentCommandLine are not in auditd records.
    static let linuxCategories: [String: Variant] = [
        "process_creation": Variant(label: "auditd execve", base: .compare(field: "Action", op: .eq, value: "process_exec"),
                                    renames: ["Image": "exe", "CurrentDirectory": "cwd", "User": "UidName", "LogonId": "ses",
                                              "ProcessId": "pid", "ParentProcessId": "ppid"]),
    ]

    static func linuxVariants(_ ls: [String: String], _ catalog: SigmaFieldCatalog) throws -> [Variant] {
        var v: Variant?
        if let category = ls["category"]?.lowercased() {
            guard let c = linuxCategories[category] else {
                throw SigmaUnsupported(reason: String(localized: "категория logsource «\(category)»: в сборе UAC нет таких событий (их пишет Sysmon for Linux)"))
            }
            v = c
        }
        if let service = ls["service"]?.lowercased() {
            guard let s = linuxServices(catalog)[service] else {
                throw SigmaUnsupported(reason: String(localized: "сервис logsource «\(service)» не сопоставлен журналам сбора UAC"))
            }
            v = v.map { Variant(label: $0.label + " · " + s.label, base: .and([$0.base, s.base]),
                                renames: $0.renames.merging(s.renames) { a, _ in a }, values: $0.values) } ?? s
        }
        return [v ?? Variant(label: String(localized: "все журналы Linux"), base: .constant(true))]
    }

    static func variants(_ ls: [String: String], _ catalog: SigmaFieldCatalog) throws -> [Variant] {
        let product = ls["product"]?.lowercased()
        if catalog.platform == .linux {
            guard product == "linux" else {
                throw SigmaUnsupported(reason: String(localized: "правило для «\(product ?? "windows")», кейс — Linux"))
            }
            return try linuxVariants(ls, catalog)
        }
        if let product, product != "windows" {
            throw SigmaUnsupported(reason: String(localized: "logsource product «\(product)» — не журналы Windows"))
        }
        if let category = ls["category"]?.lowercased() {
            guard var v = categories[category] else {
                throw SigmaUnsupported(reason: String(localized: "категория logsource «\(category)» не сопоставлена журналам .evtx"))
            }
            if let service = ls["service"]?.lowercased() {
                guard let cs = services[service] else {
                    throw SigmaUnsupported(reason: String(localized: "сервис logsource «\(service)» не сопоставлен журналу"))
                }
                v = v.map { Variant(label: $0.label, base: .and([$0.base, channels(cs)]), renames: $0.renames, values: $0.values) }
            }
            return v
        }
        if let service = ls["service"]?.lowercased() {
            guard let cs = services[service] else {
                throw SigmaUnsupported(reason: String(localized: "сервис logsource «\(service)» не сопоставлен журналу"))
            }
            return [Variant(label: cs.joined(separator: " | "), base: channels(cs))]
        }
        // product: windows only — the detection itself names Channel / EventID (Hayabusa style).
        return [Variant(label: String(localized: "все журналы (каналы задаёт само правило)"), base: .constant(true))]
    }

    // MARK: Fields

    enum Target: Equatable {
        case key(String)
        /// The whole EventData (Hayabusa `Message`): substring search in any field.
        case anyField
        case unindexed(String)
    }

    static let systemNames: [String: String] = [
        "EventID": CaseSchema.SystemKey.eventId, "Channel": CaseSchema.SystemKey.channel,
        "Provider_Name": CaseSchema.SystemKey.provider, "ProviderName": CaseSchema.SystemKey.provider,
        "Computer": CaseSchema.SystemKey.computer, "ComputerName": CaseSchema.SystemKey.computer,
        "Level": CaseSchema.SystemKey.level, "SecurityUserID": CaseSchema.SystemKey.user,
        "Keywords": CaseSchema.SystemKey.keywords,
    ]

    static let systemPaths: [String: String] = [
        "Event.System.EventID": CaseSchema.SystemKey.eventId, "Event.System.Channel": CaseSchema.SystemKey.channel,
        "Event.System.Provider_attributes.Name": CaseSchema.SystemKey.provider,
        "Event.System.Provider_Name": CaseSchema.SystemKey.provider,
        "Event.System.Computer": CaseSchema.SystemKey.computer, "Event.System.Level": CaseSchema.SystemKey.level,
        "Event.System.Security_attributes.UserID": CaseSchema.SystemKey.user,
        "Event.System.Task": CaseSchema.SystemKey.task, "Event.System.Opcode": CaseSchema.SystemKey.opcode,
        "Event.System.Keywords": CaseSchema.SystemKey.keywords,
    ]

    /// Sigma field → stored key. System fields map to the `@…` keys; Hayabusa aliases are
    /// resolved through their XML path (UserData leaves are stored without the wrapper element).
    static func target(_ field: String, _ aliases: [String: String]) -> Target {
        if let k = systemNames[field] { return .key(k) }
        guard let path = aliases[field]?.trimmingCharacters(in: .whitespaces) else { return .key(field) }
        if let k = systemPaths[path] { return .key(k) }
        if path.hasPrefix("Event.System.") { return .unindexed(path) }
        if path == "Event.EventData" { return .anyField }
        if path.hasPrefix("Event.EventData.") { return .key(String(path.dropFirst("Event.EventData.".count))) }
        if path.hasPrefix("Event.UserData.") {
            let parts = path.dropFirst("Event.UserData.".count).split(separator: ".").map(String.init)
            return .key(parts.count > 1 ? parts.dropFirst().joined(separator: ".") : parts.joined())
        }
        return .key(field)
    }

    // MARK: Compile

    final class Context {
        let catalog: SigmaFieldCatalog
        let variant: Variant
        /// Hayabusa's aliases apply to Hayabusa rules only: in SigmaHQ rules the same names
        /// are plain EventData fields (e.g. SearchFilter, ServerName).
        let aliases: [String: String]
        var absent: Set<String> = []
        var renamed: Set<String> = []

        init(_ catalog: SigmaFieldCatalog, _ variant: Variant, hayabusa: Bool) {
            self.catalog = catalog
            self.variant = variant
            aliases = hayabusa ? catalog.aliases : [:]
        }

        /// Stored key for a rule field in this variant (nil: the field is not in the case).
        func key(_ field: String) throws -> String? {
            var name = field
            if let r = variant.renames[field] {
                name = r
                renamed.insert("\(field)→\(r)")
            }
            switch SigmaCompiler.target(name, aliases) {
            case let .key(k):
                if catalog.has(k) { return k }
                absent.insert(k == field ? k : "\(field) (\(k))")
                return nil
            case .anyField:
                return nil
            case let .unindexed(path):
                throw SigmaUnsupported(reason: String(localized: "поле «\(field)» (\(path)) не индексируется"))
            }
        }

        func isAnyField(_ field: String) -> Bool {
            SigmaCompiler.target(variant.renames[field] ?? field, aliases) == .anyField
        }
    }

    public static func compile(_ rule: SigmaRule, catalog: SigmaFieldCatalog) -> CompiledSigmaRule {
        do {
            let vs = try variants(rule.logsource, catalog)
            if rule.conditions.isEmpty { throw SigmaUnsupported(reason: String(localized: "нет condition")) }
            var parts: [DQLExpr] = []
            var labels: [String] = []
            var absent: Set<String> = []
            for v in vs {
                let ctx = Context(catalog, v, hayabusa: rule.source == "Hayabusa")
                let detection = try condition(rule, ctx)
                parts.append(simplify(.and([v.base, detection])))
                labels.append(ctx.renamed.isEmpty ? v.label : v.label + ": " + ctx.renamed.sorted().joined(separator: ", "))
                absent.formUnion(ctx.absent)
            }
            let expr = simplify(parts.count == 1 ? parts[0] : .or(parts))
            return CompiledSigmaRule(rule: rule, expr: expr, unsupported: nil, variants: labels, absentFields: absent.sorted())
        } catch let u as SigmaUnsupported {
            return CompiledSigmaRule(rule: rule, expr: nil, unsupported: u.reason, variants: [], absentFields: [])
        } catch {
            return CompiledSigmaRule(rule: rule, expr: nil, unsupported: "\(error)", variants: [], absentFields: [])
        }
    }

    static func condition(_ rule: SigmaRule, _ ctx: Context) throws -> DQLExpr {
        var compiled: [String: DQLExpr] = [:]
        func search(_ name: String) throws -> DQLExpr {
            if let e = compiled[name] { return e }
            guard let s = rule.searches[name] else {
                throw SigmaUnsupported(reason: String(localized: "condition ссылается на неизвестный идентификатор «\(name)»"))
            }
            let e = try compileSearch(s, ctx)
            compiled[name] = e
            return e
        }
        let parts = try rule.conditions.map { text -> DQLExpr in
            if text.contains("|") {
                throw SigmaUnsupported(reason: String(localized: "агрегация в condition («\(text)») не поддерживается"))
            }
            var p = ConditionParser(tokens: ConditionParser.tokenize(text), names: Array(rule.searches.keys), resolve: search)
            let e = try p.parse()
            guard p.atEnd else { throw SigmaUnsupported(reason: String(localized: "не разобрано условие «\(text)»")) }
            return e
        }
        return parts.count == 1 ? parts[0] : .or(parts)
    }

    struct ConditionParser {
        var tokens: [String]
        let names: [String]
        let resolve: (String) throws -> DQLExpr
        var i = 0
        var atEnd: Bool { i >= tokens.count }

        static func tokenize(_ s: String) -> [String] {
            var out: [String] = []
            var cur = ""
            for ch in s {
                if ch == "(" || ch == ")" {
                    if !cur.isEmpty { out.append(cur); cur = "" }
                    out.append(String(ch))
                } else if ch.isWhitespace {
                    if !cur.isEmpty { out.append(cur); cur = "" }
                } else {
                    cur.append(ch)
                }
            }
            if !cur.isEmpty { out.append(cur) }
            return out
        }

        func peek() -> String? { i < tokens.count ? tokens[i] : nil }
        mutating func next() -> String? { defer { i += 1 }; return peek() }

        mutating func parse() throws -> DQLExpr { try or() }

        mutating func or() throws -> DQLExpr {
            var parts = [try and()]
            while peek()?.lowercased() == "or" { _ = next(); parts.append(try and()) }
            return parts.count == 1 ? parts[0] : .or(parts)
        }

        mutating func and() throws -> DQLExpr {
            var parts = [try not()]
            while peek()?.lowercased() == "and" { _ = next(); parts.append(try not()) }
            return parts.count == 1 ? parts[0] : .and(parts)
        }

        mutating func not() throws -> DQLExpr {
            if peek()?.lowercased() == "not" { _ = next(); return .not(try not()) }
            return try primary()
        }

        mutating func primary() throws -> DQLExpr {
            guard let t = next() else { throw SigmaUnsupported(reason: String(localized: "неожиданный конец condition")) }
            if t == "(" {
                let e = try or()
                guard next() == ")" else { throw SigmaUnsupported(reason: String(localized: "нет «)» в condition")) }
                return e
            }
            let lower = t.lowercased()
            if lower == "all" || Int(lower) != nil, peek()?.lowercased() == "of" {
                _ = next()
                guard let target = next() else { throw SigmaUnsupported(reason: String(localized: "нет цели после «of»")) }
                let matched: [String]
                if target.lowercased() == "them" {
                    matched = names.filter { !$0.hasPrefix("_") }.sorted()
                } else {
                    var p = "^"
                    for ch in target { p += ch == "*" ? ".*" : NSRegularExpression.escapedPattern(for: String(ch)) }
                    let re = try NSRegularExpression(pattern: p + "$")
                    matched = names.filter { re.firstMatch(in: $0, range: NSRange(location: 0, length: ($0 as NSString).length)) != nil }.sorted()
                }
                guard !matched.isEmpty else {
                    throw SigmaUnsupported(reason: String(localized: "«\(t) of \(target)» не находит идентификаторов"))
                }
                let exprs = try matched.map(resolve)
                if lower == "1" { return exprs.count == 1 ? exprs[0] : .or(exprs) }
                if lower == "all" { return exprs.count == 1 ? exprs[0] : .and(exprs) }
                throw SigmaUnsupported(reason: String(localized: "«\(t) of …» поддерживается только для 1 и all"))
            }
            return try resolve(t)
        }
    }

    // MARK: Searches

    static func compileSearch(_ s: SigmaSearch, _ ctx: Context) throws -> DQLExpr {
        switch s {
        case let .all(items):
            if items.isEmpty { return .constant(true) }
            let parts = try items.map { try compileItem($0, ctx) }
            return parts.count == 1 ? parts[0] : .and(parts)
        case let .any(list):
            let parts = try list.map { try compileSearch($0, ctx) }
            return parts.count == 1 ? parts[0] : .or(parts)
        case let .keywords(values):
            let parts = try values.map(keyword)
            return parts.count == 1 ? parts[0] : .or(parts)
        }
    }

    /// Keyword: case-insensitive substring of any field value.
    static func keyword(_ v: SigmaValue) throws -> DQLExpr {
        guard case let .string(text) = v else { return .constant(false) }
        var p = pieces(text)
        while p.first == .any { p.removeFirst() }
        while p.last == .any { p.removeLast() }
        guard let s = plain(p) else {
            throw SigmaUnsupported(reason: String(localized: "ключевое слово с маской внутри («\(text)») не поддерживается"))
        }
        return s.isEmpty ? .constant(true) : .text(s)
    }

    static func compileItem(_ item: SigmaItem, _ ctx: Context) throws -> DQLExpr {
        guard let field = item.field else {
            let parts = try item.values.map(keyword)
            return parts.count == 1 ? parts[0] : (item.modifiers.contains("all") ? .and(parts) : .or(parts))
        }
        var all = false, cased = false, fieldref = false
        var mode = "eq"
        var transforms: [String] = []
        var reFlags = ""
        for m in item.modifiers {
            switch m {
            case "contains", "startswith", "endswith", "re", "cidr", "gt", "gte", "lt", "lte", "exists": mode = m
            case "all": all = true
            case "cased": cased = true
            case "fieldref": fieldref = true
            case "base64", "base64offset", "wide", "utf16le", "windash": transforms.append(m)
            case "i", "m", "s": reFlags += m
            case "utf16", "utf16be": throw SigmaUnsupported(reason: String(localized: "модификатор «\(m)» не поддерживается"))
            case "expand": throw SigmaUnsupported(reason: String(localized: "модификатор expand (плейсхолдеры) не поддерживается"))
            default: throw SigmaUnsupported(reason: String(localized: "неизвестный модификатор «\(m)»"))
            }
        }
        if !reFlags.isEmpty && mode != "re" {
            throw SigmaUnsupported(reason: String(localized: "флаги i/m/s допустимы только с re"))
        }

        // `Message` (whole EventData, Hayabusa): substring search over every field.
        if ctx.isAnyField(field) {
            guard mode == "contains" || mode == "eq", transforms.isEmpty, !cased else {
                throw SigmaUnsupported(reason: String(localized: "для поля «\(field)» (вся EventData) поддерживается только contains"))
            }
            let parts = try item.values.map(keyword)
            return parts.count == 1 ? parts[0] : (all ? .and(parts) : .or(parts))
        }

        let key = try ctx.key(field)
        if mode == "exists" {
            let want = item.values.first.map { v in
                if case let .string(s) = v { return ["true", "yes"].contains(s.lowercased()) }
                return false
            } ?? true
            guard let key else { return .constant(!want) }
            return want ? .exists(field: key) : .not(.exists(field: key))
        }
        if fieldref {
            guard let key else { return .constant(false) }
            let op: DQLOp
            switch mode {
            case "eq": op = cased ? .eqExact : .eq
            case "contains": op = .contains
            case "startswith": op = .startswith
            case "endswith": op = .endswith
            default: throw SigmaUnsupported(reason: String(localized: "fieldref с «\(mode)» не поддерживается"))
            }
            var preds: [DQLExpr] = []
            for v in item.values {
                guard case let .string(other) = v else { continue }
                guard let otherKey = try ctx.key(other) else { preds.append(.constant(false)); continue }
                preds.append(.fieldCompare(field: key, op: op, other: otherKey))
            }
            if preds.isEmpty { return .constant(false) }
            return preds.count == 1 ? preds[0] : (all ? .and(preds) : .or(preds))
        }
        guard let key else {
            // The field never occurs in this case: positive matches are impossible;
            // `field: null` (the field does not exist) is always true.
            return .constant(item.values.allSatisfy { $0 == .null })
        }
        var preds: [DQLExpr] = []
        let translate = ctx.variant.values[field]
        for v in item.values {
            guard case var .string(text) = v else {
                preds.append(.not(.exists(field: key)))
                continue
            }
            if let translate, let t = translate[text.lowercased()] { text = t }
            let alternatives = try expand(text, mode: mode, transforms: transforms)
            let exprs = try alternatives.map { try predicate(key, mode, $0, raw: text, cased: cased, reFlags: reFlags) }
            preds.append(exprs.count == 1 ? exprs[0] : .or(exprs))
        }
        if preds.isEmpty { return .constant(false) }
        return preds.count == 1 ? preds[0] : (all ? .and(preds) : .or(preds))
    }

    static func predicate(_ field: String, _ mode: String, _ p: [Piece], raw: String, cased: Bool, reFlags: String) throws -> DQLExpr {
        switch mode {
        case "re":
            // Sigma regular expressions are case-sensitive unless |i.
            let flags = (reFlags.contains("i") ? "" : "(?-i)") + (reFlags.contains("m") ? "(?m)" : "") + (reFlags.contains("s") ? "(?s)" : "")
            do { _ = try NSRegularExpression(pattern: raw) } catch {
                throw SigmaUnsupported(reason: String(localized: "регулярное выражение не компилируется (ICU): ") + raw)
            }
            return .compare(field: field, op: .matches, value: flags + raw)
        case "cidr": return .compare(field: field, op: .cidr, value: raw)
        case "gt", "gte", "lt", "lte":
            guard StringKey.number(raw) != nil else {
                throw SigmaUnsupported(reason: String(localized: "«\(mode)» со значением «\(raw)» — не число"))
            }
            let op: DQLOp = ["gt": .gt, "gte": .ge, "lt": .lt, "lte": .le][mode]!
            return .compare(field: field, op: op, value: raw)
        default: break
        }
        let lead = mode == "contains" || mode == "endswith", trail = mode == "contains" || mode == "startswith"
        if cased {
            return .compare(field: field, op: .matches, value: "(?-i)(?s)^" + (lead ? ".*" : "") + regex(p) + (trail ? ".*" : "") + "$")
        }
        if let s = plain(p) {
            if s.isEmpty && mode != "eq" { return .exists(field: field) }
            switch mode {
            case "contains": return .compare(field: field, op: .contains, value: s)
            case "startswith": return .compare(field: field, op: .startswith, value: s)
            case "endswith": return .compare(field: field, op: .endswith, value: s)
            default:
                // DQL `=` treats * and ? as wildcards; a literal * / ? needs an exact regex.
                if s.contains("*") || s.contains("?") {
                    return .compare(field: field, op: .matches, value: "(?s)^" + NSRegularExpression.escapedPattern(for: s) + "$")
                }
                return .compare(field: field, op: .eq, value: s)
            }
        }
        if let l = like(p) {
            return .compare(field: field, op: .like, value: (lead ? "*" : "") + l + (trail ? "*" : ""))
        }
        return .compare(field: field, op: .matches, value: "(?s)^" + (lead ? ".*" : "") + regex(p) + (trail ? ".*" : "") + "$")
    }

    // MARK: Values (Sigma escaping: `\` escapes `*`, `?` and `\`; any other `\` is literal)

    enum Piece: Equatable {
        case lit(String)
        case any
        case one
    }

    static func pieces(_ s: String) -> [Piece] {
        var out: [Piece] = []
        var lit = ""
        func flush() {
            if !lit.isEmpty { out.append(.lit(lit)); lit = "" }
        }
        let chars = Array(s)
        var i = 0
        while i < chars.count {
            let c = chars[i]
            if c == "\\", i + 1 < chars.count, chars[i + 1] == "*" || chars[i + 1] == "?" || chars[i + 1] == "\\" {
                lit.append(chars[i + 1])
                i += 2
                continue
            }
            switch c {
            case "*": flush(); out.append(.any)
            case "?": flush(); out.append(.one)
            default: lit.append(c)
            }
            i += 1
        }
        flush()
        return out
    }

    /// The value as plain text when it has no wildcards.
    static func plain(_ p: [Piece]) -> String? {
        var s = ""
        for x in p {
            guard case let .lit(t) = x else { return nil }
            s += t
        }
        return s
    }

    /// DQL `like` pattern (nil when a literal * or ? would be read as a wildcard).
    static func like(_ p: [Piece]) -> String? {
        var s = ""
        for x in p {
            switch x {
            case let .lit(t):
                if t.contains("*") || t.contains("?") { return nil }
                s += t
            case .any: s += "*"
            case .one: s += "?"
            }
        }
        return s
    }

    static func regex(_ p: [Piece]) -> String {
        p.map { x -> String in
            switch x {
            case let .lit(t): NSRegularExpression.escapedPattern(for: t)
            case .any: ".*"
            case .one: "."
            }
        }.joined()
    }

    static let dashes = ["-", "/", "\u{2013}", "\u{2014}", "\u{2015}"]

    /// Alternatives of one value after windash / base64 / base64offset / wide.
    static func expand(_ text: String, mode: String, transforms: [String]) throws -> [[Piece]] {
        if mode == "re" || mode == "cidr" || ["gt", "gte", "lt", "lte"].contains(mode) {
            guard transforms.isEmpty else {
                throw SigmaUnsupported(reason: String(localized: "модификаторы \(transforms.joined(separator: "|")) несовместимы с \(mode)"))
            }
            return [[.lit(text)]]
        }
        var alts = [pieces(text)]
        if transforms.contains("windash") { alts = try alts.flatMap(windash) }
        let wide = transforms.contains("wide") || transforms.contains("utf16le")
        let b64 = transforms.contains("base64"), b64o = transforms.contains("base64offset")
        if wide && !b64 && !b64o {
            throw SigmaUnsupported(reason: String(localized: "wide/utf16le без base64 не поддерживается"))
        }
        if b64 || b64o {
            alts = try alts.flatMap { p -> [[Piece]] in
                guard let s = plain(p) else {
                    throw SigmaUnsupported(reason: String(localized: "base64 от значения с маской не поддерживается"))
                }
                let bytes: [UInt8] = wide ? s.utf16.flatMap { [UInt8($0 & 0xFF), UInt8($0 >> 8)] } : Array(s.utf8)
                let encoded = b64o ? base64Offsets(bytes) : [Data(bytes).base64EncodedString()]
                return encoded.map { [.lit($0)] }
            }
        }
        return alts
    }

    /// pySigma windash: a `-` or `/` at the start of a word (regex `\B[-/]\b`) becomes each of
    /// `-`, `/`, en dash, em dash and horizontal bar; several positions give every combination.
    static func windash(_ p: [Piece]) throws -> [[Piece]] {
        func isWord(_ c: Character) -> Bool { c.isLetter || c.isNumber || c == "_" }
        var positions: [(piece: Int, offset: Int)] = []
        for (pi, x) in p.enumerated() {
            guard case let .lit(t) = x else { continue }
            let chars = Array(t)
            for (ci, c) in chars.enumerated() where c == "-" || c == "/" {
                let before = ci == 0 || !isWord(chars[ci - 1])
                let after = ci + 1 < chars.count && isWord(chars[ci + 1])
                if before && after { positions.append((pi, ci)) }
            }
        }
        if positions.isEmpty { return [p] }
        guard positions.count <= 4 else {
            throw SigmaUnsupported(reason: String(localized: "windash: слишком много вариантов (\(positions.count) позиций)"))
        }
        var out: [[Piece]] = []
        var choice = [Int](repeating: 0, count: positions.count)
        while true {
            var copy = p
            for (k, pos) in positions.enumerated() {
                guard case let .lit(t) = copy[pos.piece] else { continue }
                var chars = Array(t)
                chars.replaceSubrange(pos.offset...pos.offset, with: Array(dashes[choice[k]]))
                copy[pos.piece] = .lit(String(chars))
            }
            out.append(copy)
            var k = 0
            while k < choice.count {
                choice[k] += 1
                if choice[k] < dashes.count { break }
                choice[k] = 0
                k += 1
            }
            if k == choice.count { break }
        }
        return out
    }

    /// The three encodings of a byte string at offsets 0, 1, 2 inside a longer base64 text,
    /// with the characters that depend on neighbouring bytes removed (pySigma base64offset).
    static func base64Offsets(_ raw: [UInt8]) -> [String] {
        let starts = [0, 2, 3]
        let ends: [Int?] = [nil, -3, -2]
        return (0..<3).map { i in
            let enc = Array(Data(Array(repeating: 0x20, count: i) + raw).base64EncodedString())
            let lo = starts[i]
            let hi = ends[(raw.count + i) % 3].map { enc.count + $0 } ?? enc.count
            return lo < hi ? String(enc[lo..<hi]) : ""
        }
    }

    // MARK: Simplification (constants from absent fields)

    /// Folds constants, flattens nested and/or, and drops repeated operands (a Hayabusa rule
    /// that names its own Channel repeats the logsource condition).
    static func simplify(_ e: DQLExpr) -> DQLExpr {
        func unique(_ xs: [DQLExpr]) -> [DQLExpr] {
            var seen = Set<DQLExpr>()
            return xs.filter { seen.insert($0).inserted }
        }
        switch e {
        case let .and(xs):
            var out: [DQLExpr] = []
            for x in xs.map(simplify) {
                if case .constant(false) = x { return .constant(false) }
                if case .constant(true) = x { continue }
                if case let .and(inner) = x { out += inner } else { out.append(x) }
            }
            out = unique(out)
            return out.isEmpty ? .constant(true) : (out.count == 1 ? out[0] : .and(out))
        case let .or(xs):
            var out: [DQLExpr] = []
            for x in xs.map(simplify) {
                if case .constant(true) = x { return .constant(true) }
                if case .constant(false) = x { continue }
                if case let .or(inner) = x { out += inner } else { out.append(x) }
            }
            out = unique(out)
            return out.isEmpty ? .constant(false) : (out.count == 1 ? out[0] : .or(out))
        case let .not(x):
            let s = simplify(x)
            if case let .constant(b) = s { return .constant(!b) }
            return .not(s)
        default:
            return e
        }
    }
}
