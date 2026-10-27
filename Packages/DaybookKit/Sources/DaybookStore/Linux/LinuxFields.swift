import Foundation

/// Fields of one Linux event. Names are CamelCase (they must not shadow DQL aliases such as `user`
/// or `host`) and reuse the Windows names the case already understands: user names go to
/// `TargetUserName` / `SubjectUserName` with the host as their domain (so `root` of two machines stays
/// two accounts), remote addresses to `IpAddress`, remote host names to `WorkstationName`.
struct LinuxFields {
    var list: [CaseField] = []
    let host: String

    init(host: Substring) { self.host = String(host) }
    init(host: String) { self.host = host }

    mutating func add(_ name: String, _ value: Substring?) {
        guard let v = value, !v.isEmpty else { return }
        list.append(CaseField(name, String(v)))
    }

    mutating func add(_ name: String, _ value: String?) {
        guard let v = value, !v.isEmpty else { return }
        list.append(CaseField(name, v))
    }

    /// `role` is `Target` or `Subject`.
    mutating func user<S: StringProtocol>(_ role: String, _ name: S?) {
        guard let n = name?.trimmingCharacters(in: .whitespaces), !n.isEmpty, n != "-", n != "?" else { return }
        add(role + "UserName", n)
        add(role + "DomainName", host)
    }

    /// A remote peer: an address goes to `IpAddress`, a name to `WorkstationName`.
    mutating func peer<S: StringProtocol>(_ value: S?) {
        guard let raw = value?.trimmingCharacters(in: .whitespaces), !raw.isEmpty, raw != "-" else { return }
        add(EntityNames.isIP(raw) ? "IpAddress" : "WorkstationName", raw)
    }

    mutating func action(_ a: String) { add("Action", a) }

    func has(_ name: String) -> Bool { list.contains { $0.name == name } }
}

/// Every field name the Linux parsers can write. A query on one of them in a case without such
/// events finds nothing instead of failing with "unknown field" (presets work on any collection,
/// typos are still reported).
enum LinuxVocabulary {
    static let fields = [
        "Message", "Action", "ProcessId", "Facility", "Severity", "Stage", "KeyType", "KeyFingerprint", "KeyFile",
        "AuthMethod", "UserStatus", "Reason", "IpPort", "LocalAddress", "LocalPort", "Terminal", "SessionType",
        "SessionId", "TargetUserName", "TargetDomainName", "SubjectUserName", "SubjectDomainName", "IpAddress",
        "WorkstationName", "PamModule", "PamService", "PamType", "TargetUid", "SubjectUid", "RemoteUser", "Uid",
        "Euid", "LogName", "CommandLine", "CurrentDirectory", "TargetGroup", "Environment", "Gid", "HomeDirectory",
        "Shell", "GroupName", "FirewallRule", "InInterface", "OutInterface", "SourceIp", "DestinationIp", "Protocol",
        "SourcePort", "DestinationPort", "Mac", "Type", "KernelVersion", "RunLevel", "TerminalId", "ExitStatus",
        // web, application and package logs
        "HttpMethod", "Uri", "HttpVersion", "HttpStatus", "ResponseBytes", "Referer", "UserAgent", "Ident", "Request",
        "Server", "Upstream", "Host", "ConnectionId", "Prefix", "PackageName", "PackageArch", "Version", "OldVersion",
        "PackageStatus", "DpkgPhase", "ConfigFile", "ConffileAction", "EndDate", "Install", "Upgrade", "Remove", "Purge",
        "Downgrade", "Reinstall", "Error", "Shell", "DbCommand", "DbArgument", "DbUser", "Database", "UserName",
        // audit
        "AuditId", "comm", "exe", "syscall", "key", "success", "exit", "res", "acct", "addr", "hostname", "op",
        "pid", "ppid", "auid", "uid", "euid", "gid", "ses", "tty", "cwd", "name", "proctitle", "argc", "cmd",
        "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "SyscallName", "AuidName", "UidName", "EuidName",
    ]
    // Audit's raw `uid` and the normalised `Uid` differ only in case: the first spelling wins here,
    // DQL still prefers an exact field name.
    private static let byLower = Dictionary(fields.map { ($0.lowercased(), $0) }, uniquingKeysWith: { a, _ in a })

    static func field(_ lowercased: String) -> String? { byLower[lowercased] }
}

extension Substring {
    func after(_ prefix: String) -> Substring? { hasPrefix(prefix) ? self[index(startIndex, offsetBy: prefix.count)...] : nil }

    /// Text between the first `open` and the following `close`.
    func between(_ open: String, _ close: String) -> Substring? {
        guard let a = range(of: open), let b = self[a.upperBound...].range(of: close) else { return nil }
        return self[a.upperBound..<b.lowerBound]
    }

    /// Leading run of decimal digits.
    var leadingDigits: Substring { self[..<(firstIndex { !("0"..."9").contains($0) } ?? endIndex)] }

    /// `key=value` pairs separated by `separator` (values end at the next separator).
    func keyValues(separator: Character = " ") -> [(Substring, Substring)] {
        split(separator: separator).compactMap { part in
            let p = part.trimmingCharacters(in: .whitespaces)
            guard let eq = p.firstIndex(of: "="), eq != p.startIndex else { return nil }
            let key = Substring(p[..<eq]), value = Substring(p[p.index(after: eq)...])
            return (key, value)
        }
    }
}
