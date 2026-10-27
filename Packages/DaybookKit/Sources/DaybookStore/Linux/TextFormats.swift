import EvtxCore
import Foundation

/// One record of a text log: one line for most formats, several for multi-line ones (an audit event,
/// an apt transaction, a message with a stack trace).
struct TextRecord {
    var lines: [LogLine]
    var first: LogLine { lines[0] }
    var text: String { lines.count == 1 ? lines[0].text : lines.map(\.text).joined(separator: "\n") }
}

/// What a format makes of a record.
struct ParsedRecord {
    /// nil: the record has no time of its own.
    var stamp: SyslogLine.Stamp?
    /// By the format's convention an undated record has the previous record's time (MySQL general
    /// log prints the time only when it changes); otherwise the borrowed time is flagged.
    var timeIsInherited = false
    /// nil: the collection's host.
    var host: String?
    var provider: String
    var pid: UInt32?
    var level: UInt8?
    var eventId: UInt16 = 0
    var fields: [CaseField]
    var flags: RecordFlags = []
}

protocol TextLogFormat: Sendable {
    /// Stored as the source's format.
    var name: String { get }
    /// Whether `line` belongs to the record that `first` began (multi-line records).
    func continues(_ line: LogLine, record first: LogLine) -> Bool
    /// Time and host of a record (pass 1: sort keys).
    func stamp(_ record: TextRecord) -> (stamp: SyslogLine.Stamp?, host: Substring?)
    func parse(_ record: TextRecord, plan: LinuxSourcePlan) -> ParsedRecord
}

extension TextLogFormat {
    func continues(_ line: LogLine, record first: LogLine) -> Bool { false }
}

enum TextFormats {
    /// Formats by the name stored in the case (to re-read a record).
    static func named(_ name: String) -> TextLogFormat? {
        switch name {
        case "syslog", "syslog-bsd": return SyslogFormat(name: name)
        case "audit": return AuditFormat()
        case "access": return AccessLogFormat()
        case "jsonl": return JsonLinesFormat()
        case "dpkg": return DpkgFormat()
        case "apt-history": return AptHistoryFormat()
        case "apt-term": return AptTermFormat()
        case "mysql-general": return MysqlGeneralFormat()
        case "bash-history", "zsh-history", "fish-history": return ShellHistoryFormat(name: name)
        case "text": return GenericTextFormat()
        default: return nil
        }
    }

    /// The format of a file from its name (shell histories) or its first lines.
    static func detect(_ p: LinuxSourcePlan, sample: [LogLine]) -> TextLogFormat? {
        if let h = ShellHistoryFormat.kind(of: p.originalPath) { return ShellHistoryFormat(name: h) }
        let lines = sample.filter { !$0.text.isEmpty }
        guard let firstLine = lines.first?.text else { return nil }
        func share(_ test: (String) -> Bool) -> Double {
            Double(lines.filter { test($0.text) }.count) / Double(lines.count)
        }
        if share(AuditFormat.looksLike) >= 0.75 { return AuditFormat() }
        if let s = Syslog.detect(lines) { return SyslogFormat(name: s == .bsd ? "syslog-bsd" : "syslog") }
        if share(JsonLinesFormat.looksLike) >= 0.75 { return JsonLinesFormat() }
        if share(AccessLogFormat.looksLike) >= 0.75 { return AccessLogFormat() }
        if firstLine.hasPrefix("Start-Date: ") { return AptHistoryFormat() }
        if firstLine.hasPrefix("Log started: ") { return AptTermFormat() }
        if share(DpkgFormat.looksLike) >= 0.75 { return DpkgFormat() }
        if lines.contains(where: MysqlGeneralFormat.looksLike) { return MysqlGeneralFormat() }
        // A log that starts with a time stamp; long messages (stack traces) may make most lines continuations.
        if GenericTextFormat.stampOffset(firstLine) != nil, share({ GenericTextFormat.stampOffset($0) != nil }) >= 0.05 {
            return GenericTextFormat()
        }
        return nil
    }

    /// DQL treats these names as aliases of system keys or as the event time: a field with such a
    /// name would hide them, so it is stored capitalised (`host` → `Host`) or renamed (`time` → `TimeRaw`).
    static let reserved: Set<String> = [
        "host", "computer", "channel", "log", "provider", "eventid", "id", "event_id", "level", "user", "userid", "sid",
        "file", "source", "flag", "flags", "provider_name", "eventrecordid", "task", "opcode", "keywords",
        "tag", "bookmark", "rule", "rulelevel", "anyhost", "anyuser", "anyip",
    ]

    static func safeName(_ name: String) -> String {
        let lower = name.lowercased()
        // An application's `user` is not a system account: `User` would make it one (Sysmon's field).
        if lower == "user" { return "UserName" }
        if ["time", "timestamp", "timecreated", "@time"].contains(lower) {
            return name.prefix(1).uppercased() + name.dropFirst() + "Raw"
        }
        if reserved.contains(lower), name == lower { return name.prefix(1).uppercased() + name.dropFirst() }
        return name
    }

    /// Level words of application logs → the application's scale (1 critical … 5 verbose).
    static func level(word: Substring) -> UInt8? {
        switch word.lowercased() {
        case "emerg", "emergency", "alert", "crit", "critical", "fatal", "panic", "severe": return 1
        case "err", "error", "eror": return 2
        case "warn", "warning": return 3
        case "notice", "info", "information", "informational", "note": return 4
        case "debug", "trace", "verbose", "dbg": return 5
        default: return nil
        }
    }

    /// Field names that hold a client address in application logs.
    static let addressKeys: Set<String> = ["ip", "client_ip", "clientip", "remote_addr", "remote_ip", "src_ip", "client",
                                           "source_ip", "x_forwarded_for", "xff", "real_ip", "addr", "remoteaddr"]
}
