import EvtxCore
import Foundation

/// `/var/log/dpkg.log`: `2026-09-27 01:30:49 install libfoo:amd64 <none> 1.2-3`.
struct DpkgFormat: TextLogFormat {
    var name: String { "dpkg" }
    static let actions: Set<String> = ["startup", "status", "install", "upgrade", "remove", "purge", "configure", "trigproc", "conffile"]

    static func looksLike(_ line: String) -> Bool { split(line) != nil }

    static func split(_ line: String) -> (stamp: SyslogLine.Stamp, words: [Substring])? {
        var copy = line
        guard let t = copy.withUTF8({ LinuxTime.iso($0, 0) }), t.offset == nil else { return nil }
        let u = line.utf8
        let rest = line[u.index(u.startIndex, offsetBy: t.end)...]
        let words = rest.split(separator: " ")
        guard let a = words.first, actions.contains(String(a)) else { return nil }
        return (.iso(wall: t.wall, offset: nil), words)
    }

    func stamp(_ record: TextRecord) -> (stamp: SyslogLine.Stamp?, host: Substring?) { (Self.split(record.first.text)?.stamp, nil) }

    func parse(_ record: TextRecord, plan: LinuxSourcePlan) -> ParsedRecord {
        guard let (stamp, w) = Self.split(record.first.text) else {
            return ParsedRecord(provider: "dpkg", fields: [CaseField("Message", record.text)], flags: .unparsed)
        }
        var f = LinuxFields(host: plan.host)
        f.add("Message", w.joined(separator: " "))
        func package(_ s: Substring) {
            let p = s.split(separator: ":", maxSplits: 1)
            f.add("PackageName", p[0])
            if p.count > 1 { f.add("PackageArch", p[1]) }
        }
        switch w[0] {
        case "startup":
            f.action("dpkg_startup")
            f.add("DpkgPhase", w.dropFirst().joined(separator: " "))
        case "status" where w.count >= 4:
            f.action("package_status")
            f.add("PackageStatus", w[1])
            package(w[2])
            f.add("Version", w[3])
        case "conffile" where w.count >= 3:
            f.action("package_conffile")
            f.add("ConfigFile", w[1])
            f.add("ConffileAction", w[2])
        default:
            let names = ["install": "package_install", "upgrade": "package_upgrade", "remove": "package_remove",
                         "purge": "package_purge", "configure": "package_configure", "trigproc": "package_trigger"]
            f.action(names[String(w[0])] ?? "dpkg_" + w[0])
            if w.count >= 2 { package(w[1]) }
            if w.count >= 3, w[2] != "<none>" { f.add("OldVersion", w[2]) }
            if w.count >= 4, w[3] != "<none>" { f.add("Version", w[3]) }
        }
        return ParsedRecord(stamp: stamp, provider: "dpkg", fields: f.list)
    }
}

/// Parses `Start-Date: 2026-09-27  01:30:48` (apt writes two spaces).
private func aptStamp(_ value: Substring) -> SyslogLine.Stamp? {
    var s = value.replacingOccurrences(of: "  ", with: " ").trimmingCharacters(in: .whitespaces)
    guard let t = s.withUTF8({ LinuxTime.iso($0, 0) }) else { return nil }
    return .iso(wall: t.wall, offset: t.offset)
}

/// `/var/log/apt/history.log`: one transaction per `Start-Date:` block.
struct AptHistoryFormat: TextLogFormat {
    var name: String { "apt-history" }

    func continues(_ line: LogLine, record first: LogLine) -> Bool { !line.text.hasPrefix("Start-Date: ") }

    func stamp(_ record: TextRecord) -> (stamp: SyslogLine.Stamp?, host: Substring?) {
        let t = record.first.text
        return (t.hasPrefix("Start-Date: ") ? aptStamp(t.dropFirst(12)) : nil, nil)
    }

    func parse(_ record: TextRecord, plan: LinuxSourcePlan) -> ParsedRecord {
        var f = LinuxFields(host: plan.host)
        var values: [(String, Substring)] = []
        for line in record.lines {
            guard let colon = line.text.range(of: ": ") else { continue }
            values.append((String(line.text[..<colon.lowerBound]), line.text[colon.upperBound...]))
        }
        let value = { (k: String) in values.first { $0.0 == k }?.1 }
        f.add("Message", value("Commandline") ?? Substring(record.first.text))
        f.action("apt_transaction")
        f.add("CommandLine", value("Commandline"))
        if let by = value("Requested-By") {   // "alice (1000)"
            let parts = by.split(separator: " ")
            f.user("Subject", parts.first)
            if parts.count > 1 { f.add("SubjectUid", parts[1].trimmingCharacters(in: CharacterSet(charactersIn: "()"))) }
        }
        for (k, v) in values where !["Start-Date", "Commandline", "Requested-By"].contains(k) {
            f.add(k == "End-Date" ? "EndDate" : k.replacingOccurrences(of: "-", with: ""), v)
        }
        let stamp = record.first.text.hasPrefix("Start-Date: ") ? aptStamp(record.first.text.dropFirst(12)) : nil
        return ParsedRecord(stamp: stamp, provider: "apt", fields: f.list, flags: stamp == nil ? .unparsed : [])
    }
}

/// `/var/log/apt/term.log`: the terminal output of each run, from `Log started:` to `Log ended:`.
struct AptTermFormat: TextLogFormat {
    var name: String { "apt-term" }

    func continues(_ line: LogLine, record first: LogLine) -> Bool { !line.text.hasPrefix("Log started: ") }

    func stamp(_ record: TextRecord) -> (stamp: SyslogLine.Stamp?, host: Substring?) {
        let t = record.first.text
        return (t.hasPrefix("Log started: ") ? aptStamp(t.dropFirst(13)) : nil, nil)
    }

    func parse(_ record: TextRecord, plan: LinuxSourcePlan) -> ParsedRecord {
        var f = LinuxFields(host: plan.host)
        let body = record.lines.dropFirst().filter { !$0.text.hasPrefix("Log ended: ") }.map(\.text)
        f.add("Message", body.joined(separator: "\n"))
        f.action("apt_output")
        if let end = record.lines.last(where: { $0.text.hasPrefix("Log ended: ") }) { f.add("EndDate", end.text.dropFirst(11)) }
        let stamp = stamp(record).stamp
        return ParsedRecord(stamp: stamp, provider: "apt", fields: f.list, flags: stamp == nil ? .unparsed : [])
    }
}

/// MySQL / MariaDB general query log: `260926 22:45:37\t     4 Connect\troot@localhost on db using Socket`;
/// the time is written only when it changes, so a statement without one has the previous time.
struct MysqlGeneralFormat: TextLogFormat {
    var name: String { "mysql-general" }

    static func looksLike(_ line: LogLine) -> Bool {
        line.text.hasSuffix("started with:") || statement(line.text) != nil
    }

    /// (time, connection id, command, argument) of a statement line.
    static func statement(_ line: String) -> (stamp: SyslogLine.Stamp?, id: Substring, command: Substring, argument: Substring)? {
        var copy = line
        let scanned = copy.withUTF8 { b -> (SyslogLine.Stamp, Int)? in
            guard let s = StampScanner.scan(b, 0) else { return nil }
            return (s.stamp, s.end)
        }
        let u = line.utf8
        var rest = Substring(line[u.index(u.startIndex, offsetBy: scanned?.1 ?? 0)...])
        guard rest.hasPrefix("\t") else { return nil }
        rest = rest.drop { $0 == "\t" || $0 == " " }
        let id = rest.prefix { $0.isNumber }
        guard !id.isEmpty, rest.dropFirst(id.count).hasPrefix(" ") else { return nil }
        rest = rest.dropFirst(id.count + 1)
        guard let first = rest.first, first.isLetter else { return nil }
        let tab = rest.firstIndex(of: "\t") ?? rest.endIndex
        let argument = tab < rest.endIndex ? rest[rest.index(after: tab)...] : ""
        return (scanned?.0, id, rest[..<tab], argument)
    }

    func continues(_ line: LogLine, record first: LogLine) -> Bool {
        !(line.text.hasSuffix("started with:") || Self.statement(line.text) != nil)
    }

    func stamp(_ record: TextRecord) -> (stamp: SyslogLine.Stamp?, host: Substring?) {
        (Self.statement(record.first.text)?.stamp, nil)
    }

    func parse(_ record: TextRecord, plan: LinuxSourcePlan) -> ParsedRecord {
        var f = LinuxFields(host: plan.host)
        let provider = GenericTextFormat.provider(plan)
        guard let s = Self.statement(record.first.text) else {
            f.add("Message", record.text)
            if record.first.text.hasSuffix("started with:") { f.action("db_server_start") }
            return ParsedRecord(provider: provider, fields: f.list)
        }
        let argument = ([String(s.argument)] + record.lines.dropFirst().map(\.text)).joined(separator: "\n")
        f.add("Message", "\(s.command) \(argument)".trimmingCharacters(in: .whitespaces))
        f.action("db_" + s.command.lowercased().replacingOccurrences(of: " ", with: "_"))
        f.add("ConnectionId", s.id)
        f.add("DbCommand", s.command)
        f.add("DbArgument", argument)
        if s.command == "Connect" {
            // "root@localhost on mysql using Socket"
            let a = Substring(argument)
            if let on = a.range(of: " on ") {
                f.add("DbUser", a[..<on.lowerBound])
                let after = a[on.upperBound...]
                f.add("Database", after.range(of: " using ").map { after[..<$0.lowerBound] } ?? after)
            }
        }
        return ParsedRecord(stamp: s.stamp, timeIsInherited: s.stamp == nil, provider: provider, fields: f.list)
    }
}
