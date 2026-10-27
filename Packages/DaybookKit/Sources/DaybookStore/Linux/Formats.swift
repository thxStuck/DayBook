import EvtxCore
import Foundation

/// rsyslog / syslog-ng files (see `Syslog`).
struct SyslogFormat: TextLogFormat {
    let name: String

    func stamp(_ record: TextRecord) -> (stamp: SyslogLine.Stamp?, host: Substring?) {
        guard let s = Syslog.parse(record.first.text) else { return (nil, nil) }
        return (s.stamp, s.host)
    }

    func parse(_ record: TextRecord, plan: LinuxSourcePlan) -> ParsedRecord {
        guard let s = Syslog.parse(record.first.text) else {
            return ParsedRecord(provider: "", fields: [CaseField("Message", record.text)], flags: .unparsed)
        }
        var f = LinuxFields(host: s.host)
        f.add("Message", s.message)
        var level = SyslogMessages.extract(program: s.program, message: s.message, into: &f)
        if let pid = s.pid { f.add("ProcessId", String(pid)) }
        if let pri = s.priority {
            f.add("Facility", pri >> 3 < Syslog.facilities.count ? Syslog.facilities[pri >> 3] : String(pri >> 3))
            f.add("Severity", Syslog.severities[pri & 7])
            level = Syslog.level(severity: pri & 7)
        }
        return ParsedRecord(stamp: s.stamp, host: String(s.host), provider: String(s.program), pid: s.pid, level: level, fields: f.list)
    }
}

/// Lines that start with a time stamp, possibly after a short prefix (`update-alternatives 2026-…`);
/// lines without one continue the message before them (stack traces). Picks up a level word,
/// `key=value` pairs and nginx's `, client: …, request: "…"` tail.
struct GenericTextFormat: TextLogFormat {
    var name: String { "text" }

    /// Byte offset of the time stamp: at the start or after a prefix of up to 48 bytes.
    static func stampOffset(_ line: String) -> Int? {
        var copy = line
        return copy.withUTF8 { b -> Int? in
            if StampScanner.scan(b, 0) != nil { return 0 }
            var i = 0
            while i < min(b.count, 48) {
                if b[i] == 32 || b[i] == 9, i + 1 < b.count, b[i + 1] != 32 {
                    if StampScanner.scan(b, i + 1) != nil { return i + 1 }
                }
                i += 1
            }
            return nil
        }
    }

    func continues(_ line: LogLine, record first: LogLine) -> Bool { Self.stampOffset(line.text) == nil }

    func stamp(_ record: TextRecord) -> (stamp: SyslogLine.Stamp?, host: Substring?) {
        guard let at = Self.stampOffset(record.first.text) else { return (nil, nil) }
        var copy = record.first.text
        return (copy.withUTF8 { StampScanner.scan($0, at)?.stamp }, nil)
    }

    func parse(_ record: TextRecord, plan: LinuxSourcePlan) -> ParsedRecord {
        let line = record.first.text
        var f = LinuxFields(host: plan.host)
        guard let at = Self.stampOffset(line) else {
            return ParsedRecord(provider: Self.provider(plan), fields: [CaseField("Message", record.text)], flags: .unparsed)
        }
        var copy = line
        let (stamp, end) = copy.withUTF8 { b -> (SyslogLine.Stamp?, Int) in
            guard let s = StampScanner.scan(b, at) else { return (nil, at) }
            return (s.stamp, s.end)
        }
        let u = line.utf8
        let prefix = line[..<u.index(u.startIndex, offsetBy: at)].trimmingCharacters(in: .whitespaces)
        var rest = Substring(line[u.index(u.startIndex, offsetBy: end)...])
        rest = rest.drop { $0 == " " || $0 == ":" || $0 == "\t" || $0 == "-" && rest.hasPrefix("- ") }
        var level: UInt8?
        // "[INFO] …", "INFO …", "NOTICE: …", "[error] …"
        let wordEnd = rest.firstIndex { $0 == " " || $0 == ":" || $0 == "]" } ?? rest.endIndex
        let word = rest.hasPrefix("[") ? rest[rest.index(after: rest.startIndex)..<wordEnd] : rest[..<wordEnd]
        if !word.isEmpty, let l = TextFormats.level(word: word) {
            level = l
            f.add("Severity", word)
            rest = rest[wordEnd...].drop { $0 == "]" || $0 == ":" || $0 == " " }
        }
        // nginx: "431#431: *138793 message"
        var pid: UInt32?
        if let hash = rest.firstIndex(of: "#"), let colon = rest.firstIndex(of: ":"), hash < colon,
           let p = UInt32(rest[..<hash]), rest[rest.index(after: hash)..<colon].allSatisfy(\.isNumber) {
            pid = p
            f.add("ProcessId", String(p))
            rest = rest[rest.index(after: colon)...].drop { $0 == " " }
            if rest.hasPrefix("*"), let sp = rest.firstIndex(of: " ") {
                f.add("ConnectionId", rest[rest.index(after: rest.startIndex)..<sp])
                rest = rest[rest.index(after: sp)...]
            }
        }
        let message = record.lines.count == 1 ? String(rest) : ([String(rest)] + record.lines.dropFirst().map(\.text)).joined(separator: "\n")
        f.list.insert(CaseField("Message", message), at: 0)
        if !prefix.isEmpty { f.add("Prefix", prefix) }
        Self.keyValues(rest, into: &f)
        Self.nginxTail(Substring(message), into: &f)   // after a multi-line message the tail is on its last line
        let provider = prefix.isEmpty || prefix.contains(" ") ? Self.provider(plan) : prefix
        return ParsedRecord(stamp: stamp, provider: provider, pid: pid, level: level, fields: f.list)
    }

    /// The program a log belongs to: its folder (`nginx/error.log` → nginx) or its name.
    static func provider(_ plan: LinuxSourcePlan) -> String {
        if let slash = plan.channel.firstIndex(of: "/") { return String(plan.channel[..<slash]) }
        let name = plan.channel
        return name.hasSuffix(".log") ? String(name.dropLast(4)) : name
    }

    /// `key=value` and `key="quoted value"` pairs; client addresses also become `IpAddress`.
    static func keyValues(_ s: Substring, into f: inout LinuxFields) {
        var i = s.startIndex
        var seen = Set<String>()
        while i < s.endIndex {
            guard let eq = s[i...].firstIndex(of: "=") else { break }
            var keyStart = eq
            while keyStart > s.startIndex {
                let c = s[s.index(before: keyStart)]
                guard c.isLetter || c.isNumber || c == "_" || c == "." || c == "-" else { break }
                keyStart = s.index(before: keyStart)
            }
            let key = s[keyStart..<eq]
            var vStart = s.index(after: eq)
            var vEnd: Substring.Index
            if vStart < s.endIndex, s[vStart] == "\"" {
                vStart = s.index(after: vStart)
                vEnd = s[vStart...].firstIndex(of: "\"") ?? s.endIndex
                i = vEnd < s.endIndex ? s.index(after: vEnd) : vEnd
            } else {
                vEnd = s[vStart...].firstIndex { $0 == " " || $0 == "," || $0 == ";" } ?? s.endIndex
                i = vEnd
            }
            guard !key.isEmpty, key.first!.isLetter, key.count <= 40 else { continue }
            // Only whole words: `?page=1&x=2` inside a URL is not a field of the log line.
            if keyStart > s.startIndex, !" ,;\t([{".contains(s[s.index(before: keyStart)]) { continue }
            let value = s[vStart..<vEnd]
            let name = TextFormats.safeName(String(key))
            guard seen.insert(name).inserted else { continue }
            f.add(name, value)
            if TextFormats.addressKeys.contains(key.lowercased()), EntityNames.isIP(String(value)) { f.add("IpAddress", value) }
        }
    }

    /// nginx error log: `…, client: 1.2.3.4, server: _, request: "GET / HTTP/1.1", host: "x"`.
    static func nginxTail(_ s: Substring, into f: inout LinuxFields) {
        guard let r = s.range(of: ", client: ") else { return }
        let tail = s[r.lowerBound...]
        for (key, name) in [("client", "IpAddress"), ("server", "Server"), ("request", "Request"), ("upstream", "Upstream"),
                            ("host", "Host"), ("referrer", "Referer")] {
            guard let k = tail.range(of: ", \(key): ") else { continue }
            var v = tail[k.upperBound...]
            if v.hasPrefix("\"") {
                v = v.dropFirst()
                v = v[..<(v.firstIndex(of: "\"") ?? v.endIndex)]
            } else {
                v = v[..<(v.firstIndex(of: ",") ?? v.endIndex)]
            }
            if name == "IpAddress" { f.peer(v) } else { f.add(name, v) }
        }
    }
}
