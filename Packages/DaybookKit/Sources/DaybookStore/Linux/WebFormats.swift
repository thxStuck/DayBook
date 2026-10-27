import EvtxCore
import Foundation

/// Apache / nginx access logs in the common or combined format, with whatever the server appends
/// after the user agent kept as `key=value` fields (`rt=0.061 urt="0.061" rid=…`).
struct AccessLogFormat: TextLogFormat {
    var name: String { "access" }

    struct Line {
        var client: Substring, ident: Substring, user: Substring
        var stamp: SyslogLine.Stamp
        var request: Substring, status: Substring, bytes: Substring
        var referer: Substring?, agent: Substring?
        var rest: Substring
    }

    static func looksLike(_ line: String) -> Bool { split(line) != nil }

    static func split(_ line: String) -> Line? {
        var s = Substring(line)
        func token() -> Substring? {
            guard let sp = s.firstIndex(of: " ") else { return nil }
            defer { s = s[s.index(after: sp)...] }
            return s[..<sp]
        }
        func quoted() -> Substring? {
            guard s.hasPrefix("\"") else { return nil }
            var i = s.index(after: s.startIndex)
            while i < s.endIndex {
                if s[i] == "\\" { i = s.index(i, offsetBy: 2, limitedBy: s.endIndex) ?? s.endIndex; continue }
                if s[i] == "\"" { break }
                i = s.index(after: i)
            }
            guard i < s.endIndex else { return nil }
            let v = s[s.index(after: s.startIndex)..<i]
            s = s[s.index(after: i)...].drop { $0 == " " }
            return v
        }
        guard let client = token(), let ident = token(), let user = token(), s.hasPrefix("["),
              let close = s.firstIndex(of: "]") else { return nil }
        var copy = String(s[...close])
        guard let stamp = copy.withUTF8({ StampScanner.scan($0, 0)?.stamp }) else { return nil }
        s = s[s.index(after: close)...].drop { $0 == " " }
        guard let request = quoted(), let status = token() ?? (s.isEmpty ? nil : s), status.count == 3, status.allSatisfy(\.isNumber) else { return nil }
        let bytes = (s.firstIndex(of: " ").map { _ in token() } ?? nil) ?? s
        if bytes == s { s = "" }
        let referer = quoted()
        let agent = referer == nil ? nil : quoted()
        return Line(client: client, ident: ident, user: user, stamp: stamp, request: request, status: status, bytes: bytes,
                    referer: referer, agent: agent, rest: s)
    }

    func stamp(_ record: TextRecord) -> (stamp: SyslogLine.Stamp?, host: Substring?) {
        (Self.split(record.first.text)?.stamp, nil)
    }

    func parse(_ record: TextRecord, plan: LinuxSourcePlan) -> ParsedRecord {
        guard let l = Self.split(record.first.text) else {
            return ParsedRecord(provider: GenericTextFormat.provider(plan), fields: [CaseField("Message", record.text)], flags: .unparsed)
        }
        var f = LinuxFields(host: plan.host)
        f.add("Message", "\(l.request) \(l.status) \(l.bytes)")
        f.action("http_request")
        f.peer(l.client)
        if l.user != "-" { f.add("RemoteUser", l.user) }
        if l.ident != "-" { f.add("Ident", l.ident) }
        let parts = l.request.split(separator: " ", maxSplits: 2)
        if parts.count == 3 {
            f.add("HttpMethod", parts[0])
            f.add("Uri", parts[1])
            f.add("HttpVersion", parts[2])
        } else {
            f.add("Request", l.request)
        }
        f.add("HttpStatus", l.status)
        if l.bytes != "-" { f.add("ResponseBytes", l.bytes) }
        if let r = l.referer, r != "-" { f.add("Referer", r) }
        if let a = l.agent, a != "-" { f.add("UserAgent", a) }
        GenericTextFormat.keyValues(l.rest, into: &f)
        return ParsedRecord(stamp: l.stamp, provider: GenericTextFormat.provider(plan), fields: f.list)
    }
}

/// One JSON object per line (application logs, nginx `log_format … escape=json`). Nested objects
/// are flattened (`a.b`), the time is taken from the usual keys.
struct JsonLinesFormat: TextLogFormat {
    var name: String { "jsonl" }
    static let timeKeys = ["@timestamp", "timestamp", "time", "ts", "datetime", "date", "time_iso8601", "time_local",
                           "eventTime", "logtime", "t"]
    static let messageKeys = ["message", "msg", "event", "log", "text"]

    static func looksLike(_ line: String) -> Bool {
        let t = line.trimmingCharacters(in: .whitespaces)
        return t.hasPrefix("{") && t.hasSuffix("}") && object(t) != nil
    }

    static func object(_ line: String) -> [String: Any]? {
        (try? JSONSerialization.jsonObject(with: Data(line.utf8))) as? [String: Any]
    }

    static func time(_ o: [String: Any]) -> SyslogLine.Stamp? {
        for k in timeKeys {
            guard let v = o[k] else { continue }
            if var s = v as? String {
                if let st = s.withUTF8({ StampScanner.scan($0, 0)?.stamp }) { return st }
            } else if let n = v as? NSNumber, !(n === kCFBooleanTrue || n === kCFBooleanFalse) {
                var secs = n.doubleValue
                if secs > 1e15 { secs /= 1e6 } else if secs > 1e12 { secs /= 1e3 }
                guard secs > 0 else { continue }
                return .iso(wall: FileTime.fromUnixSeconds(0) + Int64(secs * 1e7), offset: 0)
            }
        }
        return nil
    }

    static func flatten(_ o: [String: Any], prefix: String = "", into out: inout [(String, String)]) {
        for k in o.keys.sorted() {
            let name = prefix.isEmpty ? k : prefix + "." + k
            switch o[k] {
            case let d as [String: Any]: flatten(d, prefix: name, into: &out)
            case let s as String: out.append((name, s))
            case let n as NSNumber:
                out.append((name, n === kCFBooleanTrue ? "true" : n === kCFBooleanFalse ? "false" : n.stringValue))
            case is NSNull, nil: break
            case let a?:
                if let data = try? JSONSerialization.data(withJSONObject: a, options: [.sortedKeys, .withoutEscapingSlashes]) {
                    out.append((name, String(decoding: data, as: UTF8.self)))
                }
            }
        }
    }

    func stamp(_ record: TextRecord) -> (stamp: SyslogLine.Stamp?, host: Substring?) {
        (Self.object(record.first.text).flatMap(Self.time), nil)
    }

    func parse(_ record: TextRecord, plan: LinuxSourcePlan) -> ParsedRecord {
        guard let o = Self.object(record.first.text) else {
            return ParsedRecord(provider: GenericTextFormat.provider(plan), fields: [CaseField("Message", record.text)], flags: .unparsed)
        }
        var pairs: [(String, String)] = []
        Self.flatten(o, into: &pairs)
        var f = LinuxFields(host: plan.host)
        let value = { (k: String) in pairs.first { $0.0.lowercased() == k }?.1 }
        let method = value("method") ?? value("request_method")
        let status = value("status")
        let uri = value("uri") ?? value("request_uri") ?? value("request")
        let message = Self.messageKeys.lazy.compactMap { value($0) }.first
            ?? (method != nil && uri != nil ? [method!, uri!, status ?? ""].joined(separator: " ") : record.first.text)
        f.add("Message", message)
        if method != nil, status != nil { f.action("http_request") }
        for (k, v) in pairs {
            f.add(TextFormats.safeName(k), v)
        }
        if let ip = pairs.first(where: { TextFormats.addressKeys.contains($0.0.lowercased()) && EntityNames.isIP($0.1) })?.1 {
            f.add("IpAddress", ip)
        }
        let level = (value("level") ?? value("severity") ?? value("loglevel")).flatMap { TextFormats.level(word: Substring($0)) }
        return ParsedRecord(stamp: Self.time(o), provider: GenericTextFormat.provider(plan), level: level, fields: f.list)
    }
}
