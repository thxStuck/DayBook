import Foundation

/// Header of one syslog line as rsyslog/syslog-ng write it to files:
/// `[<PRI>]TIMESTAMP HOST TAG[PID]: MESSAGE`, TIMESTAMP being RFC 3339 (`2026-09-27T01:31:03.541699+03:00`,
/// Debian 12+ default) or classic BSD (`Sep 27 01:31:03`, no year and no zone).
struct SyslogLine {
    enum Stamp {
        /// Wall clock with the offset written in the line (nil: none written).
        case iso(wall: Int64, offset: Int?)
        case bsd(month: Int, day: Int, hour: Int, minute: Int, second: Int, fraction: Int64)
    }
    var stamp: Stamp
    var priority: Int?
    var host: Substring
    var program: Substring
    var pid: UInt32?
    var message: Substring
}

enum Syslog {
    enum Format: String, Sendable { case rfc3339, bsd }

    static func parse(_ line: String) -> SyslogLine? {
        var copy = line
        return copy.withUTF8 { b -> SyslogLine? in
            var i = 0
            var pri: Int?
            if b.count > 2, b[0] == 60 {   // '<'
                var j = 1, v = 0
                while j < b.count, j < 5, b[j] >= 48, b[j] <= 57 { v = v * 10 + Int(b[j] - 48); j += 1 }
                if j > 1, j < b.count, b[j] == 62, v < 192 { pri = v; i = j + 1 }
            }
            let stamp: SyslogLine.Stamp
            if let t = LinuxTime.iso(b, i, requireT: true), t.end < b.count, b[t.end] == 32 {
                stamp = .iso(wall: t.wall, offset: t.offset)
                i = t.end + 1
            } else if let t = LinuxTime.bsd(b, i), t.end < b.count, b[t.end] == 32 {
                stamp = .bsd(month: t.month, day: t.day, hour: t.hour, minute: t.minute, second: t.second, fraction: t.fraction)
                i = t.end + 1
            } else {
                return nil
            }
            while i < b.count, b[i] == 32 { i += 1 }
            let hostStart = i
            while i < b.count, b[i] != 32 { i += 1 }
            // A host name never starts with '[' (that is a level: "2026-… [INFO] …").
            guard i > hostStart, i < b.count, b[hostStart] != 91 else { return nil }
            let hostEnd = i
            i += 1
            // Tag: up to ':' (with an optional [pid] before it); no tag when a space comes first.
            let tagStart = i
            var tagEnd = -1, pidStart = -1, pidEnd = -1
            var j = i
            while j < b.count, j - tagStart < 128 {
                let c = b[j]
                if c == 91, pidStart < 0 { pidStart = j + 1 }               // '['
                else if c == 93, pidStart >= 0, pidEnd < 0 { pidEnd = j }   // ']'
                else if c == 58 { tagEnd = j; break }                        // ':'
                else if c == 32 { break }
                j += 1
            }
            var program = tagStart..<tagStart, msgStart = tagStart
            var pid: UInt32?
            if tagEnd > tagStart {
                program = tagStart..<(pidStart > 0 ? pidStart - 1 : tagEnd)
                if pidStart > 0, pidEnd > pidStart {
                    pid = UInt32(String(decoding: UnsafeBufferPointer(rebasing: b[pidStart..<pidEnd]), as: UTF8.self))
                }
                msgStart = tagEnd + 1
                if msgStart < b.count, b[msgStart] == 32 { msgStart += 1 }
            }
            func sub(_ r: Range<Int>) -> Substring {
                let u = line.utf8
                return Substring(line[u.index(u.startIndex, offsetBy: r.lowerBound)..<u.index(u.startIndex, offsetBy: r.upperBound)])
            }
            return SyslogLine(stamp: stamp, priority: pri, host: sub(hostStart..<hostEnd), program: sub(program),
                              pid: pid, message: sub(msgStart..<b.count))
        }
    }

    /// The format most sampled lines are in, when at least 3 of 4 non-empty lines parse and carry a
    /// program tag (`prog:` / `prog[pid]:`); other "time + text" logs are not syslog.
    static func detect(_ lines: [LogLine]) -> Format? {
        var iso = 0, bsd = 0, total = 0
        for l in lines where !l.text.isEmpty {
            total += 1
            guard let p = parse(l.text), !p.program.isEmpty else { continue }
            if case .iso = p.stamp { iso += 1 } else { bsd += 1 }
        }
        guard total > 0, (iso + bsd) * 4 >= total * 3 else { return nil }
        return iso >= bsd ? .rfc3339 : .bsd
    }

    static let facilities = ["kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron",
                             "authpriv", "ftp", "ntp", "security", "console", "solaris-cron",
                             "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"]
    static let severities = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]

    /// Syslog severity → the application's level scale (1 critical … 5 verbose).
    static func level(severity: Int) -> UInt8 {
        switch severity {
        case 0...2: return 1
        case 3: return 2
        case 4: return 3
        case 5, 6: return 4
        default: return 5
        }
    }
}
