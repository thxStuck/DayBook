import EvtxCore
import Foundation

/// Time stamps of Linux logs → FILETIME ticks (UTC), the unit of the case. Parsers work on the
/// line's UTF-8 bytes; `wall` values are local clock readings stored as if they were UTC.
enum LinuxTime {
    static let monthNames: [String: Int] = ["jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
                                            "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12]

    static func ticks(year: Int, month: Int, day: Int, hour: Int, minute: Int, second: Int, fraction: Int64) -> Int64 {
        let days = FileTime.days(fromCivil: Int64(year), month, day)
        let secs = days * 86_400 + Int64(hour * 3600 + minute * 60 + second)
        return FileTime.fromUnixSeconds(secs) + fraction
    }

    /// `2026-09-27T01:31:03.541699+03:00`, `…Z`, `…+0300`, `2026-09-27 01:31:03` (no zone: offset nil).
    static func iso(_ b: UnsafeBufferPointer<UInt8>, _ start: Int = 0, requireT: Bool = false) -> (wall: Int64, offset: Int?, end: Int)? {
        var i = start
        func num(_ n: Int) -> Int? {
            guard i + n <= b.count else { return nil }
            var v = 0
            for k in 0..<n {
                let c = b[i + k]
                guard c >= 48 && c <= 57 else { return nil }
                v = v * 10 + Int(c - 48)
            }
            i += n
            return v
        }
        func take(_ c: UInt8) -> Bool {
            guard i < b.count, b[i] == c else { return false }
            i += 1
            return true
        }
        guard let y = num(4), take(45), let mo = num(2), take(45), let d = num(2) else { return nil }
        guard i < b.count, b[i] == 84 || (b[i] == 32 && !requireT) else { return nil }   // 'T' or ' '
        i += 1
        guard let h = num(2), take(58), let mi = num(2), take(58), let s = num(2) else { return nil }
        guard (1...12).contains(mo), (1...31).contains(d), h < 24, mi < 60, s < 61 else { return nil }
        var frac: Int64 = 0
        if i < b.count, b[i] == 46 || b[i] == 44 {   // '.' or ','
            i += 1
            var digits = 0
            while i < b.count, b[i] >= 48, b[i] <= 57 {
                if digits < 7 { frac = frac * 10 + Int64(b[i] - 48) }
                digits += 1
                i += 1
            }
            guard digits > 0 else { return nil }
            if digits < 7 { for _ in digits..<7 { frac *= 10 } }
        }
        var offset: Int?
        if i < b.count {
            if b[i] == 90 {   // 'Z'
                offset = 0
                i += 1
            } else if b[i] == 43 || b[i] == 45 {   // '+' / '-'
                let sign = b[i] == 45 ? -1 : 1
                let save = i
                i += 1
                if let oh = num(2) {
                    _ = take(58)
                    if let om = num(2), oh < 24, om < 60 { offset = sign * (oh * 3600 + om * 60) } else { i = save }
                } else {
                    i = save
                }
            }
        }
        return (ticks(year: y, month: mo, day: d, hour: h, minute: mi, second: min(s, 59), fraction: frac), offset, i)
    }

    /// Classic syslog `Sep 27 01:31:03` (day may be space-padded). No year and no zone.
    static func bsd(_ b: UnsafeBufferPointer<UInt8>, _ start: Int = 0)
        -> (month: Int, day: Int, hour: Int, minute: Int, second: Int, fraction: Int64, end: Int)? {
        var i = start
        guard i + 15 <= b.count else { return nil }
        let name = String(decoding: UnsafeBufferPointer(rebasing: b[i..<(i + 3)]), as: UTF8.self).lowercased()
        guard let month = monthNames[name], b[i + 3] == 32 else { return nil }
        i += 4
        if b[i] == 32 { i += 1 }
        var day = 0, digits = 0
        while i < b.count, b[i] >= 48, b[i] <= 57, digits < 2 { day = day * 10 + Int(b[i] - 48); i += 1; digits += 1 }
        guard digits > 0, (1...31).contains(day), i < b.count, b[i] == 32 else { return nil }
        i += 1
        func two() -> Int? {
            guard i + 2 <= b.count, b[i] >= 48, b[i] <= 57, b[i + 1] >= 48, b[i + 1] <= 57 else { return nil }
            defer { i += 2 }
            return Int(b[i] - 48) * 10 + Int(b[i + 1] - 48)
        }
        guard let h = two(), i < b.count, b[i] == 58 else { return nil }
        i += 1
        guard let m = two(), i < b.count, b[i] == 58 else { return nil }
        i += 1
        guard let s = two(), h < 24, m < 60, s < 61 else { return nil }
        var frac: Int64 = 0
        if i < b.count, b[i] == 46 {
            i += 1
            var n = 0
            while i < b.count, b[i] >= 48, b[i] <= 57 {
                if n < 7 { frac = frac * 10 + Int64(b[i] - 48) }
                n += 1
                i += 1
            }
            if n < 7 { for _ in n..<7 { frac *= 10 } }
        }
        return (month, day, h, m, min(s, 59), frac, i)
    }
}

/// Converts local wall-clock ticks of one zone to UTC; the offset is cached per local hour.
final class ZoneConverter {
    let zone: TimeZone
    private var cache: [Int64: Int] = [:]

    init(zone: TimeZone) { self.zone = zone }

    /// Seconds east of UTC in effect at local time `wall`.
    func offset(wall: Int64) -> Int {
        let hour = (wall - FileTime.unixEpochTicks) / (3600 * FileTime.ticksPerSecond)
        if let o = cache[hour] { return o }
        let localSeconds = Double(hour * 3600)
        let guess = Date(timeIntervalSince1970: localSeconds - Double(zone.secondsFromGMT(for: Date(timeIntervalSince1970: localSeconds))))
        let o = zone.secondsFromGMT(for: guess)
        cache[hour] = o
        return o
    }

    func utc(wall: Int64) -> Int64 { wall - Int64(offset(wall: wall)) * FileTime.ticksPerSecond }
}

/// Year of classic syslog lines. Logs are written in time order, so a jump from a late month to an
/// early one (Dec → Jan) starts the next year. The newest line belongs to the year of the file's last
/// modification, or the year before when its date would lie after that time.
enum YearInference {
    static func lastYear(month: Int, day: Int, reference: Date, zone: TimeZone) -> Int {
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = zone
        let ref = cal.dateComponents([.year, .month, .day], from: reference)
        let year = ref.year ?? 1970
        return (month, day) > (ref.month ?? 12, ref.day ?? 31) ? year - 1 : year
    }
}
