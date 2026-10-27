import EvtxCore
import Foundation

/// A unit of parallel work: a run of records of one text source, or one whole binary source.
struct LinuxJob: Sendable {
    var source: Int
    /// Byte range in the (unpacked) content; whole file for binary sources.
    var bytes: Range<Int>
    /// Number of the line at `bytes.lowerBound` (1-based).
    var firstLine: Int
    /// Text format (`TextFormats.named`).
    var formatName: String?
    /// Classic syslog: year of the first dated record of the job.
    var firstYear: Int?
    /// Time given to undated records before the job's first dated record.
    var carryTs: Int64?
    /// The file has no dated record at all: undated records have the file's modification time.
    var noDates = false
}

/// Turns syslog time stamps into UTC, carrying the inferred year from line to line.
struct SyslogClock {
    let zone: ZoneConverter
    var year: Int?
    var prevMonth: Int?

    init(zone: TimeZone?, firstYear: Int?) {
        self.zone = ZoneConverter(zone: zone ?? TimeZone(identifier: "UTC")!)
        year = firstYear
    }

    mutating func time(_ stamp: SyslogLine.Stamp) -> (ts: Int64, flags: RecordFlags) {
        switch stamp {
        case let .iso(wall, offset):
            if let offset { return (wall - Int64(offset) * FileTime.ticksPerSecond, []) }
            return (zone.utc(wall: wall), .zoneAssumed)
        case let .bsd(month, day, hour, minute, second, fraction):
            if let p = prevMonth, p > month + 6 { year = (year ?? 1970) + 1 }
            prevMonth = month
            let wall = LinuxTime.ticks(year: year ?? 1970, month: month, day: day, hour: hour, minute: minute,
                                       second: second, fraction: fraction)
            return (zone.utc(wall: wall), [.yearInferred, .zoneAssumed])
        }
    }
}

enum LinuxText {
    static let recordsPerJob = 20_000

    struct Planned {
        var format: TextLogFormat
        var jobs: [LinuxJob]
        var keys: [[RecordKey]]
        /// Empty lines.
        var skipped: Int
        var noDates: Bool
    }

    /// Lines grouped into records by `format`; empty lines are reported to `skipped`.
    static func forEachRecord(_ data: Data, in range: Range<Int>, firstNumber: Int, format: TextLogFormat,
                              skipped: (LogLine) -> Void = { _ in }, _ body: (TextRecord) -> Bool) {
        var current: TextRecord?
        var stopped = false
        LogLines.forEach(data, in: range, firstNumber: firstNumber) { line in
            guard line.offset < range.upperBound else { return false }
            if line.text.isEmpty { skipped(line); return true }
            if let c = current, format.continues(line, record: c.first) {
                current!.lines.append(line)
                return true
            }
            if let c = current, !body(c) { stopped = true; return false }
            current = TextRecord(lines: [line])
            return true
        }
        if !stopped, let c = current { _ = body(c) }
    }

    /// Pass 1 of a text source: detects the format, splits the file into jobs at record starts and
    /// returns the sort key of every record. nil when no known format fits.
    // swiftlint:disable:next function_body_length
    static func plan(_ p: LinuxSourcePlan, data: Data, src: Int) -> Planned? {
        var sample: [LogLine] = []
        LogLines.forEach(data, in: 0..<data.count, firstNumber: 1) { line in
            if !line.text.isEmpty { sample.append(line) }
            return sample.count < 200
        }
        guard let format = TextFormats.detect(p, sample: sample) else { return nil }

        // Classic time stamps have no year: count year changes (Dec → Jan) to find the first one.
        var firstYear: Int?
        var sampleBsd = false
        forEachRecord(data, in: 0..<min(data.count, 1 << 20), firstNumber: 1, format: format) { r in
            if case .bsd? = format.stamp(r).stamp { sampleBsd = true; return false }
            return true
        }
        if sampleBsd {
            var wraps = 0, prev: Int?, last: (Int, Int)?
            forEachRecord(data, in: 0..<data.count, firstNumber: 1, format: format) { r in
                guard case let .bsd(month, day, _, _, _, _)? = format.stamp(r).stamp else { return true }
                if let p = prev, p > month + 6 { wraps += 1 }
                prev = month
                last = (month, day)
                return true
            }
            if let last {
                firstYear = YearInference.lastYear(month: last.0, day: last.1, reference: p.reference,
                                                   zone: p.zone ?? TimeZone(identifier: "UTC")!) - wraps
            }
        }

        var clock = SyslogClock(zone: p.zone, firstYear: firstYear)
        var jobs: [LinuxJob] = [], keys: [[RecordKey]] = [], current: [RecordKey] = []
        var job = LinuxJob(source: src, bytes: 0..<data.count, firstLine: 1, formatName: format.name, firstYear: firstYear)
        var lastTs: Int64?, firstDatedTs: Int64?
        var pending: [(job: Int, index: Int)] = []
        var skipped = 0
        var startedDated = false
        forEachRecord(data, in: 0..<data.count, firstNumber: 1, format: format, skipped: { _ in skipped += 1 }) { r in
            if current.count >= recordsPerJob {
                job.bytes = job.bytes.lowerBound..<r.first.offset
                jobs.append(job)
                keys.append(current)
                current = []
                job = LinuxJob(source: src, bytes: r.first.offset..<data.count, firstLine: r.first.number,
                               formatName: format.name, firstYear: clock.year, carryTs: lastTs)
                startedDated = false
            }
            var flags: RecordFlags = r.lines.contains(where: \.invalidText) ? .invalidText : []
            let st = format.stamp(r)
            var ts: Int64 = 0
            if let stamp = st.stamp {
                let t = clock.time(stamp)
                if !startedDated, case .bsd = stamp { job.firstYear = clock.year }
                startedDated = true
                ts = t.ts
                flags.formUnion(t.flags)
                lastTs = ts
                if firstDatedTs == nil { firstDatedTs = ts }
            } else if let lastTs {
                ts = lastTs
            } else {
                pending.append((jobs.count, current.count))
            }
            current.append(RecordKey(ts: ts, computer: st.host.map(String.init) ?? p.host, channel: p.channel,
                                     rid: UInt64(r.first.number), eid: 0, src: src, chunk: 0, off: r.first.offset, flags: flags))
            return true
        }
        jobs.append(job)
        keys.append(current)
        let fallback = firstDatedTs ?? FileTime.fromUnixSeconds(Int64(p.reference.timeIntervalSince1970.rounded(.down)))
        for (j, i) in pending { keys[j][i].ts = fallback }
        for j in jobs.indices where jobs[j].carryTs == nil {
            jobs[j].carryTs = fallback
            jobs[j].noDates = firstDatedTs == nil
        }
        return Planned(format: format, jobs: jobs, keys: keys, skipped: skipped, noDates: firstDatedTs == nil)
    }

    /// Pass 2: the records of a job, one per key of pass 1.
    static func records(_ p: LinuxSourcePlan, data: Data, job: LinuxJob) -> [CaseRecord] {
        guard let format = job.formatName.flatMap(TextFormats.named) else { return [] }
        var clock = SyslogClock(zone: p.zone, firstYear: job.firstYear)
        var out: [CaseRecord] = []
        var lastTs = job.carryTs ?? 0
        forEachRecord(data, in: job.bytes, firstNumber: job.firstLine, format: format) { r in
            let parsed = format.parse(r, plan: p)
            var flags = parsed.flags
            if r.lines.contains(where: \.invalidText) { flags.insert(.invalidText) }
            let ts: Int64
            if let stamp = parsed.stamp {
                let t = clock.time(stamp)
                ts = t.ts
                flags.formUnion(t.flags)
                lastTs = ts
            } else {
                ts = lastTs
                if !parsed.timeIsInherited { flags.insert(job.noDates ? .timeFromFile : .timeCarried) }
            }
            var c = CaseRecord(timestamp: ts, writtenTime: ts, recordId: UInt64(r.first.number), provider: parsed.provider,
                               channel: p.channel, computer: parsed.host ?? p.host, flags: flags, fields: parsed.fields)
            c.level = parsed.level
            c.processId = parsed.pid
            c.eventId = parsed.eventId
            out.append(c)
            return true
        }
        return out
    }
}

enum LinuxBinary {
    /// Keys (pass 1) and records (pass 2) of wtmp / btmp / utmp / lastlog files.
    static func events(_ p: LinuxSourcePlan, data: Data, src: Int, users: [Int: String], records: Bool)
        -> (keys: [RecordKey], records: [CaseRecord], skipped: Int) {
        var keys: [RecordKey] = [], out: [CaseRecord] = []
        switch p.kind {
        case .lastlog:
            for (i, r) in LastlogRecord.parse(data).enumerated() {
                let ts = FileTime.fromUnixSeconds(r.seconds)
                keys.append(RecordKey(ts: ts, computer: p.host, channel: p.channel, rid: UInt64(i + 1), eid: 0,
                                      src: src, chunk: 0, off: r.offset, flags: []))
                if records {
                    out.append(CaseRecord(timestamp: ts, writtenTime: ts, recordId: UInt64(i + 1), provider: "lastlog",
                                          channel: p.channel, computer: p.host, flags: [],
                                          fields: r.fields(host: p.host, user: users[r.uid])))
                }
            }
            return (keys, out, 0)
        default:
            let parsed = UtmpRecord.parse(data)
            for r in parsed.records {
                let rid = UInt64(r.offset / UtmpRecord.size + 1)
                keys.append(RecordKey(ts: r.timestamp, computer: p.host, channel: p.channel, rid: rid, eid: UInt16(r.type),
                                      src: src, chunk: 0, off: r.offset, flags: []))
                if records {
                    var c = CaseRecord(timestamp: r.timestamp, writtenTime: r.timestamp, recordId: rid, provider: p.channel,
                                       channel: p.channel, computer: p.host, flags: [],
                                       fields: r.fields(host: p.host, failed: p.kind == .btmp))
                    c.eventId = UInt16(r.type)
                    if r.pid > 0 { c.processId = UInt32(r.pid) }
                    out.append(c)
                }
            }
            return (keys, out, parsed.bad.count + (parsed.trailing > 0 ? 1 : 0))
        }
    }
}
