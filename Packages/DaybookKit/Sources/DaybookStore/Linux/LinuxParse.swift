import EvtxCore
import Foundation

/// A unit of parallel work: a run of lines of one text source, or one whole binary source.
struct LinuxJob: Sendable {
    var source: Int
    /// Byte range in the (unpacked) content; whole file for binary sources.
    var bytes: Range<Int>
    /// Number of the line at `bytes.lowerBound` (1-based).
    var firstLine: Int
    var format: Syslog.Format?
    /// Classic syslog: year of the first dated line of the job.
    var firstYear: Int?
    /// Time given to undated lines before the job's first dated line.
    var carryTs: Int64?
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
    static let linesPerJob = 200_000

    /// Pass 1 of a syslog source: detects the format, splits the file into jobs and returns the
    /// sort key of every line. nil when the content is not syslog.
    static func plan(_ p: LinuxSourcePlan, data: Data, src: Int) -> (format: Syslog.Format, jobs: [LinuxJob], keys: [[RecordKey]], skipped: Int)? {
        var sample: [LogLine] = []
        LogLines.forEach(data, in: 0..<data.count, firstNumber: 1) { line in
            if !line.text.isEmpty { sample.append(line) }
            return sample.count < 200
        }
        guard let format = Syslog.detect(sample) else { return nil }

        // Classic syslog: count year changes (Dec → Jan) to find the year of the first line.
        var firstYear: Int?
        if format == .bsd {
            var wraps = 0, prev: Int?, last: (Int, Int)?
            LogLines.forEach(data, in: 0..<data.count, firstNumber: 1) { line in
                guard let s = Syslog.parse(line.text), case let .bsd(month, day, _, _, _, _) = s.stamp else { return true }
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

        let compressed = p.size != data.count
        var clock = SyslogClock(zone: p.zone, firstYear: firstYear)
        var jobs: [LinuxJob] = []
        var keys: [[RecordKey]] = []
        var current: [RecordKey] = []
        var job = LinuxJob(source: src, bytes: 0..<data.count, firstLine: 1, format: format, firstYear: firstYear, carryTs: nil)
        var lastTs: Int64?
        var firstDatedTs: Int64?
        var pendingUndated: [(job: Int, index: Int)] = []
        var skipped = 0
        var startedDated = false
        LogLines.forEach(data, in: 0..<data.count, firstNumber: 1) { line in
            if !compressed, current.count >= linesPerJob {
                job.bytes = job.bytes.lowerBound..<line.offset
                jobs.append(job)
                keys.append(current)
                current = []
                job = LinuxJob(source: src, bytes: line.offset..<data.count, firstLine: line.number, format: format,
                               firstYear: clock.year, carryTs: lastTs)
                startedDated = false
            }
            guard !line.text.isEmpty else { skipped += 1; return true }
            var flags: RecordFlags = line.invalidText ? .invalidText : []
            var ts: Int64 = 0
            var host = p.host
            if let s = Syslog.parse(line.text) {
                let t = clock.time(s.stamp)
                if !startedDated, case .bsd = s.stamp { job.firstYear = clock.year }
                startedDated = true
                ts = t.ts
                flags.formUnion(t.flags)
                host = String(s.host)
                lastTs = ts
                if firstDatedTs == nil { firstDatedTs = ts }
            } else {
                flags.insert(.unparsed)
                if let lastTs { ts = lastTs } else { pendingUndated.append((jobs.count, current.count)) }
            }
            current.append(RecordKey(ts: ts, computer: host, channel: p.channel, rid: UInt64(line.number), eid: 0,
                                     src: src, chunk: 0, off: line.offset, flags: flags))
            return true
        }
        jobs.append(job)
        keys.append(current)
        for (j, i) in pendingUndated { keys[j][i].ts = firstDatedTs ?? 0 }
        for j in jobs.indices where jobs[j].carryTs == nil { jobs[j].carryTs = firstDatedTs }
        return (format, jobs, keys, skipped)
    }

    /// Pass 2: the records of a job, one per key of pass 1.
    static func records(_ p: LinuxSourcePlan, data: Data, job: LinuxJob) -> [CaseRecord] {
        var clock = SyslogClock(zone: p.zone, firstYear: job.firstYear)
        var out: [CaseRecord] = []
        var lastTs = job.carryTs ?? 0
        LogLines.forEach(data, in: job.bytes, firstNumber: job.firstLine) { line in
            guard line.offset < job.bytes.upperBound else { return false }
            guard !line.text.isEmpty else { return true }
            var flags: RecordFlags = line.invalidText ? .invalidText : []
            guard let s = Syslog.parse(line.text) else {
                flags.insert(.unparsed)
                out.append(CaseRecord(timestamp: lastTs, writtenTime: lastTs, recordId: UInt64(line.number), provider: "",
                                      channel: p.channel, computer: p.host, flags: flags,
                                      fields: [CaseField("Message", line.text)]))
                return true
            }
            let t = clock.time(s.stamp)
            lastTs = t.ts
            flags.formUnion(t.flags)
            var f = LinuxFields(host: s.host)
            f.add("Message", s.message)
            var level = SyslogMessages.extract(program: s.program, message: s.message, into: &f)
            if let pid = s.pid { f.add("ProcessId", String(pid)) }
            if let pri = s.priority {
                f.add("Facility", pri >> 3 < Syslog.facilities.count ? Syslog.facilities[pri >> 3] : String(pri >> 3))
                f.add("Severity", Syslog.severities[pri & 7])
                level = Syslog.level(severity: pri & 7)
            }
            var r = CaseRecord(timestamp: t.ts, writtenTime: t.ts, recordId: UInt64(line.number), provider: String(s.program),
                               channel: p.channel, computer: String(s.host), flags: flags, fields: f.list)
            r.level = level
            r.processId = s.pid
            out.append(r)
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
