import EvtxCore
import Foundation

/// Sort key of one record, gathered before event ids are assigned (pass 1 of an import).
public struct RecordKey: Sendable {
    public var ts: Int64
    /// Stable hash of computer + log: identifies the log a record number belongs to.
    public var key: UInt64
    public var rid: UInt64
    public var eid: UInt16
    public var src: UInt32
    public var chunk: UInt64
    public var off: UInt64
    public var flags: UInt32

    public init(ts: Int64, computer: String, channel: String, rid: UInt64, eid: UInt16,
                src: Int, chunk: Int, off: Int, flags: RecordFlags) {
        self.ts = ts
        key = UInt64(bitPattern: StringKey.lowerHash(computer)) &* 31 &+ UInt64(bitPattern: StringKey.lowerHash(channel))
        self.rid = rid
        self.eid = eid
        self.src = UInt32(src)
        self.chunk = UInt64(chunk)
        self.off = UInt64(off)
        self.flags = flags.rawValue
    }
}

public struct CaseField: Sendable {
    public var name: String
    public var value: String
    /// Hex dumps are kept out of the full-text index.
    public var binary: Bool

    public init(_ name: String, _ value: String, binary: Bool = false) {
        self.name = name
        self.value = value
        self.binary = binary
    }
}

/// One event as stored in the case (pass 2 of an import).
public struct CaseRecord: Sendable {
    public var timestamp: Int64
    public var writtenTime: Int64
    public var recordId: UInt64
    public var eventId: UInt16 = 0
    public var qualifiers: UInt16?
    public var version: UInt8?
    /// Application scale: 1 critical, 2 error, 3 warning, 4 information, 5 verbose.
    public var level: UInt8?
    public var task: UInt16?
    public var opcode: UInt8?
    public var keywords: UInt64?
    public var provider: String
    public var channel: String
    public var computer: String
    public var userSid: String?
    public var processId: UInt32?
    public var threadId: UInt32?
    public var flags: RecordFlags
    public var fields: [CaseField]
    /// The record as text when the source cannot simply be re-read: XML of EVTX records with a
    /// foreign or missing template, the original line or decoded record of other formats.
    public var rendered: String?

    public init(timestamp: Int64, writtenTime: Int64, recordId: UInt64, provider: String, channel: String,
                computer: String, flags: RecordFlags, fields: [CaseField], rendered: String? = nil) {
        self.timestamp = timestamp
        self.writtenTime = writtenTime
        self.recordId = recordId
        self.provider = provider
        self.channel = channel
        self.computer = computer
        self.flags = flags
        self.fields = fields
        self.rendered = rendered
    }

    public init(_ e: EvtxEvent, rendered: String?) {
        self.init(timestamp: e.timestamp, writtenTime: e.writtenTime, recordId: e.recordId, provider: e.provider,
                  channel: e.channel, computer: e.computer, flags: e.flags,
                  fields: e.fields.map { CaseField($0.name, $0.value, binary: $0.type == ValueType.binary) },
                  rendered: rendered)
        eventId = e.eventId
        qualifiers = e.qualifiers
        version = e.version
        level = e.level
        task = e.task
        opcode = e.opcode
        keywords = e.keywords
        userSid = e.userSid
        processId = e.processId
        threadId = e.threadId
    }
}

/// A source file as stored in the `source` table.
public struct CaseSource: Sendable {
    public var url: URL
    public var size: Int
    public var sha256: String
    /// `evtx`, `syslog`, `wtmp`, …
    public var format: String
    /// Log the file belongs to when it is not taken from the records (rotations share it).
    public var channel: String?
    public var host: String?
    /// Records or lines recognised and skipped (text formats).
    public var parsed: Int?
    public var skipped: Int?
    public var note: String?
    public var evtx: EvtxColumns?

    public struct EvtxColumns: Sendable {
        public var headerChunks: Int
        public var chunks: Int
        public var dirty: Bool
        public var emptyChunks: Int
        public var beyondNew: Int
        public var beyondStale: Int
        public var badHeaderCRC: Int
        public var badDataCRC: Int
        public var trailingBytes: Int
        public var version: String
    }

    public init(url: URL, size: Int, sha256: String, format: String) {
        self.url = url
        self.size = size
        self.sha256 = sha256
        self.format = format
    }
}

/// Writes a case from records of any format: sorts the pass-1 keys globally, assigns
/// time-ordered event ids (identical records from several copies collapse into one), then
/// streams the pass-2 records to a single SQLite writer while the next group is parsed.
public final class CaseWriter: @unchecked Sendable {
    public struct Assignment: Sendable {
        /// First slot of each job; slots are the jobs' keys laid end to end.
        public var jobStart: [Int]
        /// Event id per slot, or -1 for a copy of another event.
        public var assigned: [Int32]
        public var dupOf: [Int32]
        public var timestamps: [Int64]
        public var hasCopies: Set<Int32>
        public var duplicates: Int

        public func isKept(job: Int, index: Int) -> Bool { assigned[jobStart[job] + index] >= 0 }
    }

    public struct Result: Sendable {
        public var events = 0
        public var duplicates = 0
        public var carved = 0
        public var parseErrors = 0
    }

    public let caseURL: URL

    public init(caseURL: URL) {
        self.caseURL = caseURL
    }

    /// Sorts by time, then log, record number, event id; recovered records after live ones.
    public static func assign(_ jobKeys: [[RecordKey]], merge: Bool) -> Assignment {
        var jobStart = [Int](repeating: 0, count: jobKeys.count + 1)
        for j in jobKeys.indices { jobStart[j + 1] = jobStart[j] + jobKeys[j].count }
        var entries = [RecordKey]()
        entries.reserveCapacity(jobStart[jobKeys.count])
        for keys in jobKeys { entries += keys }
        let order = (0..<entries.count).sorted { a, b in
            let x = entries[a], y = entries[b]
            if x.ts != y.ts { return x.ts < y.ts }
            if x.key != y.key { return x.key < y.key }
            if x.rid != y.rid { return x.rid < y.rid }
            if x.eid != y.eid { return x.eid < y.eid }
            let cx = x.flags & RecordFlags.carved.rawValue, cy = y.flags & RecordFlags.carved.rawValue
            if cx != cy { return cx < cy }
            if x.src != y.src { return x.src < y.src }
            if x.chunk != y.chunk { return x.chunk < y.chunk }
            return x.off < y.off
        }
        var assigned = [Int32](repeating: -1, count: entries.count)
        var dupOf = [Int32](repeating: -1, count: entries.count)
        var timestamps = [Int64]()
        timestamps.reserveCapacity(entries.count)
        var lastKept = -1
        var hasCopies = Set<Int32>()
        var duplicates = 0
        for i in order {
            let e = entries[i]
            if merge, lastKept >= 0 {
                let k = entries[lastKept]
                if k.ts == e.ts && k.key == e.key && k.rid == e.rid && k.eid == e.eid {
                    dupOf[i] = assigned[lastKept]
                    hasCopies.insert(assigned[lastKept])
                    duplicates += 1
                    continue
                }
            }
            assigned[i] = Int32(timestamps.count)
            timestamps.append(e.ts)
            lastKept = i
        }
        return Assignment(jobStart: jobStart, assigned: assigned, dupOf: dupOf, timestamps: timestamps,
                          hasCopies: hasCopies, duplicates: duplicates)
    }

    /// `produce` returns, for each job of the range, one element per key of that job in the same
    /// order; elements of copies (`!isKept`) may be nil. `meta` adds case-level keys.
    // swiftlint:disable:next function_body_length function_parameter_count
    public func write(assignment a: Assignment, jobKeys: [[RecordKey]], sources: [CaseSource], groupSize: Int,
                      meta extra: [(String, String)], failedFiles: [String], requestedSources: [URL],
                      produce: @escaping @Sendable (Range<Int>) -> [[CaseRecord?]],
                      progress: @escaping @Sendable (ImportProgress) -> Void,
                      cancelled: @escaping @Sendable () -> Bool) throws -> Result {
        var result = Result()
        result.duplicates = a.duplicates
        let db = try SQLiteDB(path: caseURL.appendingPathComponent(CaseSchema.databaseName).path, create: true)
        try db.exec(CaseSchema.create)
        try db.exec("PRAGMA journal_mode = OFF; PRAGMA synchronous = OFF; PRAGMA cache_size = -262144; PRAGMA temp_store = MEMORY; PRAGMA locking_mode = EXCLUSIVE;")
        try db.exec("BEGIN")
        let interner = try Interner(db: db)
        let insertEv = try db.prepare("""
            INSERT INTO ev(id, ts, wts, src, chunk, off, rid, eid, qual, ver, lvl, task, opc, kw, prov, chan, comp, usr, pid, tid, flags, fv)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, persistent: true)
        let insertDup = try db.prepare("INSERT INTO dup(ev, src, chunk, off, flags) VALUES (?,?,?,?,?)", persistent: true)
        let insertXml = try db.prepare("INSERT INTO xml_cache(ev, xml) VALUES (?,?)", persistent: true)
        var postings: [UInt64: [UInt32]] = [:]
        var keyIds: [String: UInt32] = [:]
        func key(_ name: String) throws -> UInt32 {
            if let k = keyIds[name] { return k }
            let k = try interner.id(name, kind: CaseSchema.StrKind.name)
            keyIds[name] = k
            return k
        }
        func post(_ k: UInt32, _ v: UInt32, _ id: UInt32) {
            postings[UInt64(k) << 32 | UInt64(v), default: []].append(id)
        }
        let sysKeys = try CaseSchema.SystemKey.all.map { try key($0) }
        let (kEid, kChan, kProv, kComp, kLvl, kUser, kSrc, kTask, kOpc, kFlag) =
            (sysKeys[0], sysKeys[1], sysKeys[2], sysKeys[3], sysKeys[4], sysKeys[5], sysKeys[6], sysKeys[7], sysKeys[8], sysKeys[9])
        let kKw = sysKeys[10]
        let labels = CaseImporter.uniqueLabels(sources.map(\.url))
        let sourceNames = try labels.map { try interner.id($0) }

        let jobs = jobKeys.count
        var perSource = [(records: Int, carved: Int, dups: Int, first: Int64, last: Int64, unparsed: Int)](
            repeating: (0, 0, 0, .max, .min, 0), count: sources.count)
        let groups = stride(from: 0, to: jobs, by: max(1, groupSize)).map { $0..<min($0 + max(1, groupSize), jobs) }
        var written = 0
        var lastReport = Date.distantPast
        var current = groups.isEmpty ? [] : produce(groups[0])
        for gi in groups.indices {
            let next = Box<[[CaseRecord?]]>([])
            let pending = DispatchGroup()
            if gi + 1 < groups.count {
                let range = groups[gi + 1]
                DispatchQueue.global(qos: .userInitiated).async(group: pending) { next.value = produce(range) }
            }
            for (k, records) in current.enumerated() {
                let j = groups[gi].lowerBound + k
                for (i, rec) in records.enumerated() {
                    let slot = a.jobStart[j] + i
                    let rk = jobKeys[j][i]
                    let assignedId = a.assigned[slot]
                    guard assignedId >= 0, var e = rec else {
                        try insertDup.bind(1, Int64(a.dupOf[slot])).bind(2, Int(rk.src)).bind(3, Int64(bitPattern: rk.chunk))
                            .bind(4, Int64(bitPattern: rk.off)).bind(5, Int64(rk.flags)).run()
                        perSource[Int(rk.src)].dups += 1
                        continue
                    }
                    let id = UInt32(assignedId)
                    if a.hasCopies.contains(assignedId) { e.flags.insert(.duplicate) }
                    let prov = try interner.id(e.provider)
                    let chan = try interner.id(e.channel)
                    let comp = try interner.id(e.computer)
                    let usr = try e.userSid.map { try interner.id($0) }
                    var fv = [UInt8]()
                    fv.reserveCapacity(e.fields.count * 6)
                    for f in e.fields {
                        let k = try key(f.name)
                        let v = try interner.id(f.value, kind: f.binary ? CaseSchema.StrKind.binary : CaseSchema.StrKind.text)
                        Varint.append(k, to: &fv)
                        Varint.append(v, to: &fv)
                        post(k, v, id)
                    }
                    post(kEid, try interner.id(String(e.eventId)), id)
                    post(kChan, chan, id)
                    post(kProv, prov, id)
                    post(kComp, comp, id)
                    post(kSrc, sourceNames[Int(rk.src)], id)
                    if let l = e.level { post(kLvl, try interner.id(String(l)), id) }
                    if let usr { post(kUser, usr, id) }
                    if let t = e.task { post(kTask, try interner.id(String(t)), id) }
                    if let o = e.opcode { post(kOpc, try interner.id(String(o)), id) }
                    if let kw = e.keywords { post(kKw, try interner.id(String(format: "0x%016llx", kw)), id) }
                    for (flag, name) in RecordFlags.names where e.flags.contains(flag) { post(kFlag, try interner.id(name), id) }

                    try insertEv.bind(1, Int64(id)).bind(2, e.timestamp).bind(3, e.writtenTime).bind(4, Int(rk.src))
                        .bind(5, Int64(bitPattern: rk.chunk)).bind(6, Int64(bitPattern: rk.off))
                        .bind(7, Int64(bitPattern: e.recordId)).bind(8, Int64(e.eventId))
                        .bind(9, e.qualifiers.map { Int64($0) }).bind(10, e.version.map { Int64($0) })
                        .bind(11, e.level.map { Int64($0) }).bind(12, e.task.map { Int64($0) })
                        .bind(13, e.opcode.map { Int64($0) }).bind(14, e.keywords.map { Int64(bitPattern: $0) })
                        .bind(15, Int64(prov)).bind(16, Int64(chan)).bind(17, Int64(comp)).bind(18, usr.map { Int64($0) })
                        .bind(19, e.processId.map { Int64($0) }).bind(20, e.threadId.map { Int64($0) })
                        .bind(21, Int64(e.flags.rawValue)).bind(22, blob: fv).run()
                    if let text = e.rendered { try insertXml.bind(1, Int64(id)).bind(2, text).run() }

                    var s = perSource[Int(rk.src)]
                    if e.flags.contains(.carved) { s.carved += 1 } else { s.records += 1 }
                    if e.flags.contains(.unparsed) { s.unparsed += 1 }
                    s.first = min(s.first, e.timestamp)
                    s.last = max(s.last, e.timestamp)
                    perSource[Int(rk.src)] = s
                    if e.flags.contains(.carved) { result.carved += 1 }
                    if e.flags.contains(.parseError) { result.parseErrors += 1 }
                    written += 1
                }
            }
            pending.wait()
            current = next.value
            if Date().timeIntervalSince(lastReport) > 0.1 {
                lastReport = Date()
                progress(ImportProgress(phase: .writing, fraction: Double(gi + 1) / Double(groups.count), events: written))
            }
            if cancelled() { throw CancellationError() }
        }
        result.events = written

        // Posting lists.
        progress(ImportProgress(phase: .postings, fraction: 0, events: written))
        let insertPost = try db.prepare("INSERT INTO post(k, v, n, ids) VALUES (?,?,?,?)", persistent: true)
        for pk in postings.keys.sorted() {
            var ids = postings[pk]!
            ids.sort()
            try insertPost.bind(1, Int64(pk >> 32)).bind(2, Int64(pk & 0xFFFF_FFFF)).bind(3, ids.count)
                .bind(4, blob: Varint.encodeDeltas(ids)).run()
        }
        postings = [:]

        // Sources and metadata.
        let insertSource = try db.prepare("""
            INSERT INTO source(id, path, name, size, sha256, mtime, header_chunks, chunks, dirty, records, carved, duplicates,
                               first_ts, last_ts, empty_chunks, beyond_new, beyond_stale, bad_header_crc, bad_data_crc,
                               trailing_bytes, version, format, channel, host, parsed, skipped, note)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """)
        for (i, f) in sources.enumerated() {
            let s = perSource[i]
            let x = f.evtx
            let mtime = (try? f.url.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate)?.timeIntervalSince1970
            try insertSource.bind(1, i).bind(2, f.url.path).bind(3, labels[i]).bind(4, f.size)
                .bind(5, f.sha256).bind(6, mtime.map { Int64($0) }).bind(7, x?.headerChunks)
                .bind(8, x?.chunks).bind(9, x.map { $0.dirty ? 1 : 0 }).bind(10, s.records)
                .bind(11, s.carved).bind(12, s.dups).bind(13, s.first == .max ? nil : s.first)
                .bind(14, s.last == .min ? nil : s.last).bind(15, x?.emptyChunks).bind(16, x?.beyondNew)
                .bind(17, x?.beyondStale).bind(18, x?.badHeaderCRC).bind(19, x?.badDataCRC).bind(20, x?.trailingBytes)
                .bind(21, x?.version).bind(22, f.format).bind(23, f.channel).bind(24, f.host)
                .bind(25, f.parsed ?? (f.format == "evtx" ? nil : s.records - s.unparsed)).bind(26, f.skipped).bind(27, f.note).run()
        }
        let meta = try db.prepare("INSERT INTO meta(key, value) VALUES (?, ?)")
        for (k, v) in [("schema", String(CaseSchema.version)), ("events", String(written)),
                       ("created", ISO8601DateFormatter().string(from: Date())), ("fulltext", "0"),
                       ("carvedKept", String(result.carved)),
                       ("duplicates", String(result.duplicates)), ("parseErrors", String(result.parseErrors)),
                       ("failedFiles", failedFiles.joined(separator: "\n")),
                       ("sources", requestedSources.map(\.path).joined(separator: "\n"))] + extra {
            try meta.bind(1, k).bind(2, v).run()
        }
        try db.exec("COMMIT")

        progress(ImportProgress(phase: .finishing, fraction: 0, events: written))
        try db.exec(CaseSchema.indexes)
        try a.timestamps.withUnsafeBytes { try Data($0).write(to: caseURL.appendingPathComponent(CaseSchema.timestampsName)) }

        progress(ImportProgress(phase: .fullText, fraction: 0, events: written))
        try db.exec(CaseSchema.fullText)
        try db.exec("UPDATE meta SET value = '1' WHERE key = 'fulltext'")
        try db.exec("PRAGMA locking_mode = NORMAL; PRAGMA journal_mode = WAL; PRAGMA wal_checkpoint(TRUNCATE);")
        return result
    }
}

final class Box<T>: @unchecked Sendable {
    var value: T
    init(_ v: T) { value = v }
}
