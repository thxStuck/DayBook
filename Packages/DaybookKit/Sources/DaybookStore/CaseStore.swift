import EvtxCore
import Foundation

public struct SourceInfo: Sendable, Identifiable, Hashable {
    public let id: Int
    public let path: String
    public let name: String
    public let size: Int64
    public let sha256: String
    public let headerChunks: Int
    public let chunks: Int
    public let dirty: Bool
    public let records: Int
    public let carved: Int
    public let duplicates: Int
    public let firstTs: Int64?
    public let lastTs: Int64?
    // Chunk statistics (nil for cases created by older versions).
    public var emptyChunks: Int?
    public var beyondHeaderNew: Int?
    public var beyondHeaderStale: Int?
    public var badHeaderCRC: Int?
    public var badDataCRC: Int?
    public var trailingBytes: Int?
    public var formatVersion: String?
    // Any format (nil for cases created by older versions): `evtx`, `syslog`, `wtmp`, …
    public var format: String?
    /// Log the file belongs to (rotations share it) and the host it was collected from (Linux).
    public var channel: String?
    public var host: String?
    /// Lines or records recognised, and those not imported (empty lines, invalid records).
    public var parsed: Int?
    public var skipped: Int?
    /// Why the file was not (fully) parsed, assumptions made (year, zone), compression.
    public var note: String?

    public var isEvtx: Bool { format == nil || format == "evtx" }
}

/// The kind of system a case was built from.
public enum CasePlatform: String, Sendable {
    case windows, linux
}

/// One table row. Field values are dictionary ids resolved through `CaseStore.string(_:)`.
public struct EventRow: Sendable {
    public let id: UInt32
    public let ts: Int64
    public let writtenTime: Int64
    public let source: Int
    public let recordId: UInt64
    public let eventId: UInt16
    public let level: UInt8?
    public let task: UInt16?
    public let opcode: UInt8?
    public let keywords: UInt64?
    public let provider: String
    public let channel: String
    public let computer: String
    public let user: String?
    public let processId: UInt32?
    public let threadId: UInt32?
    public let flags: RecordFlags
    /// (key id, value id) pairs in document order.
    public let pairs: [(key: UInt32, value: UInt32)]
}

public struct EventField: Sendable, Hashable {
    public let key: String
    public let value: String
}

/// Where an event's XML and raw bytes stand. The case holds the parsed fields; the record itself
/// is re-read from its source file on demand, and that file can be slow, moved or changed.
public enum SourceRecordState: Sendable, Equatable {
    /// Not read from the source file yet.
    case pending
    case loaded
    /// The source file is gone (moved or deleted after import).
    case missingFile
    /// macOS refused access to the source file.
    case noAccess
    case unreadable(String)
    /// Another record is at the stored position: the file changed after import.
    case recordMismatch
    /// The case has no position of the record in its source file.
    case noLocation
}

public struct EventDetail: Sendable {
    public let row: EventRow
    public let fields: [EventField]
    public internal(set) var xml: String?
    /// The original line or decoded record of non-EVTX sources.
    public internal(set) var text: String?
    public internal(set) var raw: [UInt8]?
    public let duplicates: [(source: Int, chunk: Int, offset: Int)]
    /// The source file the record is re-read from.
    public let sourcePath: String?
    public internal(set) var sourceState: SourceRecordState
    let location: (chunk: Int, offset: Int)?
}

/// A value of a field with its number of events.
public struct FacetValue: Sendable, Hashable {
    public let valueId: UInt32
    public let value: String
    public let count: Int
}

/// Read side of a case. Two read-only connections (row/detail fetches and long queries)
/// so a slow query never blocks scrolling. Each connection is guarded by its own lock.
public final class CaseStore: @unchecked Sendable {
    public let url: URL
    public let eventCount: Int
    public let sources: [SourceInfo]
    public let fullTextReady: Bool
    /// Import metadata: options, totals, failed files (key → value).
    public let meta: [String: String]
    /// `windows` for cases without the key (created before Linux support).
    public let platform: CasePlatform
    private let tsFile: MappedFile
    let rowsDB: SQLiteDB
    let queryDB: SQLiteDB
    let rowsLock = NSLock()
    let queryLock = NSLock()
    private let cacheLock = NSLock()
    private var cache: [UInt32: String] = [:]
    private var cacheBytes = 0
    private var keyByName: [String: UInt32] = [:]
    private var keyByExactName: [String: UInt32] = [:]
    private var nameByKey: [UInt32: String] = [:]
    let fileLock = NSLock()
    private var openFiles: [Int: EvtxFile] = [:]
    /// Unpacked content of the last text sources read (Linux), keyed by source id.
    var textFiles: [(id: Int, data: Data)] = []
    /// Stored detection rules, keyed by the run that produced them.
    let detectionCache = DetectionCache()

    public init(url: URL) throws {
        self.url = url
        let dbPath = url.appendingPathComponent(CaseSchema.databaseName).path
        rowsDB = try SQLiteDB(path: dbPath, readOnly: true)
        queryDB = try SQLiteDB(path: dbPath, readOnly: true)
        for db in [rowsDB, queryDB] {
            try db.exec("PRAGMA mmap_size = 1073741824; PRAGMA cache_size = -131072; PRAGMA temp_store = MEMORY;")
        }
        tsFile = try MappedFile(url: url.appendingPathComponent(CaseSchema.timestampsName))
        eventCount = tsFile.size / 8
        fullTextReady = (try? rowsDB.scalar("SELECT value = '1' FROM meta WHERE key = 'fulltext'")) == 1

        var srcs: [SourceInfo] = []
        let hasStats = (try? rowsDB.scalar("SELECT count(*) FROM pragma_table_info('source') WHERE name = 'empty_chunks'")) == 1
        let hasFormat = (try? rowsDB.scalar("SELECT count(*) FROM pragma_table_info('source') WHERE name = 'format'")) == 1
        let s = try rowsDB.prepare("""
            SELECT id, path, name, size, sha256, header_chunks, chunks, dirty, records, carved, duplicates, first_ts, last_ts
            \(hasStats ? ", empty_chunks, beyond_new, beyond_stale, bad_header_crc, bad_data_crc, trailing_bytes, version" : "")
            \(hasFormat ? ", format, channel, host, parsed, skipped, note" : "")
            FROM source ORDER BY id
            """)
        while try s.step() {
            var info = SourceInfo(id: Int(s.int64(0)), path: s.string(1), name: s.string(2), size: s.int64(3),
                                  sha256: s.string(4), headerChunks: Int(s.int64(5)), chunks: Int(s.int64(6)),
                                  dirty: s.int64(7) != 0, records: Int(s.int64(8)), carved: Int(s.int64(9)),
                                  duplicates: Int(s.int64(10)), firstTs: s.optionalInt64(11), lastTs: s.optionalInt64(12))
            if hasStats {
                info.emptyChunks = s.optionalInt64(13).map(Int.init)
                info.beyondHeaderNew = s.optionalInt64(14).map(Int.init)
                info.beyondHeaderStale = s.optionalInt64(15).map(Int.init)
                info.badHeaderCRC = s.optionalInt64(16).map(Int.init)
                info.badDataCRC = s.optionalInt64(17).map(Int.init)
                info.trailingBytes = s.optionalInt64(18).map(Int.init)
                info.formatVersion = s.optionalString(19)
            }
            if hasFormat {
                let c: Int32 = hasStats ? 20 : 13
                info.format = s.optionalString(c)
                info.channel = s.optionalString(c + 1)
                info.host = s.optionalString(c + 2)
                info.parsed = s.optionalInt64(c + 3).map(Int.init)
                info.skipped = s.optionalInt64(c + 4).map(Int.init)
                info.note = s.optionalString(c + 5)
            }
            srcs.append(info)
        }
        sources = srcs
        var m: [String: String] = [:]
        let ms = try rowsDB.prepare("SELECT key, value FROM meta")
        while try ms.step() { m[ms.string(0)] = ms.string(1) }
        meta = m
        platform = CasePlatform(rawValue: m["platform"] ?? "") ?? .windows

        let k = try rowsDB.prepare("SELECT DISTINCT k FROM post")
        var keyIds: [UInt32] = []
        while try k.step() { keyIds.append(UInt32(k.int64(0))) }
        for (id, name) in zip(keyIds, try strings(keyIds)) {
            keyByName[name.lowercased()] = id
            keyByExactName[name] = id
            nameByKey[id] = name
        }
    }

    // MARK: Time

    /// TimeCreated (FILETIME) of event `id`.
    public func timestamp(_ id: UInt32) -> Int64 {
        tsFile.bytes.loadUnaligned(fromByteOffset: Int(id) * 8, as: Int64.self)
    }

    /// First id with timestamp >= ft (ids are time-ordered).
    public func lowerBound(time ft: Int64) -> UInt32 {
        var lo = 0, hi = eventCount
        while lo < hi {
            let m = (lo + hi) >> 1
            if timestamp(UInt32(m)) < ft { lo = m + 1 } else { hi = m }
        }
        return UInt32(lo)
    }

    // MARK: Strings

    public func string(_ id: UInt32) -> String { (try? strings([id]).first) ?? "" }

    public func strings(_ ids: [UInt32]) throws -> [String] {
        var out = [String?](repeating: nil, count: ids.count)
        var missing: [Int] = []
        cacheLock.lock()
        for (i, id) in ids.enumerated() {
            if let s = cache[id] { out[i] = s } else { missing.append(i) }
        }
        cacheLock.unlock()
        if !missing.isEmpty {
            var fetched: [UInt32: String] = [:]
            try rowsLock.withLock {
                let st = try rowsDB.prepare("SELECT id, s FROM str WHERE id IN (SELECT value FROM json_each(?))")
                st.bind(1, "[" + Set(missing.map { ids[$0] }).map(String.init).joined(separator: ",") + "]")
                while try st.step() { fetched[UInt32(st.int64(0))] = st.string(1) }
            }
            cacheLock.lock()
            if cacheBytes > 64 << 20 { cache.removeAll(keepingCapacity: true); cacheBytes = 0 }
            for (id, s) in fetched {
                cache[id] = s
                cacheBytes += s.utf8.count + 32
            }
            cacheLock.unlock()
            for i in missing { out[i] = fetched[ids[i]] ?? "" }
        }
        return out.map { $0 ?? "" }
    }

    // MARK: Field catalog

    public var fieldNames: [String] { nameByKey.values.sorted() }

    public func keyId(_ name: String) -> UInt32? { keyByName[name.lowercased()] }

    /// Field id only when the name matches a real field exactly (case-sensitive).
    public func exactKeyId(_ name: String) -> UInt32? { keyByExactName[name] }

    public func keyName(_ id: UInt32) -> String { nameByKey[id] ?? string(id) }

    /// Dictionary ids of `text`, compared case-insensitively unless `exact`.
    public func valueIds(_ text: String, exact: Bool = false) throws -> [UInt32] {
        try queryLock.withLock {
            let st = try queryDB.prepare("SELECT id, s FROM str WHERE hl = ?")
            st.bind(1, StringKey.lowerHash(text))
            var out: [UInt32] = []
            while try st.step() {
                let s = st.string(1)
                if exact ? s == text : s.caseInsensitiveCompare(text) == .orderedSame { out.append(UInt32(st.int64(0))) }
            }
            return out
        }
    }

    /// Posting list of `key = value`.
    public func posting(key: UInt32, value: UInt32) throws -> [UInt32] {
        try queryLock.withLock {
            let st = try queryDB.prepare("SELECT n, ids FROM post WHERE k = ? AND v = ?")
            st.bind(1, Int64(key)).bind(2, Int64(value))
            guard try st.step() else { return [] }
            let n = Int(st.int64(0))
            return st.withBlob(1) { Varint.decodeDeltas($0, count: n) }
        }
    }

    /// All values of a field with counts (most frequent first). With `within`, counts are
    /// restricted to that (sorted) id set.
    public func facet(_ key: String, within: [UInt32]? = nil, limit: Int = 200) throws -> [FacetValue] {
        guard let k = keyId(key) else { return [] }
        var items: [(UInt32, Int)] = []
        try queryLock.withLock {
            let st = try queryDB.prepare("SELECT v, n, ids FROM post WHERE k = ?")
            st.bind(1, Int64(k))
            while try st.step() {
                let v = UInt32(st.int64(0))
                if let within {
                    let n = Int(st.int64(1))
                    let ids = st.withBlob(2) { Varint.decodeDeltas($0, count: n) }
                    let c = IdSet.intersect(ids, within).count
                    if c > 0 { items.append((v, c)) }
                } else {
                    items.append((v, Int(st.int64(1))))
                }
            }
        }
        items.sort { $0.1 != $1.1 ? $0.1 > $1.1 : $0.0 < $1.0 }
        let top = Array(items.prefix(limit))
        let names = try strings(top.map(\.0))
        return zip(top, names).map { FacetValue(valueId: $0.0.0, value: $0.1, count: $0.0.1) }
    }

    public func interruptQuery() { queryDB.interrupt() }

    // MARK: Rows and details

    public func rows(_ ids: [UInt32]) throws -> [EventRow] {
        guard !ids.isEmpty else { return [] }
        struct Raw { var id: UInt32; var ts, wts: Int64; var src: Int; var rid: UInt64; var eid: UInt16
            var lvl: UInt8?; var task: UInt16?; var opc: UInt8?; var kw: UInt64?; var prov, chan, comp: UInt32
            var usr: UInt32?; var pid, tid: UInt32?; var flags: UInt32; var pairs: [UInt32] }
        var rows: [UInt32: Raw] = [:]
        try rowsLock.withLock {
            let st = try rowsDB.prepare("""
                SELECT id, ts, wts, src, rid, eid, lvl, task, opc, kw, prov, chan, comp, usr, pid, tid, flags, fv
                FROM ev WHERE id IN (SELECT value FROM json_each(?))
                """)
            st.bind(1, "[" + ids.map(String.init).joined(separator: ",") + "]")
            while try st.step() {
                let r = Raw(id: UInt32(st.int64(0)), ts: st.int64(1), wts: st.int64(2), src: Int(st.int64(3)),
                            rid: UInt64(bitPattern: st.int64(4)), eid: UInt16(truncatingIfNeeded: st.int64(5)),
                            lvl: st.optionalInt64(6).map { UInt8(truncatingIfNeeded: $0) },
                            task: st.optionalInt64(7).map { UInt16(truncatingIfNeeded: $0) },
                            opc: st.optionalInt64(8).map { UInt8(truncatingIfNeeded: $0) },
                            kw: st.optionalInt64(9).map { UInt64(bitPattern: $0) },
                            prov: UInt32(st.int64(10)), chan: UInt32(st.int64(11)), comp: UInt32(st.int64(12)),
                            usr: st.optionalInt64(13).map { UInt32($0) },
                            pid: st.optionalInt64(14).map { UInt32(truncatingIfNeeded: $0) },
                            tid: st.optionalInt64(15).map { UInt32(truncatingIfNeeded: $0) },
                            flags: UInt32(truncatingIfNeeded: st.int64(16)),
                            pairs: st.withBlob(17) { Varint.decodeAll($0) })
                rows[r.id] = r
            }
        }
        // Resolve the System strings in one batch.
        var need = Set<UInt32>()
        for r in rows.values {
            need.insert(r.prov); need.insert(r.chan); need.insert(r.comp)
            if let u = r.usr { need.insert(u) }
        }
        let needList = Array(need)
        let resolved = Dictionary(uniqueKeysWithValues: zip(needList, try strings(needList)))
        return ids.compactMap { id in
            guard let r = rows[id] else { return nil }
            var pairs: [(UInt32, UInt32)] = []
            pairs.reserveCapacity(r.pairs.count / 2)
            var i = 0
            while i + 1 < r.pairs.count { pairs.append((r.pairs[i], r.pairs[i + 1])); i += 2 }
            return EventRow(id: r.id, ts: r.ts, writtenTime: r.wts, source: r.src, recordId: r.rid, eventId: r.eid,
                            level: r.lvl, task: r.task, opcode: r.opc, keywords: r.kw,
                            provider: resolved[r.prov] ?? "", channel: resolved[r.chan] ?? "",
                            computer: resolved[r.comp] ?? "", user: r.usr.flatMap { resolved[$0] },
                            processId: r.pid, threadId: r.tid, flags: RecordFlags(rawValue: r.flags),
                            pairs: pairs.map { (key: $0.0, value: $0.1) })
        }
    }

    /// Fields and XML from the case, then the record from its source file (CLI and tests).
    public func detail(_ id: UInt32) throws -> EventDetail? {
        try caseDetail(id).map(readSourceRecord)
    }

    /// Everything the case database holds about an event. It never touches the source file, so
    /// it is fast even when that file is slow or gone; XML and raw bytes follow from
    /// `readSourceRecord`.
    public func caseDetail(_ id: UInt32) throws -> EventDetail? {
        guard let row = try rows([id]).first else { return nil }
        let keys = row.pairs.map(\.key), values = row.pairs.map(\.value)
        let names = try strings(keys), vals = try strings(values)
        let fields = zip(names, vals).map { EventField(key: $0.0, value: $0.1) }

        var xml: String?
        var location: (chunk: Int, offset: Int)?
        try rowsLock.withLock {
            let c = try rowsDB.prepare("SELECT xml FROM xml_cache WHERE ev = ?")
            c.bind(1, Int64(id))
            if try c.step() { xml = c.string(0) }
            let l = try rowsDB.prepare("SELECT chunk, off FROM ev WHERE id = ?")
            l.bind(1, Int64(id))
            if try l.step() { location = (Int(l.int64(0)), Int(l.int64(1))) }
        }
        var dups: [(Int, Int, Int)] = []
        try rowsLock.withLock {
            let d = try rowsDB.prepare("SELECT src, chunk, off FROM dup WHERE ev = ?")
            d.bind(1, Int64(id))
            while try d.step() { dups.append((Int(d.int64(0)), Int(d.int64(1)), Int(d.int64(2)))) }
        }
        let path = row.source >= 0 && row.source < sources.count ? sources[row.source].path : nil
        return EventDetail(row: row, fields: fields, xml: xml, text: nil, raw: nil,
                           duplicates: dups.map { (source: $0.0, chunk: $0.1, offset: $0.2) },
                           sourcePath: path, sourceState: location == nil ? .noLocation : .pending,
                           location: location)
    }

    /// Re-reads the record from its source file for XML and raw bytes. It can block for a long
    /// time on a slow or unreachable file: call it off the main thread.
    public func readSourceRecord(_ detail: EventDetail) -> EventDetail {
        guard detail.sourceState == .pending, let location = detail.location else { return detail }
        if detail.row.source < sources.count, !sources[detail.row.source].isEvtx { return readTextRecord(detail, at: location.offset) }
        var d = detail
        let file: EvtxFile
        do {
            file = try sourceFile(detail.row.source)
        } catch let error as EvtxError {
            d.sourceState = Self.sourceState(for: error)
            return d
        } catch {
            d.sourceState = .unreadable(String(describing: error))
            return d
        }
        guard location.chunk < file.physicalChunkCount else {
            d.sourceState = .recordMismatch
            return d
        }
        let chunk = EvtxChunk(file: file, index: location.chunk)
        guard let ref = chunk.record(at: location.offset), ref.recordId == detail.row.recordId else {
            d.sourceState = .recordMismatch
            return d
        }
        if d.xml == nil { d.xml = try? chunk.xml(ref) }
        d.raw = Array(chunk.rawBytes(ref))
        d.sourceState = .loaded
        return d
    }

    static func sourceState(for error: EvtxError) -> SourceRecordState {
        if case let .io(_, code) = error {
            switch code {
            case ENOENT, ENOTDIR: return .missingFile
            case EACCES, EPERM: return .noAccess
            default: break
            }
        }
        return .unreadable(error.description)
    }

    /// Source files are re-opened lazily (read-only) to render XML and hex on demand. The file is
    /// opened outside `rowsLock`: a slow open (network share, sleeping disk, a macOS privacy
    /// prompt) must not stall the table, which reads its rows under that lock.
    private func sourceFile(_ id: Int) throws -> EvtxFile {
        guard id >= 0, id < sources.count else { throw EvtxError.io(path: "source #\(id)", errno: ENOENT) }
        if let f = fileLock.withLock({ openFiles[id] }) { return f }
        let f = try EvtxFile(url: URL(fileURLWithPath: sources[id].path))
        return fileLock.withLock {
            if let opened = openFiles[id] { return opened }
            openFiles[id] = f
            return f
        }
    }
}
