import Compression
import EvtxCore
import Foundation

/// A systemd journal file (`/var/log/journal/<machine>/*.journal`), read-only: entries are found by
/// walking the objects in file order, so files left online (not closed cleanly) are read too.
/// Format: https://systemd.io/JOURNAL_FILE_FORMAT/
struct JournalFile {
    struct Entry {
        var offset: Int
        var seqnum: UInt64
        /// Microseconds since 1970 (UTC).
        var realtime: UInt64
        var monotonic: UInt64
        var bootId: String
        var items: [Int]
    }

    enum Compression: String { case xz, lz4, zstd }

    let data: Data
    let incompatible: UInt32
    let state: UInt8
    let headerSize: Int
    let arenaEnd: Int
    let entryCount: UInt64
    let fileId: (UInt64, UInt64)

    var compact: Bool { incompatible & 0x10 != 0 }
    var keyedHash: Bool { incompatible & 0x04 != 0 }

    init?(_ data: Data) {
        guard data.count >= 208, data.prefix(8).elementsEqual("LPKSHHRH".utf8) else { return nil }
        self.data = data
        incompatible = data.le32(12)
        state = data[16]
        headerSize = Int(data.le64(88))
        let arena = Int(clamping: data.le64(96))
        arenaEnd = min(data.count, headerSize &+ arena)
        entryCount = data.le64(152)
        fileId = (data.le64(24), data.le64(32))
        guard headerSize >= 208, headerSize < data.count else { return nil }
    }

    /// Object at `offset`: (type, flags, size) when it lies inside the file.
    func object(at offset: Int) -> (type: UInt8, flags: UInt8, size: Int)? {
        guard offset >= headerSize, offset % 8 == 0, offset + 16 <= arenaEnd else { return nil }
        let size = Int(clamping: data.le64(offset + 8))
        guard size >= 16, offset + size <= arenaEnd else { return nil }
        return (data[offset], data[offset + 1], size)
    }

    /// Entries in file order, starting at the object at `from` (a header-relative walk).
    func forEachEntry(from: Int? = nil, to: Int? = nil, _ body: (Entry) -> Bool) {
        var off = from ?? headerSize
        let end = to ?? arenaEnd
        while off < end, let o = object(at: off) {
            if o.type == 3, o.size >= 64 {   // OBJECT_ENTRY
                var items: [Int] = []
                let itemSize = compact ? 4 : 16
                var i = off + 64
                while i + itemSize <= off + o.size {
                    items.append(compact ? Int(data.le32(i)) : Int(clamping: data.le64(i)))
                    i += itemSize
                }
                let boot = (0..<16).map { String(format: "%02x", data[off + 40 + $0]) }.joined()
                let e = Entry(offset: off, seqnum: data.le64(off + 16), realtime: data.le64(off + 24),
                              monotonic: data.le64(off + 32), bootId: boot, items: items)
                if !body(e) { return }
            }
            off += (o.size + 7) & ~7
        }
    }

    /// Payload (`FIELD=value`) of a DATA object; compressed payloads are unpacked when possible.
    func payload(at offset: Int) -> (bytes: [UInt8]?, compression: Compression?, packedSize: Int)? {
        guard let o = object(at: offset), o.type == 1 else { return nil }   // OBJECT_DATA
        let start = offset + (compact ? 72 : 64)
        guard start <= offset + o.size else { return nil }
        let raw = data[start..<(offset + o.size)]
        if o.flags & 1 != 0 { return (LogBytes.unxz(Data(raw)).map(Array.init), .xz, raw.count) }
        if o.flags & 2 != 0 { return (Self.unlz4(raw), .lz4, raw.count) }
        if o.flags & 4 != 0 { return (Zstd.decompress(Array(raw)), .zstd, raw.count) }
        return (Array(raw), nil, raw.count)
    }

    /// journald's LZ4: the unpacked size (le64) followed by one LZ4 block.
    static func unlz4(_ raw: Data) -> [UInt8]? {
        guard raw.count > 8 else { return nil }
        let size = Int(clamping: raw.le64(raw.startIndex))
        guard size > 0, size < 1 << 30 else { return nil }
        var out = [UInt8](repeating: 0, count: size)
        let n = raw.dropFirst(8).withUnsafeBytes { src in
            out.withUnsafeMutableBytes { dst in
                compression_decode_buffer(dst.bindMemory(to: UInt8.self).baseAddress!, size,
                                          src.bindMemory(to: UInt8.self).baseAddress!, src.count, nil, COMPRESSION_LZ4_RAW)
            }
        }
        return n == size ? out : nil
    }
}

extension Data {
    func le32(_ at: Int) -> UInt32 {
        var v: UInt32 = 0
        Swift.withUnsafeMutableBytes(of: &v) { dst in copyBytes(to: dst.bindMemory(to: UInt8.self), from: (startIndex + at)..<(startIndex + at + 4)) }
        return UInt32(littleEndian: v)
    }

    func le64(_ at: Int) -> UInt64 {
        var v: UInt64 = 0
        Swift.withUnsafeMutableBytes(of: &v) { dst in copyBytes(to: dst.bindMemory(to: UInt8.self), from: (startIndex + at)..<(startIndex + at + 8)) }
        return UInt64(littleEndian: v)
    }
}

/// journald entries → case records.
enum JournalRecords {
    /// `system@…journal` → `journal/system`, `user-1000.journal` → `journal/user-1000`.
    static func channel(_ path: String) -> String {
        var name = (path as NSString).lastPathComponent
        if let at = name.firstIndex(of: "@") { name = String(name[..<at]) }
        for suffix in [".journal~", ".journal"] where name.hasSuffix(suffix) { name = String(name.dropLast(suffix.count)) }
        return "journal/" + name
    }

    static func ticks(_ e: JournalFile.Entry) -> Int64 {
        FileTime.unixEpochTicks + Int64(clamping: e.realtime) * 10
    }

    /// The fields of an entry as `FIELD=value` pairs; `notDecompressed` when a payload stayed packed.
    static func fields(_ f: JournalFile, _ e: JournalFile.Entry) -> (pairs: [(String, String)], notDecompressed: Bool, invalidText: Bool) {
        var pairs: [(String, String)] = []
        var packed = false, invalid = false
        for item in e.items {
            guard let p = f.payload(at: item) else { continue }
            guard let bytes = p.bytes else {
                packed = true
                // The name is not readable either: keep what is known about the value.
                pairs.append(("NotDecompressed", "\(p.compression?.rawValue ?? "?") \(p.packedSize) bytes @\(item)"))
                continue
            }
            let eq = bytes.firstIndex(of: 61) ?? bytes.count   // '='
            let name = String(decoding: bytes[..<eq], as: UTF8.self)
            let (value, bad) = bytes[min(eq + 1, bytes.count)...].withUnsafeBufferPointer { LogLines.decode($0) }
            if bad { invalid = true }
            pairs.append((name, value))
        }
        return (pairs, packed, invalid)
    }

    static func record(_ f: JournalFile, _ e: JournalFile.Entry, plan: LinuxSourcePlan) -> CaseRecord {
        let (pairs, packed, invalid) = fields(f, e)
        let value = { (k: String) in pairs.first { $0.0 == k }?.1 }
        let host = value("_HOSTNAME") ?? plan.host
        var lf = LinuxFields(host: host)
        let message = value("MESSAGE") ?? ""
        lf.add("Message", message)
        let program = value("SYSLOG_IDENTIFIER") ?? value("_COMM") ?? value("_EXE").map { ($0 as NSString).lastPathComponent } ?? "journal"
        var level = SyslogMessages.extract(program: Substring(program), message: Substring(message), into: &lf)
        if let p = value("PRIORITY").flatMap(Int.init), (0...7).contains(p) {
            level = Syslog.level(severity: p)
            lf.add("Severity", Syslog.severities[p])
        }
        let pid = value("_PID").flatMap { UInt32($0) }
        if let pid { lf.add("ProcessId", String(pid)) }
        for (k, v) in pairs where k != "MESSAGE" { lf.add(TextFormats.safeName(k), v) }
        lf.add("Seqnum", String(e.seqnum))
        lf.add("Monotonic", String(e.monotonic))
        lf.add("BootId", e.bootId)
        var flags: RecordFlags = []
        if packed { flags.insert(.notDecompressed) }
        if invalid { flags.insert(.invalidText) }
        let ts = ticks(e)
        var r = CaseRecord(timestamp: ts, writtenTime: ts, recordId: e.seqnum, provider: program, channel: plan.channel,
                           computer: host, flags: flags, fields: lf.list)
        r.level = level
        r.processId = pid
        return r
    }
}
