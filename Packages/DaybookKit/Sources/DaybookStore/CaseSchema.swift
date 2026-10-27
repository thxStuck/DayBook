import Foundation

public enum CaseSchema {
    public static let version = 2
    public static let databaseName = "case.sqlite"
    public static let timestampsName = "ts.bin"
    public static let manifestName = "manifest.json"

    /// Kinds stored in `str.kind`.
    public enum StrKind {
        public static let text: Int64 = 0
        public static let binary: Int64 = 1   // hex dumps: not full-text indexed
        public static let name: Int64 = 2     // field names
    }

    /// Virtual field names for System properties; they get posting lists like EventData
    /// fields, so `Channel = "Security"` and `TargetUserName = "x"` share one engine.
    /// The `@` prefix cannot occur in XML element or attribute names.
    public enum SystemKey {
        public static let eventId = "@EventID"
        public static let channel = "@Channel"
        public static let provider = "@Provider"
        public static let computer = "@Computer"
        public static let level = "@Level"
        public static let user = "@UserID"
        public static let source = "@Source"
        public static let task = "@Task"
        public static let opcode = "@Opcode"
        public static let flag = "@Flag"
        /// System/Keywords as Windows renders it (0x8020000000000000 = audit success).
        public static let keywords = "@Keywords"
        public static let all = [eventId, channel, provider, computer, level, user, source, task, opcode, flag, keywords]
    }

    static let create = """
    PRAGMA page_size = 8192;
    CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID;
    CREATE TABLE source(
        id INTEGER PRIMARY KEY, path TEXT NOT NULL, name TEXT NOT NULL, size INTEGER, sha256 TEXT,
        mtime REAL, header_chunks INTEGER, chunks INTEGER, dirty INTEGER, records INTEGER,
        carved INTEGER, duplicates INTEGER, first_ts INTEGER, last_ts INTEGER, error TEXT,
        empty_chunks INTEGER, beyond_new INTEGER, beyond_stale INTEGER, bad_header_crc INTEGER,
        bad_data_crc INTEGER, trailing_bytes INTEGER, version TEXT,
        format TEXT, channel TEXT, host TEXT, parsed INTEGER, skipped INTEGER, note TEXT);
    CREATE TABLE str(id INTEGER PRIMARY KEY, hl INTEGER NOT NULL, num INTEGER, kind INTEGER NOT NULL, s TEXT NOT NULL);
    CREATE TABLE ev(
        id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, wts INTEGER, src INTEGER, chunk INTEGER, off INTEGER,
        rid INTEGER, eid INTEGER, qual INTEGER, ver INTEGER, lvl INTEGER, task INTEGER, opc INTEGER,
        kw INTEGER, prov INTEGER, chan INTEGER, comp INTEGER, usr INTEGER, pid INTEGER, tid INTEGER,
        flags INTEGER, fv BLOB);
    CREATE TABLE post(k INTEGER NOT NULL, v INTEGER NOT NULL, n INTEGER NOT NULL, ids BLOB NOT NULL,
        PRIMARY KEY(k, v)) WITHOUT ROWID;
    CREATE TABLE dup(ev INTEGER NOT NULL, src INTEGER, chunk INTEGER, off INTEGER, flags INTEGER);
    CREATE TABLE xml_cache(ev INTEGER PRIMARY KEY, xml TEXT);
    CREATE TABLE tag(id INTEGER PRIMARY KEY, src_sha TEXT, chunk INTEGER, off INTEGER, ev INTEGER,
        tag TEXT, note TEXT, color TEXT, created REAL);
    CREATE TABLE saved_query(id INTEGER PRIMARY KEY, name TEXT, query TEXT, created REAL);
    """

    static let indexes = """
    CREATE INDEX str_hl ON str(hl);
    CREATE INDEX str_num ON str(num) WHERE num IS NOT NULL;
    CREATE INDEX post_v ON post(v, k);
    CREATE INDEX dup_ev ON dup(ev);
    CREATE INDEX tag_ev ON tag(ev);
    CREATE VIEW str_text AS SELECT id, s FROM str WHERE kind != 1;
    ANALYZE;
    """

    static let fullText = """
    CREATE VIRTUAL TABLE sfts USING fts5(s, content='str_text', content_rowid='id', tokenize='trigram', detail=none);
    INSERT INTO sfts(sfts) VALUES('rebuild');
    """
}

/// Stable string keys used by the case database.
public enum StringKey {
    /// FNV-1a 64 over the lowercased UTF-8 (ASCII fast path). Stable across runs, so it is
    /// stored in `str.hl` for case-insensitive equality lookups (verified against `s`).
    public static func lowerHash(_ s: String) -> Int64 {
        var h: UInt64 = 0xcbf2_9ce4_8422_2325
        var ascii = true
        for b in s.utf8 where b >= 0x80 { ascii = false; break }
        if ascii {
            for var b in s.utf8 {
                if b >= 65 && b <= 90 { b += 32 }
                h = (h ^ UInt64(b)) &* 0x100_0000_01b3
            }
        } else {
            for b in s.lowercased().utf8 { h = (h ^ UInt64(b)) &* 0x100_0000_01b3 }
        }
        return Int64(bitPattern: h)
    }

    /// Integer value of decimal ("-12") or hex ("0x1F") text, for numeric comparisons.
    public static func number(_ s: String) -> Int64? {
        let u = s.utf8
        guard !u.isEmpty, u.count <= 20 else { return nil }
        if u.count > 2, s.hasPrefix("0x") || s.hasPrefix("0X") {
            return UInt64(s.dropFirst(2), radix: 16).map { Int64(bitPattern: $0) }
        }
        guard let first = u.first, first == UInt8(ascii: "-") || (first >= 48 && first <= 57) else { return nil }
        return Int64(s)
    }
}

/// Assigns dense ids to strings during import (single writer thread). Long strings are
/// keyed by a 128-bit digest so that megabyte script blocks are not kept in memory.
final class Interner {
    private struct Digest: Hashable { let a: Int; let b: Int }
    private var small: [String: UInt32] = [:]
    private var large: [Digest: UInt32] = [:]
    private(set) var count: UInt32 = 0
    private let insert: Statement

    init(db: SQLiteDB) throws {
        insert = try db.prepare("INSERT INTO str(id, hl, num, kind, s) VALUES (?, ?, ?, ?, ?)", persistent: true)
    }

    func id(_ s: String, kind: Int64 = CaseSchema.StrKind.text) throws -> UInt32 {
        if s.utf8.count <= 96 {
            if let id = small[s] { return id }
            let id = try add(s, kind)
            small[s] = id
            return id
        }
        var h1 = Hasher(), h2 = Hasher()
        h1.combine(1 as UInt8); h1.combine(s)
        h2.combine(2 as UInt8); h2.combine(s)
        let d = Digest(a: h1.finalize(), b: h2.finalize())
        if let id = large[d] { return id }
        let id = try add(s, kind)
        large[d] = id
        return id
    }

    private func add(_ s: String, _ kind: Int64) throws -> UInt32 {
        let id = count
        count += 1
        try insert.bind(1, Int64(id)).bind(2, StringKey.lowerHash(s)).bind(3, StringKey.number(s))
            .bind(4, kind).bind(5, s).run()
        return id
    }
}
