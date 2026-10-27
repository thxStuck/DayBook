import Foundation
import SQLite3

public struct SQLiteError: Error, CustomStringConvertible, Sendable {
    public let code: Int32
    public let message: String
    public var description: String { "SQLite error \(code): \(message)" }
    public var isInterrupt: Bool { code == SQLITE_INTERRUPT }
}

private let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

/// Thin wrapper over one SQLite connection. The system library is built with
/// THREADSAFE=2: a connection must only be used by one thread at a time, so every
/// connection has a single owner (an actor or a dedicated queue).
public final class SQLiteDB: @unchecked Sendable {
    let handle: OpaquePointer

    /// `readOnly` connections are opened read-write with `PRAGMA query_only = 1`: a WAL
    /// database needs its `-shm` file, which a SQLITE_OPEN_READONLY connection cannot
    /// create. If the case sits on read-only media, it is opened as immutable instead.
    public init(path: String, readOnly: Bool = false, create: Bool = false) throws {
        var flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX
        if create { flags |= SQLITE_OPEN_CREATE }
        var db = try Self.open(path, flags)
        if db == nil, readOnly {
            let uri = "file:" + (path.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? path) + "?mode=ro&immutable=1"
            db = try Self.open(uri, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI | SQLITE_OPEN_NOMUTEX, last: true)
        } else if db == nil {
            db = try Self.open(path, flags, last: true)
        }
        handle = db!
        sqlite3_extended_result_codes(handle, 1)
        if readOnly { try exec("PRAGMA query_only = 1") }
    }

    private static func open(_ path: String, _ flags: Int32, last: Bool = false) throws -> OpaquePointer? {
        var db: OpaquePointer?
        let rc = sqlite3_open_v2(path, &db, flags, nil)
        if rc == SQLITE_OK, let db { return db }
        let msg = db.map { String(cString: sqlite3_errmsg($0)) } ?? "open failed"
        if let db { sqlite3_close_v2(db) }
        if last { throw SQLiteError(code: rc, message: "\(msg) (\(path))") }
        return nil
    }

    deinit { sqlite3_close_v2(handle) }

    func error(_ rc: Int32) -> SQLiteError {
        SQLiteError(code: rc, message: String(cString: sqlite3_errmsg(handle)))
    }

    public func exec(_ sql: String) throws {
        var err: UnsafeMutablePointer<CChar>?
        let rc = sqlite3_exec(handle, sql, nil, nil, &err)
        if rc != SQLITE_OK {
            let msg = err.map { String(cString: $0) } ?? "exec failed"
            sqlite3_free(err)
            throw SQLiteError(code: rc, message: msg)
        }
    }

    public func prepare(_ sql: String, persistent: Bool = false) throws -> Statement {
        var stmt: OpaquePointer?
        let flags = persistent ? UInt32(SQLITE_PREPARE_PERSISTENT) : 0
        let rc = sqlite3_prepare_v3(handle, sql, -1, flags, &stmt, nil)
        guard rc == SQLITE_OK, let stmt else { throw error(rc) }
        return Statement(db: self, stmt: stmt)
    }

    /// Aborts the statement currently running on this connection (safe from any thread).
    public func interrupt() { sqlite3_interrupt(handle) }

    public var lastInsertRowID: Int64 { sqlite3_last_insert_rowid(handle) }

    public func transaction<T>(_ body: () throws -> T) throws -> T {
        try exec("BEGIN")
        do {
            let r = try body()
            try exec("COMMIT")
            return r
        } catch {
            try? exec("ROLLBACK")
            throw error
        }
    }

    /// Convenience: first column of the first row as Int64.
    public func scalar(_ sql: String) throws -> Int64? {
        let s = try prepare(sql)
        return try s.step() ? s.int64(0) : nil
    }
}

public final class Statement {
    let db: SQLiteDB
    let stmt: OpaquePointer

    init(db: SQLiteDB, stmt: OpaquePointer) {
        self.db = db
        self.stmt = stmt
    }

    deinit { sqlite3_finalize(stmt) }

    @discardableResult
    public func bind(_ i: Int32, _ v: Int64) -> Statement { sqlite3_bind_int64(stmt, i, v); return self }
    @discardableResult
    public func bind(_ i: Int32, _ v: Int) -> Statement { sqlite3_bind_int64(stmt, i, Int64(v)); return self }
    @discardableResult
    public func bind(_ i: Int32, _ v: String) -> Statement {
        sqlite3_bind_text(stmt, i, v, -1, SQLITE_TRANSIENT); return self
    }
    @discardableResult
    public func bind(_ i: Int32, _ v: Int64?) -> Statement {
        if let v { sqlite3_bind_int64(stmt, i, v) } else { sqlite3_bind_null(stmt, i) }
        return self
    }
    @discardableResult
    public func bind(_ i: Int32, _ v: Int?) -> Statement { bind(i, v.map { Int64($0) }) }
    @discardableResult
    public func bind(_ i: Int32, blob: [UInt8]) -> Statement {
        blob.withUnsafeBytes { p in
            _ = sqlite3_bind_blob(stmt, i, p.baseAddress ?? UnsafeRawPointer(bitPattern: 1), Int32(p.count), SQLITE_TRANSIENT)
        }
        return self
    }
    @discardableResult
    public func bind(_ i: Int32, _ v: String?) -> Statement {
        if let v { sqlite3_bind_text(stmt, i, v, -1, SQLITE_TRANSIENT) } else { sqlite3_bind_null(stmt, i) }
        return self
    }
    @discardableResult
    public func bind(_ i: Int32, _ v: Double) -> Statement { sqlite3_bind_double(stmt, i, v); return self }
    @discardableResult
    public func bindNull(_ i: Int32) -> Statement { sqlite3_bind_null(stmt, i); return self }

    /// Returns true when a row is available.
    public func step() throws -> Bool {
        let rc = sqlite3_step(stmt)
        switch rc {
        case SQLITE_ROW: return true
        case SQLITE_DONE: return false
        default: throw db.error(rc)
        }
    }

    /// Runs to completion and resets (for INSERT/UPDATE).
    public func run() throws {
        defer { reset() }
        while try step() {}
    }

    public func reset() {
        sqlite3_reset(stmt)
        sqlite3_clear_bindings(stmt)
    }

    public func isNull(_ c: Int32) -> Bool { sqlite3_column_type(stmt, c) == SQLITE_NULL }
    public func int64(_ c: Int32) -> Int64 { sqlite3_column_int64(stmt, c) }
    public func optionalInt64(_ c: Int32) -> Int64? { isNull(c) ? nil : int64(c) }
    public func double(_ c: Int32) -> Double { sqlite3_column_double(stmt, c) }
    public func optionalString(_ c: Int32) -> String? { isNull(c) ? nil : string(c) }
    public func string(_ c: Int32) -> String {
        guard let p = sqlite3_column_text(stmt, c) else { return "" }
        return String(cString: p)
    }
    public func blob(_ c: Int32) -> [UInt8] {
        let n = Int(sqlite3_column_bytes(stmt, c))
        guard n > 0, let p = sqlite3_column_blob(stmt, c) else { return [] }
        return Array(UnsafeRawBufferPointer(start: p, count: n))
    }
    /// Zero-copy access to a blob column (valid only inside `body`).
    public func withBlob<T>(_ c: Int32, _ body: (UnsafeRawBufferPointer) -> T) -> T {
        let n = Int(sqlite3_column_bytes(stmt, c))
        return body(UnsafeRawBufferPointer(start: sqlite3_column_blob(stmt, c), count: n))
    }
}
