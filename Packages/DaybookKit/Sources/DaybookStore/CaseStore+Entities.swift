import Foundation

extension CaseSchema.SystemKey {
    /// Filter keys that match every role of an entity (host / user / IP).
    public static let hostEntity = "@HostEntity"
    public static let userEntity = "@UserEntity"
    public static let ipEntity = "@IPEntity"
    /// Bookmarks: value is a colour or "*" for any bookmark.
    public static let tag = "@Tag"

    static func entityKind(_ key: String) -> EntityKind? {
        switch key {
        case hostEntity: .host
        case userEntity: .user
        case ipEntity: .ip
        default: nil
        }
    }
}

extension CaseStore {
    public var hasEntities: Bool {
        (try? rowsLock.withLock { try rowsDB.scalar("SELECT count(*) FROM sqlite_schema WHERE name = 'entity'") }) == 1
    }

    public func entities(_ kind: EntityKind) throws -> [EntityInfo] {
        guard hasEntities else { return [] }
        return try rowsLock.withLock {
            let st = try rowsDB.prepare("""
                SELECT id, key, display, domain, sid, aliases, first_ts, last_ts, events, builtin, roles
                FROM entity WHERE kind = ? ORDER BY events DESC
                """)
            st.bind(1, kind.rawValue)
            var out: [EntityInfo] = []
            while try st.step() {
                let aliases = (try? JSONSerialization.jsonObject(with: Data(st.string(5).utf8))) as? [String] ?? []
                let rolesRaw = (try? JSONSerialization.jsonObject(with: Data(st.string(10).utf8))) as? [String: Int] ?? [:]
                var roles: [Int: Int] = [:]
                for (k, v) in rolesRaw { if let r = Int(k) { roles[r] = v } }
                let domain = st.string(3), sid = st.string(4)
                out.append(EntityInfo(id: Int(st.int64(0)), kind: kind, key: st.string(1), display: st.string(2),
                                      domain: domain.isEmpty ? nil : domain, sid: sid.isEmpty ? nil : sid,
                                      aliases: aliases, firstTs: st.optionalInt64(6), lastTs: st.optionalInt64(7),
                                      events: Int(st.int64(8)), builtin: st.int64(9) != 0, roles: roles))
            }
            return out
        }
    }

    /// Event ids of an entity (all roles, or only the given ones), time-ordered.
    public func entityEvents(_ id: Int, roles: Set<Int>? = nil) throws -> [UInt32] {
        guard hasEntities else { return [] }
        let lists: [[UInt32]] = try queryLock.withLock {
            let st = try queryDB.prepare("SELECT role, n, ids FROM entity_post WHERE entity = ?")
            st.bind(1, id)
            var out: [[UInt32]] = []
            while try st.step() {
                if let roles, !roles.contains(Int(st.int64(0))) { continue }
                let n = Int(st.int64(1))
                out.append(st.withBlob(2) { Varint.decodeDeltas($0, count: n) })
            }
            return out
        }
        return IdSet.union(lists, universe: eventCount)
    }

    public func entityLinks(_ id: Int) throws -> [EntityLink] {
        guard hasEntities else { return [] }
        return try rowsLock.withLock {
            let st = try rowsDB.prepare("""
                SELECT b, n, first_ts, last_ts FROM entity_link WHERE a = ?1
                UNION ALL SELECT a, n, first_ts, last_ts FROM entity_link WHERE b = ?1
                ORDER BY 2 DESC
                """)
            st.bind(1, id)
            var out: [EntityLink] = []
            while try st.step() {
                out.append(EntityLink(other: Int(st.int64(0)), count: Int(st.int64(1)),
                                      firstTs: st.int64(2), lastTs: st.int64(3)))
            }
            return out
        }
    }

    /// Entities matching a user-typed value: host names in any spelling, IPs in any form,
    /// users by `name`, `DOMAIN\name`, `name@domain` or SID.
    public func entityIds(_ kind: EntityKind, matching value: String) throws -> [Int] {
        guard hasEntities else { return [] }
        let v = value.trimmingCharacters(in: .whitespaces)
        var keys: [String] = []
        switch kind {
        case .host: if let k = EntityNames.hostKey(v) { keys = [k] }
        case .ip: if let k = EntityNames.ipKey(v) { keys = [k] }
        case .user:
            if v.hasPrefix("S-1-") { keys = ["sid:" + v] }
        }
        return try rowsLock.withLock {
            var out: [Int] = []
            if !keys.isEmpty {
                let st = try rowsDB.prepare("SELECT id FROM entity WHERE kind = ? AND key = ?")
                for k in keys {
                    st.bind(1, kind.rawValue).bind(2, k)
                    while try st.step() { out.append(Int(st.int64(0))) }
                    st.reset()
                }
                if !out.isEmpty || kind != .user { return out }
            }
            // Users by name: compare against the display name and every alias.
            let split = EntityNames.splitUser(v, domain: nil)
            // Linux account names are case-sensitive, Windows ones are not.
            let exact = platform == .linux
            let wantName = exact ? split?.name ?? v : split?.name.lowercased() ?? v.lowercased()
            let wantDomain = split?.domain
            let st = try rowsDB.prepare("SELECT id, display, aliases FROM entity WHERE kind = ?")
            st.bind(1, kind.rawValue)
            while try st.step() {
                let names = [st.string(1)] + ((try? JSONSerialization.jsonObject(with: Data(st.string(2).utf8))) as? [String] ?? [])
                let hit = names.contains { n in
                    guard let s = EntityNames.splitUser(n, domain: nil) else { return false }
                    return (exact ? s.name : s.name.lowercased()) == wantName && (wantDomain == nil || s.domain == wantDomain)
                }
                if hit { out.append(Int(st.int64(0))) }
            }
            return out
        }
    }

    /// Events of the entities matching `value` (all roles).
    public func entityMatching(_ kind: EntityKind, _ value: String) throws -> [UInt32] {
        IdSet.union(try entityIds(kind, matching: value).map { try entityEvents($0) }, universe: eventCount)
    }
}
