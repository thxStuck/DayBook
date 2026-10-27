import Foundation

/// Builds the host / user / IP registry of a case from its events. Works on dictionary
/// value ids during the event pass and resolves strings once per distinct value, so it
/// costs one sequential read of the `ev` table.
public final class EntityBuilder {
    public let caseURL: URL

    public init(caseURL: URL) { self.caseURL = caseURL }

    struct UserRule { let name: String; let domain: String?; let sid: String?; let role: EntityRole }

    static let userRules: [UserRule] = [
        UserRule(name: "TargetUserName", domain: "TargetDomainName", sid: "TargetUserSid", role: .target),
        UserRule(name: "SubjectUserName", domain: "SubjectDomainName", sid: "SubjectUserSid", role: .subject),
        UserRule(name: "TargetOutboundUserName", domain: "TargetOutboundDomainName", sid: nil, role: .target),
        UserRule(name: "AccountName", domain: "AccountDomain", sid: nil, role: .target),
        UserRule(name: "User", domain: nil, sid: nil, role: .subject),        // Sysmon, LSM: DOMAIN\user
        UserRule(name: "ParentUser", domain: nil, sid: nil, role: .subject),
    ]
    static let hostRules: [(String, EntityRole)] = [
        ("WorkstationName", .source), ("Workstation", .source), ("ClientName", .source),
        ("SourceHostname", .source), ("DestinationHostname", .destination), ("TargetServerName", .destination),
    ]
    static let ipRules: [(String, EntityRole)] = [
        ("IpAddress", .source), ("ClientAddress", .source), ("SourceIp", .source), ("SourceAddress", .source),
        ("Address", .source), ("ClientIP", .source), ("DestinationIp", .destination), ("DestAddress", .destination),
    ]
    static let rcmChannel = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"

    private static let none = UInt32.max

    private struct UserOcc { var name: UInt32; var domain: UInt32; var sid: UInt32; var role: UInt8; var ev: UInt32 }
    private struct SimpleOcc { var value: UInt32; var role: UInt8; var ev: UInt32 }

    @discardableResult
    public func run(progress: @Sendable (Double) -> Void = { _ in }) throws -> (hosts: Int, users: Int, ips: Int) {
        let store = try CaseStore(url: caseURL)
        let reader = try SQLiteDB(path: caseURL.appendingPathComponent(CaseSchema.databaseName).path, readOnly: true)

        // Field ids of interest (exact names).
        var userKeys: [UInt32: (rule: Int, part: Int)] = [:]   // part: 0 name, 1 domain, 2 sid
        for (i, r) in Self.userRules.enumerated() {
            if let k = store.exactKeyId(r.name) { userKeys[k] = (i, 0) }
            if let d = r.domain, let k = store.exactKeyId(d) { userKeys[k] = (i, 1) }
            if let s = r.sid, let k = store.exactKeyId(s) { userKeys[k] = (i, 2) }
        }
        var hostKeys: [UInt32: EntityRole] = [:]
        for (n, role) in Self.hostRules { if let k = store.exactKeyId(n) { hostKeys[k] = role } }
        var ipKeys: [UInt32: EntityRole] = [:]
        for (n, role) in Self.ipRules { if let k = store.exactKeyId(n) { ipKeys[k] = role } }
        let param1 = store.exactKeyId("Param1"), param2 = store.exactKeyId("Param2"), param3 = store.exactKeyId("Param3")
        let dataKey = store.exactKeyId("Data")
        let rcm = Set(try store.valueIds(Self.rcmChannel, exact: true))
        let eventLogProvider = Set(try store.valueIds("EventLog", exact: true))

        var users: [UserOcc] = []
        var hosts: [SimpleOcc] = []
        var ips: [SimpleOcc] = []
        var renames: [(old: UInt32, new: UInt32)] = []

        let total = store.eventCount
        let batch = 50_000
        let st = try reader.prepare("SELECT id, comp, usr, eid, prov, chan, fv FROM ev WHERE id >= ? AND id < ?")
        for start in stride(from: 0, to: total, by: batch) {
            st.bind(1, start).bind(2, start + batch)
            while try st.step() {
                let ev = UInt32(st.int64(0))
                hosts.append(SimpleOcc(value: UInt32(st.int64(1)), role: UInt8(EntityRole.logging.rawValue), ev: ev))
                if let usr = st.optionalInt64(2) {
                    users.append(UserOcc(name: Self.none, domain: Self.none, sid: UInt32(usr), role: UInt8(EntityRole.system.rawValue), ev: ev))
                }
                let eid = st.int64(3), prov = UInt32(st.int64(4)), chan = UInt32(st.int64(5))
                let pairs = st.withBlob(6) { Varint.decodeAll($0) }
                var parts = [UserOcc](repeating: UserOcc(name: Self.none, domain: Self.none, sid: Self.none, role: 0, ev: ev),
                                      count: Self.userRules.count)
                var data: [UInt32] = []
                var p1 = Self.none, p2 = Self.none, p3 = Self.none
                var i = 0
                while i + 1 < pairs.count {
                    let k = pairs[i], v = pairs[i + 1]
                    i += 2
                    if let u = userKeys[k] {
                        switch u.part {
                        case 0: parts[u.rule].name = v
                        case 1: parts[u.rule].domain = v
                        default: parts[u.rule].sid = v
                        }
                    }
                    if let role = hostKeys[k] { hosts.append(SimpleOcc(value: v, role: UInt8(role.rawValue), ev: ev)) }
                    if let role = ipKeys[k] { ips.append(SimpleOcc(value: v, role: UInt8(role.rawValue), ev: ev)) }
                    if k == param1 { p1 = v } else if k == param2 { p2 = v } else if k == param3 { p3 = v }
                    if k == dataKey { data.append(v) }
                }
                for (r, var o) in parts.enumerated() where o.name != Self.none || o.sid != Self.none {
                    o.role = UInt8(Self.userRules[r].role.rawValue)
                    users.append(o)
                }
                if eid == 1149, rcm.contains(chan) {
                    if p1 != Self.none { users.append(UserOcc(name: p1, domain: p2, sid: Self.none, role: UInt8(EntityRole.target.rawValue), ev: ev)) }
                    if p3 != Self.none { ips.append(SimpleOcc(value: p3, role: UInt8(EntityRole.source.rawValue), ev: ev)) }
                }
                if eid == 6011, eventLogProvider.contains(prov), data.count >= 2 { renames.append((data[0], data[1])) }
            }
            st.reset()
            progress(Double(min(start + batch, total)) / Double(max(total, 1)) * 0.7)
        }

        // Resolve every distinct value once.
        var need = Set<UInt32>()
        for u in users { for v in [u.name, u.domain, u.sid] where v != Self.none { need.insert(v) } }
        for h in hosts { need.insert(h.value) }
        for x in ips { need.insert(x.value) }
        for r in renames { need.insert(r.old); need.insert(r.new) }
        let needList = Array(need)
        let str = Dictionary(uniqueKeysWithValues: zip(needList, try store.strings(needList)))
        func s(_ v: UInt32) -> String? { v == Self.none ? nil : str[v] }

        // Entity registry being built.
        var ids: [String: Int] = [:]                 // "kind|key" → index
        var kinds: [EntityKind] = [], keys: [String] = []
        var spellings: [[String: Int]] = [], domains: [String?] = [], sids: [String?] = [], builtin: [Bool] = []
        var postings: [[Int: [UInt32]]] = []
        func entity(_ kind: EntityKind, _ key: String) -> Int {
            let k = "\(kind.rawValue)|\(key)"
            if let i = ids[k] { return i }
            let i = kinds.count
            ids[k] = i
            kinds.append(kind); keys.append(key); spellings.append([:]); domains.append(nil); sids.append(nil)
            builtin.append(false); postings.append([:])
            return i
        }
        var perEvent: [(ev: UInt32, entity: Int)] = []
        func occur(_ e: Int, _ role: UInt8, _ ev: UInt32, spelling: String?) {
            postings[e][Int(role), default: []].append(ev)
            if let spelling { spellings[e][spelling, default: 0] += 1 }
            perEvent.append((ev, e))
        }

        // Hosts (with renames from EventLog 6011 merged into the new name).
        var renameTo: [String: String] = [:]
        for r in renames {
            if let o = s(r.old).flatMap(EntityNames.hostKey), let n = s(r.new).flatMap(EntityNames.hostKey), o != n { renameTo[o] = n }
        }
        func finalHost(_ key: String) -> String {
            var k = key
            var guardCount = 0
            while let n = renameTo[k], guardCount < 16 { k = n; guardCount += 1 }
            return k
        }
        for h in hosts {
            guard let raw = s(h.value), let key = EntityNames.hostKey(raw) else { continue }
            let e = entity(.host, finalHost(key))
            occur(e, h.role, h.ev, spelling: raw)
        }
        for (old, new) in renameTo {
            let e = entity(.host, finalHost(new))
            spellings[e][old + " (" + String(localized: "прежнее имя") + ")", default: 0] += 0
        }

        // IPs.
        for x in ips {
            guard let raw = s(x.value), let key = EntityNames.ipKey(raw) else { continue }
            occur(entity(.ip, key), x.role, x.ev, spelling: key)
        }

        // Users: learn SID ↔ name pairs first, then key every occurrence.
        var sidNames: [String: [String: Int]] = [:]         // SID → "DOMAIN\name" votes
        var nameSids: [String: Set<String>] = [:]           // lower(name) → SIDs
        var parsed: [(name: String?, domain: String?, sid: String?)] = []
        parsed.reserveCapacity(users.count)
        for u in users {
            var sid = s(u.sid).flatMap { EntityNames.isValidSID($0) ? $0 : nil }
            var name: String?, dom: String?
            if let raw = s(u.name), let split = EntityNames.splitUser(raw, domain: s(u.domain)) {
                name = split.name
                dom = split.domain
            }
            // Some events put a SID (or "%{S-1-…}") where a name is expected.
            if let n = name {
                let bare = n.hasPrefix("%{") && n.hasSuffix("}") ? String(n.dropFirst(2).dropLast()) : n
                if EntityNames.isValidSID(bare) { if sid == nil { sid = bare }; name = nil; dom = nil }
            }
            parsed.append((name, dom, sid))
            if let sid, let name, !name.hasSuffix("$") {
                sidNames[sid, default: [:]][(dom.map { $0 + "\\" } ?? "") + name, default: 0] += 1
                nameSids[name.lowercased(), default: []].insert(sid)
            }
        }
        // Phase 1: key every occurrence. Phase 2: fold "name:?\x" (no domain) into the
        // only domain-qualified "name:D\x" of the same name, if there is exactly one.
        var userKeyOf = [String?](repeating: nil, count: users.count)
        var qualified: [String: Set<String>] = [:]   // lower(name) → keys with a domain
        for (i, (u, p)) in zip(users, parsed).enumerated() {
            if let name = p.name, name.hasSuffix("$") {
                // Machine account → host entity.
                if let key = EntityNames.hostKey(name) {
                    occur(entity(.host, finalHost(key)), UInt8(EntityRole.account.rawValue), u.ev, spelling: nil)
                }
                continue
            }
            if let sid = p.sid {
                userKeyOf[i] = "sid:" + sid
            } else if let name = p.name {
                let candidates = nameSids[name.lowercased()] ?? []
                if candidates.count == 1, let only = candidates.first {
                    userKeyOf[i] = "sid:" + only
                } else {
                    let key = "name:" + (p.domain ?? "?") + "\\" + name.lowercased()
                    userKeyOf[i] = key
                    if p.domain != nil { qualified[name.lowercased(), default: []].insert(key) }
                }
            }
        }
        for i in userKeyOf.indices {
            guard let key = userKeyOf[i], key.hasPrefix("name:?\\") else { continue }
            let name = String(key.dropFirst("name:?\\".count))
            if let q = qualified[name], q.count == 1, let only = q.first { userKeyOf[i] = only }
        }
        for (i, (u, p)) in zip(users, parsed).enumerated() {
            guard let key = userKeyOf[i] else { continue }
            let e = entity(.user, key)
            if let sid = p.sid { sids[e] = sid }
            if let d = p.domain, domains[e] == nil { domains[e] = d }
            occur(e, u.role, u.ev, spelling: p.name.map { (p.domain.map { $0 + "\\" } ?? "") + $0 })
            if EntityNames.isBuiltin(name: p.name, domain: p.domain, sid: p.sid ?? sids[e]) { builtin[e] = true }
        }
        progress(0.85)

        // Write.
        let db = try SQLiteDB(path: caseURL.appendingPathComponent(CaseSchema.databaseName).path)
        try db.exec("PRAGMA busy_timeout = 10000")
        try db.transaction {
            try db.exec("""
                DROP TABLE IF EXISTS entity; DROP TABLE IF EXISTS entity_post; DROP TABLE IF EXISTS entity_link;
                CREATE TABLE entity(id INTEGER PRIMARY KEY, kind INTEGER, key TEXT, display TEXT, domain TEXT, sid TEXT,
                    aliases TEXT, first_ts INTEGER, last_ts INTEGER, events INTEGER, builtin INTEGER, roles TEXT);
                CREATE TABLE entity_post(entity INTEGER, role INTEGER, n INTEGER, ids BLOB, PRIMARY KEY(entity, role)) WITHOUT ROWID;
                CREATE TABLE entity_link(a INTEGER, b INTEGER, n INTEGER, first_ts INTEGER, last_ts INTEGER, PRIMARY KEY(a, b)) WITHOUT ROWID;
                CREATE INDEX entity_kind ON entity(kind, key);
                """)
            let insE = try db.prepare("INSERT INTO entity VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")
            let insP = try db.prepare("INSERT INTO entity_post VALUES (?,?,?,?)")
            for e in 0..<kinds.count {
                var all: [UInt32] = []
                var roles: [String: Int] = [:]
                for (role, list) in postings[e] {
                    let sorted = Array(Set(list)).sorted()
                    roles[String(role)] = sorted.count
                    all += sorted
                    try insP.bind(1, e).bind(2, role).bind(3, sorted.count).bind(4, blob: Varint.encodeDeltas(sorted)).run()
                }
                let unique = Array(Set(all)).sorted()
                guard let first = unique.first, let last = unique.last else { continue }
                var display = spellings[e].max { $0.value != $1.value ? $0.value < $1.value : $0.key > $1.key }?.key ?? keys[e]
                if kinds[e] == .user, let sid = sids[e] ?? (keys[e].hasPrefix("sid:") ? String(keys[e].dropFirst(4)) : nil) {
                    sids[e] = sid
                    if let best = sidNames[sid]?.max(by: { $0.value < $1.value })?.key { display = best }
                    else if display == keys[e] { display = sid }
                    if EntityNames.isBuiltin(name: nil, domain: nil, sid: sid) { builtin[e] = true }
                }
                let aliases = spellings[e].keys.filter { $0 != display }.sorted()
                let aliasJSON = String(data: try JSONSerialization.data(withJSONObject: aliases), encoding: .utf8) ?? "[]"
                let roleJSON = String(data: try JSONSerialization.data(withJSONObject: roles, options: .sortedKeys), encoding: .utf8) ?? "{}"
                try insE.bind(1, e).bind(2, kinds[e].rawValue).bind(3, keys[e]).bind(4, display)
                    .bind(5, domains[e].map { $0 } ?? "").bind(6, sids[e] ?? "").bind(7, aliasJSON)
                    .bind(8, store.timestamp(first)).bind(9, store.timestamp(last)).bind(10, unique.count)
                    .bind(11, builtin[e] ? 1 : 0).bind(12, roleJSON).run()
            }
            // Links: entities of different kinds seen in the same event.
            perEvent.sort { $0.ev != $1.ev ? $0.ev < $1.ev : $0.entity < $1.entity }
            var links: [UInt64: (n: Int, first: UInt32, last: UInt32)] = [:]
            var i = 0
            while i < perEvent.count {
                var j = i
                while j < perEvent.count && perEvent[j].ev == perEvent[i].ev { j += 1 }
                let ev = perEvent[i].ev
                let es = Array(Set(perEvent[i..<j].map(\.entity))).sorted()
                if es.count > 1 && es.count <= 12 {
                    for a in 0..<es.count {
                        for b in (a + 1)..<es.count where kinds[es[a]] != kinds[es[b]] || kinds[es[a]] == .host {
                            let key = UInt64(es[a]) << 32 | UInt64(es[b])
                            var l = links[key] ?? (0, ev, ev)
                            l.n += 1
                            l.first = min(l.first, ev)
                            l.last = max(l.last, ev)
                            links[key] = l
                        }
                    }
                }
                i = j
            }
            let insL = try db.prepare("INSERT INTO entity_link VALUES (?,?,?,?,?)")
            for (key, l) in links {
                try insL.bind(1, Int64(key >> 32)).bind(2, Int64(key & 0xFFFF_FFFF)).bind(3, l.n)
                    .bind(4, store.timestamp(l.first)).bind(5, store.timestamp(l.last)).run()
            }
        }
        progress(1)
        return (kinds.filter { $0 == .host }.count, kinds.filter { $0 == .user }.count, kinds.filter { $0 == .ip }.count)
    }
}
