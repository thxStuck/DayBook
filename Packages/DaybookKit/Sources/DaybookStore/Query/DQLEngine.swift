import EvtxCore
import Foundation

public struct DQLGroupRow: Sendable, Hashable {
    public let values: [String]
    public let count: Int
}

public struct DQLResult: Sendable {
    /// Matching events; time-ordered unless `customOrder` (a `sort` by a field).
    public var events: ResultSet
    /// Matching events before `sort` / `limit` (always time-ordered; for the histogram).
    public var filtered: ResultSet
    public var customOrder = false
    public var descending = false
    /// The query has an explicit `sort time` stage (otherwise the viewer keeps its order).
    public var timeSort = false
    /// Canonical keys of `group by` fields (nil when the query does not group).
    public var groupKeys: [String]?
    public var groups: [DQLGroupRow] = []
    public var groupsTruncated = false
    /// Canonical keys requested by `select`.
    public var select: [String]?
    public var elapsedMs = 0.0

    public init(events: ResultSet, filtered: ResultSet? = nil) {
        self.events = events
        self.filtered = filtered ?? events
    }
}

/// Executes DQL against a case using posting lists and the value dictionary.
public final class DQLEngine: @unchecked Sendable {
    public let store: CaseStore
    /// Parses a time literal in the user's display zone into FILETIME.
    public let parseTime: @Sendable (String) -> Int64?
    public var isCancelled: @Sendable () -> Bool = { false }
    public static let maxGroups = 20_000

    public init(store: CaseStore, parseTime: @escaping @Sendable (String) -> Int64?) {
        self.store = store
        self.parseTime = parseTime
    }

    public func run(_ text: String, base: ResultSet? = nil) throws -> DQLResult {
        try run(DQLParser.parse(text), base: base)
    }

    public func run(_ q: DQLQuery, base: ResultSet? = nil) throws -> DQLResult {
        let t0 = Date()
        var events = base ?? universe
        if let f = q.filter {
            switch try eval(f) {
            case let .pos(r): events = intersect(events, r)
            case let .neg(r): events = events.subtract(r.list)
            }
        }
        var result = DQLResult(events: events, filtered: events)
        if let sel = q.select { result.select = try sel.map { try canonical($0) } }

        if let g = q.groupBy {
            result.groupKeys = try g.map { try canonical($0) }
            (result.groups, result.groupsTruncated) = try group(events, fields: g, sort: q.sort)
            if let limit = q.limit { result.groups = Array(result.groups.prefix(limit)) }
        } else {
            if let s = q.sort.first {
                if case .time = try resolve(s.field) {
                    result.descending = s.descending
                    result.timeSort = true
                } else {
                    result.events = ResultSet(list: try sortBy(events, field: s.field, descending: s.descending))
                    result.customOrder = true
                }
            }
            if let limit = q.limit, limit < result.events.count {
                if result.customOrder || !result.descending {
                    result.events = ResultSet(list: result.events.ids(0..<limit))
                } else {
                    let n = result.events.count
                    result.events = ResultSet(list: result.events.ids((n - limit)..<n))
                }
            }
        }
        result.elapsedMs = Date().timeIntervalSince(t0) * 1000
        return result
    }

    // MARK: Fields

    enum FieldRef { case time; case key(UInt32, String); case entity(EntityKind, String); case tag; case rule; case ruleLevel }

    static let entityAliases: [String: (EntityKind, String)] = [
        "anyhost": (.host, CaseSchema.SystemKey.hostEntity), "@hostentity": (.host, CaseSchema.SystemKey.hostEntity),
        "anyuser": (.user, CaseSchema.SystemKey.userEntity), "@userentity": (.user, CaseSchema.SystemKey.userEntity),
        "anyip": (.ip, CaseSchema.SystemKey.ipEntity), "@ipentity": (.ip, CaseSchema.SystemKey.ipEntity),
    ]

    static let aliases: [String: String] = [
        "host": CaseSchema.SystemKey.computer, "computer": CaseSchema.SystemKey.computer,
        "channel": CaseSchema.SystemKey.channel, "log": CaseSchema.SystemKey.channel,
        "provider": CaseSchema.SystemKey.provider,
        "eventid": CaseSchema.SystemKey.eventId, "id": CaseSchema.SystemKey.eventId, "event_id": CaseSchema.SystemKey.eventId,
        "level": CaseSchema.SystemKey.level,
        "user": CaseSchema.SystemKey.user, "userid": CaseSchema.SystemKey.user, "sid": CaseSchema.SystemKey.user,
        "file": CaseSchema.SystemKey.source, "source": CaseSchema.SystemKey.source,
        "flag": CaseSchema.SystemKey.flag, "flags": CaseSchema.SystemKey.flag,
        "provider_name": CaseSchema.SystemKey.provider, "eventrecordid": "@RecordID",
        "task": CaseSchema.SystemKey.task, "opcode": CaseSchema.SystemKey.opcode,
        "keywords": CaseSchema.SystemKey.keywords,
    ]

    private var universe: ResultSet { ResultSet(range: 0..<UInt32(store.eventCount)) }
    /// Key id of a known field that no event of the case has.
    static let absentKey = UInt32.max

    func resolve(_ field: String) throws -> FieldRef {
        let lower = field.lowercased()
        if ["time", "timestamp", "timecreated", "@time"].contains(lower) { return .time }
        if let (kind, name) = Self.entityAliases[lower] { return .entity(kind, name) }
        if ["tag", "bookmark", "@tag"].contains(lower) { return .tag }
        if lower == "@rule" { return .rule }
        if lower == "@rulelevel" { return .ruleLevel }
        // A real field with exactly this name wins over an alias (Sysmon's "User" is not
        // the System UserID alias "user").
        if let k = store.exactKeyId(field) { return .key(k, field) }
        if lower == "rule" { return .rule }
        if lower == "rulelevel" { return .ruleLevel }
        if let alias = Self.aliases[lower], let k = store.keyId(alias) { return .key(k, alias) }
        if let k = store.keyId(field) { return .key(k, store.keyName(k)) }
        // Known names without any event in this case match nothing (no posting has this key):
        // system keys (no flagged record, …) and the fields of the Linux parsers.
        if let alias = Self.aliases[lower], CaseSchema.SystemKey.all.contains(alias) { return .key(Self.absentKey, alias) }
        if store.platform == .linux, let name = LinuxVocabulary.field(lower) { return .key(Self.absentKey, name) }
        let suggestions = store.fieldNames.filter { $0.lowercased().contains(lower) }.prefix(5)
        var msg = String(localized: "Неизвестное поле «\(field)»")
        if !suggestions.isEmpty { msg += ". " + String(localized: "Похожие: ") + suggestions.joined(separator: ", ") }
        throw DQLError(message: msg, position: -1)
    }

    /// Canonical key for a field name (system aliases become `@…`, "time" stays "time").
    public func canonical(_ field: String) throws -> String {
        switch try resolve(field) {
        case .time: "time"
        case let .key(_, name): name
        case let .entity(_, name): name
        case .tag: CaseSchema.SystemKey.tag
        case .rule: "@Rule"
        case .ruleLevel: "@RuleLevel"
        }
    }

    private func key(_ field: String) throws -> UInt32 {
        switch try resolve(field) {
        case let .key(k, _): return k
        case .entity: throw DQLError(message: String(localized: "Для anyhost/anyuser/anyip поддерживаются =, !=, in"), position: -1)
        case .tag: throw DQLError(message: String(localized: "Для tag поддерживаются =, !=, in, exists"), position: -1)
        case .time: throw DQLError(message: String(localized: "Для поля time используйте <, >, between"), position: -1)
        case .rule: throw DQLError(message: String(localized: "Для rule поддерживаются =, !=, in, contains, exists (по id или названию правила)"), position: -1)
        case .ruleLevel: throw DQLError(message: String(localized: "Для rulelevel поддерживаются =, !=, in, <, <=, >, >="), position: -1)
        }
    }

    /// Events matched by stored detection rules whose id/title (or level) matches.
    private func ruleSet(_ field: FieldRef, op: String, _ value: String) throws -> ResultSet {
        guard store.hasDetections() else {
            throw DQLError(message: String(localized: "Детекты для этого кейса ещё не запускались"), position: -1)
        }
        let ids: [Int64]
        if case .ruleLevel = field {
            ids = try store.detectionRuleIds(level: op, value)
        } else if op == "contains" {
            ids = try store.cachedDetectionRules().filter { $0.title.range(of: value, options: .caseInsensitive) != nil }.map(\.id)
        } else {
            ids = try store.detectionRuleIds(matching: value)
        }
        return ResultSet(list: try store.detectionHits(ids))
    }

    private func entitySet(_ kind: EntityKind, _ values: [String]) throws -> ResultSet {
        ResultSet(list: IdSet.union(try values.map { try store.entityMatching(kind, $0) }, universe: store.eventCount))
    }

    // MARK: Evaluation

    private enum SetVal {
        case pos(ResultSet)
        case neg(ResultSet)   // complement of the set
    }

    func checkCancel() throws {
        if isCancelled() { throw CancellationError() }
    }

    private func eval(_ e: DQLExpr) throws -> SetVal {
        try checkCancel()
        switch e {
        case let .and(items):
            var pos: ResultSet?
            var negs: [ResultSet] = []
            for item in items {
                switch try eval(item) {
                case let .pos(r):
                    pos = pos.map { intersect($0, r) } ?? r
                    if pos?.isEmpty == true { return .pos(.empty) }
                case let .neg(r):
                    negs.append(r)
                }
            }
            if var p = pos {
                for n in negs { p = p.subtract(n.list) }
                return .pos(p)
            }
            return .neg(union(negs))
        case let .or(items):
            var pos: [ResultSet] = []
            var negs: [ResultSet] = []
            for item in items {
                switch try eval(item) {
                case let .pos(r): pos.append(r)
                case let .neg(r): negs.append(r)
                }
            }
            if negs.isEmpty { return .pos(union(pos)) }
            // (A ∪ ¬B ∪ ¬C) = ¬((B ∩ C) − A)
            var inter = negs[0]
            for n in negs.dropFirst() { inter = intersect(inter, n) }
            return .neg(inter.subtract(union(pos).list))
        case let .not(x):
            switch try eval(x) {
            case let .pos(r): return .neg(r)
            case let .neg(r): return .pos(r)
            }
        case let .compare(field, op, value):
            return try compare(field, op, value)
        case let .inList(field, values):
            if case .time = try resolve(field) { throw DQLError(message: String(localized: "Для поля time используйте between"), position: -1) }
            if case let .entity(kind, _) = try resolve(field) { return .pos(try entitySet(kind, values)) }
            if case .tag = try resolve(field) {
                return .pos(ResultSet(list: IdSet.union(try values.map { try store.taggedEvents(color: $0.lowercased()) }, universe: store.eventCount)))
            }
            let ref = try resolve(field)
            switch ref {
            case .rule, .ruleLevel: return .pos(union(try values.map { try ruleSet(ref, op: "=", $0) }))
            default: break
            }
            let k = try key(field)
            var lists: [ResultSet] = []
            for v in values { lists.append(try equal(k, field: field, value: v, exact: false)) }
            return .pos(union(lists))
        case let .exists(field):
            if case .tag = try resolve(field) { return .pos(ResultSet(list: try store.taggedEvents())) }
            if case .rule = try resolve(field) { return .pos(try ruleSet(.rule, op: "=", "*")) }
            let k = try key(field)
            return .pos(ResultSet(list: IdSet.union(try store.allPostings(key: k).map(\.ids), universe: store.eventCount)))
        case let .between(field, low, high):
            if case .time = try resolve(field) {
                guard let a = parseTime(low), let b = parseTime(high) else { throw timeError(low + " / " + high) }
                return .pos(timeRange(from: min(a, b), to: max(a, b)))
            }
            guard let a = StringKey.number(low), let b = StringKey.number(high) else {
                throw DQLError(message: String(localized: "between работает с числами и временем"), position: -1)
            }
            let k = try key(field)
            return .pos(postingUnion(k, try store.numericValues(key: k, op: "between", min(a, b), max(a, b))))
        case let .text(s):
            return .pos(try pattern(nil, s, mode: .contains))
        case let .constant(b):
            return .pos(b ? universe : .empty)
        case let .fieldCompare(field, op, other):
            let r = try fieldCompare(field, op == .ne ? .eq : op, other)
            return op == .ne ? .neg(r) : .pos(r)
        }
    }

    /// Events where two fields of the same event compare as `op` (first value of each field;
    /// case-insensitive except `==`). Only events that have both fields are decoded.
    private func fieldCompare(_ field: String, _ op: DQLOp, _ other: String) throws -> ResultSet {
        let a = try key(field), b = try key(other)
        let both = IdSet.intersect(IdSet.union(try store.allPostings(key: a).map(\.ids), universe: store.eventCount),
                                   IdSet.union(try store.allPostings(key: b).map(\.ids), universe: store.eventCount))
        var out: [UInt32] = []
        for start in stride(from: 0, to: both.count, by: 4096) {
            try checkCancel()
            let rows = try store.rows(Array(both[start..<min(start + 4096, both.count)]))
            var need = Set<UInt32>()
            var pairs: [(id: UInt32, x: UInt32, y: UInt32)] = []
            for r in rows {
                guard let x = r.pairs.first(where: { $0.key == a })?.value,
                      let y = r.pairs.first(where: { $0.key == b })?.value else { continue }
                need.insert(x)
                need.insert(y)
                pairs.append((r.id, x, y))
            }
            let list = Array(need)
            let text = Dictionary(uniqueKeysWithValues: zip(list, try store.strings(list)))
            for p in pairs {
                let l = text[p.x] ?? "", r = text[p.y] ?? ""
                let hit: Bool
                switch op {
                case .eqExact: hit = l == r
                case .eq: hit = p.x == p.y || l.caseInsensitiveCompare(r) == .orderedSame
                case .contains: hit = !r.isEmpty && l.range(of: r, options: .caseInsensitive) != nil
                case .startswith: hit = !r.isEmpty && l.range(of: r, options: [.caseInsensitive, .anchored]) != nil
                case .endswith: hit = !r.isEmpty && l.range(of: r, options: [.caseInsensitive, .anchored, .backwards]) != nil
                default:
                    throw DQLError(message: String(localized: "Сравнение двух полей поддерживает =, ==, !=, contains, startswith, endswith"), position: -1)
                }
                if hit { out.append(p.id) }
            }
        }
        return ResultSet(list: out)
    }

    /// Evaluates a filter expression (used by detection rules).
    public func evaluate(_ e: DQLExpr) throws -> ResultSet {
        switch try eval(e) {
        case let .pos(r): return r
        case let .neg(r): return universe.subtract(r.list)
        }
    }

    /// True when the field resolves (real field, alias, time, entity or tag).
    public func fieldExists(_ field: String) -> Bool { (try? resolve(field)) != nil }

    private func compare(_ field: String, _ op: DQLOp, _ value: String) throws -> SetVal {
        if case .tag = try resolve(field) {
            let ids = ResultSet(list: try store.taggedEvents(color: value == "*" ? nil : value.lowercased()))
            switch op {
            case .eq, .eqExact: return .pos(ids)
            case .ne: return .neg(ids)
            default: throw DQLError(message: String(localized: "Для tag поддерживаются =, !=, in, exists"), position: -1)
            }
        }
        if case let .entity(kind, _) = try resolve(field) {
            switch op {
            case .eq, .eqExact: return .pos(try entitySet(kind, [value]))
            case .ne: return .neg(try entitySet(kind, [value]))
            default: throw DQLError(message: String(localized: "Для anyhost/anyuser/anyip поддерживаются =, !=, in"), position: -1)
            }
        }
        if case .rule = try resolve(field) {
            switch op {
            case .eq, .eqExact: return .pos(try ruleSet(.rule, op: "=", value))
            case .ne: return .neg(try ruleSet(.rule, op: "=", value))
            case .contains: return .pos(try ruleSet(.rule, op: "contains", value))
            case .notContains: return .neg(try ruleSet(.rule, op: "contains", value))
            default: _ = try key(field)
            }
        }
        if case .ruleLevel = try resolve(field) {
            switch op {
            case .eq, .eqExact: return .pos(try ruleSet(.ruleLevel, op: "=", value))
            case .ne: return .neg(try ruleSet(.ruleLevel, op: "=", value))
            case .lt, .le, .gt, .ge: return .pos(try ruleSet(.ruleLevel, op: op.rawValue, value))
            default: _ = try key(field)
            }
        }
        if case .time = try resolve(field) {
            guard let ft = parseTime(value) else { throw timeError(value) }
            switch op {
            case .lt: return .pos(timeRange(from: nil, to: ft - 1))
            case .le: return .pos(timeRange(from: nil, to: ft))
            case .gt: return .pos(timeRange(from: ft + 1, to: nil))
            case .ge: return .pos(timeRange(from: ft, to: nil))
            case .eq, .eqExact: return .pos(timeRange(from: ft, to: ft + FileTime_ticksPerSecond - 1))
            case .ne: return .neg(timeRange(from: ft, to: ft + FileTime_ticksPerSecond - 1))
            default: throw DQLError(message: String(localized: "Для поля time используйте <, <=, >, >=, between"), position: -1)
            }
        }
        let k = try key(field)
        switch op {
        case .eq: return .pos(try equal(k, field: field, value: value, exact: false))
        case .eqExact: return .pos(try equal(k, field: field, value: value, exact: true))
        case .ne: return .neg(try equal(k, field: field, value: value, exact: false))
        case .lt, .le, .gt, .ge:
            guard let n = StringKey.number(value) else {
                throw DQLError(message: String(localized: "Сравнение «\(op.rawValue)» возможно только с числом (или для поля time)"), position: -1)
            }
            return .pos(postingUnion(k, try store.numericValues(key: k, op: op.rawValue, n)))
        case .contains: return .pos(try pattern(k, value, mode: .contains))
        case .notContains: return .neg(try pattern(k, value, mode: .contains))
        case .startswith: return .pos(try pattern(k, value, mode: .prefix))
        case .endswith: return .pos(try pattern(k, value, mode: .suffix))
        case .like: return .pos(try pattern(k, value, mode: .wildcard))
        case .matches: return .pos(try regex(k, value))
        case .cidr: return .pos(try cidr(k, value))
        }
    }

    private let FileTime_ticksPerSecond: Int64 = 10_000_000

    private func timeError(_ v: String) -> DQLError {
        DQLError(message: String(localized: "Не удалось разобрать время «\(v)». Формат: ГГГГ-ММ-ДД ЧЧ:ММ[:СС] (в выбранном часовом поясе; суффикс Z — UTC)"), position: -1)
    }

    private func timeRange(from: Int64?, to: Int64?) -> ResultSet {
        let lo = from.map { store.lowerBound(time: $0) } ?? 0
        let hi = to.map { store.lowerBound(time: $0 == .max ? $0 : $0 + 1) } ?? UInt32(store.eventCount)
        return ResultSet(range: lo..<max(lo, hi))
    }

    static let levelNames: [String: String] = [
        "critical": "1", "критический": "1", "error": "2", "ошибка": "2", "warning": "3", "предупреждение": "3",
        "information": "4", "info": "4", "сведения": "4", "verbose": "5", "подробно": "5",
    ]

    private func equal(_ k: UInt32, field: String, value: String, exact: Bool) throws -> ResultSet {
        var v = value
        if (try? canonical(field)) == CaseSchema.SystemKey.level, let n = Self.levelNames[value.lowercased()] { v = n }
        if v.contains("*") || v.contains("?") { return try pattern(k, v, mode: .wildcard) }
        let ids = try store.valueIds(v, exact: exact)
        var lists = try store.postings(key: k, values: ids)
        // "Information" in Event Viewer covers both level 0 (LogAlways) and 4.
        if v == "4", (try? canonical(field)) == CaseSchema.SystemKey.level {
            lists += try store.postings(key: k, values: try store.valueIds("0"))
        }
        return ResultSet(list: IdSet.union(lists, universe: store.eventCount))
    }

    func postingUnion(_ k: UInt32?, _ values: [UInt32]) -> ResultSet {
        ResultSet(list: IdSet.union((try? store.postings(key: k, values: values)) ?? [], universe: store.eventCount))
    }

    enum PatternMode { case contains, prefix, suffix, wildcard }

    /// Substring / prefix / suffix / wildcard match on the value dictionary, then the
    /// posting lists of the matching values (for one field, or every field when k is nil).
    /// Value-dictionary matches are cached per engine: detection runs evaluate the same
    /// field/pattern pairs (e.g. Image endswith \\powershell.exe) in many rules.
    var patternCache: [String: ResultSet] = [:]
    var warningsByKey: [String: String] = [:]
    var pendingWarnings: [String] = []
    let cacheLock = NSLock()

    static func patternKey(_ k: UInt32?, _ value: String, _ mode: PatternMode) -> String {
        "\(k.map(String.init) ?? "*")|\(mode)|\(value)"
    }

    private func pattern(_ k: UInt32?, _ value: String, mode: PatternMode) throws -> ResultSet {
        let cacheKey = Self.patternKey(k, value, mode)
        if let hit = cacheLock.withLock({ patternCache[cacheKey] }) { return hit }
        let r = try uncachedPattern(k, value, mode: mode)
        cacheLock.withLock { patternCache[cacheKey] = r }
        return r
    }

    private func uncachedPattern(_ k: UInt32?, _ value: String, mode: PatternMode) throws -> ResultSet {
        guard !value.isEmpty else { return .empty }
        let ascii = value.utf8.allSatisfy { $0 < 0x80 }
        let matcher = try Matcher(value, mode)
        var candidates: [UInt32]
        if ascii {
            let like: String
            switch mode {
            case .contains: like = "%" + value + "%"
            case .prefix: like = value + "%"
            case .suffix: like = "%" + value
            case .wildcard: like = Self.likeSuperset(value)
            }
            let literal = value.split(whereSeparator: { "*?%_".contains($0) }).map(\.count).max() ?? 0
            candidates = try store.likeCandidates(like, literalLength: literal)
            // LIKE treats % and _ as wildcards; recheck precisely when they occur.
            if mode == .wildcard || value.contains("%") || value.contains("_") {
                let strings = try store.strings(candidates)
                candidates = zip(candidates, strings).filter { matcher.test($0.1) }.map(\.0)
            }
        } else {
            // SQLite LIKE folds ASCII case only: scan the dictionary with Unicode folding.
            candidates = try scanDictionary(key: k) { matcher.test($0) }
        }
        try checkCancel()
        return postingUnion(k, candidates)
    }

    private func cidr(_ k: UInt32, _ value: String) throws -> ResultSet {
        guard let net = CIDR(value) else {
            throw DQLError(message: String(localized: "Некорректная подсеть «\(value)» (ожидается, например, 10.0.0.0/8)"), position: -1)
        }
        // The raw value is parsed here (not via the entity normaliser, which drops loopback
        // and unspecified addresses on purpose).
        let matched = try scanDictionary(key: k) { net.contains($0) }
        return postingUnion(k, matched)
    }

    /// SQL LIKE pattern for a wildcard pattern: `*` → `%`, `?` → `_`. Literal `%` and `_`
    /// are LIKE wildcards too, so wildcard candidates are always re-checked exactly.
    static func likeSuperset(_ value: String) -> String {
        String(value.map { $0 == "*" ? "%" : ($0 == "?" ? "_" : $0) })
    }

    /// CPU-time limit for one regular expression on one value. ICU regular expressions
    /// backtrack, so some patterns are quadratic on long values; a value that hits the limit is
    /// reported (`takeWarnings`) instead of hanging the query or being skipped silently. CPU
    /// time of the matching thread (not wall time) keeps the outcome independent of machine load.
    public static let regexBudgetSeconds = 2.0

    /// Warnings of the evaluations since the last call (e.g. regex time limits).
    public func takeWarnings() -> [String] {
        cacheLock.withLock {
            defer { pendingWarnings = [] }
            return Array(NSOrderedSet(array: pendingWarnings)) as? [String] ?? pendingWarnings
        }
    }

    private func regex(_ k: UInt32, _ pattern: String) throws -> ResultSet {
        let cacheKey = "\(k)|regex|\(pattern)"
        if let hit = cacheLock.withLock({ () -> ResultSet? in
            if let w = warningsByKey[cacheKey] { pendingWarnings.append(w) }
            return patternCache[cacheKey]
        }) { return hit }
        let re: NSRegularExpression
        do { re = try NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) } catch {
            throw DQLError(message: String(localized: "Ошибка в регулярном выражении: ") + error.localizedDescription, position: -1)
        }
        let ids = try store.values(ofKey: k).map(\.value)
        var matched: [UInt32] = []
        var aborted = 0
        let cancelled = isCancelled
        let budget = UInt64(Self.regexBudgetSeconds * 1e9)
        for start in stride(from: 0, to: ids.count, by: 4096) {
            try checkCancel()
            let batch = Array(ids[start..<min(start + 4096, ids.count)])
            let strings = try store.strings(batch)
            let outcome = parallelMap(strings.count) { i in Self.regexTest(re, strings[i], budget: budget, cancelled) }
            for (i, o) in outcome.enumerated() {
                if o == 1 { matched.append(batch[i]) } else if o == 2 { aborted += 1 }
            }
        }
        try checkCancel()
        let result = postingUnion(k, matched)
        cacheLock.withLock {
            patternCache[cacheKey] = result
            if aborted > 0 {
                let limit = String(format: "%g", Self.regexBudgetSeconds)
                let w = String(localized: "регулярное выражение «\(pattern)» по полю \(store.keyName(k)): проверка \(aborted) знач. прервана по лимиту \(limit) с процессорного времени на значение — совпадения в них не проверены")
                warningsByKey[cacheKey] = w
                pendingWarnings.append(w)
            }
        }
        return result
    }

    /// 0 — no match, 1 — match, 2 — stopped by the time limit.
    static func regexTest(_ re: NSRegularExpression, _ s: String, budget: UInt64, _ cancelled: () -> Bool) -> UInt8 {
        // ICU reports progress very often (about once per start position). Reading the wall
        // clock there is cheap; the thread's CPU time and the cancel flag (which may lock) are
        // checked at most every 20 ms.
        let cpuStart = clock_gettime_nsec_np(CLOCK_THREAD_CPUTIME_ID)
        var nextCheck = DispatchTime.now().uptimeNanoseconds + 20_000_000
        var outcome: UInt8 = 0
        re.enumerateMatches(in: s, options: [.reportProgress], range: NSRange(location: 0, length: (s as NSString).length)) { result, _, stop in
            if result != nil {
                outcome = 1
                stop.pointee = true
                return
            }
            let now = DispatchTime.now().uptimeNanoseconds
            guard now > nextCheck else { return }
            nextCheck = now + 20_000_000
            if clock_gettime_nsec_np(CLOCK_THREAD_CPUTIME_ID) - cpuStart > budget || cancelled() {
                outcome = 2
                stop.pointee = true
            }
        }
        return outcome
    }

    /// Tests every distinct value (of one field, or of the whole dictionary) in batches.
    private func scanDictionary(key: UInt32?, _ test: (String) -> Bool) throws -> [UInt32] {
        let ids: [UInt32]
        if let key {
            ids = try store.values(ofKey: key).map(\.value)
        } else {
            ids = Array(0..<UInt32(try store.dictionarySize()))
        }
        var out: [UInt32] = []
        for start in stride(from: 0, to: ids.count, by: 4096) {
            try checkCancel()
            let batch = Array(ids[start..<min(start + 4096, ids.count)])
            for (id, s) in zip(batch, try store.strings(batch)) where test(s) { out.append(id) }
        }
        return out
    }

    struct Matcher {
        let value: String
        let mode: PatternMode
        let regex: NSRegularExpression?

        init(_ value: String, _ mode: PatternMode) throws {
            self.value = value
            self.mode = mode
            if mode == .wildcard {
                // `*` any run, `?` one character; everything else (backslashes included) is
                // literal, so Windows paths like C:\Users\*\AppData\* work as typed.
                var p = "^"
                for ch in value {
                    switch ch {
                    case "*": p += ".*"
                    case "?": p += "."
                    default: p += NSRegularExpression.escapedPattern(for: String(ch))
                    }
                }
                regex = try NSRegularExpression(pattern: p + "$", options: [.caseInsensitive, .dotMatchesLineSeparators])
            } else {
                regex = nil
            }
        }

        func test(_ s: String) -> Bool {
            switch mode {
            case .contains: return s.range(of: value, options: .caseInsensitive) != nil
            case .prefix: return s.range(of: value, options: [.caseInsensitive, .anchored]) != nil
            case .suffix: return s.range(of: value, options: [.caseInsensitive, .anchored, .backwards]) != nil
            case .wildcard:
                return regex?.firstMatch(in: s, range: NSRange(location: 0, length: (s as NSString).length)) != nil
            }
        }
    }

    // MARK: Set helpers

    private func intersect(_ a: ResultSet, _ b: ResultSet) -> ResultSet {
        switch (a.storage, b.storage) {
        case let (.range(x), .range(y)):
            let lo = max(x.lowerBound, y.lowerBound), hi = min(x.upperBound, y.upperBound)
            return ResultSet(range: lo..<max(lo, hi))
        case let (.range(x), .list): return b.clamp(x)
        case let (.list, .range(y)): return a.clamp(y)
        case let (.list(x), .list(y)): return ResultSet(list: IdSet.intersect(x, y))
        }
    }

    private func union(_ sets: [ResultSet]) -> ResultSet {
        if sets.isEmpty { return .empty }
        if sets.count == 1 { return sets[0] }
        return ResultSet(list: IdSet.union(sets.map(\.list), universe: store.eventCount))
    }

    // MARK: Group by / sort

    /// Value id per element of `list` for one field (UInt32.max when absent).
    private func column(_ k: UInt32, _ events: ResultSet) throws -> [UInt32] {
        let n = events.count
        var col = [UInt32](repeating: .max, count: n)
        let list: [UInt32]? = { if case let .list(l) = events.storage { return l } else { return nil } }()
        let start = events.count > 0 ? events.id(at: 0) : 0
        for (v, ids) in try store.allPostings(key: k) {
            try checkCancel()
            for id in ids {
                let pos: Int
                if let list {
                    let p = IdSet.lowerBound(list, id)
                    guard p < n, list[p] == id else { continue }
                    pos = p
                } else {
                    guard id >= start, Int(id - start) < n else { continue }
                    pos = Int(id - start)
                }
                if col[pos] == .max { col[pos] = v }
            }
        }
        return col
    }

    private func group(_ events: ResultSet, fields: [String], sort: [DQLSort]) throws -> ([DQLGroupRow], Bool) {
        let keys = try fields.map { try key($0) }
        let cols = try keys.map { try column($0, events) }
        var counts: [[UInt32]: Int] = [:]
        for i in 0..<events.count {
            counts[cols.map { $0[i] }, default: 0] += 1
        }
        var rows = counts.map { ($0.key, $0.value) }
        let byCountAsc = sort.first.map { $0.field.lowercased() == "count" && !$0.descending } ?? false
        rows.sort { byCountAsc ? $0.1 < $1.1 : $0.1 > $1.1 }
        let truncated = rows.count > Self.maxGroups
        rows = Array(rows.prefix(Self.maxGroups))
        var ids = Set<UInt32>()
        for r in rows { for v in r.0 where v != .max { ids.insert(v) } }
        let idList = Array(ids)
        let names = Dictionary(uniqueKeysWithValues: zip(idList, try store.strings(idList)))
        var out = rows.map { r in
            DQLGroupRow(values: r.0.map { $0 == .max ? "—" : (names[$0] ?? "") }, count: r.1)
        }
        if let s = sort.first, s.field.lowercased() != "count", let i = fields.firstIndex(where: { $0.lowercased() == s.field.lowercased() }) {
            out.sort { a, b in
                let o = a.values[i].localizedStandardCompare(b.values[i])
                return s.descending ? o == .orderedDescending : o == .orderedAscending
            }
        }
        return (out, truncated)
    }

    /// Events ordered by a field's value (numeric when both values are numbers), time order
    /// within equal values; events without the field go last.
    private func sortBy(_ events: ResultSet, field: String, descending: Bool) throws -> [UInt32] {
        let k = try key(field)
        let list = events.list
        var postings = try store.allPostings(key: k)
        let names = try store.strings(postings.map(\.value))
        var order = Array(postings.indices)
        order.sort { a, b in
            let x = names[a], y = names[b]
            if let nx = StringKey.number(x), let ny = StringKey.number(y), nx != ny { return descending ? nx > ny : nx < ny }
            let o = x.localizedStandardCompare(y)
            return descending ? o == .orderedDescending : o == .orderedAscending
        }
        var out: [UInt32] = []
        out.reserveCapacity(list.count)
        var seen = Bitmap(count: store.eventCount)
        for i in order {
            try checkCancel()
            for id in IdSet.intersect(postings[i].ids, list) where !seen.contains(id) {
                seen.insert(id)
                out.append(id)
            }
        }
        for id in list where !seen.contains(id) { out.append(id) }
        postings = []
        return out
    }
}

extension CaseStore {
    func dictionarySize() throws -> Int {
        try queryLock.withLock { Int(try queryDB.scalar("SELECT max(id) + 1 FROM str") ?? 0) }
    }
}


/// IPv4 / IPv6 network for the `cidr` operator.
struct CIDR {
    let bytes: [UInt8]
    let prefix: Int

    init?(_ text: String) {
        let parts = text.trimmingCharacters(in: .whitespaces).split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count <= 2, let addr = parts.first.map(String.init), let ip = CIDR.parse(addr) else { return nil }
        bytes = ip
        let max = ip.count * 8
        if parts.count == 2 {
            guard let p = Int(parts[1]), p >= 0, p <= max else { return nil }
            prefix = p
        } else {
            prefix = max
        }
    }

    static func parse(_ s: String) -> [UInt8]? {
        var v4 = in_addr(), v6 = in6_addr()
        if inet_pton(AF_INET, s, &v4) == 1 { return withUnsafeBytes(of: &v4) { Array($0) } }
        if inet_pton(AF_INET6, s, &v6) == 1 { return withUnsafeBytes(of: &v6) { Array($0) } }
        return nil
    }

    /// Accepts IPv4, IPv6, IPv4-mapped IPv6 (`::ffff:10.0.0.1` matches IPv4 networks),
    /// `[addr]` and a zone suffix (`fe80::1%12`).
    func contains(_ text: String) -> Bool {
        var s = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.hasPrefix("["), let close = s.firstIndex(of: "]") { s = String(s[s.index(after: s.startIndex)..<close]) }
        if let pct = s.firstIndex(of: "%") { s = String(s[..<pct]) }
        guard var other = CIDR.parse(s) else { return false }
        if bytes.count == 4, other.count == 16, other[0..<10].allSatisfy({ $0 == 0 }), other[10] == 0xFF, other[11] == 0xFF {
            other = Array(other[12...])
        }
        guard other.count == bytes.count else { return false }
        var bits = prefix
        for i in 0..<bytes.count where bits > 0 {
            let n = min(8, bits)
            let mask = UInt8(truncatingIfNeeded: 0xFF << (8 - n))
            if bytes[i] & mask != other[i] & mask { return false }
            bits -= n
        }
        return true
    }
}

extension DQLExpr {
    /// DQL text of the expression (round-trips through `DQLParser`).
    public var dql: String {
        func q(_ s: String) -> String {
            let plain = !s.isEmpty && s.unicodeScalars.allSatisfy { CharacterSet.alphanumerics.contains($0) || "._-@$:/".unicodeScalars.contains($0) }
                && !["and", "or", "not", "in", "true", "false", "exists", "between"].contains(s.lowercased())
            return plain ? s : "\"" + s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
        }
        func f(_ s: String) -> String {
            s.unicodeScalars.allSatisfy { CharacterSet.alphanumerics.contains($0) || "._-@".unicodeScalars.contains($0) } && !s.isEmpty
                ? s : "`" + s + "`"
        }
        func op(_ o: DQLOp) -> String {
            switch o {
            case .eq: "="
            case .eqExact: "=="
            case .ne: "!="
            case .lt: "<"
            case .le: "<="
            case .gt: ">"
            case .ge: ">="
            case .contains: "contains"
            case .notContains: "not contains"
            case .startswith: "startswith"
            case .endswith: "endswith"
            case .like: "like"
            case .matches: "matches"
            case .cidr: "cidr"
            }
        }
        switch self {
        case let .and(xs): return xs.map { $0.dqlGrouped }.joined(separator: " and ")
        case let .or(xs): return xs.map { $0.dqlGrouped }.joined(separator: " or ")
        case let .not(x): return "not " + x.dqlGrouped
        case let .compare(field, o, value): return "\(f(field)) \(op(o)) \(q(value))"
        case let .inList(field, values): return "\(f(field)) in (\(values.map(q).joined(separator: ", ")))"
        case let .exists(field): return "\(f(field)) exists"
        case let .between(field, low, high): return "\(f(field)) between \(q(low)) and \(q(high))"
        case let .text(s): return "\"" + s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
        case let .constant(b): return b ? "true" : "false"
        case let .fieldCompare(field, o, other): return "\(f(field)) \(op(o)) `\(other)`"
        }
    }

    var dqlGrouped: String {
        switch self {
        case .and, .or: "(" + dql + ")"
        default: dql
        }
    }
}
