import DaybookStore
import Foundation

/// Differential check of the detection engine: evaluates the original Sigma rule directly on
/// each candidate event (byte-wise comparisons of lowercased values, regex-based wildcards, its
/// own condition evaluation) and compares the result with the stored engine hits. Shares only
/// the logsource / field mapping tables and the value transforms (windash, base64) with the
/// compiler; matching itself is implemented independently of the engine (no dictionary,
/// postings, Aho–Corasick or globs).
public enum SigmaVerifier {
    public struct Mismatch: Sendable {
        public let rule: SigmaRule
        /// Engine hits the direct evaluation rejects.
        public let extra: [UInt32]
        /// Events the direct evaluation matches but the engine did not.
        public let missing: [UInt32]
    }

    public struct Report: Sendable {
        public var rulesChecked = 0
        public var eventsChecked = 0
        public var skipped: [(String, String)] = []
        public var mismatches: [Mismatch] = []
        /// Rules whose direct evaluation hit the regex time limit (comparison not conclusive).
        public var inconclusive: [String] = []
    }

    /// One field value: original text and its lowercased UTF-8 bytes.
    struct Value {
        let text: String
        let lower: [UInt8]
        init(_ s: String) {
            text = s
            lower = Array(s.lowercased().utf8)
        }
    }

    /// Event fields by stored key name (all values of repeated fields).
    typealias Fields = [String: [Value]]

    public static func run(store: CaseStore, rules set: SigmaRuleSet, maxCandidates: Int = 400_000,
                           progress: (Int, Int) -> Void = { _, _ in }) throws -> Report {
        let catalog = SigmaFieldCatalog(has: { store.exactKeyId($0) != nil }, aliases: set.aliases, platform: store.platform)
        let engine = DQLEngine(store: store, parseTime: { _ in nil })
        let stored = Dictionary(try store.detectionRules().map { ("\($0.source)|\($0.path)", $0) }, uniquingKeysWith: { a, _ in a })
        var report = Report()

        // Group rules by their candidate set (logsource base plus the rule's own equality
        // conditions on system fields), so each set of events is decoded once.
        var groups: [String: (ids: [UInt32], rules: [(SigmaRule, [UInt32])])] = [:]
        for rule in set.rules {
            let c = SigmaCompiler.compile(rule, catalog: catalog)
            guard let expr = c.expr, let d = stored["\(rule.source)|\(rule.path)"], d.evaluated else { continue }
            // A rule that is constantly false here (its fields never occur) is still checked
            // directly on the events of its logsource: the direct evaluation must find nothing.
            let target: DQLExpr = expr == .constant(false)
                ? .or((try? SigmaCompiler.variants(rule.logsource, catalog))?.map(\.base) ?? [])
                : expr
            guard let narrowing = narrowing(target) else {
                report.skipped.append((rule.title, String(localized: "нет сужающих условий по системным полям")))
                continue
            }
            let key = narrowing.dql
            if groups[key] == nil {
                let ids = try engine.evaluate(narrowing).list
                groups[key] = (ids, [])
            }
            guard groups[key]!.ids.count <= maxCandidates else {
                report.skipped.append((rule.title, String(localized: "слишком много кандидатов: \(groups[key]!.ids.count)")))
                continue
            }
            groups[key]!.rules.append((rule, try store.detectionHits([d.id])))
        }

        var done = 0
        let total = groups.values.reduce(0) { $0 + $1.rules.count }
        for (_, g) in groups.sorted(by: { $0.key < $1.key }) {
            let events = try decode(store, g.ids)
            report.eventsChecked += events.count
            let results = parallelEvaluate(g.rules.map(\.0), events: events, aliases: set.aliases, catalog: catalog)
            for (i, (rule, hits)) in g.rules.enumerated() {
                guard let direct = results[i] else {
                    report.inconclusive.append(rule.title)
                    continue
                }
                let engineSet = Set(hits), directSet = Set(direct)
                let extra = hits.filter { !directSet.contains($0) }
                let missing = direct.filter { !engineSet.contains($0) }
                if !extra.isEmpty || !missing.isEmpty {
                    report.mismatches.append(Mismatch(rule: rule, extra: extra, missing: missing))
                }
                report.rulesChecked += 1
            }
            done += g.rules.count
            progress(done, total)
        }
        return report
    }

    /// Conjuncts on system keys that every matching event satisfies (OR over variants).
    static func narrowing(_ e: DQLExpr) -> DQLExpr? {
        func isSystem(_ f: String) -> Bool { [CaseSchema.SystemKey.channel, CaseSchema.SystemKey.eventId, CaseSchema.SystemKey.provider].contains(f) }
        switch e {
        case let .or(xs):
            let parts = xs.map(narrowing)
            guard parts.allSatisfy({ $0 != nil }) else { return nil }
            return .or(parts.map { $0! })
        case let .and(xs):
            let sys = xs.filter { x in
                switch x {
                case let .compare(f, op, _): return isSystem(f) && (op == .eq || op == .like)
                case let .inList(f, _): return isSystem(f)
                case let .or(ys): return ys.allSatisfy { if case let .compare(f, .eq, _) = $0 { return isSystem(f) } else { return false } }
                default: return false
                }
            }
            return sys.isEmpty ? nil : (sys.count == 1 ? sys[0] : .and(sys))
        case let .compare(f, _, _) where isSystem(f): return e
        case let .inList(f, _) where isSystem(f): return e
        default: return nil
        }
    }

    static func decode(_ store: CaseStore, _ ids: [UInt32]) throws -> [(UInt32, Fields)] {
        var out: [(UInt32, Fields)] = []
        out.reserveCapacity(ids.count)
        for start in stride(from: 0, to: ids.count, by: 4096) {
            let rows = try store.rows(Array(ids[start..<min(start + 4096, ids.count)]))
            var need = Set<UInt32>()
            for r in rows { for p in r.pairs { need.insert(p.value) } }
            let list = Array(need)
            let strings = try store.strings(list)
            var values: [UInt32: Value] = [:]
            values.reserveCapacity(list.count)
            for (id, s) in zip(list, strings) { values[id] = Value(s) }
            for r in rows {
                var f: Fields = [:]
                for p in r.pairs { f[store.keyName(p.key), default: []].append(values[p.value] ?? Value("")) }
                f[CaseSchema.SystemKey.eventId] = [Value(String(r.eventId))]
                f[CaseSchema.SystemKey.channel] = [Value(r.channel)]
                f[CaseSchema.SystemKey.provider] = [Value(r.provider)]
                f[CaseSchema.SystemKey.computer] = [Value(r.computer)]
                if let l = r.level { f[CaseSchema.SystemKey.level] = [Value(String(l))] }
                if let kw = r.keywords { f[CaseSchema.SystemKey.keywords] = [Value(String(format: "0x%016llx", kw))] }
                if let u = r.user { f[CaseSchema.SystemKey.user] = [Value(u)] }
                out.append((r.id, f))
            }
        }
        return out
    }

    /// Hits per rule (nil when a regular expression hit the time limit). Parallel over events
    /// in slices, so groups with few rules and many events still use every core.
    static func parallelEvaluate(_ rules: [SigmaRule], events: [(UInt32, Fields)], aliases: [String: String],
                                 catalog: SigmaFieldCatalog) -> [[UInt32]?] {
        final class Box: @unchecked Sendable {
            var v: [[[UInt32]]]
            var timeout: [Bool]
            let lock = NSLock()
            init(_ n: Int, _ slices: Int) { v = Array(repeating: Array(repeating: [], count: slices), count: n); timeout = Array(repeating: false, count: n) }
        }
        let slices = max(1, min(64, events.count / 512))
        let box = Box(rules.count, slices)
        DispatchQueue.concurrentPerform(iterations: rules.count * slices) { job in
            let i = job / slices, s = job % slices
            let rule = rules[i]
            let lo = s * events.count / slices, hi = (s + 1) * events.count / slices
            var hits: [UInt32] = []
            for (id, f) in events[lo..<hi] {
                do {
                    if try matches(rule, f, aliases: aliases, catalog: catalog) { hits.append(id) }
                } catch is RegexTimeout {
                    box.lock.withLock { box.timeout[i] = true }
                } catch {}
            }
            box.lock.withLock { box.v[i][s] = hits }
        }
        return (0..<rules.count).map { box.timeout[$0] ? nil : box.v[$0].flatMap { $0 } }
    }

    // MARK: Direct evaluation

    struct Unsupported: Error {}

    /// Compiled regular expressions and expanded values, shared by the worker threads.
    final class Memo: @unchecked Sendable {
        private var regexes: [String: NSRegularExpression?] = [:]
        private var expansions: [String: [[SigmaCompiler.Piece]]] = [:]
        private let lock = NSLock()

        func regex(_ pattern: String, _ opts: NSRegularExpression.Options) -> NSRegularExpression? {
            let key = "\(opts.rawValue)|\(pattern)"
            if let hit = lock.withLock({ regexes[key] }) { return hit }
            let re = try? NSRegularExpression(pattern: pattern, options: opts)
            lock.withLock { regexes[key] = re }
            return re
        }

        func expand(_ text: String, _ mode: String, _ transforms: [String]) throws -> [[SigmaCompiler.Piece]] {
            let key = "\(mode)|\(transforms.joined(separator: ","))|\(text)"
            if let hit = lock.withLock({ expansions[key] }) { return hit }
            let r = try SigmaCompiler.expand(text, mode: mode, transforms: transforms)
            lock.withLock { expansions[key] = r }
            return r
        }
    }

    static let memo = Memo()

    struct RegexTimeout: Error {}

    /// Regular-expression results per (pattern, value), with the same per-value time limit as
    /// the engine; a value that hits it makes the rule's comparison inconclusive.
    final class RegexResults: @unchecked Sendable {
        struct Key: Hashable { let pattern: String; let options: UInt; let text: Int; let length: Int }
        private var results: [Key: Bool] = [:]
        private var timedOut = Set<Key>()
        private let lock = NSLock()

        func match(_ re: NSRegularExpression, _ text: String) throws -> Bool {
            // Values can be megabytes (script blocks): key by hash and length, not the text.
            let key = Key(pattern: re.pattern, options: re.options.rawValue, text: text.hashValue, length: text.utf8.count)
            if let r = lock.withLock({ results[key] }) { return r }
            if lock.withLock({ timedOut.contains(key) }) { throw RegexTimeout() }
            // Same CPU-time limit as the engine (thread CPU time, checked every 20 ms).
            let budget = UInt64(DQLEngine.regexBudgetSeconds * 1e9)
            let cpuStart = clock_gettime_nsec_np(CLOCK_THREAD_CPUTIME_ID)
            var nextCheck = DispatchTime.now().uptimeNanoseconds + 20_000_000
            var found = false, stopped = false
            re.enumerateMatches(in: text, options: [.reportProgress], range: NSRange(location: 0, length: (text as NSString).length)) { m, _, stop in
                if m != nil { found = true; stop.pointee = true; return }
                let now = DispatchTime.now().uptimeNanoseconds
                guard now > nextCheck else { return }
                nextCheck = now + 20_000_000
                if clock_gettime_nsec_np(CLOCK_THREAD_CPUTIME_ID) - cpuStart > budget { stopped = true; stop.pointee = true }
            }
            if stopped && !found {
                lock.withLock { _ = timedOut.insert(key) }
                throw RegexTimeout()
            }
            lock.withLock { results[key] = found }
            return found
        }
    }

    static let regexResults = RegexResults()

    static func matches(_ rule: SigmaRule, _ f: Fields, aliases: [String: String], catalog: SigmaFieldCatalog) throws -> Bool {
        let variants = try SigmaCompiler.variants(rule.logsource, catalog)
        for v in variants {
            guard baseMatches(v.base, f) else { continue }
            var cache: [String: Bool] = [:]
            func search(_ name: String) throws -> Bool {
                if let b = cache[name] { return b }
                guard let s = rule.searches[name] else { throw Unsupported() }
                let b = try evalSearch(s, f, v, rule.source == "Hayabusa" ? aliases : [:])
                cache[name] = b
                return b
            }
            for c in rule.conditions where try evalCondition(c, Array(rule.searches.keys), search) { return true }
        }
        return false
    }

    static func baseMatches(_ e: DQLExpr, _ f: Fields) -> Bool {
        switch e {
        case let .and(xs): return xs.allSatisfy { baseMatches($0, f) }
        case let .or(xs): return xs.contains { baseMatches($0, f) }
        case .constant(true): return true
        case let .compare(field, .eq, value): return (f[field] ?? []).contains { $0.text.caseInsensitiveCompare(value) == .orderedSame }
        case let .compare(field, .like, value):
            let prefix = Array((value.hasSuffix("*") ? String(value.dropLast()) : value).lowercased().utf8)
            return (f[field] ?? []).contains { $0.lower.starts(with: prefix) }
        case let .inList(field, values): return (f[field] ?? []).contains { v in values.contains { $0.caseInsensitiveCompare(v.text) == .orderedSame } }
        default: return false
        }
    }

    static func evalCondition(_ text: String, _ names: [String], _ search: (String) throws -> Bool) throws -> Bool {
        let t = SigmaCompiler.ConditionParser.tokenize(text)
        var i = 0
        func peek() -> String? { i < t.count ? t[i].lowercased() : nil }
        func orExpr() throws -> Bool {
            var r = try andExpr()
            while peek() == "or" { i += 1; let x = try andExpr(); r = r || x }
            return r
        }
        func andExpr() throws -> Bool {
            var r = try notExpr()
            while peek() == "and" { i += 1; let x = try notExpr(); r = r && x }
            return r
        }
        func notExpr() throws -> Bool {
            if peek() == "not" { i += 1; return !(try notExpr()) }
            return try atom()
        }
        func atom() throws -> Bool {
            guard i < t.count else { throw Unsupported() }
            let tok = t[i]
            i += 1
            if tok == "(" {
                let r = try orExpr()
                guard i < t.count, t[i] == ")" else { throw Unsupported() }
                i += 1
                return r
            }
            if tok.lowercased() == "all" || tok == "1", peek() == "of", i + 1 < t.count {
                let target = t[i + 1]
                i += 2
                let selected: [String] = target.lowercased() == "them"
                    ? names.filter { !$0.hasPrefix("_") }
                    : names.filter { n in
                        // fnmatch-style: only * is special in identifier patterns.
                        let parts = target.split(separator: "*", omittingEmptySubsequences: false).map(String.init)
                        guard parts.count > 1 else { return n == target }
                        var rest = Substring(n)
                        guard rest.hasPrefix(parts[0]) else { return false }
                        rest = rest.dropFirst(parts[0].count)
                        for p in parts.dropFirst().dropLast() where !p.isEmpty {
                            guard let r = rest.range(of: p) else { return false }
                            rest = rest[r.upperBound...]
                        }
                        return parts.last!.isEmpty || rest.hasSuffix(parts.last!)
                    }
                guard !selected.isEmpty else { throw Unsupported() }
                return tok == "1" ? try selected.contains(where: search) : try selected.allSatisfy(search)
            }
            return try search(tok)
        }
        return try orExpr()
    }

    static func evalSearch(_ s: SigmaSearch, _ f: Fields, _ v: SigmaCompiler.Variant, _ aliases: [String: String]) throws -> Bool {
        switch s {
        case let .all(items): return try items.allSatisfy { try evalItem($0, f, v, aliases) }
        case let .any(list): return try list.contains { try evalSearch($0, f, v, aliases) }
        case let .keywords(values): return values.contains { keywordMatches($0, f) }
        }
    }

    static func keywordMatches(_ v: SigmaValue, _ f: Fields) -> Bool {
        guard case let .string(text) = v else { return false }
        var p = SigmaCompiler.pieces(text)
        while p.first == .any { p.removeFirst() }
        while p.last == .any { p.removeLast() }
        guard let s = SigmaCompiler.plain(p) else { return false }
        if s.isEmpty { return true }
        let needle = Array(s.lowercased().utf8)
        return f.values.contains { $0.contains { find($0.lower, needle) } }
    }

    static func lookup(_ field: String, _ f: Fields, _ v: SigmaCompiler.Variant, _ aliases: [String: String]) throws -> [Value]? {
        switch SigmaCompiler.target(v.renames[field] ?? field, aliases) {
        case let .key(k): return f[k]
        case .anyField: return nil
        case .unindexed: throw Unsupported()
        }
    }

    static func evalItem(_ item: SigmaItem, _ f: Fields, _ v: SigmaCompiler.Variant, _ aliases: [String: String]) throws -> Bool {
        guard let field = item.field else {
            let r = item.values.map { keywordMatches($0, f) }
            return item.modifiers.contains("all") ? r.allSatisfy { $0 } : r.contains(true)
        }
        if SigmaCompiler.target(v.renames[field] ?? field, aliases) == .anyField {
            let r = item.values.map { keywordMatches($0, f) }
            return item.modifiers.contains("all") ? r.allSatisfy { $0 } : r.contains(true)
        }
        let mods = item.modifiers
        let present = try lookup(field, f, v, aliases)
        if mods.contains("exists") {
            let want = item.values.first.map { if case let .string(s) = $0 { return ["true", "yes"].contains(s.lowercased()) } else { return false } } ?? true
            return (present != nil) == want
        }
        let mode = mods.first { ["contains", "startswith", "endswith", "re", "cidr", "gt", "gte", "lt", "lte"].contains($0) } ?? "eq"
        let all = mods.contains("all"), cased = mods.contains("cased")
        if mods.contains("fieldref") {
            guard let left = present?.first else { return false }
            let r = try item.values.map { val -> Bool in
                guard case let .string(other) = val, let right = try lookup(other, f, v, aliases)?.first else { return false }
                if cased && mode == "eq" { return left.text == right.text }
                let l = left.lower, rr = right.lower
                switch mode {
                case "contains": return !rr.isEmpty && find(l, rr)
                case "startswith": return !rr.isEmpty && l.starts(with: rr)
                case "endswith": return !rr.isEmpty && l.count >= rr.count && Array(l.suffix(rr.count)) == rr
                default: return l == rr
                }
            }
            return all ? r.allSatisfy { $0 } : r.contains(true)
        }
        let transforms = mods.filter { ["base64", "base64offset", "wide", "utf16le", "windash"].contains($0) }
        let translate = v.values[field]
        let results = try item.values.map { val -> Bool in
            guard case var .string(text) = val else { return present == nil }
            guard let values = present else { return false }
            if let translate, let t = translate[text.lowercased()] { text = t }
            let alternatives = try memo.expand(text, mode, transforms)
            return try alternatives.contains { p in try values.contains { try valueMatches($0, p, raw: text, mode: mode, cased: cased, mods: mods) } }
        }
        return all ? results.allSatisfy { $0 } : results.contains(true)
    }

    /// Substring search on bytes (memmem).
    static func find(_ hay: [UInt8], _ needle: [UInt8]) -> Bool {
        if needle.isEmpty { return true }
        if needle.count > hay.count { return false }
        return hay.withUnsafeBytes { h in
            needle.withUnsafeBytes { n in memmem(h.baseAddress, h.count, n.baseAddress, n.count) != nil }
        }
    }

    static func valueMatches(_ value: Value, _ p: [SigmaCompiler.Piece], raw: String, mode: String, cased: Bool, mods: [String]) throws -> Bool {
        switch mode {
        case "re":
            var opts: NSRegularExpression.Options = []
            if mods.contains("i") { opts.insert(.caseInsensitive) }
            if mods.contains("m") { opts.insert(.anchorsMatchLines) }
            if mods.contains("s") { opts.insert(.dotMatchesLineSeparators) }
            guard let re = memo.regex(raw, opts) else { return false }
            return try regexResults.match(re, value.text)
        case "cidr": return cidr(value.text, raw)
        case "gt", "gte", "lt", "lte":
            guard let a = number(value.text), let b = number(raw) else { return false }
            switch mode {
            case "gt": return a > b
            case "gte": return a >= b
            case "lt": return a < b
            default: return a <= b
            }
        default: break
        }
        if !cased, let only = SigmaCompiler.plain(p) {
            // Plain values: byte comparison of lowercased text.
            let b = Array(only.lowercased().utf8), a = value.lower
            switch mode {
            case "contains": return find(a, b)
            case "startswith": return a.starts(with: b)
            case "endswith": return a.count >= b.count && Array(a.suffix(b.count)) == b
            default: return a == b
            }
        }
        // Wildcards and |cased: a regular expression built here (independent of the engine's globs).
        var pattern = "^" + (mode == "contains" || mode == "endswith" ? ".*" : "")
        for x in p {
            switch x {
            case let .lit(t): pattern += NSRegularExpression.escapedPattern(for: t)
            case .any: pattern += ".*"
            case .one: pattern += "."
            }
        }
        pattern += (mode == "contains" || mode == "startswith" ? ".*" : "") + "$"
        var opts: NSRegularExpression.Options = [.dotMatchesLineSeparators]
        if !cased { opts.insert(.caseInsensitive) }
        guard let re = memo.regex(pattern, opts) else { return false }
        return try regexResults.match(re, value.text)
    }

    static func number(_ s: String) -> Double? {
        let t = s.trimmingCharacters(in: .whitespaces)
        if t.lowercased().hasPrefix("0x") { return UInt64(t.dropFirst(2), radix: 16).map(Double.init) }
        return Double(t)
    }

    static func cidr(_ value: String, _ net: String) -> Bool {
        func bytes(_ s: String) -> [UInt8]? {
            var a = in_addr(), b = in6_addr()
            if inet_pton(AF_INET, s, &a) == 1 { return withUnsafeBytes(of: &a) { Array($0) } }
            if inet_pton(AF_INET6, s, &b) == 1 { return withUnsafeBytes(of: &b) { Array($0) } }
            return nil
        }
        let parts = net.split(separator: "/")
        guard let n = bytes(String(parts[0])) else { return false }
        var v = value.trimmingCharacters(in: .whitespaces)
        if let pct = v.firstIndex(of: "%") { v = String(v[..<pct]) }
        guard var x = bytes(v) else { return false }
        if n.count == 4, x.count == 16, x[0..<10].allSatisfy({ $0 == 0 }), x[10] == 0xFF, x[11] == 0xFF { x = Array(x[12...]) }
        guard x.count == n.count else { return false }
        let bits = parts.count > 1 ? Int(parts[1]) ?? n.count * 8 : n.count * 8
        for i in 0..<bits {
            let byte = i / 8, bit = UInt8(0x80) >> UInt8(i % 8)
            if n[byte] & bit != x[byte] & bit { return false }
        }
        return true
    }
}
