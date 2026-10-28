import DaybookStore
import Foundation

/// Compiles a rule set for a case, evaluates every rule and stores the results (including
/// rules that could not be evaluated, with the reason).
public enum SigmaRunner {
    public struct Summary: Sendable {
        public let total: Int
        public let evaluated: Int
        public let unsupported: Int
        public let failedToParse: Int
        public let errors: Int
        public let withHits: Int
        public let hitEvents: Int
        public let elapsedMs: Double
    }

    /// - Parameter progress: (rules done, rules total).
    @discardableResult
    public static func run(store: CaseStore, rules set: SigmaRuleSet,
                           progress: @Sendable (Int, Int) -> Void = { _, _ in },
                           isCancelled: @escaping @Sendable () -> Bool = { false }) throws -> Summary {
        let t0 = Date()
        let catalog = SigmaFieldCatalog(has: { store.exactKeyId($0) != nil }, aliases: set.aliases, platform: store.platform)
        let engine = DQLEngine(store: store, parseTime: { _ in nil })
        // Rules of the other system are not evaluated (counted in the run's metadata); rules
        // without a product (own rules) are compiled and report their own reason.
        var set = set
        let allRules = set.rules
        set.rules = allRules.filter { $0.platform == nil || $0.platform == store.platform }
        // Rules that failed to load are listed for their own system only (by folder / source).
        let failures = set.failures
        set.failures = failures.filter { f in
            let windows = f.source == "Hayabusa" || f.path.hasPrefix("rules/windows/")
            let linux = f.path.hasPrefix("rules/linux/")
            return store.platform == .linux ? !windows : !linux
        }
        let otherPlatform = allRules.count - set.rules.count + failures.count - set.failures.count
        engine.isCancelled = isCancelled

        var hostPostings: [[UInt32]] = []
        if let k = store.exactKeyId(CaseSchema.SystemKey.computer) {
            hostPostings = try store.allPostings(key: k).map(\.ids)
        }

        var out: [DetectionRule] = []
        var yaml: [String] = []
        var hits: [[UInt32]] = []
        let total = set.rules.count + set.failures.count
        var hitUnion = Bitmap(count: store.eventCount)
        var hitEvents = 0

        // Compile everything first, then evaluate all substring / wildcard predicates in one
        // pass per field (Aho–Corasick) before the rules themselves are evaluated.
        let tCompile = Date()
        let compiled = set.rules.map { SigmaCompiler.compile($0, catalog: catalog) }
        let compileMs = Date().timeIntervalSince(tCompile) * 1000
        let tPrefetch = Date()
        var requests: [(field: String, op: DQLOp, value: String)] = []
        func collect(_ e: DQLExpr) {
            switch e {
            case let .and(xs), let .or(xs): xs.forEach(collect)
            case let .not(x): collect(x)
            case let .compare(field, op, value) where [.contains, .notContains, .startswith, .endswith, .like].contains(op):
                requests.append((field, op, value))
            default: break
            }
        }
        for c in compiled { if let e = c.expr { collect(e) } }
        try engine.prefetch(requests)
        let prefetchMs = Date().timeIntervalSince(tPrefetch) * 1000
        let tEval = Date()

        for (n, rule) in set.rules.enumerated() {
            if isCancelled() { throw CancellationError() }
            if n % 25 == 0 { progress(n, total) }
            let c = compiled[n]
            var ids: [UInt32] = []
            var failure: String?
            let r0 = Date()
            _ = engine.takeWarnings()
            if let expr = c.expr {
                do {
                    ids = try engine.evaluate(expr).list
                } catch is CancellationError {
                    throw CancellationError()
                } catch let e as DQLError {
                    failure = e.message
                } catch {
                    failure = "\(error)"
                }
            }
            var d = DetectionRule(ruleId: rule.id, source: rule.source, path: rule.path, title: rule.title,
                                  level: rule.level, status: rule.status, author: rule.author,
                                  description: rule.description, date: rule.date, modified: rule.modified,
                                  tags: rule.tags, references: rule.references, falsePositives: rule.falsepositives,
                                  logsource: rule.logsourceText, query: c.query, variants: c.variants,
                                  absentFields: c.absentFields, unsupported: c.unsupported, error: failure)
            d.elapsedMs = Date().timeIntervalSince(r0) * 1000
            d.warnings = engine.takeWarnings()
            d.hits = ids.count
            if let first = ids.first, let last = ids.last {
                d.firstTs = store.timestamp(first)
                d.lastTs = store.timestamp(last)
                d.hosts = hostPostings.reduce(0) { $0 + (IdSet.intersect($1, ids).isEmpty ? 0 : 1) }
                for id in ids where !hitUnion.contains(id) {
                    hitUnion.insert(id)
                    hitEvents += 1
                }
            }
            out.append(d)
            yaml.append(rule.yaml)
            hits.append(ids)
        }
        for f in set.failures {
            out.append(DetectionRule(ruleId: "", source: f.source, path: f.path, title: f.title ?? f.path, level: nil,
                                     status: nil, author: nil, description: nil, date: nil, modified: nil, tags: [],
                                     references: [], falsePositives: [], logsource: "", query: "", variants: [],
                                     absentFields: [], unsupported: String(localized: "не загружено: ") + f.message, error: nil))
            yaml.append(f.yaml)
            hits.append([])
        }
        progress(total, total)

        let evalMs = Date().timeIntervalSince(tEval) * 1000
        let elapsed = Date().timeIntervalSince(t0) * 1000
        let summary = Summary(total: total, evaluated: out.filter(\.evaluated).count,
                              unsupported: out.filter { $0.unsupported != nil }.count - set.failures.count,
                              failedToParse: set.failures.count, errors: out.filter { $0.error != nil }.count,
                              withHits: out.filter { $0.hits > 0 }.count, hitEvents: hitEvents, elapsedMs: elapsed)
        let iso = ISO8601DateFormatter()
        var meta: [String: String] = [
            "started": iso.string(from: t0), "finished": iso.string(from: Date()),
            "elapsed_ms": String(Int(elapsed)), "rules_total": String(total), "evaluated": String(summary.evaluated),
            "unsupported": String(summary.unsupported), "failed": String(summary.failedToParse),
            "errors": String(summary.errors), "with_hits": String(summary.withHits), "hit_events": String(hitEvents),
            "compile_ms": String(Int(compileMs)), "prefetch_ms": String(Int(prefetchMs)), "evaluate_ms": String(Int(evalMs)),
            "prefetch_predicates": String(requests.count),
            "platform": store.platform.rawValue, "other_platform": String(otherPlatform),
        ]
        if let g = set.generated { meta["pack_generated"] = g }
        let sources = set.sources.map { s -> [String: Any] in
            ["name": s.name, "url": s.url, "version": s.version, "license": s.license, "licenseURL": s.licenseURL, "count": s.count]
        }
        if let data = try? JSONSerialization.data(withJSONObject: sources, options: [.sortedKeys]) {
            meta["sources"] = String(data: data, encoding: .utf8)
        }
        try DetectionWriter(store: store).replace(rules: out, yaml: yaml, hits: hits, meta: meta)
        return summary
    }
}
