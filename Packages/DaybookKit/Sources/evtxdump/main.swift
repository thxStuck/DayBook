import DaybookSigma
import DaybookStore
import EvtxCore
import Foundation

// evtxdump — diagnostics and differential-testing tool for EvtxCore.
//   evtxdump stats <file|dir>...           per-file health and parse statistics
//   evtxdump carve <file|dir>...           slack-space recovery statistics
//   evtxdump xml <file> [--limit N] [--jsonl]
//   evtxdump json <file> [--limit N]

let usage = """
usage: evtxdump stats|carve <file|dir>...
       evtxdump xml <file> [--limit N] [--jsonl]
       evtxdump json <file> [--limit N]
"""

func fail(_ msg: String) -> Never {
    FileHandle.standardError.write((msg + "\n").data(using: .utf8)!)
    exit(2)
}

func openFiles(_ paths: [String]) -> [EvtxFile] {
    findEvtxFiles(paths.map { URL(fileURLWithPath: $0) }).compactMap { url in
        do { return try EvtxFile(url: url) } catch {
            FileHandle.standardError.write("skip \(url.lastPathComponent): \(error)\n".data(using: .utf8)!)
            return nil
        }
    }
}

func jsonString(_ s: String) -> String {
    var r = "\""
    for ch in s.unicodeScalars {
        switch ch {
        case "\"": r += "\\\""
        case "\\": r += "\\\\"
        case "\n": r += "\\n"
        case "\r": r += "\\r"
        case "\t": r += "\\t"
        default:
            if ch.value < 0x20 { r += String(format: "\\u%04x", ch.value) } else { r.unicodeScalars.append(ch) }
        }
    }
    return r + "\""
}

struct ChunkStat: Sendable {
    var valid = false, badHeaderCRC = false, badDataCRC = false, beyond = false, stale = false
    var records = 0, parseErrors = 0, missing = 0, foreign = 0, invalidText = 0, timeSkew = 0
    var minTs = Int64.max, maxTs = Int64.min
    var firstError: String?
}

func stats(_ paths: [String]) {
    let files = openFiles(paths)
    let t0 = Date()
    let summaries = parallelMap(files.count) { files[$0].summarizeChunks() }
    let jobs = files.indices.flatMap { f in (0..<files[f].physicalChunkCount).map { (f, $0) } }
    let results = parallelMap(jobs.count) { j -> ChunkStat in
        let (fi, ci) = jobs[j]
        let file = files[fi]
        let chunk = EvtxChunk(file: file, index: ci)
        var s = ChunkStat()
        guard let h = chunk.header else { return s }
        s.valid = true
        s.badHeaderCRC = !h.headerChecksumValid
        s.badDataCRC = !h.recordsChecksumValid
        let pos = file.positionFlags(chunk: ci, summaries: summaries[fi])
        s.beyond = pos.contains(.beyondHeader)
        s.stale = pos.contains(.staleChunk)
        for r in chunk.records() {
            let (e, err) = chunk.eventWithError(r)
            s.records += 1
            if e.flags.contains(.parseError) {
                s.parseErrors += 1
                if s.firstError == nil { s.firstError = "rid \(r.recordId) @\(ci):\(r.offset): \(err.map { "\($0)" } ?? "?")" }
            }
            if e.flags.contains(.missingTemplate) { s.missing += 1 }
            if e.flags.contains(.foreignTemplate) { s.foreign += 1 }
            if e.flags.contains(.invalidText) { s.invalidText += 1 }
            if e.flags.contains(.timeSkew) { s.timeSkew += 1 }
            s.minTs = min(s.minTs, e.timestamp)
            s.maxTs = max(s.maxTs, e.timestamp)
        }
        return s
    }
    let elapsed = Date().timeIntervalSince(t0)

    var total = ChunkStat()
    var totalBytes = 0, totalBeyondChunks = 0, totalStaleChunks = 0
    var offset = 0
    print("file | ver | dirty | hdrChunks | chunks | valid | beyond(new/stale) | badCRC(h/d) | records | parseErr | skew | range (UTC)")
    for (fi, file) in files.enumerated() {
        let rs = results[offset..<(offset + file.physicalChunkCount)]
        offset += file.physicalChunkCount
        var s = ChunkStat()
        var beyondNew = 0, beyondStale = 0
        for r in rs {
            s.valid = s.valid || r.valid
            s.records += r.records; s.parseErrors += r.parseErrors; s.missing += r.missing
            s.foreign += r.foreign; s.invalidText += r.invalidText; s.timeSkew += r.timeSkew
            s.minTs = min(s.minTs, r.minTs); s.maxTs = max(s.maxTs, r.maxTs)
            if r.beyond && r.records > 0 { if r.stale { beyondStale += 1 } else { beyondNew += 1 } }
            if r.firstError != nil && s.firstError == nil { s.firstError = r.firstError }
        }
        let validCount = rs.filter(\.valid).count
        let crcH = rs.filter(\.badHeaderCRC).count, crcD = rs.filter(\.badDataCRC).count
        let range = s.records > 0 ? FileTime.format(s.minTs, fractionDigits: 0, separator: 32, zulu: false)
            + " … " + FileTime.format(s.maxTs, fractionDigits: 0, separator: 32, zulu: false) : "-"
        print("\(file.url.lastPathComponent) | \(file.header.majorVersion).\(file.header.minorVersion) | \(file.header.isDirty ? 1 : 0) | \(file.header.chunkCount) | \(file.physicalChunkCount) | \(validCount) | \(beyondNew)/\(beyondStale) | \(crcH)/\(crcD) | \(s.records) | \(s.parseErrors) | \(s.timeSkew) | \(range)")
        if let e = s.firstError { print("    first error: \(e)") }
        total.records += s.records; total.parseErrors += s.parseErrors; total.missing += s.missing
        total.invalidText += s.invalidText; total.timeSkew += s.timeSkew
        totalBytes += file.fileSize
        totalBeyondChunks += beyondNew
        totalStaleChunks += beyondStale
        _ = summaries[fi]
    }
    print(String(format: "TOTAL files=%d bytes=%d records=%d parseErrors=%d missingTemplate=%d invalidText=%d timeSkew=%d beyondHeaderChunks(new)=%d stale=%d time=%.3fs (%.0f MB/s)",
                 files.count, totalBytes, total.records, total.parseErrors, total.missing, total.invalidText,
                 total.timeSkew, totalBeyondChunks, totalStaleChunks, elapsed, Double(totalBytes) / elapsed / 1e6))
}

func carve(_ paths: [String]) {
    let files = openFiles(paths)
    let t0 = Date()
    let library = TemplateLibrary()
    let jobs = files.indices.flatMap { f in (0..<files[f].physicalChunkCount).map { (f, $0) } }
    // Pass 1: live records (collect ids, compile templates into the library).
    let liveIds = parallelMap(jobs.count) { j -> [UInt64] in
        let chunk = EvtxChunk(file: files[jobs[j].0], index: jobs[j].1)
        let recs = chunk.records()
        for r in recs { _ = chunk.event(r) }
        chunk.registerTemplates(in: library)
        return recs.map(\.recordId)
    }
    var live = [Int: Set<UInt64>]()
    for (j, ids) in liveIds.enumerated() { live[jobs[j].0, default: []].formUnion(ids) }
    // Pass 2: carve slack.
    struct CarveStat: Sendable { var found = 0, parsed = 0, foreign = 0, missing = 0, errors = 0; var ids: [UInt64] = [] }
    let carved = parallelMap(jobs.count) { j -> CarveStat in
        let chunk = EvtxChunk(file: files[jobs[j].0], index: jobs[j].1, library: library)
        var s = CarveStat()
        for r in chunk.carve() {
            s.found += 1
            let e = chunk.event(r)
            if e.flags.contains(.parseError) { s.errors += 1 } else { s.parsed += 1 }
            if e.flags.contains(.foreignTemplate) { s.foreign += 1 }
            if e.flags.contains(.missingTemplate) { s.missing += 1 }
            s.ids.append(r.recordId)
        }
        return s
    }
    var perFile = [Int: (found: Int, newIds: Set<UInt64>)]()
    var t = CarveStat()
    for (j, s) in carved.enumerated() {
        t.found += s.found; t.parsed += s.parsed; t.foreign += s.foreign; t.missing += s.missing; t.errors += s.errors
        let f = jobs[j].0
        var entry = perFile[f] ?? (0, [])
        entry.found += s.found
        for id in s.ids where !(live[f]?.contains(id) ?? false) { entry.newIds.insert(id) }
        perFile[f] = entry
    }
    for (f, e) in perFile.sorted(by: { $0.value.found > $1.value.found }) where e.found > 0 {
        print("\(files[f].url.lastPathComponent) | carved \(e.found) | ids not among live: \(e.newIds.count)")
    }
    let newTotal = perFile.values.reduce(0) { $0 + $1.newIds.count }
    print(String(format: "TOTAL carved=%d parsedOK=%d parseErrors=%d foreignTemplate=%d missingTemplate=%d newIds=%d library=%d time=%.3fs",
                 t.found, t.parsed, t.errors, t.foreign, t.missing, newTotal, library.count, Date().timeIntervalSince(t0)))
}

func dump(_ path: String, xml: Bool, jsonl: Bool, limit: Int) {
    guard let file = openFiles([path]).first else { fail("cannot open \(path)") }
    var n = 0
    for ci in 0..<file.physicalChunkCount {
        let chunk = EvtxChunk(file: file, index: ci)
        for r in chunk.records() {
            if n >= limit { return }
            n += 1
            if xml {
                let text: String
                do { text = try chunk.xml(r) } catch { text = "<!-- parse error: \(error) -->" }
                let off = file.dataOffset + ci * EvtxFile.chunkSize + r.offset
                print(jsonl ? "{\"off\":\(off),\"rid\":\(r.recordId),\"xml\":\(jsonString(text))}" : text)
            } else {
                let e = chunk.event(r)
                var s = "{\"rid\":\(e.recordId),\"time\":\(jsonString(FileTime.iso8601(e.timestamp)))"
                s += ",\"provider\":\(jsonString(e.provider)),\"eid\":\(e.eventId),\"channel\":\(jsonString(e.channel))"
                s += ",\"computer\":\(jsonString(e.computer)),\"level\":\(e.level.map(String.init) ?? "null")"
                s += ",\"user\":\(e.userSid.map(jsonString) ?? "null"),\"flags\":\(e.flags.rawValue),\"fields\":["
                s += e.fields.map { "[\(jsonString($0.name)),\(jsonString($0.value))]" }.joined(separator: ",")
                print(s + "]}")
            }
        }
    }
}

var args = Array(CommandLine.arguments.dropFirst())
guard let cmd = args.first else { fail(usage) }
args.removeFirst()
var limit = Int.max
if let i = args.firstIndex(of: "--limit"), i + 1 < args.count {
    limit = Int(args[i + 1]) ?? .max
    args.removeSubrange(i...(i + 1))
}
let jsonl = args.contains("--jsonl")
args.removeAll { $0 == "--jsonl" }

func ingest(_ args: [String]) {
    let paths = args.filter { !$0.hasPrefix("--") }
    guard paths.count >= 2 else { fail("usage: evtxdump ingest <case.daybook> <file|dir>... [--windows|--linux] [--no-merge] [--no-carve] [--no-hash]") }
    let inputs = paths.dropFirst().map { URL(fileURLWithPath: $0) }
    let caseURL = URL(fileURLWithPath: paths[0])
    // Without a flag: Linux when the folders hold an extracted UAC collection and no EVTX files.
    let linux = args.contains("--linux") || (!args.contains("--windows") && findEvtxFiles(inputs).isEmpty
                                             && !UacCollection.find(in: inputs).isEmpty)
    let t0 = Date()
    let lastPhase = Locked<String>("")
    let report: @Sendable (ImportProgress) -> Void = { p in
        if lastPhase.swap(p.phase.rawValue) != p.phase.rawValue {
            print(String(format: "%7.3fs  %@  (events %d)", Date().timeIntervalSince(t0), p.phase.rawValue, p.events))
        }
    }
    do {
        let s: ImportSummary
        if linux {
            var options = LinuxImportOptions()
            options.hashSources = !args.contains("--no-hash")
            print("linux (UAC)")
            s = try UacImporter(sources: inputs, caseURL: caseURL, options: options).run(progress: report)
        } else {
            var options = ImportOptions()
            options.mergeDuplicates = !args.contains("--no-merge")
            options.carveSlack = !args.contains("--no-carve")
            options.hashSources = !args.contains("--no-hash")
            s = try CaseImporter(sources: inputs, caseURL: caseURL, options: options).run(progress: report)
        }
        print("files=\(s.files) events=\(s.events) duplicates=\(s.duplicates) carved=\(s.carved) parseErrors=\(s.parseErrors) failed=\(s.failedFiles.count) elapsed=\(String(format: "%.2f", s.elapsed))s")
        for f in s.failedFiles { print("  failed: \(f)") }
    } catch {
        fail("ingest failed: \(error)")
    }
}

/// evtxdump query <case.daybook> [key=value | key!=value]... [--facet key]
func query(_ args: [String]) {
    guard let path = args.first else { fail("usage: evtxdump query <case.daybook> [key=value|key!=value]... [--facet key]") }
    do {
        var t = Date()
        let store = try CaseStore(url: URL(fileURLWithPath: path))
        print(String(format: "open: %.1f ms, events %d, fields %d, fulltext %@", Date().timeIntervalSince(t) * 1000,
                     store.eventCount, store.fieldNames.count, store.fullTextReady ? "yes" : "no"))
        var filters: [FieldFilter] = []
        var facetKey: String?
        var rest = Array(args.dropFirst())
        if let i = rest.firstIndex(of: "--facet"), i + 1 < rest.count { facetKey = rest[i + 1]; rest.removeSubrange(i...(i + 1)) }
        for a in rest {
            if let r = a.range(of: "!=") {
                filters.append(FieldFilter(key: String(a[..<r.lowerBound]), value: String(a[r.upperBound...]), negated: true))
            } else if let r = a.range(of: "=") {
                filters.append(FieldFilter(key: String(a[..<r.lowerBound]), value: String(a[r.upperBound...])))
            }
        }
        t = Date()
        let result = try store.evaluate(filters)
        print(String(format: "evaluate: %.1f ms -> %d events", Date().timeIntervalSince(t) * 1000, result.count))
        t = Date()
        let rows = try store.rows(result.ids(0..<min(5, result.count)))
        print(String(format: "rows: %.1f ms", Date().timeIntervalSince(t) * 1000))
        for r in rows {
            let fields = r.pairs.prefix(4).map { store.keyName($0.key) + "=" + store.string($0.value) }.joined(separator: " ")
            print("  #\(r.id) \(FileTime.format(r.ts, fractionDigits: 3, separator: 32, zulu: false)) \(r.computer) \(r.channel) \(r.eventId) | \(fields.prefix(160))")
        }
        if let facetKey {
            t = Date()
            let f = try store.facet(facetKey, within: result.list)
            print(String(format: "facet %@: %.1f ms", facetKey, Date().timeIntervalSince(t) * 1000))
            for v in f.prefix(10) { print("  \(v.count)\t\(v.value)") }
        }
        if let first = rows.first {
            t = Date()
            let d = try store.detail(first.id)
            print(String(format: "detail: %.1f ms, xml %d chars, text %d chars, raw %d bytes, dups %d", Date().timeIntervalSince(t) * 1000,
                         d?.xml?.count ?? 0, d?.text?.count ?? 0, d?.raw?.count ?? 0, d?.duplicates.count ?? 0))
            if let d { print("source: \(d.sourceState)") }
            if let text = d?.text { print(text.prefix(600)) }
        }
    } catch {
        fail("query failed: \(error)")
    }
}

/// evtxdump dql <case.daybook> "<query>" — runs a DQL query (times in UTC).
func dql(_ args: [String]) {
    guard args.count >= 2 else { fail("usage: evtxdump dql <case.daybook> \"<query>\"") }
    do {
        let store = try CaseStore(url: URL(fileURLWithPath: args[0]))
        let engine = DQLEngine(store: store) { text in
            // Minimal UTC parser for the CLI: "YYYY-MM-DD[ HH:MM[:SS]]".
            let parts = text.split(whereSeparator: { $0 == " " || $0 == "T" })
            let d = parts.first?.split(separator: "-").compactMap { Int64($0) } ?? []
            guard d.count == 3 else { return nil }
            var secs: Int64 = 0
            if parts.count > 1 {
                let t = parts[1].split(separator: ":").compactMap { Int64($0) }
                secs = (t.first ?? 0) * 3600 + (t.count > 1 ? t[1] * 60 : 0) + (t.count > 2 ? t[2] : 0)
            }
            return FileTime.fromUnixSeconds(FileTime.days(fromCivil: d[0], Int(d[1]), Int(d[2])) * 86_400 + secs)
        }
        let r = try engine.run(args[1])
        print(String(format: "%.1f ms -> %d events%@", r.elapsedMs, r.events.count,
                     r.customOrder ? " (custom order)" : r.descending ? " (desc)" : ""))
        if let keys = r.groupKeys {
            print("  group by \(keys.joined(separator: ", ")): \(r.groups.count) groups\(r.groupsTruncated ? " (truncated)" : "")")
            for g in r.groups.prefix(12) { print("  \(g.count)\t\(g.values.joined(separator: " | "))") }
        } else {
            let n = r.events.count
            let idx = r.customOrder || !r.descending ? Array(0..<min(5, n)) : Array((max(0, n - 5)..<n).reversed())
            let rows = try store.rows(idx.map { r.events.id(at: $0) })
            for row in rows {
                let f = row.pairs.prefix(3).map { store.keyName($0.key) + "=" + store.string($0.value).prefix(60) }.joined(separator: " ")
                print("  \(FileTime.format(row.ts, fractionDigits: 3, separator: 32, zulu: false)) \(row.computer) \(row.eventId) | \(f)")
            }
        }
    } catch let e as DQLError {
        print("DQL error at \(e.position): \(e.message)")
    } catch {
        fail("dql failed: \(error)")
    }
}

/// evtxdump entities <case.daybook> [--rebuild]
func entities(_ args: [String]) {
    guard let path = args.first else { fail("usage: evtxdump entities <case.daybook> [--rebuild]") }
    let url = URL(fileURLWithPath: path)
    do {
        if args.contains("--rebuild") {
            let t0 = Date()
            let r = try EntityBuilder(caseURL: url).run()
            print(String(format: "rebuilt in %.2fs: hosts=%d users=%d ips=%d", Date().timeIntervalSince(t0), r.hosts, r.users, r.ips))
        }
        let store = try CaseStore(url: url)
        for kind in EntityKind.allCases {
            let list = try store.entities(kind)
            print("== \(kind) (\(list.count))")
            for e in list.prefix(kind == .user ? 25 : 15) {
                let roles = e.roles.sorted { $0.key < $1.key }.map { "\(EntityRole(rawValue: $0.key).map { "\($0)" } ?? "?")=\($0.value)" }.joined(separator: ",")
                print("  \(e.events)\t\(e.display)\(e.builtin ? " [builtin]" : "")\(e.sid.map { " " + $0 } ?? "") | aliases: \(e.aliases.prefix(4).joined(separator: "; ")) | \(roles)")
            }
        }
    } catch {
        fail("entities failed: \(error)")
    }
}

/// evtxdump sessions|processes <case.daybook>
func analysis(_ cmd: String, _ args: [String]) {
    guard let path = args.first else { fail("usage: evtxdump \(cmd) <case.daybook>") }
    do {
        let store = try CaseStore(url: URL(fileURLWithPath: path))
        let t0 = Date()
        if cmd == "sessions" {
            let a = store.platform == .linux ? try LinuxSessionBuilder.build(store) : try SessionBuilder.build(store)
            let closed = a.sessions.filter { $0.end != nil }.count
            print(String(format: "%.0f ms: sessions=%d closed=%d open=%d privileged=%d unmatchedEnds=%d hostsWithoutBoot=%@",
                         Date().timeIntervalSince(t0) * 1000, a.sessions.count, closed, a.sessions.count - closed,
                         a.sessions.filter(\.privileged).count, a.unmatchedEnds, a.hostsWithoutBootInfo.joined(separator: ",")))
            var byType: [Int: Int] = [:]
            for s in a.sessions { byType[s.logonType ?? -1, default: 0] += 1 }
            print("  by type: \(byType.sorted { $0.key < $1.key })")
            let rdp = try RDPSessionBuilder.build(store)
            print("  RDP (LSM) chains: \(rdp.count)")
            for r in rdp.prefix(5) { print("    \(r.host) #\(r.sessionId) \(r.user) \(r.address): \(r.steps)") }
        } else {
            for source in store.platform == .linux ? [.audit] : ProcessSource.allCases.filter({ $0 != .audit }) {
                let f = try ProcessTreeBuilder.build(store, source: source)
                print(String(format: "%@: %.0f ms processes=%d roots=%d synthetic=%d linkedByPID=%d", source.rawValue,
                             Date().timeIntervalSince(t0) * 1000, f.processCount, f.roots.count, f.syntheticCount, f.pidLinkedCount))
                func depth(_ n: ProcessNode) -> Int { 1 + (n.children?.map(depth).max() ?? 0) }
                print("  max depth \(f.roots.map(depth).max() ?? 0); top roots: " + f.roots.prefix(4).map { "\($0.name)(\($0.children?.count ?? 0))\($0.synthetic ? "*" : "")" }.joined(separator: ", "))
            }
        }
    } catch {
        fail("\(cmd) failed: \(error)")
    }
}

/// evtxdump sigma <case.daybook> --pack rules.json [--dir rules/] [--compile-only] [--rule <id|path part>] [--top N]
func sigma(_ args: [String]) {
    guard let path = args.first, let packIdx = args.firstIndex(of: "--pack"), packIdx + 1 < args.count else {
        fail("usage: evtxdump sigma <case.daybook> --pack rules.json [--dir <folder>] [--compile-only] [--rule <id|path>] [--top N]")
    }
    func opt(_ name: String) -> String? { args.firstIndex(of: name).flatMap { $0 + 1 < args.count ? args[$0 + 1] : nil } }
    do {
        let t0 = Date()
        var set = try SigmaRuleSet.pack(Data(contentsOf: URL(fileURLWithPath: args[packIdx + 1])))
        if let dir = opt("--dir") { set.merge(.folder(URL(fileURLWithPath: dir), name: "custom")) }
        print(String(format: "loaded %d rules (%d failed to load, %d aliases) in %.2fs", set.rules.count, set.failures.count,
                     set.aliases.count, Date().timeIntervalSince(t0)))
        for f in set.failures { print("  not loaded: \(f.source) \(f.path): \(f.message)") }
        let store = try CaseStore(url: URL(fileURLWithPath: path))
        let catalog = SigmaFieldCatalog(has: { store.exactKeyId($0) != nil }, aliases: set.aliases, platform: store.platform)
        if let needle = opt("--rule") {
            for r in set.rules where r.id == needle || r.path.contains(needle) {
                let c = SigmaCompiler.compile(r, catalog: catalog)
                print("== \(r.title) [\(r.source) \(r.path)]")
                print("variants: \(c.variants.joined(separator: " ; "))")
                print("absent fields: \(c.absentFields.joined(separator: ", "))")
                print(c.unsupported.map { "UNSUPPORTED: " + $0 } ?? c.query)
            }
            return
        }
        if args.contains("--verify") {
            let t1 = Date()
            let r = try SigmaVerifier.run(store: store, rules: set)
            print(String(format: "verify: %d rules, %d candidate events checked, %d skipped, %d mismatches, %.1fs",
                         r.rulesChecked, r.eventsChecked, r.skipped.count, r.mismatches.count, Date().timeIntervalSince(t1)))
            for (title, why) in r.skipped.prefix(10) { print("  skipped: \(title): \(why)") }
            for title in r.inconclusive { print("  inconclusive (regex time limit): \(title)") }
            for m in r.mismatches.prefix(40) {
                print("  MISMATCH \(m.rule.title) [\(m.rule.path)]: engine-only \(m.extra.count) \(m.extra.prefix(3)), direct-only \(m.missing.count) \(m.missing.prefix(3))")
            }
            return
        }
        if args.contains("--compile-only") {
            let t1 = Date()
            let compiled = set.rules.map { SigmaCompiler.compile($0, catalog: catalog) }
            print(String(format: "compiled in %.2fs", Date().timeIntervalSince(t1)))
            var reasons: [String: Int] = [:]
            for c in compiled { if let u = c.unsupported { reasons[u, default: 0] += 1 } }
            print("supported: \(compiled.filter { $0.unsupported == nil }.count), unsupported: \(reasons.values.reduce(0, +))")
            for (r, n) in reasons.sorted(by: { $0.value > $1.value }) { print("  \(n)\t\(r)") }
            return
        }
        let summary = try SigmaRunner.run(store: store, rules: set)
        print(String(format: "run: %d rules, %d evaluated, %d unsupported, %d not loaded, %d errors, %d with hits, %d events hit, %.2fs",
                     summary.total, summary.evaluated, summary.unsupported, summary.failedToParse, summary.errors,
                     summary.withHits, summary.hitEvents, summary.elapsedMs / 1000))
        let rules = try store.detectionRules()
        let top = Int(opt("--top") ?? "") ?? 15
        print("slowest:")
        for r in rules.sorted(by: { $0.elapsedMs > $1.elapsedMs }).prefix(8) {
            print(String(format: "  %7.1f ms  %@ [%@]", r.elapsedMs, r.title, r.path))
        }
        for r in rules where r.error != nil { print("  error: \(r.title) [\(r.path)]: \(r.error!)") }
        for r in rules where !r.warnings.isEmpty { print("  warning: \(r.title) [\(r.path)]: \(r.warnings.joined(separator: "; "))") }
        let meta = try store.detectionMeta()
        print("phases: compile \(meta["compile_ms"] ?? "?") ms, prefetch \(meta["prefetch_ms"] ?? "?") ms (\(meta["prefetch_predicates"] ?? "?") predicates), evaluate \(meta["evaluate_ms"] ?? "?") ms")
        print("hits by level (top \(top)):")
        for r in rules.filter({ $0.hits > 0 }).sorted(by: { ($0.levelRank, $0.hits) > ($1.levelRank, $1.hits) }).prefix(top) {
            print("  \(r.level ?? "?")\t\(r.hits)\t\(r.hosts) host(s)\t\(r.title) [\(r.source)]")
        }
    } catch {
        fail("sigma failed: \(error)")
    }
}

/// evtxdump export <case.daybook> <out.csv|.jsonl|.xlsx> [DQL] [--fields a,b]
func exportCmd(_ args: [String]) {
    guard args.count >= 2 else { fail("usage: evtxdump export <case.daybook> <out.csv|out.jsonl|out.xlsx> [DQL] [--fields a,b]") }
    let out = URL(fileURLWithPath: args[1])
    let format: ExportFormat = out.pathExtension == "xlsx" ? .xlsx : out.pathExtension == "jsonl" ? .jsonl : .csv
    let fields = args.firstIndex(of: "--fields").flatMap { $0 + 1 < args.count ? args[$0 + 1].split(separator: ",").map(String.init) : nil } ?? []
    let query = args.count > 2 && !args[2].hasPrefix("--") ? args[2] : ""
    do {
        let store = try CaseStore(url: URL(fileURLWithPath: args[0]))
        let r = try DQLEngine(store: store, parseTime: { _ in nil }).run(query)
        let t0 = Date()
        let n = try CaseExporter(store: store, format: format, fields: fields, zoneLabel: "UTC") { FileTime.iso8601($0) }
            .export(r.events, to: out, info: [("Query", query)])
        print(String(format: "exported %d rows to %@ in %.2fs", n, out.path, Date().timeIntervalSince(t0)))
    } catch {
        fail("export failed: \(error)")
    }
}

final class Locked<T>: @unchecked Sendable {
    private var value: T
    private let lock = NSLock()
    init(_ v: T) { value = v }
    func swap(_ v: T) -> T { lock.lock(); defer { lock.unlock() }; let old = value; value = v; return old }
}

/// evtxdump pack-rules <sigma_all_rules.zip> <tag> [hayabusa.zip <commit>] <out.json> [--sigma-published T] [--hayabusa-published T]
func packRules(_ all: [String]) {
    var args = all
    func option(_ name: String) -> String? {
        guard let i = args.firstIndex(of: name), i + 1 < args.count else { return nil }
        defer { args.removeSubrange(i...(i + 1)) }
        return args[i + 1]
    }
    let sigmaPublished = option("--sigma-published"), hayabusaPublished = option("--hayabusa-published")
    guard args.count == 3 || args.count == 5 else {
        fail("usage: evtxdump pack-rules <sigma_all_rules.zip> <release tag> [<hayabusa-rules.zip> <commit>] <out.json>")
    }
    do {
        let sigma = SigmaPackBuilder.Archive(data: try Data(contentsOf: URL(fileURLWithPath: args[0])), version: args[1],
                                             published: sigmaPublished, url: "https://github.com/SigmaHQ/sigma/releases/download/\(args[1])/sigma_all_rules.zip")
        let hayabusa = args.count == 5 ? SigmaPackBuilder.Archive(data: try Data(contentsOf: URL(fileURLWithPath: args[2])),
                                                                  version: args[3], published: hayabusaPublished,
                                                                  url: "https://codeload.github.com/Yamato-Security/hayabusa-rules/zip/\(args[3])") : nil
        let t0 = Date()
        let (json, s) = try SigmaPackBuilder.build(sigma: sigma, hayabusa: hayabusa)
        try json.write(to: URL(fileURLWithPath: args.last!))
        print(String(format: "%.0f ms: SigmaHQ %@ windows=%d linux=%d · Hayabusa %@ %d · aliases %d · %.1f MB", Date().timeIntervalSince(t0) * 1000,
                     s.sigmaVersion, s.sigmaWindows, s.sigmaLinux, s.hayabusaVersion, s.hayabusa, s.aliases, Double(json.count) / 1e6))
    } catch {
        fail("pack-rules failed: \(error)")
    }
}

switch cmd {
case "pack-rules": packRules(args)
case "ingest": ingest(args)
case "query": query(args)
case "dql": dql(args)
case "entities": entities(args)
case "sigma": sigma(args)
case "export": exportCmd(args)
case "sessions", "processes": analysis(cmd, args)
case "stats": stats(args)
case "carve": carve(args)
case "xml", "json":
    guard let path = args.first else { fail(usage) }
    dump(path, xml: cmd == "xml", jsonl: jsonl, limit: limit)
default: fail(usage)
}
