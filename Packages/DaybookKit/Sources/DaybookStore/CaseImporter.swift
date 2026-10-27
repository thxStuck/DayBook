import CryptoKit
import EvtxCore
import Foundation

public struct ImportOptions: Sendable {
    /// Recover records from chunk slack space.
    public var carveSlack = true
    /// SHA-256 of every source file (chain of custody).
    public var hashSources = true
    /// Collapse identical events (live copy + VSS copy + slack remnant) into one event that
    /// carries the `.duplicate` ("has copies") flag. When off, every copy is its own event.
    public var mergeDuplicates = true
    public init() {}
}

public struct ImportProgress: Sendable {
    public enum Phase: String, Sendable {
        case scanning, hashing, indexing, carving, sorting, writing, postings, finishing, fullText, entities, done
    }
    public var phase: Phase
    public var fraction: Double
    public var events: Int
}

public struct ImportSummary: Sendable, Codable {
    public var files = 0
    public var failedFiles: [String] = []
    public var events = 0
    public var duplicates = 0
    /// Plausible records found in slack (before collapsing copies).
    public var carvedFound = 0
    public var carved = 0
    public var parseErrors = 0
    public var elapsed: Double = 0
}

/// Builds a case database from EVTX sources. Two passes: (1) parse every record's System
/// part in parallel to get sort keys, sort globally and assign time-ordered ids;
/// (2) re-parse in parallel and stream rows to a single SQLite writer.
public final class CaseImporter: @unchecked Sendable {
    public let sources: [URL]
    public let caseURL: URL
    public let options: ImportOptions

    public init(sources: [URL], caseURL: URL, options: ImportOptions = ImportOptions()) {
        self.sources = sources
        self.caseURL = caseURL
        self.options = options
    }

    public func run(progress: @escaping @Sendable (ImportProgress) -> Void,
                    cancelled: @escaping @Sendable () -> Bool = { false }) throws -> ImportSummary {
        let t0 = Date()
        var summary = ImportSummary()
        let fm = FileManager.default
        guard !fm.fileExists(atPath: caseURL.path) else {
            throw CocoaError(.fileWriteFileExists, userInfo: [NSFilePathErrorKey: caseURL.path])
        }
        try fm.createDirectory(at: caseURL, withIntermediateDirectories: true)
        do {
            summary = try build(progress: progress, cancelled: cancelled)
        } catch {
            try? fm.removeItem(at: caseURL)
            throw error
        }
        progress(ImportProgress(phase: .entities, fraction: 0, events: summary.events))
        try EntityBuilder(caseURL: caseURL).run()
        summary.elapsed = Date().timeIntervalSince(t0)
        try writeManifest(summary)
        progress(ImportProgress(phase: .done, fraction: 1, events: summary.events))
        return summary
    }

    private func checkCancel(_ cancelled: @Sendable () -> Bool) throws {
        if cancelled() { throw CancellationError() }
    }

    // swiftlint:disable:next function_body_length
    private func build(progress: @escaping @Sendable (ImportProgress) -> Void,
                       cancelled: @escaping @Sendable () -> Bool) throws -> ImportSummary {
        var summary = ImportSummary()
        progress(ImportProgress(phase: .scanning, fraction: 0, events: 0))

        // Open sources.
        var opened: [EvtxFile] = []
        for url in findEvtxFiles(sources) {
            do { opened.append(try EvtxFile(url: url)) } catch {
                summary.failedFiles.append("\(url.path): \(error)")
            }
        }
        let files = opened
        guard files.count < Int(UInt16.max) else { throw EvtxError.badRecord(offset: 0, reason: "too many files") }
        guard !files.isEmpty else {
            throw CocoaError(.fileReadNoSuchFile, userInfo: [NSLocalizedDescriptionKey: String(localized: "В выбранных источниках не найдено ни одного файла EVTX") + (summary.failedFiles.isEmpty ? "" : ": " + summary.failedFiles.joined(separator: "; "))])
        }
        summary.files = files.count

        progress(ImportProgress(phase: .hashing, fraction: 0, events: 0))
        let hashes: [String] = options.hashSources ? parallelMap(files.count) { i in
            SHA256.hash(data: files[i].mapped.bytes).map { String(format: "%02x", $0) }.joined()
        } : Array(repeating: "", count: files.count)
        try checkCancel(cancelled)

        // Pass 1a: live records → sort keys; compile templates into the shared library.
        let library = TemplateLibrary()
        let summaries = parallelMap(files.count) { files[$0].summarizeChunks() }
        let jobs: [(Int, Int)] = files.indices.flatMap { f in (0..<files[f].physicalChunkCount).map { (f, $0) } }
        progress(ImportProgress(phase: .indexing, fraction: 0, events: 0))
        let live: [[RecordKey]] = parallelMap(jobs.count) { j in
            let (fi, ci) = jobs[j]
            let chunk = EvtxChunk(file: files[fi], index: ci)
            let pos = files[fi].positionFlags(chunk: ci, summaries: summaries[fi])
            let out = chunk.records().map { r -> RecordKey in
                Self.key(chunk.event(r, systemOnly: true), r, fi, ci, extra: pos)
            }
            chunk.registerTemplates(in: library)
            return out
        }
        try checkCancel(cancelled)

        // Pass 1b: slack carving with templates from the whole case.
        progress(ImportProgress(phase: .carving, fraction: 0, events: 0))
        let carved: [[RecordKey]] = options.carveSlack ? parallelMap(jobs.count) { j in
            let (fi, ci) = jobs[j]
            let chunk = EvtxChunk(file: files[fi], index: ci, library: library)
            return chunk.carve().map { r in Self.key(chunk.event(r, systemOnly: true), r, fi, ci, extra: []) }
        } : Array(repeating: [], count: jobs.count)
        try checkCancel(cancelled)

        // Sort globally and assign ids; identical events (same computer, channel, record id,
        // time and event id) from several copies or from slack collapse into one.
        progress(ImportProgress(phase: .sorting, fraction: 0, events: 0))
        summary.carvedFound = carved.reduce(0) { $0 + $1.count }
        let jobKeys = jobs.indices.map { live[$0] + carved[$0] }
        let assignment = CaseWriter.assign(jobKeys, merge: options.mergeDuplicates)
        try checkCancel(cancelled)

        // Pass 2: re-parse in parallel (in groups) while the writer stores the previous group.
        let carveSlack = options.carveSlack
        let produce: @Sendable (Range<Int>) -> [[CaseRecord?]] = { range in
            parallelMap(range.count) { k in
                let j = range.lowerBound + k
                let (fi, ci) = jobs[j]
                let chunk = EvtxChunk(file: files[fi], index: ci, library: library)
                let pos = files[fi].positionFlags(chunk: ci, summaries: summaries[fi])
                var refs = chunk.records().map { r -> EvtxRecordRef in var r = r; r.flags.formUnion(pos); return r }
                if carveSlack { refs += chunk.carve() }
                return refs.enumerated().map { i, r -> CaseRecord? in
                    guard assignment.isKept(job: j, index: i) else { return nil }
                    let e = chunk.event(r)
                    let needsXml = e.flags.contains(.foreignTemplate) || e.flags.contains(.missingTemplate)
                    return CaseRecord(e, rendered: needsXml ? (try? chunk.xml(r)) : nil)
                }
            }
        }
        let sourceRows: [CaseSource] = files.enumerated().map { i, f in
            var empty = 0, beyondNew = 0, beyondStale = 0, badHeader = 0, badData = 0
            for c in summaries[i] {
                guard c.valid else { empty += 1; continue }
                if !c.headerChecksumValid { badHeader += 1 }
                if !c.recordsChecksumValid { badData += 1 }
                guard c.recordCount > 0 else { continue }
                let pos = f.positionFlags(chunk: c.index, summaries: summaries[i])
                if pos.contains(.staleChunk) { beyondStale += 1 } else if pos.contains(.beyondHeader) { beyondNew += 1 }
            }
            var s = CaseSource(url: f.url, size: f.fileSize, sha256: hashes[i], format: "evtx")
            s.evtx = CaseSource.EvtxColumns(headerChunks: Int(f.header.chunkCount), chunks: f.physicalChunkCount,
                                            dirty: f.header.isDirty, emptyChunks: empty, beyondNew: beyondNew,
                                            beyondStale: beyondStale, badHeaderCRC: badHeader, badDataCRC: badData,
                                            trailingBytes: f.trailingBytes,
                                            version: "\(f.header.majorVersion).\(f.header.minorVersion)")
            return s
        }
        let written = try CaseWriter(caseURL: caseURL).write(
            assignment: assignment, jobKeys: jobKeys, sources: sourceRows, groupSize: 256,
            meta: [("platform", "windows"),
                   ("option.carveSlack", options.carveSlack ? "1" : "0"),
                   ("option.mergeDuplicates", options.mergeDuplicates ? "1" : "0"),
                   ("option.hashSources", options.hashSources ? "1" : "0"),
                   ("carvedFound", String(summary.carvedFound))],
            failedFiles: summary.failedFiles, requestedSources: sources,
            produce: produce, progress: progress, cancelled: cancelled)
        summary.events = written.events
        summary.duplicates = written.duplicates
        summary.carved = written.carved
        summary.parseErrors = written.parseErrors
        return summary
    }

    /// Shortest distinguishing labels: the file name, extended with parent folders only
    /// where names collide (several hosts each have a Security.evtx).
    static func uniqueLabels(_ urls: [URL]) -> [String] {
        let parts = urls.map { $0.standardizedFileURL.pathComponents }
        var depth = [Int](repeating: 1, count: urls.count)
        func label(_ i: Int) -> String { parts[i].suffix(depth[i]).joined(separator: "/") }
        for _ in 0..<64 {
            var groups: [String: [Int]] = [:]
            for i in urls.indices { groups[label(i), default: []].append(i) }
            let clashes = groups.values.filter { $0.count > 1 }
            if clashes.isEmpty { break }
            var progressed = false
            for g in clashes { for i in g where depth[i] < parts[i].count { depth[i] += 1; progressed = true } }
            if !progressed { break }
        }
        return urls.indices.map(label)
    }

    private static func key(_ e: EvtxEvent, _ r: EvtxRecordRef, _ fi: Int, _ ci: Int, extra: RecordFlags) -> RecordKey {
        RecordKey(ts: e.timestamp, computer: e.computer, channel: e.channel, rid: e.recordId, eid: e.eventId,
                  src: fi, chunk: ci, off: r.offset, flags: r.flags.union(extra))
    }

    private func writeManifest(_ summary: ImportSummary) throws {
        try Self.writeManifest(caseURL: caseURL, sources: sources, summary: summary, platform: "windows")
    }

    static func writeManifest(caseURL: URL, sources: [URL], summary: ImportSummary, platform: String) throws {
        struct Manifest: Codable {
            var app = "DayBookEvtxMacOS"
            var schema = CaseSchema.version
            var created = Date()
            var platform: String
            var sources: [String]
            var summary: ImportSummary
        }
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        enc.dateEncodingStrategy = .iso8601
        let data = try enc.encode(Manifest(platform: platform, sources: sources.map(\.path), summary: summary))
        try data.write(to: caseURL.appendingPathComponent(CaseSchema.manifestName))
    }
}
