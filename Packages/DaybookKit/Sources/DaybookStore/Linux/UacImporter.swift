import CryptoKit
import EvtxCore
import Foundation

public struct LinuxImportOptions: Sendable {
    /// SHA-256 of every source file (chain of custody).
    public var hashSources = true
    public init() {}
}

/// Builds a case from extracted UAC collections of Linux systems: syslog-format logs under
/// `/var/log` (plain or rotated `.gz` / `.xz`) and the login records (wtmp, btmp, utmp, lastlog).
/// Every file under `/var/log` is listed as a source; files of formats not parsed yet say so.
public final class UacImporter: @unchecked Sendable {
    public let sources: [URL]
    public let caseURL: URL
    public let options: LinuxImportOptions

    public init(sources: [URL], caseURL: URL, options: LinuxImportOptions = LinuxImportOptions()) {
        self.sources = sources
        self.caseURL = caseURL
        self.options = options
    }

    public func run(progress: @escaping @Sendable (ImportProgress) -> Void,
                    cancelled: @escaping @Sendable () -> Bool = { false }) throws -> ImportSummary {
        let t0 = Date()
        let fm = FileManager.default
        guard !fm.fileExists(atPath: caseURL.path) else {
            throw CocoaError(.fileWriteFileExists, userInfo: [NSFilePathErrorKey: caseURL.path])
        }
        try fm.createDirectory(at: caseURL, withIntermediateDirectories: true)
        var summary: ImportSummary
        do {
            summary = try build(progress: progress, cancelled: cancelled)
        } catch {
            try? fm.removeItem(at: caseURL)
            throw error
        }
        progress(ImportProgress(phase: .entities, fraction: 0, events: summary.events))
        try EntityBuilder(caseURL: caseURL).run()
        summary.elapsed = Date().timeIntervalSince(t0)
        try CaseImporter.writeManifest(caseURL: caseURL, sources: sources, summary: summary, platform: "linux")
        progress(ImportProgress(phase: .done, fraction: 1, events: summary.events))
        return summary
    }

    private struct FileResult {
        var jobs: [LinuxJob] = []
        var keys: [[RecordKey]] = []
        var format: String
        var skipped = 0
        var notes: [String] = []
        var error: String?
    }

    // swiftlint:disable:next function_body_length
    private func build(progress: @escaping @Sendable (ImportProgress) -> Void,
                       cancelled: @escaping @Sendable () -> Bool) throws -> ImportSummary {
        var summary = ImportSummary()
        progress(ImportProgress(phase: .scanning, fraction: 0, events: 0))
        let collections = UacCollection.find(in: sources)
        guard !collections.isEmpty else {
            throw CocoaError(.fileReadNoSuchFile, userInfo: [NSLocalizedDescriptionKey: String(localized: "В выбранных папках не найден распакованный сбор UAC: нужна папка [root] и рядом uac.log, live_response или bodyfile")])
        }
        let plans = LinuxPlan.sources(collections)
        let users = collections.map { $0.users() }
        if cancelled() { throw CancellationError() }

        progress(ImportProgress(phase: .hashing, fraction: 0, events: 0))
        let hashes: [String] = options.hashSources ? parallelMap(plans.count) { i in
            guard let data = try? Data(contentsOf: plans[i].url, options: .alwaysMapped) else { return "" }
            return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        } : Array(repeating: "", count: plans.count)
        if cancelled() { throw CancellationError() }

        // Pass 1: formats, jobs and sort keys.
        progress(ImportProgress(phase: .indexing, fraction: 0, events: 0))
        let results: [FileResult] = parallelMap(plans.count) { i in Self.scan(plans[i], src: i, users: users[plans[i].collection]) }
        if cancelled() { throw CancellationError() }
        var jobs: [LinuxJob] = [], jobKeys: [[RecordKey]] = []
        for r in results {
            jobs += r.jobs
            jobKeys += r.keys
            if let e = r.error { summary.failedFiles.append(e) }
        }

        progress(ImportProgress(phase: .sorting, fraction: 0, events: 0))
        let assignment = CaseWriter.assign(jobKeys, merge: false)
        if cancelled() { throw CancellationError() }

        // Pass 2: records, re-read job by job (a file split into several jobs is read or unpacked once).
        let allJobs = jobs, allKeys = jobKeys
        let contents = ContentCache(jobs.map(\.source))
        let produce: @Sendable (Range<Int>) -> [[CaseRecord?]] = { range in
            parallelMap(range.count) { k in
                let j = range.lowerBound + k
                let job = allJobs[j], plan = plans[job.source], keys = allKeys[j]
                var records: [CaseRecord] = []
                defer { contents.finished(job.source) }
                if let data = contents.content(job.source, url: plan.url) {
                    switch plan.kind {
                    case .text: records = LinuxText.records(plan, data: data, job: job)
                    default: records = LinuxBinary.events(plan, data: data, src: job.source,
                                                          users: users[plan.collection], records: true).records
                    }
                }
                // One record per key, at the key's time (the file is evidence: it should not change between
                // passes, but if it does the case must stay consistent).
                return keys.enumerated().map { i, key -> CaseRecord? in
                    var r = i < records.count ? records[i] : CaseRecord(
                        timestamp: key.ts, writtenTime: key.ts, recordId: key.rid, provider: "", channel: plan.channel,
                        computer: plan.host, flags: [.parseError],
                        fields: [CaseField("Message", String(localized: "Запись не прочитана повторно: файл изменился во время импорта"))])
                    r.timestamp = key.ts
                    r.writtenTime = key.ts
                    return r
                }
            }
        }

        let sourceRows: [CaseSource] = plans.enumerated().map { i, p in
            var s = CaseSource(url: p.url, size: p.size, sha256: hashes[i], format: results[i].format)
            s.channel = p.channel
            s.host = p.host
            s.skipped = results[i].skipped
            s.note = results[i].notes.isEmpty ? nil : results[i].notes.joined(separator: "; ")
            return s
        }
        let infos = collections.map(\.info)
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys]
        let infoJSON = String(data: (try? enc.encode(infos)) ?? Data("[]".utf8), encoding: .utf8) ?? "[]"
        let written = try CaseWriter(caseURL: caseURL).write(
            assignment: assignment, jobKeys: jobKeys, sources: sourceRows, groupSize: 8,
            meta: [("platform", "linux"), ("collector", "uac"), ("uac.collections", infoJSON),
                   ("option.hashSources", options.hashSources ? "1" : "0")],
            failedFiles: summary.failedFiles, requestedSources: sources,
            produce: produce, progress: progress, cancelled: cancelled)
        summary.files = results.filter { !$0.keys.allSatisfy(\.isEmpty) }.count
        summary.events = written.events
        summary.parseErrors = written.parseErrors
        return summary
    }

    /// Pass 1 of one source file.
    private static func scan(_ p: LinuxSourcePlan, src: Int, users: [Int: String]) -> FileResult {
        switch p.kind {
        case let .unsupported(name):
            let note = name == "journal" ? String(localized: "журнал systemd (journald): разбор пока не поддерживается")
                                         : String(localized: "формат \(name) пока не поддерживается")
            return FileResult(format: name, notes: [note])
        default: break
        }
        if p.size == 0 { return FileResult(format: "empty", notes: [String(localized: "пустой файл")]) }
        let read = LogBytes.read(p.url)
        var notes: [String] = []
        if read.compression != .none { notes.append(String(localized: "сжат \(read.compression.rawValue)")) }
        guard let data = read.data else {
            let reason = read.error ?? String(localized: "файл не читается")
            return FileResult(format: "unreadable", notes: notes + [reason], error: "\(p.url.path): \(reason)")
        }
        switch p.kind {
        case .text:
            guard let plan = LinuxText.plan(p, data: data, src: src) else {
                if data.prefix(4096).contains(0) {
                    return FileResult(format: "binary", notes: notes + [String(localized: "двоичный файл — формат не поддерживается")])
                }
                return FileResult(format: "text", notes: notes + [String(localized: "формат строк не распознан — файл не разобран")])
            }
            var r = FileResult(jobs: plan.jobs, keys: plan.keys, format: plan.format.name)
            let all = plan.keys.joined()
            r.skipped = plan.skipped
            let assumed = all.contains { $0.flags & RecordFlags.zoneAssumed.rawValue != 0 }
            if all.contains(where: { $0.flags & RecordFlags.yearInferred.rawValue != 0 }) {
                notes.append(p.referenceFromBodyfile
                    ? String(localized: "год восстановлен по времени изменения файла из bodyfile")
                    : String(localized: "год восстановлен по времени изменения копии файла"))
            }
            if plan.noDates {
                notes.append(p.referenceFromBodyfile
                    ? String(localized: "у записей нет своего времени: взято время изменения файла из bodyfile")
                    : String(localized: "у записей нет своего времени: взято время изменения копии файла"))
            }
            if assumed {
                notes.append(p.zone == nil ? String(localized: "пояс в строках не указан и в сборе не записан: принято UTC")
                                           : String(localized: "пояс в строках не указан: принят \(p.zoneName) из uac.log"))
            }
            r.notes = notes
            return r
        default:
            let e = LinuxBinary.events(p, data: data, src: src, users: users, records: false)
            let job = LinuxJob(source: src, bytes: 0..<data.count, firstLine: 1)
            let format: String
            switch p.kind {
            case .wtmp: format = "wtmp"
            case .btmp: format = "btmp"
            case .lastlog: format = "lastlog"
            default: format = "utmp"
            }
            var r = FileResult(jobs: [job], keys: [e.keys], format: format)
            r.skipped = e.skipped
            if e.skipped > 0 { notes.append(String(localized: "записей с недопустимым типом или временем, а также неполных: \(e.skipped)")) }
            r.notes = notes
            return r
        }
    }
}

/// Unpacked content of the files being written, shared by the jobs of one file and dropped after
/// its last job.
final class ContentCache: @unchecked Sendable {
    private let lock = NSLock()
    private var data: [Int: Data] = [:]
    private var remaining: [Int: Int] = [:]
    private var fileLocks: [Int: NSLock] = [:]

    init(_ jobSources: [Int]) {
        for s in jobSources { remaining[s, default: 0] += 1 }
    }

    func content(_ source: Int, url: URL) -> Data? {
        let fileLock = lock.withLock { () -> NSLock in
            if let l = fileLocks[source] { return l }
            let l = NSLock()
            fileLocks[source] = l
            return l
        }
        return fileLock.withLock {
            if let d = lock.withLock({ data[source] }) { return d }
            guard let d = LogBytes.read(url).data else { return nil }
            lock.withLock { data[source] = d }
            return d
        }
    }

    func finished(_ source: Int) {
        lock.withLock {
            remaining[source, default: 1] -= 1
            if remaining[source]! <= 0 { data[source] = nil }
        }
    }
}
