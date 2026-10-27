import AppKit
import DaybookStore
import EvtxCore
import Foundation
import Observation

/// Keeps macOS from throttling long user-initiated work (App Nap) while the window is in the
/// background, and from idle-sleeping in the middle of an import.
nonisolated final class ActivityToken: @unchecked Sendable {
    private let token: NSObjectProtocol
    init(_ reason: String) {
        token = ProcessInfo.processInfo.beginActivity(options: [.userInitiated], reason: reason)
    }
    func end() { ProcessInfo.processInfo.endActivity(token) }
}

/// Runs CPU-heavy work on a GCD thread instead of Swift's cooperative pool, whose threads must
/// not block: `DispatchQueue.concurrentPerform` inside the work then gets every core.
nonisolated func runOffPool<T: Sendable>(_ work: @escaping @Sendable () -> T) async -> T {
    await withCheckedContinuation { cont in
        DispatchQueue.global(qos: .userInitiated).async { cont.resume(returning: work()) }
    }
}

/// Time at which each import phase started (for the scripted import report).
nonisolated final class PhaseLog: @unchecked Sendable {
    private let lock = NSLock()
    private var lines: [String] = []
    private var last: ImportProgress.Phase?
    func note(_ phase: ImportProgress.Phase, _ t: TimeInterval) {
        lock.withLock {
            guard phase != last else { return }
            last = phase
            lines.append(String(format: "%8.3fs  %@", t, "\(phase)"))
        }
    }
    var text: String { lock.withLock { lines.joined(separator: "\n") + "\n" } }
}

nonisolated final class CancelFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false
    var isSet: Bool { lock.withLock { value } }
    func set() { lock.withLock { value = true } }
}

/// Progress of a running import (shown as a sheet).
@Observable
final class ImportState {
    let sources: [URL]
    let caseURL: URL
    var phase: ImportProgress.Phase = .scanning
    var fraction: Double = 0
    var events = 0
    var error: String?
    var startedAt = Date()
    @ObservationIgnored let cancel = CancelFlag()

    init(sources: [URL], caseURL: URL) {
        self.sources = sources
        self.caseURL = caseURL
    }

    var phaseTitle: String {
        switch phase {
        case .scanning: String(localized: "Поиск файлов журналов")
        case .hashing: String(localized: "SHA-256 исходных файлов")
        case .indexing: String(localized: "Разбор записей")
        case .carving: String(localized: "Восстановление записей из slack")
        case .sorting: String(localized: "Сортировка по времени и дедупликация")
        case .writing: String(localized: "Запись событий в базу кейса")
        case .postings: String(localized: "Индекс полей")
        case .finishing: String(localized: "Индексы базы")
        case .fullText: String(localized: "Полнотекстовый индекс")
        case .entities: String(localized: "Реестр хостов, пользователей и IP")
        case .done: String(localized: "Готово")
        }
    }
}

/// What a new case is built from.
enum ImportKind: String, Hashable {
    case windows, linux

    struct Found: Sendable {
        var evtxFiles: Int
        var collections: [UacInfo]
        /// Linux when there are UAC collections and no EVTX files, else Windows.
        var suggested: ImportKind { !collections.isEmpty && evtxFiles == 0 ? .linux : .windows }
    }

    nonisolated static func detect(_ sources: [URL]) -> Found {
        Found(evtxFiles: findEvtxFiles(sources).count, collections: UacCollection.find(in: sources).map(\.info))
    }
}

struct PendingImport: Identifiable {
    let id = UUID()
    let sources: [URL]
    let caseURL: URL
}

@Observable
final class AppModel {
    var caseModel: CaseModel?
    var importState: ImportState?
    /// Sources and case location chosen; waiting for the user to confirm import options.
    var pendingImport: PendingImport?
    var alert: String?
    private(set) var recentCases: [URL] = []

    init() {
        recentCases = (AppDefaults.store.stringArray(forKey: "recentCases") ?? [])
            .map { URL(fileURLWithPath: $0) }
            .filter { FileManager.default.fileExists(atPath: $0.appendingPathComponent(CaseSchema.databaseName).path) }
        // `-openCase <path>` opens a case at launch (scripting and UI tests).
        let args = ProcessInfo.processInfo.arguments
        if let i = args.firstIndex(of: "-openCase"), i + 1 < args.count {
            open(URL(fileURLWithPath: args[i + 1]))
        }
        // `-importLogs <folder> -importTo <case.daybook>` imports with the saved options and
        // writes `<case>.import-report.txt` with phase timings (measuring the app's own path).
        if let i = args.firstIndex(of: "-importLogs"), i + 1 < args.count,
           let j = args.firstIndex(of: "-importTo"), j + 1 < args.count {
            let caseURL = URL(fileURLWithPath: args[j + 1])
            try? FileManager.default.removeItem(at: caseURL)
            var o = ImportOptions()
            o.carveSlack = AppDefaults.store.object(forKey: "import.carveSlack") as? Bool ?? true
            o.mergeDuplicates = AppDefaults.store.object(forKey: "import.mergeDuplicates") as? Bool ?? true
            o.hashSources = AppDefaults.store.object(forKey: "import.hashSources") as? Bool ?? true
            // `-importKind linux` imports the folder as a UAC collection.
            let kind = args.firstIndex(of: "-importKind").flatMap { $0 + 1 < args.count ? ImportKind(rawValue: args[$0 + 1]) : nil }
            startImport(sources: [URL(fileURLWithPath: args[i + 1])], caseURL: caseURL, kind: kind ?? .windows, options: o)
        }
    }

    // MARK: New case

    func newCaseFromLogs() {
        let open = NSOpenPanel()
        open.title = String(localized: "Выберите папку с журналами (.evtx) или распакованный сбор UAC")
        open.prompt = String(localized: "Выбрать")
        open.canChooseDirectories = true
        open.canChooseFiles = true
        open.allowsMultipleSelection = true
        guard open.runModal() == .OK, !open.urls.isEmpty else { return }
        let sources = open.urls

        let save = NSSavePanel()
        save.title = String(localized: "Где сохранить кейс")
        save.prompt = String(localized: "Создать кейс")
        let base = sources.count == 1 ? sources[0].deletingPathExtension().lastPathComponent : "Case"
        save.nameFieldStringValue = base + ".daybook"
        let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent("DayBook")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        save.directoryURL = dir
        guard save.runModal() == .OK, var caseURL = save.url else { return }
        if caseURL.pathExtension != "daybook" { caseURL.appendPathExtension("daybook") }
        // The save panel already asked before replacing an existing item.
        if FileManager.default.fileExists(atPath: caseURL.path) {
            do { try FileManager.default.removeItem(at: caseURL) } catch {
                alert = error.localizedDescription
                return
            }
        }
        pendingImport = PendingImport(sources: sources, caseURL: caseURL)
    }

    func startImport(sources: [URL], caseURL: URL, kind: ImportKind = .windows, options: ImportOptions = ImportOptions()) {
        pendingImport = nil
        let state = ImportState(sources: sources, caseURL: caseURL)
        importState = state
        let run: @Sendable (@escaping @Sendable (ImportProgress) -> Void, @escaping @Sendable () -> Bool) throws -> ImportSummary
        switch kind {
        case .windows:
            let importer = CaseImporter(sources: sources, caseURL: caseURL, options: options)
            run = { try importer.run(progress: $0, cancelled: $1) }
        case .linux:
            var o = LinuxImportOptions()
            o.hashSources = options.hashSources
            let importer = UacImporter(sources: sources, caseURL: caseURL, options: o)
            run = { try importer.run(progress: $0, cancelled: $1) }
        }
        let cancel = state.cancel
        let activity = ActivityToken("Импорт журналов")
        Task.detached(priority: .userInitiated) { [weak self] in
            defer { activity.end() }
            do {
                let t0 = Date()
                let phases = PhaseLog()
                let summary = try run({ p in
                    phases.note(p.phase, Date().timeIntervalSince(t0))
                    Task { @MainActor in
                        state.phase = p.phase
                        state.fraction = p.fraction
                        state.events = p.events
                    }
                }, { cancel.isSet })
                if ProcessInfo.processInfo.arguments.contains("-importTo") {
                    let report = String(format: "app import: %.2fs, events=%d\n", Date().timeIntervalSince(t0), summary.events) + phases.text
                    try? report.write(to: caseURL.appendingPathExtension("import-report.txt"), atomically: true, encoding: .utf8)
                }
                await MainActor.run {
                    self?.importState = nil
                    self?.open(caseURL)
                    // Sigma rules of the bundled packs are Windows rules: Linux cases skip them.
                    if kind == .windows, AppDefaults.store.object(forKey: "import.runDetections") as? Bool ?? true {
                        self?.caseModel?.runDetections()
                    }
                }
            } catch is CancellationError {
                await MainActor.run { self?.importState = nil }
            } catch {
                await MainActor.run { state.error = "\(error)" }
            }
        }
    }

    // MARK: Open / close

    func openCasePanel() {
        let open = NSOpenPanel()
        open.title = String(localized: "Открыть кейс DayBook")
        open.canChooseDirectories = true
        open.canChooseFiles = false
        open.treatsFilePackagesAsDirectories = false
        guard open.runModal() == .OK, let url = open.url else { return }
        self.open(url)
    }

    func open(_ url: URL) {
        do {
            let store = try CaseStore(url: url)
            caseModel = CaseModel(store: store, url: url)
            remember(url)
        } catch {
            alert = String(localized: "Не удалось открыть кейс: ") + "\(error)"
        }
    }

    func closeCase() { caseModel = nil }

    private func remember(_ url: URL) {
        recentCases.removeAll { $0.standardizedFileURL == url.standardizedFileURL }
        recentCases.insert(url, at: 0)
        recentCases = Array(recentCases.prefix(10))
        AppDefaults.store.set(recentCases.map(\.path), forKey: "recentCases")
    }
}
