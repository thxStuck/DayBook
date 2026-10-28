import AppKit
import DaybookSigma
import DaybookStore
import EvtxCore
import Foundation
import Observation

struct FacetSection: Identifiable {
    let id: String          // key
    let title: String
    let values: [FacetValue]
    /// Number of distinct values of the field (the list may show only the top ones).
    let total: Int
}

enum MainMode: String, CaseIterable, Identifiable {
    case events, timeline, logs, system, detections, hosts, users, ips, sessions, processes
    var id: String { rawValue }
    var title: String {
        switch self {
        case .events: String(localized: "События")
        case .timeline: String(localized: "Таймлайн")
        case .logs: String(localized: "Журналы")
        case .hosts: String(localized: "Хосты")
        case .users: String(localized: "Пользователи")
        case .ips: String(localized: "IP-адреса")
        case .sessions: String(localized: "Сеансы")
        case .processes: String(localized: "Процессы")
        case .detections: String(localized: "Детекты")
        case .system: String(localized: "Система")
        }
    }
    var icon: String {
        switch self {
        case .events: "list.bullet.rectangle"
        case .timeline: "calendar.day.timeline.left"
        case .logs: "doc.text.magnifyingglass"
        case .detections: "shield.lefthalf.filled"
        case .hosts: "desktopcomputer"
        case .users: "person.2"
        case .ips: "network"
        case .sessions: "person.badge.clock"
        case .processes: "point.3.connected.trianglepath.dotted"
        case .system: "server.rack"
        }
    }

    var kind: EntityKind? {
        switch self {
        case .hosts: .host
        case .users: .user
        case .ips: .ip
        default: nil
        }
    }
}

/// State of one opened case: query + chip filters + time window → result, groups,
/// histogram, selection and details.
@Observable
final class CaseModel {
    let store: CaseStore
    let url: URL
    var title: String { url.deletingPathExtension().lastPathComponent }
    var isLinux: Bool { store.platform == .linux }
    /// Sections of the main window; Linux cases add "System" (the collection's own data).
    var modes: [MainMode] {
        isLinux ? [.events, .timeline, .logs, .system, .detections, .hosts, .users, .ips, .sessions, .processes]
            : MainMode.allCases.filter { $0 != .system }
    }

    // Inputs
    var queryText = ""
    private(set) var appliedQuery = ""
    private(set) var filters: [FieldFilter] = []
    private(set) var timeFrom: Int64?
    private(set) var timeTo: Int64?

    // Outputs
    private(set) var result: ResultSet
    private(set) var filtered: ResultSet
    private(set) var groupKeys: [String]?
    private(set) var groups: [DQLGroupRow] = []
    private(set) var groupsTruncated = false
    private(set) var selectedGroup: DQLGroupRow?
    private(set) var histogram: Histogram?
    var histogramFullRange = AppDefaults.store.bool(forKey: "histogramFullRange") {
        didSet {
            AppDefaults.store.set(histogramFullRange, forKey: "histogramFullRange")
            let store = self.store, events = filtered, full = histogramFullRange
            Task { [weak self] in
                let h = await Task.detached { HistogramBuilder.build(store: store, events: events, fullRange: full) }.value
                self?.histogram = h
            }
        }
    }
    /// Bumped whenever the result or its order changes (table reloads).
    private(set) var generation = 0
    /// Bumped when only rendering changes (time zone, columns): visible cells refresh.
    private(set) var displayGeneration = 0
    private(set) var lastQueryMs: Double = 0
    private(set) var querying = false
    var queryError: String?
    var errorMessage: String?
    var exportProgress: Double?

    var ascending = true {
        didSet { resetRows(); generation += 1 }
    }
    private var customOrder = false

    var columns: [ColumnSpec] = ColumnSpec.defaults {
        didSet { displayGeneration += 1 }
    }

    var timeZone: TimeZoneChoice {
        didSet {
            formatter = TimeFormatter(zone: timeZone)
            AppDefaults.store.set(timeZone.storageValue, forKey: "timeZone")
            displayGeneration += 1
        }
    }

    @ObservationIgnored private(set) var formatter: TimeFormatter
    @ObservationIgnored let rows: RowProvider
    @ObservationIgnored private var queryTask: Task<Void, Never>?
    @ObservationIgnored private var queryCancel = CancelFlag()
    @ObservationIgnored private var groupTask: Task<Void, Never>?

    var mode: MainMode = .events {
        didSet {
            if let k = mode.kind { loadEntities(k) }
            if mode == .sessions { loadSessions() }
            if mode == .processes { loadProcesses(processSource) }
            if mode == .detections, detections == nil { loadDetections() }
        }
    }
    private(set) var sessions: SessionAnalysis?
    private(set) var rdpSessions: [RDPSession]?
    private(set) var forests: [ProcessSource: ProcessForest] = [:]
    var processSource: ProcessSource = .sysmon {
        didSet { loadProcesses(processSource) }
    }
    private(set) var analysisError: String?

    /// Right-hand event details panel (events and timeline); opened by clicking an event.
    var showDetails = AppDefaults.store.object(forKey: "showDetails") as? Bool ?? true {
        didSet { AppDefaults.store.set(showDetails, forKey: "showDetails") }
    }

    /// Log viewer ("Журналы"): a second model over the same case with its own query state,
    /// so browsing one log does not touch the investigation in "События".
    let isViewer: Bool
    /// Filters that define the viewer's scope (the selected log file); not shown as chips.
    private(set) var scopeFilters: [FieldFilter] = []
    /// `@Source` label of the log shown in the viewer.
    private(set) var viewerLog: String?
    @ObservationIgnored private var viewerStorage: CaseModel?
    /// The main model of a viewer: actions that open another section go there.
    @ObservationIgnored weak var owner: CaseModel?
    var logViewer: CaseModel {
        if let v = viewerStorage { return v }
        let v = CaseModel(store: store, url: url, viewer: true)
        v.owner = self
        viewerStorage = v
        return v
    }

    /// Shows one log file in the viewer (newest events first, like Event Viewer).
    func showLog(_ label: String, query: String = "") {
        if label.hasPrefix(Self.channelPrefix) { showChannel(String(label.dropFirst(Self.channelPrefix.count)), query: query); return }
        viewerLog = label
        scopeFilters = [FieldFilter(key: CaseSchema.SystemKey.source, value: label)]
        runQuery(text: query)
    }

    /// `viewerLog` of a whole log (a Linux log with its rotations) rather than one file.
    static let channelPrefix = "#log:"

    func showChannel(_ channel: String, query: String = "") {
        viewerLog = Self.channelPrefix + channel
        scopeFilters = [FieldFilter(key: CaseSchema.SystemKey.channel, value: channel)]
        runQuery(text: query)
    }

    // Detections (Sigma rules evaluated against the case, stored in it)
    private(set) var detections: [DetectionRule]?
    private(set) var detectionMeta: [String: String] = [:]
    private(set) var detectionProgress: (done: Int, total: Int)?
    private(set) var detectionError: String?
    /// Rules that matched the selected event.
    private(set) var eventDetections: [DetectionRule] = []
    var selectedDetection: Int64?
    @ObservationIgnored private var detectionCancel: CancelFlag?
    @ObservationIgnored private var detectionIndex: [UInt32: [Int64]] = [:]
    @ObservationIgnored private var detectionById: [Int64: DetectionRule] = [:]
    private(set) var entities: [EntityKind: [EntityInfo]] = [:]
    private(set) var entityLinks: [EntityLink] = []
    private(set) var selectedEntity: EntityInfo?
    var timelineColumns: [ColumnSpec] = ColumnSpec.timeline

    private(set) var selectedId: UInt32?
    private(set) var detail: EventDetail?
    /// Set to scroll the table to an event (token changes on every request).
    private(set) var scrollRequest: (id: UInt32, token: Int)?
    private(set) var tags: [UInt32: EventTag] = [:]
    @ObservationIgnored private var annotations: CaseAnnotations?
    private(set) var facets: [FacetSection] = []
    var history: [String] = AppDefaults.store.stringArray(forKey: "queryHistory") ?? []

    init(store: CaseStore, url: URL, viewer: Bool = false) {
        self.store = store
        self.url = url
        isViewer = viewer
        let zone = TimeZoneChoice(storageValue: AppDefaults.store.string(forKey: "timeZone") ?? "utc")
        timeZone = zone
        formatter = TimeFormatter(zone: zone)
        let all = ResultSet(range: 0..<UInt32(store.eventCount))
        result = all
        filtered = all
        rows = RowProvider(store: store)
        if viewer {
            columns = store.platform == .linux ? ColumnSpec.linuxViewer : ColumnSpec.viewer
            ascending = false
            result = .empty
            filtered = .empty
            rows.reset(result: .empty, ascending: false, ordered: true)
            loadTags()
            loadDetections()
            return
        }
        rows.reset(result: all, ascending: true, ordered: true)
        if store.platform == .linux {
            columns = ColumnSpec.linux
            timelineColumns = ColumnSpec.linuxTimeline
            processSource = .audit
        }
        loadFacets()
        loadTags()
        loadDetections()
        for kind in EntityKind.allCases { loadEntities(kind) }
        runQuery()
    }

    // MARK: Bookmarks

    private func loadTags() {
        annotations = try? CaseAnnotations(store: store)
        tags = Dictionary(((try? annotations?.all()) ?? []).map { ($0.event, $0) }, uniquingKeysWith: { a, _ in a })
    }

    func setTag(_ id: UInt32, color: String?) {
        do {
            if let color {
                if let t = try annotations?.set(event: id, color: color, note: tags[id]?.note ?? "") { tags[id] = t }
            } else {
                try annotations?.remove(event: id)
                tags[id] = nil
            }
            displayGeneration += 1
        } catch {
            errorMessage = String(localized: "Не удалось сохранить закладку: ") + "\(error)"
        }
    }

    func setNote(_ id: UInt32, _ note: String) {
        do {
            if let t = try annotations?.set(event: id, color: tags[id]?.color ?? "yellow", note: note) { tags[id] = t }
            displayGeneration += 1
        } catch {
            errorMessage = String(localized: "Не удалось сохранить заметку: ") + "\(error)"
        }
    }

    func toggleBookmarkOnSelection() {
        guard let id = selectedId else { return }
        setTag(id, color: tags[id] == nil ? "red" : nil)
    }

    /// Selects an event and scrolls to it; if the current filters hide it, they are reset.
    func jump(to id: UInt32) {
        if mode.kind != nil { mode = .events }
        if rows.index(of: id) == nil {
            filters.removeAll()
            timeFrom = nil
            timeTo = nil
            queryText = ""
            runQuery()
        }
        select(id)
        scrollRequest = (id, (scrollRequest?.token ?? 0) + 1)
    }

    var isGrouped: Bool { groupKeys != nil }

    // MARK: Filters

    func addFilter(key: String, value: String, negated: Bool) {
        if filters.contains(where: { $0.key == key && $0.value == value && $0.negated == negated }) { return }
        filters.append(FieldFilter(key: key, value: value, negated: negated))
        runQuery()
    }

    func removeFilter(_ id: UUID) {
        filters.removeAll { $0.id == id }
        runQuery()
    }

    func toggleFilter(_ id: UUID) {
        guard let i = filters.firstIndex(where: { $0.id == id }) else { return }
        filters[i].enabled.toggle()
        runQuery()
    }

    func invertFilter(_ id: UUID) {
        guard let i = filters.firstIndex(where: { $0.id == id }) else { return }
        filters[i].negated.toggle()
        runQuery()
    }

    /// Something narrows the events: a query, a filter or a time window.
    var hasSearch: Bool {
        !queryText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || !filters.isEmpty
            || timeFrom != nil || timeTo != nil
    }

    /// Clears the query, the filters and the time window («Сбросить всё», ⌘K).
    func resetSearch() {
        filters.removeAll()
        timeFrom = nil
        timeTo = nil
        runQuery(text: "")
    }

    func clearFilters() {
        filters.removeAll()
        timeFrom = nil
        timeTo = nil
        runQuery()
    }

    func setTimeWindow(from: Int64?, to: Int64?) {
        timeFrom = from
        timeTo = to
        runQuery()
    }

    /// Display name of a filter key (`@Channel` → "Журнал").
    func keyTitle(_ key: String) -> String {
        switch key {
        case CaseSchema.SystemKey.channel: String(localized: "Журнал")
        case CaseSchema.SystemKey.computer: String(localized: "Компьютер")
        case CaseSchema.SystemKey.eventId: "EventID"
        case CaseSchema.SystemKey.provider: String(localized: "Источник")
        case CaseSchema.SystemKey.level: String(localized: "Уровень")
        case CaseSchema.SystemKey.user: String(localized: "Пользователь")
        case CaseSchema.SystemKey.source: String(localized: "Файл")
        case CaseSchema.SystemKey.flag: String(localized: "Флаг")
        case CaseSchema.SystemKey.task: "Task"
        case CaseSchema.SystemKey.opcode: "Opcode"
        case CaseSchema.SystemKey.keywords: "Keywords"
        case "@Rule": String(localized: "Правило")
        case "@RuleLevel": String(localized: "Уровень правила")
        case CaseSchema.SystemKey.hostEntity: String(localized: "Хост (любая роль)")
        case CaseSchema.SystemKey.userEntity: String(localized: "Пользователь (любая роль)")
        case CaseSchema.SystemKey.ipEntity: String(localized: "IP (любая роль)")
        default: key
        }
    }

    // MARK: Query

    func runQuery(text: String? = nil) {
        if let text { queryText = text }
        queryTask?.cancel()
        queryCancel.set()
        let cancel = CancelFlag()
        queryCancel = cancel
        let filters = scopeFilters + self.filters, query = queryText, store = self.store
        let zone = timeZone, from = timeFrom, to = timeTo, fullRange = histogramFullRange
        querying = true
        queryTask = Task { [weak self] in
            let outcome: Result<(DQLResult, Histogram?), Error> = await Task.detached(priority: .userInitiated) {
                Result {
                    let base = try store.evaluate(filters, from: from, to: to)
                    var r: DQLResult
                    if query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                        r = DQLResult(events: base)
                    } else {
                        let tf = TimeFormatter(zone: zone)
                        let engine = DQLEngine(store: store) { tf.parse($0) }
                        engine.isCancelled = { cancel.isSet }
                        r = try engine.run(query, base: base)
                    }
                    return (r, HistogramBuilder.build(store: store, events: r.filtered, fullRange: fullRange))
                }
            }.value
            guard let self, !Task.isCancelled, !cancel.isSet else { return }
            self.querying = false
            switch outcome {
            case let .success((r, h)):
                self.apply(r, histogram: h, query: query)
            case let .failure(e as DQLError):
                self.queryError = e.position >= 0
                    ? e.message + String(localized: " (позиция \(e.position + 1))") : e.message
            case .failure(is CancellationError):
                break
            case let .failure(e):
                self.queryError = "\(e)"
            }
        }
    }

    private func apply(_ r: DQLResult, histogram: Histogram?, query: String) {
        queryError = nil
        appliedQuery = query
        lastQueryMs = r.elapsedMs
        filtered = r.filtered
        result = r.events
        customOrder = r.customOrder
        // Only an explicit `sort time` changes the order; otherwise the user's choice (or the
        // viewer's newest-first default) is kept.
        if !r.customOrder && r.timeSort { ascending = !r.descending }
        groupKeys = r.groupKeys
        groups = r.groups
        groupsTruncated = r.groupsTruncated
        selectedGroup = nil
        self.histogram = histogram
        if let sel = r.select { applySelect(sel) }
        resetRows()
        generation += 1
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmed.isEmpty && !isViewer {
            history.removeAll { $0 == trimmed }
            history.insert(trimmed, at: 0)
            history = Array(history.prefix(50))
            AppDefaults.store.set(history, forKey: "queryHistory")
        }
    }

    private func resetRows() {
        rows.reset(result: result, ascending: customOrder ? true : ascending, ordered: !customOrder)
        if customOrder && !ascending {
            rows.reset(result: ResultSet(list: result.list.reversed()), ascending: true, ordered: false)
        }
    }

    private func applySelect(_ keys: [String]) {
        var cols: [ColumnSpec] = [ColumnSpec(kind: .time, width: 175)]
        for k in keys {
            let kind: ColumnSpec.Kind
            switch k {
            case "time": continue
            case CaseSchema.SystemKey.computer: kind = .computer
            case CaseSchema.SystemKey.channel: kind = .channel
            case CaseSchema.SystemKey.eventId: kind = .eventId
            case CaseSchema.SystemKey.level: kind = .level
            case CaseSchema.SystemKey.provider: kind = .provider
            case CaseSchema.SystemKey.user: kind = .user
            case CaseSchema.SystemKey.source: kind = .source
            default: kind = .field(k)
            }
            cols.append(ColumnSpec(kind: kind, width: kind == .eventId ? 60 : 170))
        }
        cols.append(ColumnSpec(kind: .summary, width: 520))
        columns = cols
    }

    func cancelQuery() {
        queryCancel.set()
        store.interruptQuery()
        queryTask?.cancel()
        querying = false
    }

    // MARK: Groups

    /// Shows the events of one group (like the left panel of a SIEM).
    func selectGroup(_ g: DQLGroupRow?) {
        selectedGroup = g
        groupTask?.cancel()
        guard let g, let keys = groupKeys else {
            result = filtered
            resetRows()
            generation += 1
            return
        }
        let store = self.store, base = filtered
        groupTask = Task { [weak self] in
            let ids: ResultSet? = await Task.detached(priority: .userInitiated) {
                var r = base
                for (k, v) in zip(keys, g.values) {
                    if v == "—" {
                        r = r.subtract((try? store.eventsWithField(k)) ?? [])
                    } else {
                        r = r.intersect((try? store.matching(key: k, value: v, exact: true)) ?? [])
                    }
                }
                return r
            }.value
            guard let self, !Task.isCancelled, let ids, self.selectedGroup == g else { return }
            self.result = ids
            self.resetRows()
            self.generation += 1
        }
    }

    /// Turns a group into permanent chips and leaves group mode.
    func drillDown(_ g: DQLGroupRow) {
        guard let keys = groupKeys else { return }
        for (k, v) in zip(keys, g.values) where v != "—" {
            filters.append(FieldFilter(key: k, value: v))
        }
        queryText = Self.removingGroupStage(queryText)
        runQuery()
    }

    static func removingGroupStage(_ q: String) -> String {
        q.components(separatedBy: "|")
            .filter { !$0.trimmingCharacters(in: .whitespaces).lowercased().hasPrefix("group") }
            .joined(separator: "|")
            .trimmingCharacters(in: .whitespaces)
    }

    // MARK: Selection

    func select(_ id: UInt32?) {
        guard id != selectedId else { return }
        selectedId = id
        // Fields come from the case and appear at once. XML and raw bytes are re-read from the
        // source file, which can be slow or unreachable (network share, sleeping disk, a pending
        // macOS privacy prompt); the panel shows that state instead of waiting. Answers for an
        // older selection are dropped. GCD threads rather than the Swift task pool: an open()
        // that hangs must not take a pool thread the UI depends on.
        if let id {
            let store = self.store
            Task { [weak self] in
                let d = await runOffPool { try? store.caseDetail(id) }
                guard let self, self.selectedId == id else { return }
                self.detail = d
                guard let d, d.sourceState == .pending else { return }
                let full = await runOffPool { store.readSourceRecord(d) }
                guard self.selectedId == id else { return }
                self.detail = full
            }
        } else {
            detail = nil
        }
        eventDetections = id.flatMap { detectionIndex[$0] }?.compactMap { detectionById[$0] }
            .sorted { ($0.levelRank, $1.title) > ($1.levelRank, $0.title) } ?? []
    }

    // MARK: Columns

    func addColumn(field: String) {
        guard !columns.contains(where: { $0.kind == .field(field) }) else { return }
        let at = columns.firstIndex(where: { $0.kind == .summary }) ?? columns.count
        columns.insert(ColumnSpec(kind: .field(field), width: 160), at: at)
    }

    func toggleColumn(_ kind: ColumnSpec.Kind) {
        if let i = columns.firstIndex(where: { $0.kind == kind }) { columns.remove(at: i) }
        else { columns.insert(ColumnSpec(kind: kind, width: 150), at: max(0, columns.count - 1)) }
    }

    func removeColumn(id: String) { columns.removeAll { $0.id == id && $0.kind != .time } }

    // MARK: Export

    func export(_ format: ExportFormat) {
        let panel = NSSavePanel()
        panel.title = String(localized: "Экспорт результата")
        let ext = format == .jsonl ? "jsonl" : format == .xlsx ? "xlsx" : "csv"
        panel.nameFieldStringValue = "\(title)-export.\(ext)"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let fields = columns.compactMap { if case let .field(n) = $0.kind { return n } else { return nil } }
        let events: ResultSet = {
            if customOrder { return result }
            return ascending ? result : ResultSet(list: result.list.reversed())
        }()
        let zone = timeZone
        let exporter = CaseExporter(store: store, format: format, fields: fields,
                                    zoneLabel: zone.headerLabel(at: nil)) { ft in TimeFormatter(zone: zone).string(ft) }
        // What produced this result (shown on the XLSX "export info" sheet).
        let fmt = formatter
        var info: [(String, String)] = [(String(localized: "Запрос DQL"), appliedQuery.isEmpty ? "—" : appliedQuery)]
        let active = filters.filter(\.enabled)
        info.append((String(localized: "Фильтры"), active.isEmpty ? "—" : active.map { "\(keyTitle($0.key)) \($0.negated ? "≠" : "=") \($0.value)" }.joined(separator: "; ")))
        if timeFrom != nil || timeTo != nil {
            let a = timeFrom.map { "\(fmt.string($0)) (\(FileTime.iso8601($0)))" } ?? "…"
            let b = timeTo.map { "\(fmt.string($0)) (\(FileTime.iso8601($0)))" } ?? "…"
            info.append((String(localized: "Временное окно"), "\(a) — \(b)"))
        }
        info.append((String(localized: "Порядок строк"), customOrder ? String(localized: "по полю запроса") : (ascending ? String(localized: "по времени, по возрастанию") : String(localized: "по времени, по убыванию"))))
        let exportInfo = info
        exportProgress = 0
        let activity = ActivityToken("Экспорт событий")
        Task { [weak self] in
            let outcome: Result<Int, Error> = await Task.detached(priority: .userInitiated) {
                defer { activity.end() }
                return Result {
                    try exporter.export(events, to: url, info: exportInfo, progress: { p in
                        Task { @MainActor in self?.exportProgress = p }
                    })
                }
            }.value
            self?.exportProgress = nil
            if case let .failure(e) = outcome { self?.errorMessage = String(localized: "Экспорт не удался: ") + (e as NSError).localizedDescription }
            else { NSWorkspace.shared.activateFileViewerSelecting([url]) }
        }
    }

    // MARK: Sessions and process trees (computed on demand)

    func loadSessions() {
        guard sessions == nil else { return }
        let store = self.store
        Task { [weak self] in
            let r: Result<(SessionAnalysis, [RDPSession]), Error> = await Task.detached(priority: .userInitiated) {
                Result {
                    store.platform == .linux ? (try LinuxSessionBuilder.build(store), [])
                                             : (try SessionBuilder.build(store), try RDPSessionBuilder.build(store))
                }
            }.value
            switch r {
            case let .success((a, rdp)): self?.sessions = a; self?.rdpSessions = rdp
            case let .failure(e): self?.analysisError = "\(e)"
            }
        }
    }

    func loadProcesses(_ source: ProcessSource) {
        guard forests[source] == nil else { return }
        let store = self.store
        Task { [weak self] in
            let r: Result<ProcessForest, Error> = await Task.detached(priority: .userInitiated) {
                Result { try ProcessTreeBuilder.build(store, source: source) }
            }.value
            switch r {
            case let .success(f): self?.forests[source] = f
            case let .failure(e): self?.analysisError = "\(e)"
            }
        }
    }

    // MARK: Detections

    func loadDetections() {
        let store = self.store
        Task { [weak self] in
            let loaded: ([DetectionRule], [String: String], [UInt32: [Int64]]) = await Task.detached(priority: .userInitiated) {
                let rules = (try? store.detectionRules()) ?? []
                var index: [UInt32: [Int64]] = [:]
                for r in rules where r.hits > 0 {
                    for id in (try? store.detectionHits([r.id])) ?? [] { index[id, default: []].append(r.id) }
                }
                return (rules, (try? store.detectionMeta()) ?? [:], index)
            }.value
            guard let self else { return }
            self.detections = loaded.0
            self.detectionMeta = loaded.1
            self.detectionIndex = loaded.2
            self.detectionById = Dictionary(loaded.0.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
            let id = self.selectedId
            self.selectedId = nil
            self.select(id)
        }
    }

    /// Evaluates the bundled rules (and the custom folder, if set) against the case and
    /// stores the results in it, replacing the previous run.
    func runDetections() {
        guard detectionProgress == nil else { return }
        let cancel = CancelFlag()
        detectionCancel = cancel
        detectionProgress = (0, 0)
        detectionError = nil
        let store = self.store
        let folder = AppDefaults.store.string(forKey: RuleLibrary.customFolderKey)
        let activity = ActivityToken("Sigma-детекты")
        Task { [weak self] in
            let outcome: Result<SigmaRunner.Summary, Error> = await runOffPool {
                defer { activity.end() }
                return Result {
                    let set = try RuleLibrary.load(customFolder: folder)
                    return try SigmaRunner.run(store: store, rules: set, progress: { done, total in
                        Task { @MainActor in self?.detectionProgress = (done, total) }
                    }, isCancelled: { cancel.isSet })
                }
            }
            guard let self else { return }
            self.detectionProgress = nil
            self.detectionCancel = nil
            switch outcome {
            case .success: self.loadDetections()
            case let .failure(e) where !(e is CancellationError):
                self.detectionError = String(localized: "Детекты не выполнены: ") + "\(e)"
            default: break
            }
        }
    }

    func cancelDetections() { detectionCancel?.set() }

    /// DQL for the events of one rule (stable rule id when it has one).
    static func detectionQuery(_ r: DetectionRule) -> String {
        let v = r.ruleId.isEmpty ? r.title : r.ruleId
        return "rule = \"" + v.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }

    func showDetection(_ r: DetectionRule, timeline: Bool = false) {
        showQuery(Self.detectionQuery(r), timeline: timeline)
    }

    func openDetection(_ id: Int64) {
        if let owner { owner.openDetection(id); return }
        selectedDetection = id
        mode = .detections
    }

    /// A jump from another screen (an entity, session, process, rule or log) starts a new search
    /// in the events view. The query, filters and time window left from earlier work would
    /// silently narrow it: a rule query left from «Детекты» hid every event of an IP. Earlier
    /// queries stay in the query history.
    private func newSearch(timeline: Bool, filters: [FieldFilter] = [], query: String = "") {
        self.filters = filters
        timeFrom = nil
        timeTo = nil
        mode = timeline ? .timeline : .events
        runQuery(text: query)
    }

    /// Runs a query as a new search in the events table (analysis screens, rules).
    func showQuery(_ q: String, timeline: Bool = false) {
        if let owner { owner.showQuery(q, timeline: timeline); return }
        newSearch(timeline: timeline, query: q)
    }

    /// One log file in the events view with the viewer's level and DQL filter, as a new search.
    func showSource(_ name: String, query: String) {
        if let owner { owner.showSource(name, query: query); return }
        newSearch(timeline: false, filters: [FieldFilter(key: CaseSchema.SystemKey.source, value: name)], query: query)
    }

    /// A whole log (all its rotations) as a new search in "Events".
    func showChannelInEvents(_ channel: String, query: String) {
        if let owner { owner.showChannelInEvents(channel, query: query); return }
        newSearch(timeline: false, filters: [FieldFilter(key: CaseSchema.SystemKey.channel, value: channel)], query: query)
    }

    /// DQL time literal in UTC (exact, independent of the display zone).
    static func utcLiteral(_ ft: Int64) -> String { "\"" + FileTime.iso8601(ft) + "\"" }

    /// Events of one logon session: same host, the logon id in any logon-id field, inside
    /// the session's time span. Only fields present in the case are used.
    func sessionQuery(_ s: LogonSession) -> String {
        if isLinux {
            // Linux: what the user and the terminal did while the session lasted.
            let user = s.user.split(separator: "\\").last.map(String.init) ?? s.user
            let tty = s.logonId.components(separatedBy: " · ").first ?? s.logonId
            var q = "host = \"\(s.host)\" and (TargetUserName = \"\(user)\" or SubjectUserName = \"\(user)\" or Terminal = \"\(tty)\")"
            q += " and time >= \(Self.utcLiteral(s.start))"
            if let end = s.end { q += " and time <= \(Self.utcLiteral(end))" }
            return q
        }
        let fields = ["TargetLogonId", "SubjectLogonId", "LogonId"].filter { store.keyId($0) != nil }
        let idPart = fields.map { "\($0) = \(s.logonId)" }.joined(separator: " or ")
        var q = "host = \"\(s.host)\" and (\(idPart)) and time >= \(Self.utcLiteral(s.start))"
        if let end = s.end { q += " and time <= \(Self.utcLiteral(end))" }
        return q
    }

    /// Events of one process: by ProcessGuid (Sysmon) or by PID within its lifetime (4688).
    func processQuery(_ n: ProcessNode) -> String? {
        if let guid = n.guid {
            let fields = ["ProcessGuid", "ParentProcessGuid", "SourceProcessGuid", "TargetProcessGuid"].filter { store.keyId($0) != nil }
            return fields.map { "\($0) = \"\(guid)\"" }.joined(separator: " or ")
        }
        guard let pid = n.pid, let start = n.start else { return nil }
        // Linux audit: the process's own records (pid) and those of its children (ppid).
        let fields = (isLinux ? ["pid", "ppid"] : ["NewProcessId", "ProcessId"]).filter { store.keyId($0) != nil }
        var q = "host = \"\(n.host)\" and (\(fields.map { "\($0) = \(pid)" }.joined(separator: " or "))) and time >= \(Self.utcLiteral(start))"
        if let end = n.end { q += " and time <= \(Self.utcLiteral(end))" }
        return q
    }

    // MARK: Entities (hosts, users, IPs)

    func loadEntities(_ kind: EntityKind) {
        guard entities[kind] == nil else { return }
        let store = self.store
        Task { [weak self] in
            let list = await Task.detached(priority: .userInitiated) { (try? store.entities(kind)) ?? [] }.value
            self?.entities[kind] = list
        }
    }

    func entity(_ id: Int) -> EntityInfo? {
        for list in entities.values { if let e = list.first(where: { $0.id == id }) { return e } }
        return nil
    }

    func selectEntity(_ e: EntityInfo?) {
        selectedEntity = e
        entityLinks = []
        guard let e else { return }
        for k in EntityKind.allCases { loadEntities(k) }
        let store = self.store
        Task { [weak self] in
            let links = await Task.detached(priority: .userInitiated) { (try? store.entityLinks(e.id)) ?? [] }.value
            guard self?.selectedEntity == e else { return }
            self?.entityLinks = links
        }
    }

    /// Value used in an entity filter chip (resolvable by `CaseStore.entityIds`).
    static func filterValue(_ e: EntityInfo) -> String {
        switch e.kind {
        case .host, .ip: e.key
        case .user: e.sid ?? e.display
        }
    }

    static func filterKey(_ kind: EntityKind) -> String {
        switch kind {
        case .host: CaseSchema.SystemKey.hostEntity
        case .user: CaseSchema.SystemKey.userEntity
        case .ip: CaseSchema.SystemKey.ipEntity
        }
    }

    /// Every event of the given entities (all roles at once) as a new search: a jump from the
    /// host, user and IP screens.
    func showEvents(of entities: [EntityInfo], negated: Bool = false, timeline: Bool = false) {
        if let owner { owner.showEvents(of: entities, negated: negated, timeline: timeline); return }
        newSearch(timeline: timeline, filters: entities.map {
            FieldFilter(key: Self.filterKey($0.kind), value: Self.filterValue($0), negated: negated)
        })
    }

    /// Narrows the current search to an entity (sidebar clicks in the events view).
    func filterEvents(by e: EntityInfo, negated: Bool = false, timeline: Bool = false) {
        if let owner { owner.filterEvents(by: e, negated: negated, timeline: timeline); return }
        addFilter(key: Self.filterKey(e.kind), value: Self.filterValue(e), negated: negated)
        mode = timeline ? .timeline : .events
    }

    // MARK: Facets (global counts for the sidebar)

    private func loadFacets() {
        let store = self.store
        Task { [weak self] in
            let sections: [FacetSection] = await Task.detached(priority: .utility) {
                let keys: [(String, String, Int)] = store.platform == .linux ? [
                    (CaseSchema.SystemKey.channel, String(localized: "Журналы"), 100),
                    (CaseSchema.SystemKey.computer, String(localized: "Компьютеры"), 100),
                    ("Action", String(localized: "Действия"), 60),
                    (CaseSchema.SystemKey.provider, String(localized: "Программы"), 60),
                    (CaseSchema.SystemKey.flag, String(localized: "Флаги записей"), 20),
                ] : [
                    (CaseSchema.SystemKey.channel, String(localized: "Журналы"), 100),
                    (CaseSchema.SystemKey.computer, String(localized: "Компьютеры"), 100),
                    (CaseSchema.SystemKey.eventId, "Event ID", 60),
                    (CaseSchema.SystemKey.flag, String(localized: "Флаги записей"), 20),
                ]
                return keys.compactMap { key, title, limit in
                    guard let values = try? store.facet(key, limit: limit), !values.isEmpty else { return nil }
                    return FacetSection(id: key, title: title, values: values, total: (try? store.distinctValues(key)) ?? values.count)
                }
            }.value
            self?.facets = sections
        }
    }
}
