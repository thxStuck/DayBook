import DaybookStore
import EvtxCore
import SwiftUI

/// The case's log files, grouped like Windows Event Viewer: "Windows Logs" and
/// "Applications and Services Logs" (by provider). Shown in the sidebar in the "Журналы" section.
struct LogTreeSections: View {
    let model: CaseModel
    @AppStorage("logs.hideEmpty") private var hideEmpty = false

    struct Log: Identifiable {
        let source: SourceInfo
        let channel: String
        var id: String { source.name }
        var events: Int { source.records + source.carved }
    }

    static let windowsLogs = ["application", "security", "setup", "system", "forwardedevents"]

    /// Channel name from the file name (Windows stores "A/B" as "A%4B.evtx"); other formats store it.
    static func channel(_ s: SourceInfo) -> String {
        if !s.isEvtx { return s.channel ?? s.name }
        return URL(fileURLWithPath: s.path).deletingPathExtension().lastPathComponent.replacingOccurrences(of: "%4", with: "/")
    }

    static func logs(_ sources: [SourceInfo]) -> [Log] {
        sources.map { Log(source: $0, channel: channel($0)) }
            .sorted { $0.channel.localizedStandardCompare($1.channel) == .orderedAscending }
    }

    var body: some View {
        if model.isLinux { linuxBody } else { windowsBody }
    }

    /// Linux: logs of /var/log by name; a log with rotations opens whole, its files one by one inside.
    @ViewBuilder private var linuxBody: some View {
        let viewer = model.logViewer
        let all = Self.logs(model.store.sources).filter { !hideEmpty || $0.events > 0 }
        let byChannel = Dictionary(grouping: all, by: \.channel)
        Section {
            ForEach(byChannel.keys.sorted { $0.localizedStandardCompare($1) == .orderedAscending }, id: \.self) { channel in
                let files = (byChannel[channel] ?? []).sorted { $0.source.name.localizedStandardCompare($1.source.name) == .orderedAscending }
                if files.count == 1, let log = files.first {
                    row(log, title: channel, viewer: viewer, duplicated: [])
                } else {
                    DisclosureGroup {
                        ForEach(files) { row($0, title: URL(fileURLWithPath: $0.source.path).lastPathComponent, viewer: viewer, duplicated: []) }
                    } label: {
                        let selected = viewer.viewerLog == CaseModel.channelPrefix + channel
                        HStack {
                            Text(channel).lineLimit(1).truncationMode(.middle)
                            Spacer(minLength: 4)
                            Text(files.reduce(0) { $0 + $1.events }.formatted())
                                .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                        }
                        .contentShape(Rectangle())
                        .fontWeight(selected ? .semibold : .regular)
                        .onTapGesture { viewer.showChannel(channel, query: viewer.queryText) }
                        .help(String(localized: "Журнал целиком: \(files.count) файлов с ротациями"))
                    }
                }
            }
        } header: {
            HStack {
                Text("Журналы /var/log")
                Spacer()
                Toggle("Без пустых", isOn: $hideEmpty)
                    .toggleStyle(.checkbox)
                    .controlSize(.mini)
                    .help("Скрыть журналы без событий (файлы остаются в кейсе и в сведениях о кейсе)")
            }
        }
    }

    @ViewBuilder private var windowsBody: some View {
        let viewer = model.logViewer
        let all = Self.logs(model.store.sources)
        let duplicated = Set(Dictionary(grouping: all, by: { $0.channel.lowercased() }).filter { $0.value.count > 1 }.keys)
        let visible = all.filter { !hideEmpty || $0.events > 0 }
        let windows = visible.filter { Self.windowsLogs.contains($0.channel.lowercased()) }
        let others = visible.filter { !Self.windowsLogs.contains($0.channel.lowercased()) }
        let groups = Dictionary(grouping: others) { log -> String in
            log.channel.split(separator: "/", maxSplits: 1).first.map(String.init) ?? log.channel
        }
        Section {
            ForEach(windows) { row($0, title: $0.channel, viewer: viewer, duplicated: duplicated) }
        } header: {
            Text("Журналы Windows")
        }
        Section {
            ForEach(groups.keys.sorted { $0.localizedStandardCompare($1) == .orderedAscending }, id: \.self) { provider in
                let items = groups[provider] ?? []
                if items.count == 1, let log = items.first {
                    row(log, title: Self.short(log.channel), viewer: viewer, duplicated: duplicated)
                } else {
                    DisclosureGroup {
                        ForEach(items) { log in
                            let part = log.channel.split(separator: "/", maxSplits: 1).dropFirst().first.map(String.init) ?? log.channel
                            row(log, title: part, viewer: viewer, duplicated: duplicated)
                        }
                    } label: {
                        HStack {
                            Text(Self.short(provider)).lineLimit(1).truncationMode(.middle).help(provider)
                            Spacer(minLength: 4)
                            Text(items.reduce(0) { $0 + $1.events }.formatted())
                                .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                        }
                    }
                }
            }
        } header: {
            HStack {
                Text("Журналы приложений и служб")
                Spacer()
                Toggle("Без пустых", isOn: $hideEmpty)
                    .toggleStyle(.checkbox)
                    .controlSize(.mini)
                    .help("Скрыть журналы без событий (файлы остаются в кейсе и в сведениях о кейсе)")
            }
        }
    }

    /// "Microsoft-Windows-Sysmon/Operational" → "Sysmon/Operational" (the full name is in the tooltip).
    static func short(_ name: String) -> String {
        name.hasPrefix("Microsoft-Windows-") ? String(name.dropFirst("Microsoft-Windows-".count)) : name
    }

    private func row(_ log: Log, title: String, viewer: CaseModel, duplicated: Set<String>) -> some View {
        let selected = viewer.viewerLog == log.source.name
        return HStack(spacing: 6) {
            VStack(alignment: .leading, spacing: 0) {
                Text(title).lineLimit(1).truncationMode(.middle)
                if duplicated.contains(log.channel.lowercased()) {
                    Text(log.source.name).font(.caption2).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                }
            }
            Spacer(minLength: 4)
            Text(log.events.formatted()).font(.caption.monospacedDigit()).foregroundStyle(.secondary)
        }
        .opacity(log.events == 0 ? 0.45 : 1)
        .contentShape(Rectangle())
        .listRowBackground(selected ? Color.accentColor.opacity(0.22) : Color.clear)
        .onTapGesture { viewer.showLog(log.source.name, query: viewer.queryText) }
        .help("\(log.channel)\n\(log.source.path)")
    }
}

/// Event Viewer–style browsing of one log: newest events first, level filter, details below.
struct LogsView: View {
    let model: CaseModel
    @State private var levels: Set<Int> = []
    @State private var audit: Set<String> = []
    @State private var filterText = ""
    @AppStorage("logs.detailHeight") private var detailHeight = 300.0

    static let levelNames: [(Int, String)] = [
        (1, String(localized: "Критический")), (2, String(localized: "Ошибка")), (3, String(localized: "Предупреждение")),
        (4, String(localized: "Сведения")), (5, String(localized: "Подробно")),
    ]
    static let auditKinds: [(String, String)] = [
        ("0x8020000000000000", String(localized: "Аудит успеха")), ("0x8010000000000000", String(localized: "Аудит отказа")),
    ]

    var body: some View {
        let v = model.logViewer
        VStack(spacing: 0) {
            if let label = v.viewerLog, label.hasPrefix(CaseModel.channelPrefix) {
                let channel = String(label.dropFirst(CaseModel.channelPrefix.count))
                channelHeader(v, channel, model.store.sources.filter { !$0.isEvtx && $0.channel == channel })
                Divider()
                FilterBar(model: v, showsReset: false)
                Divider()
                GeometryReader { geo in
                    let h = min(max(detailHeight, 120), max(120, geo.size.height - 140))
                    VStack(spacing: 0) {
                        FlexibleTable {
                            EventTable(model: v, generation: v.generation, displayGeneration: v.displayGeneration, columns: v.columns)
                        }
                        RowSplitHandle(height: $detailHeight, range: 120...1200)
                        DetailView(model: v).frame(height: h)
                    }
                }
            } else if let label = v.viewerLog, let src = model.store.sources.first(where: { $0.name == label }) {
                header(v, src)
                Divider()
                FilterBar(model: v, showsReset: false)
                Divider()
                // Table above, details below (Event Viewer layout); plain SwiftUI split with a
                // draggable divider instead of NSSplitView.
                GeometryReader { geo in
                    let h = min(max(detailHeight, 120), max(120, geo.size.height - 140))
                    VStack(spacing: 0) {
                        FlexibleTable {
                            EventTable(model: v, generation: v.generation, displayGeneration: v.displayGeneration, columns: v.columns)
                        }
                        RowSplitHandle(height: $detailHeight, range: 120...1200)
                        DetailView(model: v).frame(height: h)
                    }
                }
            } else {
                ContentUnavailableView("Выберите журнал", systemImage: "doc.text.magnifyingglass",
                                       description: Text("Слева — журналы кейса, как в «Просмотре событий» Windows. События выбранного журнала показываются здесь, новые сверху; это не меняет запрос в разделе «События»."))
            }
        }
        .onAppear {
            guard v.viewerLog == nil else { return }
            let logs = LogTreeSections.logs(model.store.sources).filter { $0.events > 0 }
            if model.isLinux {
                if let first = logs.first(where: { $0.channel == "auth.log" || $0.channel == "secure" }) ?? logs.first {
                    v.showChannel(first.channel)
                }
            } else if let first = logs.first(where: { $0.channel.lowercased() == "security" }) ?? logs.first {
                v.showLog(first.source.name)
            }
        }
    }

    /// A whole Linux log: its files (rotations) and how much of them was parsed.
    private func channelHeader(_ v: CaseModel, _ channel: String, _ files: [SourceInfo]) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline) {
                Text(channel).font(.headline).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                Text("\(files.reduce(0) { $0 + $1.records }.formatted()) записей · файлов: \(files.count)")
                    .font(.callout).foregroundStyle(.secondary)
                Spacer(minLength: 8)
                Button("Открыть в «Событиях»") { model.showChannelInEvents(channel, query: v.queryText) }
                    .help("Новый поиск в разделе «События»: этот журнал с тем же фильтром DQL")
            }
            ForEach(files) { f in
                Text("\(f.path) · \(f.records.formatted())\(f.note.map { " · " + $0 } ?? "")")
                    .font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
            }
            linuxFilterRow(v)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
    }

    private func linuxFilterRow(_ v: CaseModel) -> some View {
        HStack(spacing: 6) {
            TextField("Фильтр DQL, например Action = auth_failure", text: $filterText)
                .textFieldStyle(.roundedBorder)
                .frame(minWidth: 160, maxWidth: 420)
                .onSubmit { apply(v) }
            if !filterText.isEmpty {
                Button("Сбросить") {
                    filterText = ""
                    apply(v)
                }
                .buttonStyle(.borderless)
            }
            if let e = v.queryError {
                Text(e).font(.caption).foregroundStyle(.red).textSelection(.enabled)
            }
        }
    }

    private func header(_ v: CaseModel, _ src: SourceInfo) -> some View {
        let channel = LogTreeSections.channel(src)
        return VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline) {
                Text(channel).font(.headline).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                Text("\(src.records.formatted()) записей\(src.carved > 0 ? String(localized: " + \(src.carved.formatted()) восстановлено из slack") : "")")
                    .font(.callout).foregroundStyle(.secondary)
                Spacer(minLength: 8)
                Button("Открыть в «Событиях»") { model.showSource(src.name, query: v.queryText) }
                    .help("Новый поиск в разделе «События»: этот журнал с теми же уровнями и фильтром DQL")
            }
            Text(src.path + (src.note.map { " · " + $0 } ?? "")).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
            if !src.isEvtx {
                linuxFilterRow(v)
            } else {
            HStack(spacing: 6) {
                ForEach(Self.levelNames, id: \.0) { level, name in
                    chip(name, on: levels.contains(level)) {
                        if levels.contains(level) { levels.remove(level) } else { levels.insert(level) }
                        apply(v)
                    }
                }
                if channel.lowercased() == "security" {
                    Divider().frame(height: 16)
                    ForEach(Self.auditKinds, id: \.0) { kw, name in
                        chip(name, on: audit.contains(kw)) {
                            if audit.contains(kw) { audit.remove(kw) } else { audit.insert(kw) }
                            apply(v)
                        }
                    }
                }
                TextField("Фильтр DQL, например EventID = 4624", text: $filterText)
                    .textFieldStyle(.roundedBorder)
                    .frame(minWidth: 160, maxWidth: 360)
                    .onSubmit { apply(v) }
                if !levels.isEmpty || !audit.isEmpty || !filterText.isEmpty {
                    Button("Сбросить") {
                        levels = []
                        audit = []
                        filterText = ""
                        apply(v)
                    }
                    .buttonStyle(.borderless)
                }
            }
            if let e = v.queryError {
                Text(e).font(.caption).foregroundStyle(.red).textSelection(.enabled)
            }
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
    }

    private func chip(_ title: String, on: Bool, _ action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(title)
                .font(.callout)
                .padding(.horizontal, 8)
                .padding(.vertical, 2)
                .background(on ? Color.accentColor.opacity(0.25) : Color.secondary.opacity(0.1), in: Capsule())
        }
        .buttonStyle(.plain)
        .fixedSize()
    }

    /// Level / audit / DQL filter of the viewer (empty selection = everything).
    private func apply(_ v: CaseModel) {
        var parts: [String] = []
        if !levels.isEmpty { parts.append("level in (\(levels.sorted().map(String.init).joined(separator: ", ")))") }
        if !audit.isEmpty { parts.append("keywords in (\(audit.sorted().joined(separator: ", ")))") }
        let t = filterText.trimmingCharacters(in: .whitespacesAndNewlines)
        if !t.isEmpty { parts.append("(\(t))") }
        if let label = v.viewerLog { v.showLog(label, query: parts.joined(separator: " and ")) }
    }
}
