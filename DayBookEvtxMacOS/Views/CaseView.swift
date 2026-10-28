import DaybookStore
import EvtxCore
import SwiftUI

struct CaseView: View {
    let model: CaseModel
    @State private var showInfo = false
    @AppStorage("showHistogram") private var showHistogram = true
    @AppStorage("groupsWidth") private var groupsWidth = 320.0
    @AppStorage("detailsWidth") private var detailsWidth = 360.0

    var body: some View {
        NavigationSplitView {
            SidebarView(model: model)
                .navigationSplitViewColumnWidth(min: 200, ideal: 270, max: 420)
        } detail: {
            // Own details panel instead of `.inspector`: the inspector opened and closed with the
            // section, which collapsed its NSSplitView item and moved toolbar items between toolbar
            // sections, and AppKit went into a constraint-update loop (NSGenericException, crash).
            GeometryReader { geo in
                let range = 260.0...max(260.0, min(900.0, Double(geo.size.width) - 360))
                HStack(spacing: 0) {
                    mainContent
                        .frame(minWidth: 0, maxWidth: .infinity, minHeight: 0, maxHeight: .infinity)
                    if model.showDetails && Self.hasDetailsPanel(model.mode) {
                        SplitHandle(width: $detailsWidth, range: range, trailingPanel: true)
                        DetailView(model: model)
                            .frame(width: min(max(detailsWidth, range.lowerBound), range.upperBound))
                            .frame(maxHeight: .infinity)
                    }
                }
            }
        }
        .navigationTitle(model.title)
        .navigationSubtitle(Text("\(model.store.eventCount.formatted()) событий · \(model.store.sources.count) файлов"))
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button { showInfo = true } label: { Label("Сведения о кейсе", systemImage: "info.circle") }
                    .help("Статистика импорта по каждому файлу: чанки, CRC, восстановленные записи, копии, SHA-256")
            }
            ToolbarItem(placement: .primaryAction) {
                TimeZoneMenu(model: model)
            }
            ToolbarItem(placement: .primaryAction) {
                Menu {
                    Button("CSV") { model.export(.csv) }
                        .help("RFC 4180, запятая, UTF-8; значения без изменений")
                    Button("CSV для Excel (;)") { model.export(.csvExcel) }
                        .help("Точка с запятой и BOM. Значения, начинающиеся с = + - @, получают апостроф впереди, чтобы Excel не выполнял их как формулы (Excel апостроф не показывает)")
                    Button("JSON Lines") { model.export(.jsonl) }
                    Button("Excel (XLSX)") { model.export(.xlsx) }
                        .help("До 1 048 575 строк. Значения записываются как текст, а не формулы; второй лист — сведения об экспорте: запрос, фильтры, часовой пояс, исходные файлы с SHA-256")
                } label: {
                    if let p = model.exportProgress {
                        ProgressView(value: p).frame(width: 60)
                    } else {
                        Label("Экспорт", systemImage: "square.and.arrow.up")
                    }
                }
                .help("Экспорт текущего результата")
                .disabled(model.exportProgress != nil)
            }
            ToolbarItem(placement: .primaryAction) {
                Toggle(isOn: $showHistogram) { Label("Гистограмма", systemImage: "chart.bar.xaxis") }
                    .help("Показать или скрыть гистограмму по времени")
            }
            ToolbarItem(placement: .primaryAction) {
                Button { model.showDetails.toggle() } label: {
                    Label("Детали", systemImage: "sidebar.right")
                }
                .help("Показать или скрыть панель деталей")
                .disabled(!Self.hasDetailsPanel(model.mode))
            }
        }
        .sheet(isPresented: $showInfo) { CaseInfoView(model: model) { showInfo = false } }
        .alert("Ошибка", isPresented: Binding(get: { model.errorMessage != nil }, set: { if !$0 { model.errorMessage = nil } })) {
            Button("OK") { model.errorMessage = nil }
        } message: {
            Text(model.errorMessage ?? "")
        }
    }

    /// Modes that show event details in the right-hand details panel.
    static func hasDetailsPanel(_ mode: MainMode) -> Bool { [.events, .timeline, .sessions, .processes].contains(mode) }

    private var mainContent: some View {
        VStack(spacing: 0) {
            if let kind = model.mode.kind {
                EntitiesView(model: model, kind: kind)
                    .id(kind)
            } else if model.mode == .sessions {
                SessionsView(model: model)
            } else if model.mode == .processes {
                ProcessTreeView(model: model)
            } else if model.mode == .detections {
                DetectionsView(model: model)
            } else if model.mode == .logs {
                LogsView(model: model)
            } else if model.mode == .system {
                SystemView(model: model)
            } else {
                QueryBar(model: model)
                Divider()
                FilterBar(model: model)
                if showHistogram {
                    Divider()
                    HistogramView(model: model)
                }
                Divider()
                if model.isGrouped {
                    // Plain SwiftUI split: NSSplitView-based HSplitView went into a
                    // constraint-update loop together with the flexible table.
                    GeometryReader { geo in
                        let w = min(max(groupsWidth, 180), max(180, geo.size.width - 280))
                        HStack(spacing: 0) {
                            GroupsView(model: model).frame(width: w)
                            SplitHandle(width: $groupsWidth, range: 180...560)
                            eventTable
                        }
                    }
                } else {
                    eventTable
                }
            }
        }
    }

    private var eventTable: some View {
        FlexibleTable {
            EventTable(model: model, generation: model.generation, displayGeneration: model.displayGeneration,
                       columns: model.mode == .timeline ? model.timelineColumns : model.columns,
                       timeline: model.mode == .timeline)
        }
    }
}

/// Gives an AppKit table exactly the space it is offered, so its own size (the sum of the
/// column widths) never pushes the rest of the window off-screen.
struct FlexibleTable<Content: View>: View {
    @ViewBuilder let content: () -> Content

    var body: some View {
        GeometryReader { geo in
            content().frame(width: geo.size.width, height: geo.size.height)
        }
    }
}

/// Draggable vertical divider for `HStack`-based splits.
struct SplitHandle: View {
    @Binding var width: Double
    let range: ClosedRange<Double>
    /// The resized panel is to the right of the handle: dragging left makes it wider.
    var trailingPanel = false
    @State private var start: Double?

    var body: some View {
        Rectangle()
            .fill(Color(nsColor: .separatorColor))
            .frame(width: 1)
            .padding(.horizontal, 3)
            .contentShape(Rectangle())
            .onHover { inside in
                if inside { NSCursor.resizeLeftRight.push() } else { NSCursor.pop() }
            }
            .gesture(DragGesture(minimumDistance: 1, coordinateSpace: .global)
                .onChanged { v in
                    // Start from the width actually shown: the stored one may exceed the current range.
                    if start == nil { start = min(max(width, range.lowerBound), range.upperBound) }
                    let delta = trailingPanel ? -v.translation.width : v.translation.width
                    width = min(max((start ?? width) + delta, range.lowerBound), range.upperBound)
                }
                .onEnded { _ in start = nil })
    }
}

/// Draggable horizontal divider; dragging up makes the lower pane taller.
struct RowSplitHandle: View {
    @Binding var height: Double
    let range: ClosedRange<Double>
    @State private var start: Double?

    var body: some View {
        Rectangle()
            .fill(Color(nsColor: .separatorColor))
            .frame(height: 1)
            .padding(.vertical, 3)
            .contentShape(Rectangle())
            .onHover { inside in
                if inside { NSCursor.resizeUpDown.push() } else { NSCursor.pop() }
            }
            .gesture(DragGesture(minimumDistance: 1, coordinateSpace: .global)
                .onChanged { v in
                    if start == nil { start = height }
                    height = min(max((start ?? height) - v.translation.height, range.lowerBound), range.upperBound)
                }
                .onEnded { _ in start = nil })
    }
}

struct FilterBar: View {
    let model: CaseModel
    /// The log viewer resets with its own button, which also clears its level chips and DQL field.
    var showsReset = true

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "line.3.horizontal.decrease.circle")
                .foregroundStyle(.secondary)
            if model.filters.isEmpty && model.timeFrom == nil && model.timeTo == nil {
                Text("Нажмите на значение в таблице, деталях или боковой панели, чтобы добавить фильтр")
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                Spacer(minLength: 8)
            } else {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 6) {
                        if model.timeFrom != nil || model.timeTo != nil { timeChip }
                        ForEach(model.filters) { f in FilterChip(model: model, filter: f) }
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: 28, alignment: .leading)
            }
            if showsReset && model.hasSearch {
                Button {
                    model.resetSearch()
                } label: {
                    Label("Сбросить всё", systemImage: "xmark.circle")
                }
                .buttonStyle(.borderless)
                .fixedSize()
                .keyboardShortcut("k", modifiers: .command)
                .help("Очистить запрос, фильтры и интервал времени (⌘K). Прежние запросы остаются в истории.")
            }
            if model.querying { ProgressView().controlSize(.small) }
            Text("\((model.isGrouped && model.selectedGroup == nil ? model.filtered.count : model.result.count).formatted()) событий")
                .font(.callout.monospacedDigit())
                .fixedSize()
            Text("\(String(format: "%.1f", model.lastQueryMs)) мс")
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
                .fixedSize()
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 5)
        .frame(minHeight: 32)
    }

    private var timeChip: some View {
        let f = model.formatter
        let from = model.timeFrom.map { f.string($0) } ?? "…"
        let to = model.timeTo.map { f.string($0) } ?? "…"
        return HStack(spacing: 4) {
            Image(systemName: "clock")
            Text("\(from) – \(to)")
            Button { model.setTimeWindow(from: nil, to: nil) } label: { Image(systemName: "xmark.circle.fill") }
                .buttonStyle(.plain)
                .foregroundStyle(.secondary)
        }
        .font(.callout.monospacedDigit())
        .padding(.horizontal, 8)
        .padding(.vertical, 3)
        .background(Color.orange.opacity(0.2), in: Capsule())
    }
}

struct FilterChip: View {
    let model: CaseModel
    let filter: FieldFilter

    var body: some View {
        HStack(spacing: 4) {
            Text(model.keyTitle(filter.key)).fontWeight(.medium)
            Text(filter.negated ? "≠" : "=")
            Text(EventTableCoordinator.short(filter.value))
            Button {
                model.removeFilter(filter.id)
            } label: {
                Image(systemName: "xmark.circle.fill")
            }
            .buttonStyle(.plain)
            .foregroundStyle(.secondary)
        }
        .font(.callout)
        .padding(.horizontal, 8)
        .padding(.vertical, 3)
        .background((filter.negated ? Color.red : Color.accentColor).opacity(filter.enabled ? 0.18 : 0.06),
                    in: Capsule())
        .opacity(filter.enabled ? 1 : 0.5)
        .strikethrough(!filter.enabled)
        .onTapGesture { model.toggleFilter(filter.id) }
        .contextMenu {
            Button(filter.enabled ? String(localized: "Выключить") : String(localized: "Включить")) { model.toggleFilter(filter.id) }
            Button(filter.negated ? String(localized: "Сделать «=»") : String(localized: "Сделать «≠»")) { model.invertFilter(filter.id) }
            Button("Удалить") { model.removeFilter(filter.id) }
        }
        .help(filter.value)
    }
}

struct TimeZoneMenu: View {
    let model: CaseModel

    var body: some View {
        Menu {
            Button("UTC") { model.timeZone = .utc }
            Menu("Смещение UTC±") {
                ForEach(TimeZoneChoice.fixedOffsets, id: \.self) { s in
                    Button(TimeZoneChoice.offsetLabel(s)) { model.timeZone = .offset(s) }
                }
            }
            Menu("Часовой пояс (с переходом на летнее время)") {
                ForEach(TimeZoneChoice.namedZones, id: \.self) { id in
                    Button(id) { model.timeZone = .named(id) }
                }
            }
            Button("Локальное время Mac") { model.timeZone = .local }
        } label: {
            Label(model.timeZone.label, systemImage: "clock")
        }
        .help("Часовой пояс отображения. В кейсе время хранится в UTC.")
    }
}
