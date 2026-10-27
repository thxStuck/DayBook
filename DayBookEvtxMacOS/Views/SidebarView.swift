import DaybookStore
import EvtxCore
import SwiftUI

/// Facets: click adds `= value`, ⌥-click (or the context menu) adds `≠ value`.
struct SidebarView: View {
    let model: CaseModel
    @State private var expanded: Set<String> = ["bookmarks", "presets", "detections", "hosts", "users", CaseSchema.SystemKey.channel]

    var body: some View {
        List {
            Section {
                ForEach(model.modes) { navRow($0) }
            } header: {
                Text("Разделы")
            }
            if model.mode == .logs {
                LogTreeSections(model: model)
            } else if model.mode == .events || model.mode == .timeline {
                facetSections
            }
        }
        .listStyle(.sidebar)
        .scrollContentBackground(SnapshotRunner.active ? .hidden : .automatic)
        .background(SnapshotRunner.active ? Color(nsColor: .windowBackgroundColor) : Color.clear)
    }

    /// One section entry; the current one is highlighted.
    private func navRow(_ m: MainMode) -> some View {
        HStack(spacing: 8) {
            Label(m.title, systemImage: m.icon)
            Spacer(minLength: 4)
            if let badge = badge(m) {
                Text(badge).font(.caption.monospacedDigit()).foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 1)
        .contentShape(Rectangle())
        .listRowBackground(model.mode == m ? Color.accentColor.opacity(0.22) : Color.clear)
        .fontWeight(model.mode == m ? .semibold : .regular)
        .onTapGesture { model.mode = m }
    }

    private func badge(_ m: MainMode) -> String? {
        switch m {
        case .logs: String(model.store.sources.filter { $0.records + $0.carved > 0 }.count)
        case .detections: model.detections.map { String($0.filter { $0.hits > 0 }.count) }
        case .hosts: model.entities[.host].map { String($0.count) }
        case .users: model.entities[.user].map { String($0.count) }
        case .ips: model.entities[.ip].map { String($0.count) }
        default: nil
        }
    }

    /// Facets of the event views: presets, detections, files, bookmarks, entities, top values.
    @ViewBuilder private var facetSections: some View {
            Section(isExpanded: binding("presets")) {
                ForEach(model.isLinux ? Presets.linux : Presets.all, id: \.group) { group in
                    DisclosureGroup(group.group) {
                        ForEach(group.items) { p in
                            Text(p.title)
                                .lineLimit(1)
                                .contentShape(Rectangle())
                                .onTapGesture { model.runQuery(text: p.query) }
                                .help(p.query)
                        }
                    }
                }
            } header: {
                Text("Пресеты")
            }
            if let rules = model.detections, rules.contains(where: { $0.hits > 0 }) {
                Section(isExpanded: binding("detections")) {
                    ForEach([(5, "critical"), (4, "high"), (3, "medium"), (2, "low"), (1, "informational")], id: \.0) { rank, name in
                        let count = rules.filter { $0.hits > 0 && $0.levelRank == rank }.count
                        if count > 0 {
                            HStack(spacing: 6) {
                                LevelBadge(level: name)
                                Text("правил: \(count)").lineLimit(1)
                                Spacer()
                            }
                            .contentShape(Rectangle())
                            .onTapGesture {
                                model.mode = .events
                                model.runQuery(text: "rulelevel = \(name)")
                            }
                            .help("rulelevel = \(name)")
                        }
                    }
                    Text("Все сработавшие правила…")
                        .foregroundStyle(.secondary)
                        .contentShape(Rectangle())
                        .onTapGesture { model.mode = .detections }
                } header: {
                    Text("Детекты")
                }
            }
            Section(isExpanded: binding("sources")) {
                ForEach(model.store.sources.filter { $0.records + $0.carved > 0 }) { s in
                    facetRow(title: s.name, count: s.records + s.carved, key: CaseSchema.SystemKey.source, value: s.name,
                             badge: s.dirty ? "dirty" : nil)
                        .help(s.path + "\nSHA-256: " + s.sha256)
                }
            } header: {
                Text("Файлы журналов")
            }
            if !model.tags.isEmpty {
                Section(isExpanded: binding("bookmarks")) {
                    ForEach(model.tags.values.sorted { $0.event < $1.event }) { t in
                        HStack(spacing: 6) {
                            Image(systemName: "bookmark.fill").foregroundStyle(Color(nsColor: EventTableCoordinator.tagColor(t.color)))
                            VStack(alignment: .leading, spacing: 1) {
                                Text(model.formatter.string(model.store.timestamp(t.event))).font(.caption.monospacedDigit())
                                if !t.note.isEmpty { Text(t.note).lineLimit(2) }
                            }
                        }
                        .contentShape(Rectangle())
                        .onTapGesture { model.jump(to: t.event) }
                        .contextMenu {
                            Button("Перейти к событию") { model.jump(to: t.event) }
                            Button("Убрать закладку") { model.setTag(t.event, color: nil) }
                        }
                    }
                } header: {
                    Text("Закладки")
                }
            }
            entitySection(.host, "hosts", String(localized: "Хосты"), limit: 40)
            entitySection(.user, "users", String(localized: "Пользователи"), limit: 40)
            entitySection(.ip, "ips", String(localized: "IP-адреса"), limit: 30)
            ForEach(model.facets) { section in
                Section(isExpanded: binding(section.id)) {
                    ForEach(section.values, id: \.valueId) { v in
                        facetRow(title: v.value, count: v.count, key: section.id, value: v.value, badge: nil)
                    }
                    if section.total > section.values.count {
                        Button("Показаны \(section.values.count) из \(section.total.formatted()) — все значения…") {
                            model.mode = .events
                            model.runQuery(text: "| group by \(section.id)")
                        }
                        .buttonStyle(.link)
                        .font(.caption)
                    }
                } header: {
                    Text(section.title)
                }
            }
    }

    @ViewBuilder
    private func entitySection(_ kind: EntityKind, _ id: String, _ title: String, limit: Int) -> some View {
        let list = model.entities[kind] ?? []
        Section(isExpanded: binding(id)) {
            ForEach(list.prefix(limit)) { e in
                HStack(spacing: 6) {
                    if e.builtin { Image(systemName: "gearshape").foregroundStyle(.secondary).help("Встроенная учётная запись") }
                    Text(e.display).lineLimit(1).truncationMode(.middle)
                    Spacer(minLength: 4)
                    Text(e.events.formatted()).font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                }
                .contentShape(Rectangle())
                .onTapGesture { model.filterEvents(by: e, negated: NSEvent.modifierFlags.contains(.option)) }
                .contextMenu {
                    Button("Показать все события") { model.filterEvents(by: e) }
                    Button("Показать в таймлайне") { model.filterEvents(by: e, timeline: true) }
                    Button("Исключить") { model.filterEvents(by: e, negated: true) }
                }
                .help(([e.sid].compactMap { $0 } + e.aliases).joined(separator: "\n"))
            }
            if list.count > limit {
                Button("Все (\(list.count))…") { model.mode = kind == .host ? .hosts : kind == .user ? .users : .ips }
                    .buttonStyle(.link)
            }
        } header: {
            Text(title)
        }
        .onAppear { model.loadEntities(kind) }
    }

    private func binding(_ id: String) -> Binding<Bool> {
        Binding(get: { expanded.contains(id) },
                set: { if $0 { expanded.insert(id) } else { expanded.remove(id) } })
    }

    private func facetRow(title: String, count: Int, key: String, value: String, badge: String?) -> some View {
        HStack(spacing: 6) {
            Text(title.isEmpty ? "—" : title)
                .lineLimit(1)
                .truncationMode(.middle)
            if let badge {
                Text(badge)
                    .font(.caption2)
                    .padding(.horizontal, 4)
                    .background(.orange.opacity(0.25), in: Capsule())
            }
            Spacer(minLength: 4)
            Text(count.formatted())
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
        }
        .contentShape(Rectangle())
        .onTapGesture {
            let negate = NSEvent.modifierFlags.contains(.option)
            model.addFilter(key: key, value: value, negated: negate)
        }
        .contextMenu {
            Button("Фильтр  = \(title)") { model.addFilter(key: key, value: value, negated: false) }
            Button("Исключить  ≠ \(title)") { model.addFilter(key: key, value: value, negated: true) }
            Button("Копировать") { EventTableCoordinator.copy(value) }
        }
    }
}
