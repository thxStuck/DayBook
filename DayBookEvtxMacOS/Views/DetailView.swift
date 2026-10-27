import AppKit
import DaybookStore
import EvtxCore
import SwiftUI

struct DetailView: View {
    let model: CaseModel
    @State private var tab = 0

    var body: some View {
        if let d = model.detail {
            VStack(spacing: 0) {
                Picker("", selection: $tab) {
                    Text("Поля").tag(0)
                    // Linux sources have no XML: the original line or the decoded binary record.
                    if model.isLinux { Text("Запись").tag(1) } else { Text("XML").tag(1) }
                    Text("Hex").tag(2)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .padding(8)
                Divider()
                switch tab {
                case 0:
                    FieldsView(model: model, detail: d)
                case 1:
                    if let xml = d.xml ?? d.text { MonoTextView(text: xml) } else { SourceStateView(detail: d) }
                default:
                    if let raw = d.raw { MonoTextView(text: Self.hexDump(raw)) } else { SourceStateView(detail: d) }
                }
            }
        } else {
            ContentUnavailableView("Событие не выбрано", systemImage: "doc.text.magnifyingglass",
                                   description: Text("Выберите строку в таблице."))
        }
    }

    static func hexDump(_ bytes: [UInt8]) -> String {
        var out = ""
        out.reserveCapacity(bytes.count * 4 + 64)
        for line in stride(from: 0, to: bytes.count, by: 16) {
            let chunk = bytes[line..<min(line + 16, bytes.count)]
            out += String(format: "%08X  ", line)
            for i in 0..<16 {
                out += i < chunk.count ? String(format: "%02X ", chunk[chunk.startIndex + i]) : "   "
                if i == 7 { out += " " }
            }
            out += " |" + String(chunk.map { $0 >= 0x20 && $0 < 0x7F ? Character(Unicode.Scalar($0)) : "." }) + "|\n"
        }
        return out
    }
}

/// Why XML or raw bytes are not shown (yet): the record is re-read from its source file, which
/// may be slow, moved, changed or closed to the app.
private struct SourceStateView: View {
    let detail: EventDetail
    @State private var slow = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            switch detail.sourceState {
            case .pending:
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Читаю запись из исходного файла…")
                }
                if slow {
                    Text("Файл не отвечает дольше 3 секунд: сетевая папка недоступна, диск спит или macOS ждёт разрешения на доступ к папке.")
                        .foregroundStyle(.orange)
                }
            case .loaded:
                Text("XML этой записи не собирается: запись повреждена. Сырые байты — на вкладке «Hex».")
            case .missingFile:
                Text("Исходный файл не найден — его переместили или удалили после импорта.")
            case .noAccess:
                Text("macOS не дала доступ к исходному файлу. Разрешите доступ к папке: «Системные настройки» → «Конфиденциальность и безопасность» → «Файлы и папки».")
            case let .unreadable(reason):
                Text("Не удалось прочитать исходный файл: \(reason)")
            case .recordMismatch:
                Text("По сохранённому положению в файле другая запись: файл изменился после импорта.")
            case .noLocation:
                Text("В кейсе нет положения этой записи в исходном файле.")
            }
            if let path = detail.sourcePath {
                Text(path)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
            Text("Вкладка «Поля» берёт данные из кейса и от исходного файла не зависит.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(12)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .task(id: detail.row.id) {
            slow = false
            try? await Task.sleep(for: .seconds(3))
            if !Task.isCancelled { slow = true }
        }
    }
}

private struct MonoTextView: View {
    let text: String
    var body: some View {
        ScrollView([.vertical, .horizontal]) {
            Text(text)
                .font(.system(size: 11, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(10)
        }
    }
}

private struct FieldRow: Identifiable {
    let id: Int
    let title: String
    let value: String
    let filterKey: String?
    let filterValue: String?
    let isEventData: Bool
}

private struct FieldsView: View {
    let model: CaseModel
    let detail: EventDetail

    var body: some View {
        ScrollView { FieldsContent(model: model, detail: detail) }
    }
}

/// The field list itself (also rendered directly by the snapshot runner).
struct FieldsContent: View {
    let model: CaseModel
    let detail: EventDetail

    var body: some View {
        let rows = makeRows()
        // Events have tens of fields, not thousands: a plain VStack is cheap enough
        // and keeps text selection and layout predictable.
        VStack(alignment: .leading, spacing: 0) {
                if !model.eventDetections.isEmpty {
                    header(String(localized: "Сработавшие правила (\(model.eventDetections.count))"))
                    ForEach(model.eventDetections) { r in
                        Button { model.openDetection(r.id) } label: {
                            HStack(alignment: .firstTextBaseline, spacing: 6) {
                                LevelBadge(level: r.level).frame(minWidth: 88, alignment: .leading)
                                VStack(alignment: .leading, spacing: 1) {
                                    Text(r.title).font(.callout).multilineTextAlignment(.leading)
                                    // Author attribution (Detection Rule License 1.1).
                                    Text("Автор: \(r.author ?? "—") · \(r.source)").font(.caption).foregroundStyle(.secondary)
                                }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .help(String(localized: "Открыть правило на экране «Детекты»"))
                        .padding(.horizontal, 10)
                        .padding(.vertical, 2)
                    }
                }
                header(String(localized: "Система"))
                ForEach(rows.filter { !$0.isEventData }) { row(for: $0) }
                header(String(localized: "Данные события"))
                ForEach(rows.filter(\.isEventData)) { row(for: $0) }
                if !detail.duplicates.isEmpty {
                    header(String(localized: "Копии этой записи"))
                    ForEach(Array(detail.duplicates.enumerated()), id: \.offset) { _, d in
                        let name = d.source < model.store.sources.count ? model.store.sources[d.source].name : "?"
                        Text("\(name) · chunk \(d.chunk) · offset \(d.offset)")
                            .font(.caption).foregroundStyle(.secondary)
                            .padding(.horizontal, 10).padding(.vertical, 2)
                    }
                }
        }
        .padding(.bottom, 10)
    }

    private func header(_ title: String) -> some View {
        Text(title)
            .font(.headline)
            .padding(.horizontal, 10)
            .padding(.top, 12)
            .padding(.bottom, 4)
    }

    private func row(for f: FieldRow) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(f.title)
                .font(.callout)
                .foregroundStyle(.secondary)
                .frame(width: 150, alignment: .trailing)
                .lineLimit(2)
                .help(f.title)
            Text(f.value.isEmpty ? "—" : f.value)
                .font(.system(.callout, design: f.isEventData ? .monospaced : .default))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 3)
        .contentShape(Rectangle())
        .contextMenu {
            if let key = f.filterKey, let value = f.filterValue {
                Button("Фильтр  = \(EventTableCoordinator.short(value))") { model.addFilter(key: key, value: value, negated: false) }
                Button("Исключить  ≠ \(EventTableCoordinator.short(value))") { model.addFilter(key: key, value: value, negated: true) }
            }
            if f.isEventData {
                Button("Добавить колонку «\(f.title)»") { model.addColumn(field: f.title) }
            }
            Button("Копировать значение") { EventTableCoordinator.copy(f.value) }
            Button("Копировать «имя: значение»") { EventTableCoordinator.copy("\(f.title): \(f.value)") }
        }
    }

    private func makeRows() -> [FieldRow] {
        let e = detail.row
        let fmt = model.formatter
        let K = CaseSchema.SystemKey.self
        var rows: [FieldRow] = []
        func add(_ title: String, _ value: String, _ key: String? = nil, _ filterValue: String? = nil) {
            rows.append(FieldRow(id: rows.count, title: title, value: value, filterKey: key,
                                 filterValue: filterValue ?? (key == nil ? nil : value), isEventData: false))
        }
        var byName: [String: String] = [:]
        for f in detail.fields where byName[f.key] == nil { byName[f.key] = f.value }
        if !model.isLinux, let d = EventDescriber.describe(provider: e.provider, channel: e.channel, eventId: e.eventId, field: { byName[$0] }) {
            add(String(localized: "Описание"), d)
        }
        if let tag = model.tags[e.id] {
            add(String(localized: "Закладка"), EventTableCoordinator.tagTitle(tag.color) + (tag.note.isEmpty ? "" : " — " + tag.note))
        }
        add(String(localized: "Время") + " (\(model.timeZone.headerLabel(at: e.ts)))", fmt.string(e.ts))
        add(String(localized: "Время UTC"), FileTime.iso8601(e.ts))
        if e.writtenTime != e.ts { add(String(localized: "Время записи (UTC)"), FileTime.iso8601(e.writtenTime)) }
        let source = e.source < model.store.sources.count ? model.store.sources[e.source] : nil
        if model.isLinux {
            // Linux: no event ids or SIDs; the record number is the line (text) or the record (binary).
            let binary = ["wtmp", "btmp", "utmp", "lastlog"].contains(source?.format ?? "")
            add(String(localized: "Журнал"), e.channel, K.channel)
            add(String(localized: "Программа"), e.provider, K.provider)
            add(String(localized: "Компьютер"), e.computer, K.computer)
            if let l = e.level { add(String(localized: "Уровень"), EventText.level(l, keywords: nil), K.level, String(l)) }
            if binary, source?.format != "lastlog" { add(String(localized: "Тип записи (ut_type)"), String(e.eventId), K.eventId) }
            add(binary ? String(localized: "Номер записи") : String(localized: "Номер строки"), String(e.recordId))
            if let p = e.processId { add("PID", String(p)) }
        } else {
            add("EventID", String(e.eventId), K.eventId)
            add(String(localized: "Журнал"), e.channel, K.channel)
            add(String(localized: "Источник"), e.provider, K.provider)
            add(String(localized: "Компьютер"), e.computer, K.computer)
            add(String(localized: "Уровень"), EventText.level(e.level, keywords: e.keywords), K.level, e.level.map(String.init))
            if let u = e.user { add(String(localized: "Пользователь (SID)"), u, K.user) }
            add("EventRecordID", String(e.recordId))
            if let t = e.task { add("Task", String(t), K.task) }
            if let o = e.opcode { add("Opcode", String(o), K.opcode) }
            if let k = e.keywords { add("Keywords", "0x" + String(k, radix: 16)) }
            if let p = e.processId { add("ProcessID / ThreadID", "\(p) / \(e.threadId.map(String.init) ?? "—")") }
        }
        if let s = source {
            add(String(localized: "Файл"), s.name, K.source)
            add(String(localized: "Путь"), s.path)
        }
        let flags = EventText.flags(e.flags)
        if !flags.isEmpty { add(String(localized: "Флаги"), flags.joined(separator: ", ")) }
        for f in detail.fields {
            // %%NNNN parameter codes: show the meaning next to the raw code.
            let translated = EventDescriber.param(f.value)
            let shown = translated == f.value ? f.value : "\(translated)  (\(f.value))"
            rows.append(FieldRow(id: rows.count, title: f.key, value: shown, filterKey: f.key,
                                 filterValue: f.value, isEventData: true))
        }
        return rows
    }
}
