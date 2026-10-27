import DaybookStore
import EvtxCore
import SwiftUI

/// Everything the import did, per file — nothing summarised away.
struct CaseInfoView: View {
    let model: CaseModel
    let dismiss: () -> Void
    @State private var flags: [Int: [String: Int]] = [:]

    private var store: CaseStore { model.store }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Сведения о кейсе").font(.title2.bold())
                Spacer()
                Button("Копировать таблицу (TSV)") { EventTableCoordinator.copy(tsv()) }
                Button("Закрыть", action: dismiss).keyboardShortcut(.defaultAction)
            }
            summary
            Divider()
            ScrollView([.horizontal, .vertical]) {
                Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 6) {
                    GridRow {
                        ForEach(headers, id: \.self) { Text($0).font(.caption.bold()).foregroundStyle(.secondary) }
                    }
                    Divider()
                    ForEach(store.sources) { s in
                        GridRow {
                            ForEach(Array(cells(s).enumerated()), id: \.offset) { i, c in
                                Text(c)
                                    .font(i == 0 ? .callout.weight(.medium) : .callout.monospacedDigit())
                                    .foregroundStyle(highlight(i, s) ? Color.orange : Color.primary)
                                    .textSelection(.enabled)
                                    .lineLimit(1)
                            }
                        }
                        .help(s.path)
                    }
                }
                .padding(.vertical, 4)
            }
        }
        .padding(20)
        .frame(minWidth: 1100, minHeight: 600)
        .task {
            let store = self.store
            flags = await Task.detached { (try? store.flagCountsBySource()) ?? [:] }.value
        }
    }

    private var summary: some View {
        let m = store.meta
        let yes = String(localized: "да"), no = String(localized: "нет")
        func opt(_ k: String) -> String { m[k] == "1" ? yes : (m[k] == "0" ? no : "—") }
        if model.isLinux { return AnyView(linuxSummary) }
        return AnyView(VStack(alignment: .leading, spacing: 4) {
            Text("Событий в кейсе: \(store.eventCount.formatted()) · файлов: \(store.sources.count) · создан: \(m["created"] ?? "—") · схема \(m["schema"] ?? "?")")
            Text("Восстановлено из slack: найдено \(m["carvedFound"] ?? "—"), уникальных \(m["carvedKept"] ?? "—") · схлопнуто копий: \(m["duplicates"] ?? "—") · ошибок разбора: \(m["parseErrors"] ?? "—")")
            Text("Параметры импорта: carving \(opt("option.carveSlack")) · объединение копий \(opt("option.mergeDuplicates")) · SHA-256 \(opt("option.hashSources")) · полнотекстовый индекс \(store.fullTextReady ? yes : no)")
            if let failed = m["failedFiles"], !failed.isEmpty {
                Text("Не удалось открыть:\n" + failed).foregroundStyle(.red).textSelection(.enabled)
            }
            Text("Время событий хранится в UTC (FILETIME, 100 нс); отображение — в выбранном поясе.")
                .foregroundStyle(.secondary)
        }
        .font(.callout))
    }

    /// Linux: what UAC recorded about each collection, and how many files were parsed.
    private var linuxSummary: some View {
        let m = store.meta
        let infos = (try? JSONDecoder().decode([UacInfo].self, from: Data((m["uac.collections"] ?? "[]").utf8))) ?? []
        let parsedFiles = store.sources.filter { $0.records > 0 }.count
        return VStack(alignment: .leading, spacing: 4) {
            Text("Событий в кейсе: \(store.eventCount.formatted()) · файлов: \(store.sources.count), из них с событиями: \(parsedFiles) · создан: \(m["created"] ?? "—") · схема \(m["schema"] ?? "?")")
            ForEach(infos, id: \.path) { c in
                Text("Сбор UAC \(c.version ?? "?"): \(c.hostname ?? "?") · \(c.os ?? "?") \(c.arch ?? "") · пояс \(c.timeZone ?? "не указан") · \(c.started ?? "—") — \(c.finished ?? "—") · ошибок в uac.log: \(c.errors)")
                Text("\(c.path) · \(c.commandLine ?? "")").foregroundStyle(.secondary).textSelection(.enabled)
            }
            Text("SHA-256 исходных файлов: \(m["option.hashSources"] == "1" ? String(localized: "да") : String(localized: "нет")) · ошибок разбора: \(m["parseErrors"] ?? "—") · полнотекстовый индекс \(store.fullTextReady ? String(localized: "да") : String(localized: "нет"))")
            if let failed = m["failedFiles"], !failed.isEmpty {
                Text("Не удалось прочитать:\n" + failed).foregroundStyle(.red).textSelection(.enabled)
            }
            Text("Время событий хранится в UTC; строки без пояса или года пересчитаны из пояса системы и даты файла и помечены флагами. Разобрано — строк или записей с распознанной структурой; пропущено — пустых строк и неполных записей.")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .font(.callout)
    }

    private var headers: [String] { model.isLinux ? Self.linuxHeaders : Self.headers }

    static let linuxHeaders: [String] = [
        String(localized: "Файл"), String(localized: "Журнал"), String(localized: "Хост"), String(localized: "Формат"),
        String(localized: "Размер"), "SHA-256", String(localized: "Событий"), String(localized: "Разобрано"),
        String(localized: "Пропущено"), String(localized: "Первое"), String(localized: "Последнее"),
        String(localized: "Флаги записей"), String(localized: "Примечание"),
    ]

    static let headers: [String] = [
        String(localized: "Файл"), String(localized: "Размер"), "SHA-256", String(localized: "Версия"), "Dirty",
        String(localized: "Чанков (заголовок / физ.)"), String(localized: "Пустых"),
        String(localized: "За заголовком: новые / устар."), String(localized: "CRC заг. / данных"),
        String(localized: "Хвост, байт"), String(localized: "Событий"), String(localized: "Восстановл."),
        String(localized: "Копий схлопнуто"), String(localized: "Первое"), String(localized: "Последнее"),
        String(localized: "Флаги записей"),
    ]

    private func cells(_ s: SourceInfo) -> [String] {
        func n(_ v: Int?) -> String { v.map { $0.formatted() } ?? "—" }
        let f = flags[s.id] ?? [:]
        let flagText = f.sorted { $0.key < $1.key }.map { "\($0.key) \($0.value)" }.joined(separator: ", ")
        if model.isLinux {
            return [
                s.name, s.channel ?? "—", s.host ?? "—", s.format ?? "—",
                ByteCountFormatter.string(fromByteCount: s.size, countStyle: .file),
                s.sha256.isEmpty ? "—" : s.sha256,
                s.records.formatted(), n(s.parsed), n(s.skipped),
                s.firstTs.map { model.formatter.string($0) } ?? "—",
                s.lastTs.map { model.formatter.string($0) } ?? "—",
                flagText.isEmpty ? "—" : flagText,
                s.note ?? "",
            ]
        }
        return [
            s.name,
            ByteCountFormatter.string(fromByteCount: s.size, countStyle: .file),
            s.sha256.isEmpty ? "—" : s.sha256,
            s.formatVersion ?? "—",
            s.dirty ? String(localized: "да") : String(localized: "нет"),
            "\(s.headerChunks) / \(s.chunks)",
            n(s.emptyChunks),
            "\(n(s.beyondHeaderNew)) / \(n(s.beyondHeaderStale))",
            "\(n(s.badHeaderCRC)) / \(n(s.badDataCRC))",
            n(s.trailingBytes),
            s.records.formatted(),
            s.carved.formatted(),
            s.duplicates.formatted(),
            s.firstTs.map { model.formatter.string($0) } ?? "—",
            s.lastTs.map { model.formatter.string($0) } ?? "—",
            flagText.isEmpty ? "—" : flagText,
        ]
    }

    /// Columns worth a second look are highlighted (stale header, CRC errors, …).
    private func highlight(_ column: Int, _ s: SourceInfo) -> Bool {
        if model.isLinux {
            switch column {
            case 7: return (s.parsed ?? 0) < s.records
            case 12: return s.records == 0 && s.size > 0
            default: return false
            }
        }
        switch column {
        case 7: return (s.beyondHeaderNew ?? 0) + (s.beyondHeaderStale ?? 0) > 0
        case 8: return (s.badHeaderCRC ?? 0) + (s.badDataCRC ?? 0) > 0
        case 9: return (s.trailingBytes ?? 0) > 0
        case 15: return (flags[s.id]?["parseError"] ?? 0) > 0
        default: return false
        }
    }

    private func tsv() -> String {
        ([headers + [String(localized: "Путь")]] + store.sources.map { cells($0) + [$0.path] })
            .map { $0.joined(separator: "\t") }.joined(separator: "\n")
    }
}
