import AppKit
import DaybookStore
import EvtxCore

/// A table column. System columns map to virtual keys (`@Channel`, …) for click-to-filter.
struct ColumnSpec: Identifiable, Hashable {
    enum Kind: Hashable {
        case time, computer, channel, eventId, level, provider, user, source, recordId, summary, actor
        case field(String)
    }

    let kind: Kind
    var width: CGFloat

    var id: String {
        if case let .field(name) = kind { return "f:" + name }
        return "\(kind)"
    }

    var title: String {
        switch kind {
        case .time: String(localized: "Время")
        case .computer: String(localized: "Компьютер")
        case .channel: String(localized: "Журнал")
        case .eventId: "ID"
        case .level: String(localized: "Уровень")
        case .provider: String(localized: "Источник")
        case .user: String(localized: "Пользователь (SID)")
        case .source: String(localized: "Файл")
        case .recordId: "RecordID"
        case .summary: String(localized: "Описание / данные события")
        case .actor: String(localized: "Пользователь")
        case let .field(name): name
        }
    }

    /// Key used for `=` / `!=` filters on this column.
    var filterKey: String? {
        switch kind {
        case .computer: CaseSchema.SystemKey.computer
        case .channel: CaseSchema.SystemKey.channel
        case .eventId: CaseSchema.SystemKey.eventId
        case .level: CaseSchema.SystemKey.level
        case .provider: CaseSchema.SystemKey.provider
        case .user: CaseSchema.SystemKey.user
        case .source: CaseSchema.SystemKey.source
        case let .field(name): name
        case .time, .recordId, .summary, .actor: nil
        }
    }

    static let defaults: [ColumnSpec] = [
        ColumnSpec(kind: .time, width: 175),
        ColumnSpec(kind: .computer, width: 150),
        ColumnSpec(kind: .channel, width: 170),
        ColumnSpec(kind: .eventId, width: 55),
        ColumnSpec(kind: .level, width: 95),
        ColumnSpec(kind: .summary, width: 620),
    ]

    static let optional: [Kind] = [.actor, .provider, .user, .source, .recordId]

    /// Log viewer: Event Viewer's column order (level, date and time, source, event id).
    static let viewer: [ColumnSpec] = [
        ColumnSpec(kind: .level, width: 110),
        ColumnSpec(kind: .time, width: 175),
        ColumnSpec(kind: .provider, width: 230),
        ColumnSpec(kind: .eventId, width: 60),
        ColumnSpec(kind: .computer, width: 150),
        ColumnSpec(kind: .summary, width: 640),
    ]

    /// Linux: no event ids; the program that wrote the line instead.
    static let linux: [ColumnSpec] = [
        ColumnSpec(kind: .time, width: 175),
        ColumnSpec(kind: .computer, width: 130),
        ColumnSpec(kind: .channel, width: 150),
        ColumnSpec(kind: .provider, width: 150),
        ColumnSpec(kind: .summary, width: 720),
    ]

    static let linuxViewer: [ColumnSpec] = [
        ColumnSpec(kind: .time, width: 175),
        ColumnSpec(kind: .provider, width: 170),
        ColumnSpec(kind: .computer, width: 130),
        ColumnSpec(kind: .summary, width: 760),
    ]

    static let linuxTimeline: [ColumnSpec] = [
        ColumnSpec(kind: .time, width: 190),
        ColumnSpec(kind: .channel, width: 150),
        ColumnSpec(kind: .computer, width: 130),
        ColumnSpec(kind: .actor, width: 150),
        ColumnSpec(kind: .provider, width: 140),
        ColumnSpec(kind: .summary, width: 760),
    ]

    static let timeline: [ColumnSpec] = [
        ColumnSpec(kind: .time, width: 190),
        ColumnSpec(kind: .channel, width: 200),
        ColumnSpec(kind: .computer, width: 140),
        ColumnSpec(kind: .actor, width: 170),
        ColumnSpec(kind: .eventId, width: 55),
        ColumnSpec(kind: .summary, width: 760),
    ]
}

/// Human-readable names for the System/Level and audit keywords (as Event Viewer shows them).
enum EventText {
    static func level(_ level: UInt8?, keywords: UInt64?) -> String {
        if let kw = keywords {
            if kw & 0x0020_0000_0000_0000 != 0 { return String(localized: "Аудит успеха") }
            if kw & 0x0010_0000_0000_0000 != 0 { return String(localized: "Аудит отказа") }
        }
        switch level {
        case 1: return String(localized: "Критический")
        case 2: return String(localized: "Ошибка")
        case 3: return String(localized: "Предупреждение")
        case 0, 4, nil: return String(localized: "Сведения")
        case 5: return String(localized: "Подробно")
        case let l?: return String(l)
        }
    }

    static func flags(_ f: RecordFlags) -> [String] {
        var out: [String] = []
        if f.contains(.carved) { out.append(String(localized: "восстановлено из slack")) }
        if f.contains(.beyondHeader) && !f.contains(.staleChunk) { out.append(String(localized: "чанк за заголовком (новые данные)")) }
        if f.contains(.staleChunk) { out.append(String(localized: "устаревший чанк")) }
        if f.contains(.afterGap) { out.append(String(localized: "после повреждённого участка")) }
        if f.contains(.parseError) { out.append(String(localized: "ошибка разбора")) }
        if f.contains(.chunkDataCRC) || f.contains(.chunkHeaderCRC) { out.append(String(localized: "CRC чанка не совпадает")) }
        if f.contains(.timeSkew) { out.append(String(localized: "TimeCreated ≠ время записи")) }
        if f.contains(.foreignTemplate) { out.append(String(localized: "шаблон из другого чанка")) }
        if f.contains(.missingTemplate) { out.append(String(localized: "шаблон не найден")) }
        if f.contains(.invalidText) { out.append(String(localized: "некорректные символы в тексте")) }
        if f.contains(.duplicate) { out.append(String(localized: "есть копии в других файлах/slack (см. «Копии этой записи»)")) }
        if f.contains(.sizeMismatch) { out.append(String(localized: "копия размера записи не совпадает")) }
        if f.contains(.yearInferred) { out.append(String(localized: "года в строке нет — восстановлен по дате файла")) }
        if f.contains(.zoneAssumed) { out.append(String(localized: "пояса в строке нет — принят пояс системы из сбора")) }
        if f.contains(.timeFromFile) { out.append(String(localized: "своего времени нет — время изменения файла")) }
        if f.contains(.notDecompressed) { out.append(String(localized: "сжатое значение не распаковано")) }
        if f.contains(.unparsed) { out.append(String(localized: "строка не разобрана — время предыдущей строки")) }
        return out
    }
}
