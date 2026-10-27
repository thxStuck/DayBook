import EvtxCore
import Foundation

public enum ExportFormat: String, Sendable, CaseIterable {
    case csv          // RFC 4180, comma, UTF-8
    case csvExcel     // semicolon + UTF-8 BOM (opens directly in Excel with a Russian locale);
                      // cells starting with = + - @ tab CR get a leading ' (no formula execution)
    case jsonl        // one JSON object per event
    case xlsx         // Excel workbook: events sheet (text cells are never formulas) + export info sheet
}

/// Streams events (in display order) to CSV or JSON Lines. Every row carries the time in
/// the chosen zone and in UTC, plus the source file, record id and the file's SHA-256 so
/// exported evidence can be traced back.
public struct CaseExporter: Sendable {
    public let store: CaseStore
    public let format: ExportFormat
    /// Extra field columns (field names), exported after the System columns.
    public let fields: [String]
    public let zoneLabel: String
    public let formatLocal: @Sendable (Int64) -> String

    public init(store: CaseStore, format: ExportFormat, fields: [String], zoneLabel: String,
                formatLocal: @escaping @Sendable (Int64) -> String) {
        self.store = store
        self.format = format
        self.fields = fields
        self.zoneLabel = zoneLabel
        self.formatLocal = formatLocal
    }

    /// - Parameter info: key/value lines for the XLSX "export info" sheet (query, filters, …).
    public func export(_ events: ResultSet, to url: URL, info: [(String, String)] = [],
                       progress: @Sendable (Double) -> Void = { _ in },
                       cancelled: @Sendable () -> Bool = { false }) throws -> Int {
        if format == .xlsx { return try exportXLSX(events, to: url, info: info, progress: progress, cancelled: cancelled) }
        FileManager.default.createFile(atPath: url.path, contents: nil)
        guard let out = FileHandle(forWritingAtPath: url.path) else {
            throw CocoaError(.fileWriteNoPermission, userInfo: [NSFilePathErrorKey: url.path])
        }
        defer { try? out.close() }
        let sep = format == .csvExcel ? ";" : ","
        var buffer = ""
        func flush(force: Bool = false) throws {
            if force || buffer.utf8.count > 1 << 20 {
                try out.write(contentsOf: Data(buffer.utf8))
                buffer = ""
            }
        }
        let systemHeader = ["Time (\(zoneLabel))", "TimeUTC", "Computer", "Channel", "Provider", "EventID", "Level",
                            "UserSID", "RecordID", "SourceFile", "SourceSHA256", "Flags"]
        if format != .jsonl {
            if format == .csvExcel { buffer += "\u{FEFF}" }
            buffer += (systemHeader + fields + ["EventData"]).map { Self.csv($0, sep) }.joined(separator: sep) + "\r\n"
        }
        let fieldKeys = fields.map { store.keyId($0) }
        var written = 0
        let batch = 2048
        for start in stride(from: 0, to: events.count, by: batch) {
            if cancelled() { throw CancellationError() }
            let rows = try store.rows(events.ids(start..<min(start + batch, events.count)))
            var need = Set<UInt32>()
            for r in rows { for p in r.pairs { need.insert(p.key); need.insert(p.value) } }
            let needList = Array(need)
            let strings = Dictionary(uniqueKeysWithValues: zip(needList, try store.strings(needList)))
            for r in rows {
                let source = r.source < store.sources.count ? store.sources[r.source] : nil
                let flags = Self.flagNames(r.flags)
                let pairs = r.pairs.map { (strings[$0.key] ?? "", strings[$0.value] ?? "") }
                switch format {
                case .jsonl:
                    var data: [(String, [String])] = []
                    for (k, v) in pairs {
                        if let i = data.firstIndex(where: { $0.0 == k }) { data[i].1.append(v) } else { data.append((k, [v])) }
                    }
                    var o = "{\"time\":\(Self.json(formatLocal(r.ts))),\"time_utc\":\(Self.json(FileTime.iso8601(r.ts)))"
                    o += ",\"computer\":\(Self.json(r.computer)),\"channel\":\(Self.json(r.channel)),\"provider\":\(Self.json(r.provider))"
                    o += ",\"event_id\":\(r.eventId),\"level\":\(r.level.map(String.init) ?? "null")"
                    o += ",\"user_sid\":\(r.user.map(Self.json) ?? "null"),\"record_id\":\(r.recordId)"
                    o += ",\"source_file\":\(Self.json(source?.path ?? "")),\"source_sha256\":\(Self.json(source?.sha256 ?? ""))"
                    o += ",\"flags\":[\(flags.map(Self.json).joined(separator: ","))],\"data\":{"
                    o += data.map { k, vs in Self.json(k) + ":" + (vs.count == 1 ? Self.json(vs[0]) : "[" + vs.map(Self.json).joined(separator: ",") + "]") }
                        .joined(separator: ",")
                    buffer += o + "}}\n"
                case .csv, .csvExcel, .xlsx:
                    var cells = [formatLocal(r.ts), FileTime.iso8601(r.ts), r.computer, r.channel, r.provider,
                                 String(r.eventId), r.level.map(String.init) ?? "", r.user ?? "", String(r.recordId),
                                 source?.name ?? "", source?.sha256 ?? "", flags.joined(separator: " ")]
                    for k in fieldKeys {
                        let v = k.flatMap { key in r.pairs.first { $0.key == key }.flatMap { strings[$0.value] } }
                        cells.append(v ?? "")
                    }
                    cells.append(pairs.map { "\($0.0): \($0.1)" }.joined(separator: " | "))
                    buffer += cells.map { Self.csv(format == .csvExcel ? Self.excelSafe($0) : $0, sep) }.joined(separator: sep) + "\r\n"
                }
                written += 1
            }
            try flush()
            progress(Double(min(start + batch, events.count)) / Double(max(events.count, 1)))
        }
        try flush(force: true)
        return written
    }

    static func flagNames(_ f: RecordFlags) -> [String] {
        RecordFlags.names.filter { f.contains($0.0) }.map(\.1)
    }

    /// Log values are attacker-controlled: a command line such as `=cmd|' /C calc'!A0` must not
    /// become an Excel formula. A leading apostrophe makes Excel treat the cell as text (and is
    /// not displayed); the plain CSV format keeps values byte-for-byte.
    public static func excelSafe(_ s: String) -> String {
        guard let c = s.unicodeScalars.first, ["=", "+", "-", "@", "\t", "\r"].contains(c) else { return s }
        return "'" + s
    }

    public static func csv(_ s: String, _ sep: String) -> String {
        guard s.contains(sep) || s.contains("\"") || s.contains("\n") || s.contains("\r") else { return s }
        return "\"" + s.replacingOccurrences(of: "\"", with: "\"\"") + "\""
    }

    static func json(_ s: String) -> String {
        var r = "\""
        for ch in s.unicodeScalars {
            switch ch {
            case "\"": r += "\\\""
            case "\\": r += "\\\\"
            case "\n": r += "\\n"
            case "\r": r += "\\r"
            case "\t": r += "\\t"
            default:
                if ch.value < 0x20 { r += String(format: "\\u%04x", ch.value) } else { r.unicodeScalars.append(ch) }
            }
        }
        return r + "\""
    }
}

extension CaseExporter {
    func exportXLSX(_ events: ResultSet, to url: URL, info: [(String, String)],
                    progress: @Sendable (Double) -> Void, cancelled: @Sendable () -> Bool) throws -> Int {
        guard events.count <= XLSX.maxRows else {
            throw CocoaError(.fileWriteUnknown, userInfo: [NSLocalizedDescriptionKey: String(localized: "В XLSX помещается не больше 1 048 575 строк, а в результате \(events.count). Сузьте запрос или выберите CSV / JSON Lines.")])
        }
        let archive = try ZipWriter(url: url)
        let sheetName = String(localized: "События"), infoName = String(localized: "Сведения")
        try archive.entry("[Content_Types].xml") { try $0(Data(XLSX.contentTypes.utf8)) }
        try archive.entry("_rels/.rels") { try $0(Data(XLSX.rootRels.utf8)) }
        try archive.entry("xl/workbook.xml") { try $0(Data(XLSX.workbook([sheetName, infoName]).utf8)) }
        try archive.entry("xl/_rels/workbook.xml.rels") { try $0(Data(XLSX.workbookRels(2).utf8)) }
        try archive.entry("xl/styles.xml") { try $0(Data(XLSX.styles.utf8)) }

        let header = ["Time (\(zoneLabel))", "TimeUTC", "Computer", "Channel", "Provider", "EventID", "Level",
                      "UserSID", "RecordID", "SourceFile", "SourceSHA256", "Flags"] + fields + ["EventData"]
        let widths = [24.0, 30, 22, 34, 30, 9, 7, 16, 11, 34, 20, 18] + fields.map { _ in 24.0 } + [100]
        let fieldKeys = fields.map { store.keyId($0) }
        var written = 0, truncated = 0
        try archive.entry("xl/worksheets/sheet1.xml") { append in
            var buf = XLSX.sheetStart(widths: widths, frozenHeader: true)
            truncated += XLSX.row(1, header.map { .text($0) }, bold: true, into: &buf)
            for start in stride(from: 0, to: events.count, by: 2048) {
                if cancelled() { throw CancellationError() }
                let rows = try store.rows(events.ids(start..<min(start + 2048, events.count)))
                var need = Set<UInt32>()
                for r in rows { for p in r.pairs { need.insert(p.key); need.insert(p.value) } }
                let needList = Array(need)
                let strings = Dictionary(uniqueKeysWithValues: zip(needList, try store.strings(needList)))
                for r in rows {
                    let source = r.source < store.sources.count ? store.sources[r.source] : nil
                    var cells: [XLSX.Cell] = [.text(formatLocal(r.ts)), .text(FileTime.iso8601(r.ts)), .text(r.computer),
                                              .text(r.channel), .text(r.provider), .number(Int64(r.eventId)),
                                              r.level.map { .number(Int64($0)) } ?? .text(""), .text(r.user ?? ""),
                                              .number(Int64(bitPattern: r.recordId)), .text(source?.name ?? ""),
                                              .text(source?.sha256 ?? ""), .text(Self.flagNames(r.flags).joined(separator: " "))]
                    for k in fieldKeys {
                        cells.append(.text(k.flatMap { key in r.pairs.first { $0.key == key }.flatMap { strings[$0.value] } } ?? ""))
                    }
                    cells.append(.text(r.pairs.map { "\(strings[$0.key] ?? ""): \(strings[$0.value] ?? "")" }.joined(separator: " | ")))
                    written += 1
                    truncated += XLSX.row(written + 1, cells, into: &buf)
                }
                try append(Data(buf.utf8))
                buf = ""
                progress(Double(min(start + 2048, events.count)) / Double(max(events.count, 1)))
            }
            buf += "</sheetData><autoFilter ref=\"A1:\(XLSX.column(header.count - 1))\(written + 1)\"/></worksheet>"
            try append(Data(buf.utf8))
        }

        try archive.entry("xl/worksheets/sheet2.xml") { append in
            var buf = XLSX.sheetStart(widths: [34, 120], frozenHeader: false)
            var n = 0
            func line(_ k: String, _ v: String, bold: Bool = false) {
                n += 1
                _ = XLSX.row(n, [.text(k), .text(v)], bold: bold, into: &buf)
            }
            line(String(localized: "Кейс"), store.url.path, bold: true)
            line(String(localized: "Экспорт (UTC)"), ISO8601DateFormatter().string(from: Date()))
            line(String(localized: "Часовой пояс колонки времени"), zoneLabel)
            for (k, v) in info { line(k, v) }
            line(String(localized: "Событий в экспорте"), String(written))
            line(String(localized: "Ячеек, обрезанных до 32 767 символов (лимит Excel)"), String(truncated))
            n += 1
            line(String(localized: "Исходные файлы"), String(localized: "путь · SHA-256 · записей"), bold: true)
            for s in store.sources {
                line(s.name, "\(s.path) · \(s.sha256.isEmpty ? "—" : s.sha256) · \(s.records)")
            }
            buf += "</sheetData></worksheet>"
            try append(Data(buf.utf8))
        }
        try archive.finish()
        return written
    }
}
