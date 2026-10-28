import AppKit
import DaybookStore
import SwiftUI

nonisolated struct DetectionRow: Identifiable, Sendable {
    let r: DetectionRule
    var id: Int64 { r.id }
    var level: Int { r.levelRank }
    var title: String { r.title }
    var hits: Int { r.hits }
    var hosts: Int { r.hosts }
    var first: Int64 { r.firstTs ?? .max }
    var last: Int64 { r.lastTs ?? .min }
    var source: String { r.source }
    var author: String { r.author ?? "" }
    var status: String { r.status ?? "" }
}

enum DetectionScope: String, CaseIterable, Identifiable {
    case hits, evaluated, problems, all
    var id: String { rawValue }
    var title: String {
        switch self {
        case .hits: String(localized: "Сработавшие")
        case .evaluated: String(localized: "Все вычисленные")
        case .problems: String(localized: "Не вычислены / с замечаниями")
        case .all: String(localized: "Все правила")
        }
    }
}

struct LevelBadge: View {
    let level: String?

    var body: some View {
        Text(Self.title(level))
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 6)
            .padding(.vertical, 1)
            .background(Self.color(level).opacity(0.18), in: Capsule())
            .foregroundStyle(Self.color(level))
    }

    static func title(_ level: String?) -> String {
        switch level?.lowercased() {
        case "critical": String(localized: "критический")
        case "high": String(localized: "высокий")
        case "medium": String(localized: "средний")
        case "low": String(localized: "низкий")
        case "informational": String(localized: "информ.")
        default: level ?? "—"
        }
    }

    static func color(_ level: String?) -> Color {
        switch level?.lowercased() {
        case "critical": .red
        case "high": .orange
        case "medium": .yellow
        case "low": .blue
        default: .secondary
        }
    }
}

struct DetectionsView: View {
    let model: CaseModel
    @State private var sortOrder = [KeyPathComparator(\DetectionRow.level, order: .reverse)]
    @State private var search = ""
    @State private var minLevel = 0
    @State private var scope = DetectionScope.hits
    @State private var showLicenses = false
    @State private var showUpdate = false
    @AppStorage(RuleLibrary.customFolderKey) private var customFolder = ""

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            Divider()
            content
            Divider()
            footer
        }
        .onAppear { if model.detections == nil { model.loadDetections() } }
        .sheet(isPresented: $showLicenses) { RuleLicensesView(meta: model.detectionMeta) { showLicenses = false } }
        .sheet(isPresented: $showUpdate) { RuleUpdateView(model: model) { showUpdate = false } }
    }

    private var toolbar: some View {
        HStack(spacing: 10) {
            Picker("", selection: $scope) {
                ForEach(DetectionScope.allCases) { Text($0.title).tag($0) }
            }
            .fixedSize()
            Picker("Уровень", selection: $minLevel) {
                Text("Любой уровень").tag(0)
                Text("≥ низкий").tag(2)
                Text("≥ средний").tag(3)
                Text("≥ высокий").tag(4)
                Text("критический").tag(5)
            }
            .fixedSize()
            TextField("Поиск: название, автор, тег, путь", text: $search)
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 300)
            Spacer()
            if let p = model.detectionProgress {
                ProgressView(value: p.total > 0 ? Double(p.done) / Double(p.total) : 0)
                    .frame(width: 120)
                Text(p.total > 0 ? "\(p.done) / \(p.total)" : String(localized: "загрузка правил…"))
                    .font(.caption).monospacedDigit().foregroundStyle(.secondary)
                Button("Остановить") { model.cancelDetections() }
            } else {
                Menu {
                    Button("Выбрать папку своих правил…") { chooseFolder() }
                    if !customFolder.isEmpty {
                        Button("Не использовать папку «\(URL(fileURLWithPath: customFolder).lastPathComponent)»") { customFolder = "" }
                    }
                    Divider()
                    Button("Экспорт сработавших правил — CSV для Excel…") { exportRules(excel: true) }
                    Button("Экспорт сработавших правил — CSV…") { exportRules(excel: false) }
                    Divider()
                    Button("Наборы правил и лицензии…") { showLicenses = true }
                } label: {
                    Label("Правила", systemImage: "list.bullet.rectangle")
                }
                .fixedSize()
                Button {
                    showUpdate = true
                } label: {
                    Label("Обновить Sigma-правила", systemImage: "arrow.triangle.2.circlepath")
                }
                .help("Проверить новый релиз SigmaHQ и правила Hayabusa на GitHub и скачать, если они новее установленных")
                Button(model.detections?.isEmpty == false ? String(localized: "Запустить заново") : String(localized: "Запустить детекты")) { model.runDetections() }
            }
        }
        .padding(8)
    }

    @ViewBuilder private var content: some View {
        if let e = model.detectionError {
            Text(e).foregroundStyle(.red).textSelection(.enabled).padding()
        }
        if model.detections == nil {
            ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if model.detections!.isEmpty {
            emptyState
        } else {
            HSplitView {
                table.frame(minWidth: 380, maxWidth: .infinity, maxHeight: .infinity)
                Group {
                    if let id = model.selectedDetection, let r = model.detections?.first(where: { $0.id == id }) {
                        RuleCard(model: model, rule: r)
                    } else {
                        Text("Выберите правило").foregroundStyle(.secondary).frame(maxWidth: .infinity, maxHeight: .infinity)
                    }
                }
                .frame(minWidth: 260, idealWidth: 400, maxWidth: 640, maxHeight: .infinity)
            }
        }
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "shield.lefthalf.filled").font(.system(size: 40)).foregroundStyle(.secondary)
            Text("Детекты для этого кейса ещё не запускались").font(.title3)
            Text("Будут проверены правила SigmaHQ и Hayabusa из поставки (и папка своих правил, если выбрана). Каждое правило переводится в DQL; что не удалось перевести, будет показано с причиной. Результаты сохраняются в кейсе.")
                .multilineTextAlignment(.center).foregroundStyle(.secondary).frame(maxWidth: 520)
            Button("Запустить детекты") { model.runDetections() }.disabled(model.detectionProgress != nil)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var rows: [DetectionRow] {
        let q = search.lowercased()
        return (model.detections ?? []).lazy
            .filter { r in
                switch scope {
                case .hits: r.hits > 0
                case .evaluated: r.evaluated
                case .problems: !r.evaluated || !r.warnings.isEmpty
                case .all: true
                }
            }
            .filter { minLevel == 0 || $0.levelRank >= minLevel }
            .filter { r in
                q.isEmpty || r.title.lowercased().contains(q) || (r.author?.lowercased().contains(q) ?? false)
                    || r.path.lowercased().contains(q) || r.tags.contains { $0.lowercased().contains(q) } || r.ruleId.lowercased() == q
            }
            .map(DetectionRow.init)
            .sorted(using: sortOrder)
    }

    private var table: some View {
        let fmt = model.formatter
        return Table(rows, selection: Binding(get: { model.selectedDetection }, set: { model.selectedDetection = $0 }), sortOrder: $sortOrder) {
            TableColumn("Уровень", value: \.level) { r in LevelBadge(level: r.r.level) }.width(min: 60, ideal: 90)
            TableColumn("Правило", value: \.title) { r in
                HStack(spacing: 4) {
                    if r.r.unsupported != nil { Image(systemName: "nosign").foregroundStyle(.secondary).help(r.r.unsupported!) }
                    else if r.r.error != nil { Image(systemName: "exclamationmark.octagon").foregroundStyle(.red).help(r.r.error!) }
                    else if !r.r.warnings.isEmpty { Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange).help(r.r.warnings.joined(separator: "\n")) }
                    Text(r.title).lineLimit(1)
                }
            }.width(min: 140, ideal: 360)
            TableColumn("Событий", value: \.hits) { r in Text(r.hits > 0 ? "\(r.hits)" : "—").monospacedDigit() }.width(min: 45, ideal: 70)
            TableColumn("Хостов", value: \.hosts) { r in Text(r.hosts > 0 ? "\(r.hosts)" : "").monospacedDigit() }.width(min: 35, ideal: 55)
            // Rule author next to every match (Detection Rule License 1.1).
            TableColumn("Автор", value: \.author).width(min: 70, ideal: 170)
            TableColumn("Первое", value: \.first) { r in Text(r.r.firstTs.map { fmt.string($0) } ?? "").monospacedDigit() }.width(min: 80, ideal: 165)
            TableColumn("Последнее", value: \.last) { r in Text(r.r.lastTs.map { fmt.string($0) } ?? "").monospacedDigit() }.width(min: 80, ideal: 165)
            TableColumn("Набор", value: \.source).width(min: 40, ideal: 80)
            TableColumn("Статус", value: \.status).width(min: 35, ideal: 70)
        }
        .contextMenu(forSelectionType: Int64.self) { ids in
            if let id = ids.first, let r = model.detections?.first(where: { $0.id == id }) {
                Button("События правила") { model.showDetection(r) }.disabled(r.hits == 0)
                Button("События правила в таймлайне") { model.showDetection(r, timeline: true) }.disabled(r.hits == 0)
                Divider()
                Button("Скопировать DQL правила") { copy(r.query) }.disabled(r.query.isEmpty)
                Button("Скопировать запрос событий") { copy(CaseModel.detectionQuery(r)) }
            }
        } primaryAction: { ids in
            if let id = ids.first, let r = model.detections?.first(where: { $0.id == id }), r.hits > 0 { model.showDetection(r) }
        }
    }

    private var footer: some View {
        let m = model.detectionMeta
        let rules = model.detections ?? []
        return HStack(spacing: 6) {
            if let finished = m["finished"] {
                Text("Прогон \(finished.replacingOccurrences(of: "T", with: " ").replacingOccurrences(of: "Z", with: " UTC"))")
                Text("· правил \(m["rules_total"] ?? "?"): вычислено \(m["evaluated"] ?? "?"), не поддерживается \(m["unsupported"] ?? "?"), не загружено \(m["failed"] ?? "?"), ошибок \(m["errors"] ?? "?"), с замечаниями \(rules.filter { !$0.warnings.isEmpty }.count)")
                Text("· сработало \(m["with_hits"] ?? "?") на \(m["hit_events"] ?? "?") событиях")
                if let other = m["other_platform"], other != "0" {
                    Text("· правил другой системы не применялось: \(other)")
                        .help("К кейсу применяются правила его системы: Windows — к журналам .evtx, Linux — к сборам UAC")
                }
                Text("· \(String(format: "%.1f", (Double(m["elapsed_ms"] ?? "") ?? 0) / 1000)) с")
                    .help("Компиляция \(m["compile_ms"] ?? "?") мс, предрасчёт подстрок \(m["prefetch_ms"] ?? "?") мс (\(m["prefetch_predicates"] ?? "?") предикатов), вычисление \(m["evaluate_ms"] ?? "?") мс")
            } else {
                Text("Детекты не запускались")
            }
            Spacer()
            Button(Self.packLabel) { showLicenses = true }.buttonStyle(.link)
        }
        .font(.caption)
        .foregroundStyle(.secondary)
        .lineLimit(1)
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
    }

    /// The pack in use: versions of SigmaHQ and Hayabusa, downloaded or bundled.
    static var packLabel: String {
        guard let info = RuleUpdater.shared.installed else { return String(localized: "Правила: SigmaHQ, Hayabusa — DRL 1.1") }
        let parts = info.sources.map { "\($0.name) \(RuleUpdateView.version($0))" }.joined(separator: ", ")
        return (info.installed ? String(localized: "Правила (скачаны): ") : String(localized: "Правила (встроенные): ")) + parts + " — DRL 1.1"
    }

    /// Matched rules (with authors, as DRL 1.1 requires) for a report, times in the display zone and UTC.
    private func exportRules(excel: Bool) {
        let rules = (model.detections ?? []).filter { $0.hits > 0 }
            .sorted { ($0.levelRank, $0.hits) > ($1.levelRank, $1.hits) }
        let panel = NSSavePanel()
        panel.title = String(localized: "Экспорт сработавших правил")
        panel.nameFieldStringValue = "\(model.title)-detections.csv"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let fmt = model.formatter
        let text = DetectionExport.csv(rules, excel: excel, zoneLabel: model.timeZone.headerLabel(at: nil)) { fmt.string($0) }
        do { try text.write(to: url, atomically: true, encoding: .utf8) } catch {
            model.errorMessage = String(localized: "Экспорт не удался: ") + "\(error)"
        }
    }

    private func chooseFolder() {
        let panel = NSOpenPanel()
        panel.title = String(localized: "Папка с правилами Sigma (.yml)")
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        customFolder = url.path
    }

    private func copy(_ s: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(s, forType: .string)
    }
}

/// Everything known about one rule: attribution (DRL 1.1), why it did or did not run, how it
/// was translated, and its hits.
struct RuleCard: View {
    let model: CaseModel
    let rule: DetectionRule
    @State private var yaml: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                header
                problems
                if rule.hits > 0 { hits }
                if let d = rule.description, !d.isEmpty { Text(d).textSelection(.enabled) }
                translation
                metadata
                DisclosureGroup("Исходный YAML") {
                    Text(yaml ?? "")
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .onAppear { if yaml == nil { yaml = (try? model.store.detectionYAML(rule.id)) ?? "" } }
                }
            }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .id(rule.id)
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(rule.title).font(.title3.bold()).textSelection(.enabled)
            HStack(spacing: 6) {
                LevelBadge(level: rule.level)
                if let s = rule.status { Text(s).font(.caption).foregroundStyle(.secondary) }
                Text("·").foregroundStyle(.secondary)
                Text(rule.source).font(.caption).foregroundStyle(.secondary)
            }
            // Attribution required by the Detection Rule License 1.1.
            Text("Автор: \(rule.author ?? String(localized: "не указан"))").font(.callout).textSelection(.enabled)
            Text("\(rule.path) · id \(rule.ruleId.isEmpty ? "—" : rule.ruleId)")
                .font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
            if let d = rule.date {
                Text("Создано \(d)\(rule.modified.map { String(localized: ", изменено \($0)") } ?? "")").font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder private var problems: some View {
        if let u = rule.unsupported {
            note("nosign", .secondary, String(localized: "Правило не вычислялось"), u)
        }
        if let e = rule.error {
            note("exclamationmark.octagon", .red, String(localized: "Ошибка вычисления"), e)
        }
        ForEach(rule.warnings, id: \.self) { w in
            note("exclamationmark.triangle", .orange, String(localized: "Замечание"), w)
        }
        if !rule.absentFields.isEmpty {
            note("questionmark.circle", .orange, String(localized: "Поля, которых нет в этом кейсе"),
                 rule.absentFields.joined(separator: ", ") + "\n" + String(localized: "Условия по ним ложны (а «поле: null» — истинно), поэтому отсутствие срабатываний не означает, что активности не было."))
        }
    }

    private var hits: some View {
        let fmt = model.formatter
        return VStack(alignment: .leading, spacing: 6) {
            Text("Сработало на \(rule.hits) событиях, хостов: \(rule.hosts)").font(.headline)
            if let a = rule.firstTs, let b = rule.lastTs {
                Text("\(fmt.string(a)) — \(fmt.string(b))").monospacedDigit().font(.callout)
            }
            HStack {
                Button("События") { model.showDetection(rule) }
                Button("В таймлайне") { model.showDetection(rule, timeline: true) }
            }
        }
    }

    private var translation: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Как проверялось").font(.headline)
            if !rule.logsource.isEmpty { Text("logsource: \(rule.logsource)").font(.caption).foregroundStyle(.secondary) }
            ForEach(rule.variants, id: \.self) { v in Text("• \(v)").font(.callout) }
            if !rule.query.isEmpty {
                Text(rule.query)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 6))
                HStack {
                    Button("Выполнить этот DQL") { model.showQuery(rule.query) }
                    Button("Скопировать") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(rule.query, forType: .string)
                    }
                    Spacer()
                    Text("\(String(format: "%.1f", rule.elapsedMs)) мс").font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }

    @ViewBuilder private var metadata: some View {
        if !rule.tags.isEmpty {
            VStack(alignment: .leading, spacing: 4) {
                Text("Теги").font(.headline)
                ForEach(rule.tags, id: \.self) { t in
                    if let url = Self.attackURL(t) { Link(t, destination: url).font(.callout) } else { Text(t).font(.callout) }
                }
            }
        }
        if !rule.falsePositives.isEmpty {
            VStack(alignment: .leading, spacing: 4) {
                Text("Ложные срабатывания (по мнению автора)").font(.headline)
                ForEach(rule.falsePositives, id: \.self) { Text("• \($0)").font(.callout) }
            }
        }
        if !rule.references.isEmpty {
            VStack(alignment: .leading, spacing: 4) {
                Text("Ссылки").font(.headline)
                ForEach(rule.references, id: \.self) { r in
                    if let url = URL(string: r), url.scheme?.hasPrefix("http") == true { Link(r, destination: url).font(.caption) }
                    else { Text(r).font(.caption).textSelection(.enabled) }
                }
            }
        }
    }

    private func note(_ icon: String, _ color: Color, _ title: String, _ text: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: icon).foregroundStyle(color)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.callout.weight(.semibold))
                Text(text).font(.callout).textSelection(.enabled)
            }
        }
        .padding(8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(color.opacity(0.08), in: RoundedRectangle(cornerRadius: 6))
    }

    /// attack.t1059.001 → https://attack.mitre.org/techniques/T1059/001/
    static func attackURL(_ tag: String) -> URL? {
        let t = tag.lowercased()
        guard t.hasPrefix("attack.t") else { return nil }
        let parts = t.dropFirst("attack.".count).split(separator: ".")
        guard let tech = parts.first, tech.dropFirst().allSatisfy(\.isNumber) else { return nil }
        var path = "https://attack.mitre.org/techniques/" + tech.uppercased() + "/"
        if parts.count > 1, parts[1].allSatisfy(\.isNumber) { path += parts[1] + "/" }
        return URL(string: path)
    }
}

/// Rule sets, versions, links and the Detection Rule License text.
struct RuleLicensesView: View {
    let meta: [String: String]
    let close: () -> Void

    private var sources: [[String: Any]] {
        if let s = meta["sources"], let data = s.data(using: .utf8),
           let arr = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] { return arr }
        guard let url = RuleLibrary.packURL, let data = try? Data(contentsOf: url),
              let doc = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [] }
        return doc["sources"] as? [[String: Any]] ?? []
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Наборы правил").font(.title2.bold())
            ForEach(Array(sources.enumerated()), id: \.offset) { _, s in
                VStack(alignment: .leading, spacing: 2) {
                    Text("\(s["name"] as? String ?? "?") — \(s["count"] as? Int ?? 0) правил").font(.headline)
                    if let v = s["version"] as? String, !v.isEmpty { Text("Версия: \(v)").font(.caption) }
                    if let u = s["url"] as? String, let url = URL(string: u), url.scheme != nil { Link(u, destination: url).font(.caption) }
                    if let l = s["license"] as? String {
                        if let lu = s["licenseURL"] as? String, let url = URL(string: lu), url.scheme != nil {
                            Link(l, destination: url).font(.caption)
                        } else {
                            Text(l).font(.caption)
                        }
                    }
                }
            }
            Text("Автор каждого правила показан в его карточке и в деталях события — этого требует лицензия DRL 1.1. Псевдонимы полей Hayabusa взяты из config/eventkey_alias.txt репозитория hayabusa-rules и применяются только к правилам Hayabusa.")
                .font(.caption).foregroundStyle(.secondary)
            Divider()
            ScrollView {
                Text(RuleLibrary.licenseText).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(minHeight: 200)
            HStack {
                Spacer()
                Button("Закрыть", action: close).keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 640, height: 560)
    }
}
