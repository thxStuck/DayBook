import DaybookStore
import EvtxCore
import SwiftUI

// MARK: Sessions

nonisolated struct SessionRow: Identifiable, Sendable {
    let s: LogonSession
    var id: Int { s.id }
    var start: Int64 { s.start }
    var end: Int64 { s.end ?? .max }
    var duration: Int64 { s.duration ?? .max }
    var user: String { s.user }
    var type: Int { s.logonType ?? -1 }
    var source: String { [s.workstation, s.ip].compactMap { $0 }.joined(separator: " / ") }
    var host: String { s.host }
    var logonId: String { s.logonId }
    var privileged: Int { s.privileged ? 1 : 0 }
}

struct SessionsView: View {
    let model: CaseModel
    @State private var tab = 0
    @State private var sortOrder = [KeyPathComparator(\SessionRow.start)]
    @State private var search = ""
    @State private var type = -2
    @State private var selection: Int?

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                if model.isLinux {
                    Text("Входы wtmp: вход → выход на том же терминале или перезагрузка").font(.callout).foregroundStyle(.secondary)
                } else {
                    Picker("", selection: $tab) {
                        Text("Входы 4624").tag(0).help("Вход 4624 → выход 4634/4647")
                        Text("RDP").tag(1).help("Цепочки TerminalServices-LocalSessionManager")
                    }
                    .pickerStyle(.segmented)
                    .fixedSize()
                }
                if tab == 0, !model.isLinux {
                    Picker("Тип", selection: $type) {
                        Text("Все типы").tag(-2)
                        ForEach([0, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13], id: \.self) { t in
                            Text("\(t) — \(EventDescriber.logonTypeName(String(t)) ?? "")").tag(t)
                        }
                    }
                    .fixedSize()
                }
                TextField("Поиск: пользователь, источник, хост, LogonId", text: $search)
                    .textFieldStyle(.roundedBorder)
                    .frame(minWidth: 120, maxWidth: 320)
                Spacer()
                if model.sessions == nil { ProgressView().controlSize(.small) }
            }
            .padding(8)
            Divider()
            if tab == 0 { logons } else { rdp }
            Divider()
            footer
        }
        .onAppear { model.loadSessions() }
    }

    private var rows: [SessionRow] {
        let q = search.lowercased()
        return (model.sessions?.sessions ?? []).lazy
            .filter { type == -2 || $0.logonType == type }
            .filter { s in
                q.isEmpty || s.user.lowercased().contains(q) || s.host.lowercased().contains(q)
                    || (s.workstation?.lowercased().contains(q) ?? false) || (s.ip?.contains(q) ?? false)
                    || s.logonId.lowercased().contains(q)
            }
            .map(SessionRow.init)
            .sorted(using: sortOrder)
    }

    private var logons: some View {
        let fmt = model.formatter
        return Table(rows, selection: $selection, sortOrder: $sortOrder) {
            TableColumn("Начало", value: \.start) { r in Text(fmt.string(r.start)).monospacedDigit() }.width(min: 100, ideal: 175)
            TableColumn("Конец", value: \.end) { r in
                Text(r.s.end.map { fmt.string($0) } ?? String(localized: "не закрыт")).monospacedDigit()
                    .foregroundStyle(r.s.end == nil ? .orange : .primary)
            }.width(min: 100, ideal: 175)
            TableColumn("Длительность", value: \.duration) { r in Text(r.s.duration.map(Self.duration) ?? "—").monospacedDigit() }
                .width(min: 55, ideal: 100)
            TableColumn("Пользователь", value: \.user).width(min: 80, ideal: 200)
            TableColumn("Тип", value: \.type) { r in
                Text(r.s.logonType.map { "\($0) \(EventDescriber.logonTypeName(String($0)) ?? "")" } ?? "?")
            }.width(min: 50, ideal: 120)
            TableColumn("Источник", value: \.source).width(min: 60, ideal: 170)
            TableColumn("Привил.", value: \.privileged) { r in Text(r.s.privileged ? "4672" : "") }.width(min: 35, ideal: 50)
            TableColumn("Хост", value: \.host).width(min: 55, ideal: 150)
            TableColumn("LogonId", value: \.logonId).width(min: 50, ideal: 110)
        }
        .contextMenu(forSelectionType: Int.self) { ids in
            if let id = ids.first, let s = model.sessions?.sessions.first(where: { $0.id == id }) {
                Button("События сеанса") { model.showQuery(sessionQuery(s)) }
                Button("События сеанса в таймлайне") { model.showQuery(sessionQuery(s), timeline: true) }
                Divider()
                Button("Событие входа (4624)") { model.jump(to: s.startEvent) }
                if let e = s.endEvent { Button("Событие выхода") { model.jump(to: e) } }
            }
        } primaryAction: { ids in
            if let id = ids.first, let s = model.sessions?.sessions.first(where: { $0.id == id }) { model.showQuery(sessionQuery(s)) }
        }
        // The session's logon event (4624) in the details panel.
        .onChange(of: selection) { _, id in
            if let id, let s = model.sessions?.sessions.first(where: { $0.id == id }) { model.select(s.startEvent) }
        }
    }

    private var rdp: some View {
        let fmt = model.formatter
        let list = (model.rdpSessions ?? []).filter { r in
            search.isEmpty || r.user.lowercased().contains(search.lowercased()) || r.address.contains(search) || r.host.lowercased().contains(search.lowercased())
        }
        return Table(list) {
            TableColumn("Начало") { r in Text(fmt.string(r.start)).monospacedDigit() }.width(min: 100, ideal: 175)
            TableColumn("Конец") { r in Text(r.end.map { fmt.string($0) } ?? String(localized: "не закрыт")).monospacedDigit() }
                .width(min: 100, ideal: 175)
            TableColumn("Хост", value: \.host).width(min: 100, ideal: 140)
            TableColumn("Сеанс", value: \.sessionId).width(50)
            TableColumn("Пользователь", value: \.user).width(min: 140, ideal: 200)
            TableColumn("Адрес", value: \.address).width(min: 90, ideal: 130)
            TableColumn("Шаги", value: \.steps).width(min: 200, ideal: 420)
        }
        .contextMenu(forSelectionType: RDPSession.ID.self) { ids in
            if let id = ids.first, let r = model.rdpSessions?.first(where: { $0.id == id }), let first = r.events.first {
                Button("Первое событие цепочки") { model.jump(to: first) }
                Button("События LSM этого сеанса") {
                    model.showQuery("channel = \"\(RDPSessionBuilder.channel)\" and host = \"\(r.host)\" and time >= \(CaseModel.utcLiteral(r.start))" +
                                    (r.end.map { " and time <= \(CaseModel.utcLiteral($0))" } ?? ""))
                }
            }
        }
    }

    private var footer: some View {
        let a = model.sessions
        return HStack(alignment: .top) {
            if tab == 0 {
                Text("Сопоставление: вход 4624 и выход 4634/4647 по TargetLogonId на том же хосте в пределах одной загрузки (границы загрузок — события 12, 6005, 4608). Привилегии — 4672 с тем же SubjectLogonId.")
            } else {
                Text("Цепочки строятся по SessionID хоста в журнале TerminalServices-LocalSessionManager: 21 начинает цепочку, 23 закрывает.")
            }
            Spacer()
            if let a, tab == 0 {
                Text(String(localized: "Сеансов \(a.sessions.count.formatted()) · незакрытых \(a.sessions.filter { $0.end == nil }.count.formatted()) · выходов без входа \(a.unmatchedEnds.formatted())")
                     + (a.hostsWithoutBootInfo.isEmpty ? "" : String(localized: " · нет данных о загрузках: \(a.hostsWithoutBootInfo.joined(separator: ", "))")))
            }
        }
        .font(.caption)
        .foregroundStyle(.secondary)
        .padding(8)
    }

    private func sessionQuery(_ s: LogonSession) -> String { model.sessionQuery(s) }

    static func duration(_ ticks: Int64) -> String {
        let s = ticks / FileTime.ticksPerSecond
        if s < 60 { return String(localized: "\(s) с") }
        if s < 3600 { return String(localized: "\(s / 60) мин \(s % 60) с") }
        if s < 86_400 { return String(localized: "\(s / 3600) ч \(s / 60 % 60) мин") }
        return String(localized: "\(s / 86_400) д \(s / 3600 % 24) ч")
    }
}

// MARK: Process tree

struct ProcessTreeView: View {
    let model: CaseModel
    @State private var selection: Int?
    @State private var search = ""

    var body: some View {
        let forest = model.forests[model.processSource]
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                if model.isLinux {
                    Text("Запуски программ из auditd (execve)").font(.callout).foregroundStyle(.secondary)
                } else {
                    Picker("", selection: Binding(get: { model.processSource }, set: { model.processSource = $0 })) {
                        Text("Sysmon 1/5").tag(ProcessSource.sysmon).help("Sysmon 1/5 — связь по ProcessGuid")
                        Text("Security 4688").tag(ProcessSource.security).help("Security 4688/4689 — связь по PID")
                    }
                    .pickerStyle(.segmented)
                    .fixedSize()
                }
                TextField("Поиск по образу или командной строке", text: $search)
                    .textFieldStyle(.roundedBorder)
                    .frame(minWidth: 120, maxWidth: 340)
                Spacer()
                if forest == nil { ProgressView().controlSize(.small) }
            }
            .padding(8)
            Divider()
            if let forest {
                if search.isEmpty {
                    tree(forest)
                } else {
                    matches(forest)
                }
                Divider()
                legend(forest)
            } else {
                Spacer()
            }
        }
        .onAppear { model.loadProcesses(model.processSource) }
    }

    private func nodeName(_ n: ProcessNode) -> some View {
        HStack(spacing: 4) {
            if n.synthetic {
                Image(systemName: "questionmark.circle").foregroundStyle(.orange)
                    .help("Нет события создания этого процесса в журнале: узел собран из полей родителя у дочерних процессов")
            } else if n.linkedByPID {
                Image(systemName: "link").foregroundStyle(.secondary)
                    .help("Родитель определён по PID (эвристика): последний процесс с этим PID на том же хосте и в той же загрузке, ещё не завершённый")
            }
            Text(n.name).fontWeight(n.synthetic ? .regular : .medium)
        }
        .help(n.image)
    }

    private func tree(_ forest: ProcessForest) -> some View {
        let fmt = model.formatter
        return Table(forest.roots, children: \.children, selection: $selection) {
            TableColumn("Процесс") { n in nodeName(n) }.width(min: 150, ideal: 300)
            TableColumn("PID") { n in Text(n.pid ?? "").monospacedDigit() }.width(min: 40, ideal: 70)
            TableColumn("Запуск") { n in Text(n.start.map { fmt.string($0) } ?? "—").monospacedDigit() }.width(min: 90, ideal: 175)
            TableColumn("Завершение") { n in Text(n.end.map { fmt.string($0) } ?? "").monospacedDigit() }.width(min: 90, ideal: 175)
            TableColumn("Пользователь") { n in Text(n.user ?? "") }.width(min: 60, ideal: 170)
            TableColumn("Хост") { n in Text(n.host) }.width(min: 50, ideal: 120)
            TableColumn("Командная строка") { n in Text(n.commandLine ?? "").lineLimit(1).help(n.commandLine ?? "") }
                .width(min: 80, ideal: 600)
        }
        .onChange(of: selection) { _, id in select(id, in: forest) }
        .contextMenu(forSelectionType: Int.self) { ids in menu(ids, forest) }
    }

    private func matches(_ forest: ProcessForest) -> some View {
        let fmt = model.formatter
        let q = search.lowercased()
        var found: [(ProcessNode, String)] = []
        func walk(_ n: ProcessNode, _ path: [String]) {
            if n.image.lowercased().contains(q) || (n.commandLine?.lowercased().contains(q) ?? false) {
                found.append((n, path.joined(separator: " › ")))
            }
            for c in n.children ?? [] { walk(c, path + [n.name]) }
        }
        for r in forest.roots { walk(r, []) }
        let rows = found.prefix(5000).map { MatchRow(node: $0.0, path: $0.1) }
        return Table(rows, selection: $selection) {
            TableColumn("Процесс") { r in nodeName(r.node) }.width(min: 140, ideal: 260)
            TableColumn("Предки") { r in Text(r.path).lineLimit(1).help(r.path) }.width(min: 100, ideal: 360)
            TableColumn("Запуск") { r in Text(r.node.start.map { fmt.string($0) } ?? "—").monospacedDigit() }.width(min: 90, ideal: 175)
            TableColumn("Командная строка") { r in Text(r.node.commandLine ?? "").lineLimit(1).help(r.node.commandLine ?? "") }
                .width(min: 80, ideal: 520)
        }
        .onChange(of: selection) { _, id in select(id, in: forest) }
        .contextMenu(forSelectionType: Int.self) { ids in menu(ids, forest) }
    }

    struct MatchRow: Identifiable {
        let node: ProcessNode
        let path: String
        var id: Int { node.id }
    }

    private func find(_ id: Int, _ forest: ProcessForest) -> ProcessNode? {
        func walk(_ n: ProcessNode) -> ProcessNode? {
            if n.id == id { return n }
            for c in n.children ?? [] { if let f = walk(c) { return f } }
            return nil
        }
        for r in forest.roots { if let f = walk(r) { return f } }
        return nil
    }

    private func select(_ id: Int?, in forest: ProcessForest) {
        guard let id, let n = find(id, forest), let e = n.event else { return }
        model.select(e)
    }

    @ViewBuilder
    private func menu(_ ids: Set<Int>, _ forest: ProcessForest) -> some View {
        if let id = ids.first, let n = find(id, forest) {
            if let e = n.event { Button("Перейти к событию создания") { model.jump(to: e) } }
            if let q = processQuery(n) {
                Button("События этого процесса") { model.showQuery(q) }
                Button("События этого процесса в таймлайне") { model.showQuery(q, timeline: true) }
            }
            Button("Копировать командную строку") { EventTableCoordinator.copy(n.commandLine ?? n.image) }
            Button("Копировать путь") { EventTableCoordinator.copy(n.image) }
        }
    }

    private func processQuery(_ n: ProcessNode) -> String? { model.processQuery(n) }

    private func legend(_ f: ProcessForest) -> some View {
        HStack {
            Text(model.processSource == .sysmon
                 ? String(localized: "Связь родитель → потомок записана Sysmon (ParentProcessGuid) — точная.")
                 : model.processSource == .audit
                 ? String(localized: "auditd пишет PPID; exec не меняет PID, поэтому процесс, запускавший несколько программ, виден несколько раз. Связь восстановлена эвристически (значок 🔗), «образ неизвестен» — родитель, чей запуск не попал в журнал.")
                 : String(localized: "В 4688 записан только PID родителя: связь восстановлена эвристически (значок 🔗). PID переиспользуются, проверяйте по времени."))
            Spacer()
            Text(String(localized: "Процессов \(f.processCount.formatted()) · без события создания \(f.syntheticCount.formatted())")
                 + (model.processSource != .sysmon ? String(localized: " · связано по PID \(f.pidLinkedCount.formatted())") : "")
                 + (f.repeatedGuidEvents > 0 ? String(localized: " · повторных GUID \(f.repeatedGuidEvents)") : ""))
        }
        .font(.caption)
        .foregroundStyle(.secondary)
        .padding(8)
    }
}
