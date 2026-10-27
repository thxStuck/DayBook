import Charts
import DaybookStore
import EvtxCore
import SwiftUI

struct QueryBar: View {
    @Bindable var model: CaseModel
    @State private var showHelp = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .top, spacing: 8) {
                Image(systemName: "chevron.right.2")
                    .foregroundStyle(.secondary)
                    .padding(.top, 3)
                TextField(model.isLinux ? "DQL: Action = auth_failure | group by IpAddress, TargetUserName"
                                        : "DQL: EventID = 4624 and LogonType = 3 | group by IpAddress, TargetUserName",
                          text: $model.queryText, axis: .vertical)
                    .font(.system(size: 13, design: .monospaced))
                    .textFieldStyle(.plain)
                    .lineLimit(1...5)
                    .onSubmit { model.runQuery() }
                if !model.queryText.isEmpty {
                    Button {
                        model.runQuery(text: "")
                    } label: {
                        Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary)
                    }
                    .buttonStyle(.borderless)
                    .padding(.top, 2)
                    .help("Очистить запрос")
                }
                if model.querying {
                    Button("Стоп") { model.cancelQuery() }
                } else {
                    Button("Выполнить") { model.runQuery() }
                        .keyboardShortcut(.return, modifiers: .command)
                }
                Menu {
                    if model.history.isEmpty { Text("История пуста") }
                    ForEach(model.history.prefix(25), id: \.self) { q in
                        Button(q.count > 90 ? String(q.prefix(90)) + "…" : q) { model.runQuery(text: q) }
                    }
                } label: {
                    Image(systemName: "clock.arrow.circlepath")
                }
                .menuIndicator(.hidden)
                .fixedSize()
                .help("История запросов")
                Button { showHelp.toggle() } label: { Image(systemName: "questionmark.circle") }
                    .buttonStyle(.borderless)
                    .help("Синтаксис DQL")
                    .popover(isPresented: $showHelp, arrowEdge: .bottom) { DQLHelp() }
            }
            if let err = model.queryError {
                Label(err, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
    }
}

struct DQLHelp: View {
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 10) {
                Text("Язык запросов DQL").font(.title3.bold())
                Text("Фильтр, затем стадии через «|». Значения без пробелов можно писать без кавычек; сравнение «=» без учёта регистра.")
                    .foregroundStyle(.secondary)
                example("EventID = 4624 and LogonType in (3, 10)", "входы по сети и RDP")
                example("TargetUserName != \"SYSTEM\" and not IpAddress = \"-\"", "отрицания: != и not")
                example("CommandLine contains \"-enc\"", "подстрока (также startswith, endswith)")
                example("Image like \"*\\powershell.exe\"", "маска: * и ?")
                example("TargetUserName matches \"^svc_\"", "регулярное выражение")
                example("\"mimikatz\"", "поиск по всем полям")
                example("time between \"2026-09-30 10:00\" and \"2026-09-30 12:00\"", "время в выбранном поясе (Z — UTC)")
                example("KeyLength > 0", "числа: < <= > >= between")
                example("`Threat Name` exists", "имя поля с пробелами — в обратных кавычках")
                example("EventID = 4625 | group by TargetUserName, IpAddress | sort count desc | limit 50", "группировка")
                example("EventID = 4688 | sort NewProcessName | select time, host, NewProcessName, CommandLine", "сортировка и колонки")
                Divider()
                Text("Алиасы: host, channel, provider, id (EventID), level, user (SID), file, flag, time")
                    .font(.caption)
                Text("Флаги: carved, beyondHeader, stale, afterGap, parseError, timeSkew, foreignTemplate")
                    .font(.caption)
                Text("Запрос не превращается в SQL: он разбирается и выполняется как операции над множествами, поэтому SQL-инъекции невозможны.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(16)
        }
        .frame(width: 560, height: 520)
    }

    private func example(_ q: String, _ note: LocalizedStringKey) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(verbatim: q).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
            Text(note).font(.caption).foregroundStyle(.secondary)
        }
    }
}

/// Left panel in group mode: value | count, like a SIEM aggregation.
struct GroupsView: View {
    let model: CaseModel

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Кол-во").frame(width: 70, alignment: .trailing)
                Text((model.groupKeys ?? []).map { model.keyTitle($0) }.joined(separator: " · "))
                    .lineLimit(1)
                Spacer()
                Text("\(model.groups.count.formatted())\(model.groupsTruncated ? "+" : "") групп")
                    .foregroundStyle(.secondary)
            }
            .font(.caption.bold())
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            Divider()
            List(selection: Binding(get: { model.selectedGroup }, set: { model.selectGroup($0) })) {
                ForEach(model.groups, id: \.self) { g in
                    HStack(spacing: 10) {
                        Text(g.count.formatted())
                            .font(.callout.monospacedDigit())
                            .frame(width: 70, alignment: .trailing)
                        Text(g.values.joined(separator: "  ·  "))
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                    .tag(g)
                    .contextMenu {
                        Button("Превратить в фильтры и показать события") { model.drillDown(g) }
                        Button("Копировать") { EventTableCoordinator.copy(g.values.joined(separator: "\t") + "\t\(g.count)") }
                    }
                    .onTapGesture(count: 2) { model.drillDown(g) }
                }
            }
            .listStyle(.plain)
        }
    }
}

struct HistogramView: View {
    let model: CaseModel
    @State private var selection: ClosedRange<Date>?

    var body: some View {
        if let h = model.histogram, !h.bins.isEmpty {
            ZStack(alignment: .topTrailing) {
                Chart(h.bins) { b in
                    RectangleMark(xStart: .value("Начало", FileTime.date(b.start)),
                                  xEnd: .value("Конец", FileTime.date(b.end)),
                                  yStart: .value("0", 0),
                                  yEnd: .value("События", b.count))
                        .foregroundStyle(Color.accentColor.opacity(0.75))
                }
                .chartXSelection(range: $selection)
                .chartYAxis { AxisMarks(position: .leading, values: .automatic(desiredCount: 3)) }
                .environment(\.timeZone, model.timeZone.zone)
                .padding(.horizontal, 10)
                .padding(.vertical, 6)
                if let s = selection {
                    Button {
                        let from = FileTime.fromUnixSeconds(Int64(s.lowerBound.timeIntervalSince1970))
                        let to = FileTime.fromUnixSeconds(Int64(s.upperBound.timeIntervalSince1970.rounded(.up)))
                        selection = nil
                        model.setTimeWindow(from: from, to: to)
                    } label: {
                        Label("Фильтр по выделению", systemImage: "line.3.horizontal.decrease")
                    }
                    .controlSize(.small)
                    .padding(8)
                }
            }
            .frame(height: 96)
            .overlay(alignment: .bottomTrailing) {
                if h.outliers > 0 || h.fullRange {
                    Button {
                        model.histogramFullRange.toggle()
                    } label: {
                        Text(h.fullRange
                             ? String(localized: "Весь диапазон · обрезать выбросы")
                             : String(localized: "Вне оси: \(h.outliersBefore.formatted()) раньше, \(h.outliersAfter.formatted()) позже · показать всё"))
                    }
                    .buttonStyle(.link)
                    .font(.caption)
                    .padding(.trailing, 12)
                    .padding(.bottom, 2)
                    .help("События с аномальными датами (например, 1601 год) не попадают на ось по умолчанию, но остаются в таблице и запросах")
                }
            }
        }
    }
}
