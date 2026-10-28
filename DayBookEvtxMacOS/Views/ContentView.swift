import DaybookStore
import SwiftUI

struct ContentView: View {
    @Bindable var app: AppModel

    var body: some View {
        Group {
            if let c = app.caseModel {
                CaseView(model: c)
                    .id(ObjectIdentifier(c))
            } else {
                WelcomeView(app: app)
            }
        }
        .sheet(item: $app.importState) { state in
            ImportSheet(state: state) { app.importState = nil }
        }
        .sheet(item: $app.pendingImport) { p in
            ImportOptionsSheet(pending: p,
                               start: { app.startImport(sources: p.sources, caseURL: p.caseURL, kind: $0, options: $1) },
                               cancel: { app.pendingImport = nil })
        }
        .alert("Ошибка", isPresented: Binding(get: { app.alert != nil }, set: { if !$0 { app.alert = nil } })) {
            Button("OK") { app.alert = nil }
        } message: {
            Text(app.alert ?? "")
        }
        .task { SnapshotRunner.runIfRequested(app: app) }
    }
}

extension ImportState: Identifiable {
    var id: ObjectIdentifier { ObjectIdentifier(self) }
}

struct WelcomeView: View {
    let app: AppModel

    var body: some View {
        VStack(spacing: 22) {
            Image(systemName: "list.bullet.rectangle.portrait")
                .font(.system(size: 54))
                .foregroundStyle(.tint)
            VStack(spacing: 6) {
                Text("DayBookEvtxMacOS").font(.largeTitle.bold())
                Text("Просмотр и анализ журналов Windows (.evtx) и сборов Linux (UAC) на macOS")
                    .foregroundStyle(.secondary)
            }
            HStack(spacing: 12) {
                Button {
                    app.newCaseFromLogs()
                } label: {
                    Label("Новый кейс из журналов…", systemImage: "folder.badge.plus")
                        .frame(minWidth: 220)
                }
                .controlSize(.large)
                .buttonStyle(.borderedProminent)
                .keyboardShortcut("n")

                Button {
                    app.openCasePanel()
                } label: {
                    Label("Открыть кейс…", systemImage: "tray.and.arrow.up")
                        .frame(minWidth: 160)
                }
                .controlSize(.large)
            }
            if !app.recentCases.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Недавние кейсы").font(.headline)
                    ForEach(app.recentCases, id: \.self) { url in
                        Button {
                            app.open(url)
                        } label: {
                            HStack {
                                Image(systemName: "doc.text")
                                Text(url.deletingPathExtension().lastPathComponent)
                                Text(url.deletingLastPathComponent().path)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                                    .truncationMode(.head)
                            }
                        }
                        .buttonStyle(.link)
                    }
                }
                .frame(maxWidth: 560, alignment: .leading)
                .padding(.top, 8)
            }
            Text("Исходные файлы открываются только для чтения и не изменяются.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct ImportSheet: View {
    let state: ImportState
    let dismiss: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Импорт журналов").font(.title2.bold())
            Text(state.sources.map(\.lastPathComponent).joined(separator: ", "))
                .foregroundStyle(.secondary)
                .lineLimit(2)
            if let error = state.error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
                HStack {
                    Spacer()
                    Button("Закрыть", action: dismiss).keyboardShortcut(.defaultAction)
                }
            } else {
                Text(state.phaseTitle).font(.headline)
                if state.phase == .writing {
                    ProgressView(value: state.fraction)
                } else {
                    ProgressView().progressViewStyle(.linear)
                }
                HStack {
                    if state.events > 0 { Text("\(state.events.formatted()) событий") }
                    Spacer()
                    TimelineView(.periodic(from: state.startedAt, by: 0.5)) { ctx in
                        Text("\(String(format: "%.1f", ctx.date.timeIntervalSince(state.startedAt))) с")
                            .monospacedDigit()
                    }
                }
                .font(.callout)
                .foregroundStyle(.secondary)
                HStack {
                    Spacer()
                    Button("Отмена") { state.cancel.set() }
                        .keyboardShortcut(.cancelAction)
                }
            }
        }
        .padding(24)
        .frame(width: 520)
    }
}


/// Import options, shown before every import so nothing happens implicitly. The kind of system is
/// chosen here: Windows (EVTX files) or Linux (an extracted UAC collection); it is preselected
/// from what the chosen folders contain.
struct ImportOptionsSheet: View {
    let pending: PendingImport
    let start: (ImportKind, ImportOptions) -> Void
    let cancel: () -> Void
    @AppStorage("import.carveSlack") private var carveSlack = true
    @AppStorage("import.mergeDuplicates") private var mergeDuplicates = true
    @AppStorage("import.hashSources") private var hashSources = true
    @AppStorage("import.runDetections") private var runDetections = true
    @AppStorage("import.fileTimeline") private var fileTimeline = true
    @State private var kind: ImportKind = .windows
    @State private var found: ImportKind.Found?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Параметры импорта").font(.title2.bold())
            VStack(alignment: .leading, spacing: 2) {
                Text("Источники:").font(.headline)
                ForEach(pending.sources, id: \.self) { Text($0.path).font(.callout).textSelection(.enabled) }
                Text("Кейс: \(pending.caseURL.path)").font(.callout).foregroundStyle(.secondary).padding(.top, 4)
            }
            Divider()
            HStack(alignment: .firstTextBaseline) {
                Text("Система:").font(.headline)
                Picker("", selection: $kind) {
                    Text("Windows — журналы .evtx").tag(ImportKind.windows)
                    Text("Linux — сбор UAC").tag(ImportKind.linux)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(maxWidth: 380)
            }
            foundSummary
            if kind == .windows {
                option($carveSlack, "Восстанавливать записи из slack-области чанков",
                       "Остатки старых записей после freeSpaceOffset. Каждая восстановленная запись помечается флагом carved.")
                option($mergeDuplicates, "Объединять одинаковые записи",
                       "Одна и та же запись из живого журнала, теневой копии и slack показывается одним событием с флагом «есть копии»; все места нахождения видны в деталях. Если выключить — каждая копия будет отдельной строкой.")
                option($hashSources, "Считать SHA-256 исходных файлов",
                       "Для фиксации исходных данных (chain of custody): хеш попадает в сведения о кейсе и в экспорт.")
                option($runDetections, "Запустить Sigma-детекты после импорта",
                       "Правила SigmaHQ и Hayabusa из поставки (DRL 1.1) и папка своих правил, если выбрана. Идёт в фоне после открытия кейса; результаты сохраняются в кейсе, их можно перезапустить на экране «Детекты».")
            } else {
                Text("Папка считается распакованным сбором UAC (Unix-like Artifacts Collector): журналы берутся из [root]/var/log, истории оболочек — из домашних папок, сведения о системе — из uac.log. Разбираются syslog (auth.log, syslog, kern.log…), журналы systemd (journald, включая сжатие zstd), auditd, журналы веб-серверов (access, JSON, error), dpkg и apt, общий журнал MySQL, журналы вида «время + текст», wtmp, btmp, utmp, lastlog и истории bash, zsh, fish — включая ротации .gz и .xz. Файлы, которые не разобраны, тоже попадают в список источников с причиной.")
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
                option($runDetections, "Запустить Sigma-детекты после импорта",
                       "Правила SigmaHQ для Linux (auditd, auth, sshd, sudo, cron, запуски процессов) из установленного набора и папка своих правил. Идёт в фоне после открытия кейса.")
                option($fileTimeline, "Таймлайн файловой системы (bodyfile)",
                       "Времена изменения, доступа, смены метаданных и создания каждого файла из bodyfile сбора; совпадающие времена файла — одно событие с меткой MACB. На больших системах это миллионы событий.")
                option($hashSources, "Считать SHA-256 исходных файлов",
                       "Для фиксации исходных данных (chain of custody): хеш попадает в сведения о кейсе и в экспорт.")
            }
            Text("Исходные файлы открываются только для чтения и не изменяются.")
                .font(.footnote).foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("Отмена", action: cancel).keyboardShortcut(.cancelAction)
                Button("Начать импорт") {
                    var o = ImportOptions()
                    o.carveSlack = carveSlack
                    o.mergeDuplicates = mergeDuplicates
                    o.hashSources = hashSources
                    start(kind, o)
                }
                .keyboardShortcut(.defaultAction)
                .disabled(found == nil)
            }
        }
        .padding(24)
        .frame(width: 640)
        .task {
            let sources = pending.sources
            let f = await Task.detached(priority: .userInitiated) { ImportKind.detect(sources) }.value
            found = f
            kind = f.suggested
        }
    }

    /// What the chosen folders contain, so the choice of system is an informed one.
    @ViewBuilder private var foundSummary: some View {
        if let f = found {
            VStack(alignment: .leading, spacing: 3) {
                if f.collections.isEmpty {
                    Text("Сбор UAC не найден (нужна папка [root] и рядом uac.log, live_response или bodyfile).")
                } else {
                    ForEach(f.collections, id: \.path) { c in
                        Text("Сбор UAC: \(c.hostname ?? "?") · UAC \(c.version ?? "?") · \(c.os ?? "?") · пояс \(c.timeZone ?? "не указан") · \(c.started ?? "")")
                    }
                }
                Text("Файлов .evtx: \(f.evtxFiles.formatted())")
                if kind == .linux, f.collections.isEmpty {
                    Label("Для Linux выберите распакованный сбор UAC (архив .tar.gz сначала распакуйте).", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }
                if kind == .windows, f.evtxFiles == 0 {
                    Label("В выбранных источниках нет файлов .evtx.", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }
            }
            .font(.callout)
            .foregroundStyle(.secondary)
        } else {
            HStack(spacing: 6) {
                ProgressView().controlSize(.small)
                Text("Определяю содержимое папок…").font(.callout).foregroundStyle(.secondary)
            }
        }
    }

    private func option(_ value: Binding<Bool>, _ title: LocalizedStringKey, _ note: LocalizedStringKey) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Toggle(title, isOn: value)
            Text(note).font(.caption).foregroundStyle(.secondary).padding(.leading, 20)
        }
    }
}
