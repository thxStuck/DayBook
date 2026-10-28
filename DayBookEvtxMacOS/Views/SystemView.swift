import AppKit
import DaybookStore
import SwiftUI

/// Linux cases: what UAC recorded about the system — command output taken at collection time
/// (processes, network, packages…), the collector's own lists and the collected configuration and
/// autostart files. Files are read from the collection folder, read-only, on demand.
struct SystemView: View {
    let model: CaseModel
    @State private var artifacts: [UacArtifact] = []
    @State private var missing: [UacInfo] = []
    @State private var loaded = false
    @State private var selection: String?
    @State private var filter = ""
    @State private var content: (text: String, truncated: Bool)?
    @AppStorage("system.listWidth") private var listWidth = 360.0

    var body: some View {
        HStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 0) {
                header
                Divider()
                TextField("Фильтр по имени", text: $filter)
                    .textFieldStyle(.roundedBorder)
                    .padding(8)
                list
            }
            .frame(width: listWidth)
            Divider()
            viewer.frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .task { await load() }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            ForEach(model.store.uacCollections, id: \.path) { c in
                Text("\(c.hostname ?? "?") · \(c.os ?? "?") \(c.arch ?? "")").font(.headline)
                Text("UAC \(c.version ?? "?") · пояс \(c.timeZone ?? "не указан")").font(.callout)
                Text("\(c.started ?? "—") — \(c.finished ?? "—")").font(.caption).foregroundStyle(.secondary)
            }
            ForEach(missing, id: \.path) { c in
                Label("Папка сбора не найдена: \(c.path)", systemImage: "exclamationmark.triangle")
                    .font(.caption).foregroundStyle(.orange).textSelection(.enabled)
            }
        }
        .padding(10)
    }

    private var list: some View {
        let shown = filter.isEmpty ? artifacts : artifacts.filter { $0.name.localizedCaseInsensitiveContains(filter) }
        let groups = Dictionary(grouping: shown, by: \.group)
        let order = shown.reduce(into: [String]()) { if !$0.contains($1.group) { $0.append($1.group) } }
        return List(selection: $selection) {
            if !loaded {
                HStack(spacing: 6) { ProgressView().controlSize(.small); Text("Читаю папку сбора…") }
            } else if artifacts.isEmpty {
                Text("В сборе нет вывода команд и файлов настроек (или папка сбора недоступна).").foregroundStyle(.secondary)
            }
            ForEach(order, id: \.self) { g in
                Section(g) {
                    ForEach(groups[g] ?? []) { a in
                        HStack {
                            Text(a.name).lineLimit(1).truncationMode(.middle).help(a.url.path)
                            Spacer(minLength: 4)
                            Text(ByteCountFormatter.string(fromByteCount: Int64(a.size), countStyle: .file))
                                .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                        }
                        .tag(a.id)
                    }
                }
            }
        }
        .listStyle(.sidebar)
        .onChange(of: selection) { _, id in
            guard let a = artifacts.first(where: { $0.id == id }) else { content = nil; return }
            Task {
                let t = await Task.detached(priority: .userInitiated) { UacCollection.text(of: a) }.value
                if selection == a.id { content = t }
            }
        }
    }

    @ViewBuilder private var viewer: some View {
        if let a = artifacts.first(where: { $0.id == selection }) {
            VStack(alignment: .leading, spacing: 0) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(a.name).font(.headline).textSelection(.enabled)
                    Text(a.url.path).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                    if content?.truncated == true {
                        Text("Показаны первые 4 МБ файла.").font(.caption).foregroundStyle(.orange)
                    }
                }
                .padding(10)
                Divider()
                if let c = content {
                    PlainTextView(text: c.text)
                } else {
                    ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
        } else {
            ContentUnavailableView("Выберите файл", systemImage: "doc.text",
                                   description: Text("Слева — вывод команд на момент сбора (live_response), списки UAC и собранные файлы настроек и автозапуска. Файлы читаются из папки сбора и не изменяются."))
        }
    }

    private func load() async {
        guard !loaded else { return }
        let infos = model.store.uacCollections
        let found = await Task.detached(priority: .userInitiated) { () -> ([UacArtifact], [UacInfo]) in
            var all: [UacArtifact] = [], missing: [UacInfo] = []
            for info in infos {
                if let c = UacCollection(info: info) { all += c.artifacts() } else { missing.append(info) }
            }
            return (all, missing)
        }.value
        artifacts = found.0
        missing = found.1
        loaded = true
    }
}

/// Large read-only text (NSTextView: SwiftUI Text is slow with megabytes).
struct PlainTextView: NSViewRepresentable {
    let text: String

    func makeNSView(context: Context) -> NSScrollView {
        let scroll = NSTextView.scrollableTextView()
        if let tv = scroll.documentView as? NSTextView {
            tv.isEditable = false
            tv.isSelectable = true
            tv.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
            tv.textContainerInset = NSSize(width: 8, height: 8)
            tv.isHorizontallyResizable = true
            tv.textContainer?.widthTracksTextView = false
            tv.textContainer?.containerSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
        }
        scroll.hasHorizontalScroller = true
        return scroll
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        guard let tv = scroll.documentView as? NSTextView, tv.string != text else { return }
        tv.string = text
        tv.scroll(.zero)
    }
}
