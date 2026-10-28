import DaybookSigma
import SwiftUI

/// The "Update Sigma rules" sheet: installed and latest versions, what would be downloaded, then
/// the download, the check and the result.
struct RuleUpdateView: View {
    let model: CaseModel
    let close: () -> Void
    private var updater: RuleUpdater { RuleUpdater.shared }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Обновление Sigma-правил").font(.title2.bold())
            installedSection
            Divider()
            latestSection
            stateLine
            HStack {
                if updater.installed?.installed == true {
                    Button("Вернуть встроенные правила") { updater.revertToBundled() }
                        .disabled(updater.busy)
                        .help("Удалить скачанный набор: приложение снова использует правила, вшитые в эту версию")
                }
                Spacer()
                Button("Закрыть", action: close).keyboardShortcut(.cancelAction)
                if case .installed = updater.state {
                    Button("Запустить детекты заново") {
                        model.runDetections()
                        close()
                    }
                    .keyboardShortcut(.defaultAction)
                } else if let plan = updater.plan, plan.anything {
                    Button("Скачать и установить") { updater.install() }
                        .keyboardShortcut(.defaultAction)
                        .disabled(updater.busy)
                } else {
                    Button("Проверить обновления") { updater.check() }
                        .keyboardShortcut(.defaultAction)
                        .disabled(updater.busy)
                }
            }
        }
        .padding(20)
        .frame(width: 620)
        .onAppear { if updater.plan == nil, !updater.busy { updater.check() } }
    }

    private var installedSection: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(updater.installed?.installed == true ? "Установлен скачанный набор" : "Используются правила, встроенные в приложение")
                .font(.headline)
            ForEach(updater.installed?.sources ?? [], id: \.name) { s in
                Text("\(s.name): \(Self.version(s)) · правил \(s.count)\(Self.platforms(s))")
                    .font(.callout).textSelection(.enabled)
            }
            if let g = updater.installed?.generated, !g.isEmpty {
                Text("Набор собран \(g.replacingOccurrences(of: "T", with: " ").replacingOccurrences(of: "Z", with: " UTC"))")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder private var latestSection: some View {
        if let p = updater.plan {
            VStack(alignment: .leading, spacing: 3) {
                Text("Последние версии на GitHub").font(.headline)
                Text("SigmaHQ: релиз \(p.sigma.tag) от \(String(p.sigma.published.prefix(10))) · \(Self.size(p.sigma.size))\(p.sigmaNewer ? String(localized: " — новее установленной") : String(localized: " — установлена"))")
                    .font(.callout)
                Text("Hayabusa: \(String(p.hayabusa.sha.prefix(7))) от \(String(p.hayabusa.date.prefix(10)))\(p.hayabusaNewer ? String(localized: " — новее установленной") : String(localized: " — установлена"))")
                    .font(.callout)
                if p.anything {
                    Text("Будут скачаны архив \(RuleUpdater.sigmaAsset) из релиза SigmaHQ (SHA-256 сверяется с опубликованным GitHub) и архив правил Hayabusa этого коммита; из них соберётся новый набор правил Windows и Linux. Встроенные правила останутся запасными.")
                        .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    @ViewBuilder private var stateLine: some View {
        switch updater.state {
        case .idle: EmptyView()
        case .checking: progress(String(localized: "Проверяю релизы на GitHub…"))
        case .checked:
            if updater.plan?.anything == false {
                Label("Правила актуальны", systemImage: "checkmark.circle").foregroundStyle(.green)
            }
        case let .downloading(what): progress(String(localized: "Скачиваю \(what)…"))
        case .building: progress(String(localized: "Проверяю архивы и собираю набор правил…"))
        case let .installed(message):
            Label(message, systemImage: "checkmark.circle").foregroundStyle(.green).textSelection(.enabled)
        case let .failed(message):
            Label(message, systemImage: "exclamationmark.triangle").foregroundStyle(.orange).textSelection(.enabled)
        }
    }

    private func progress(_ text: String) -> some View {
        HStack(spacing: 6) {
            ProgressView().controlSize(.small)
            Text(text)
        }
    }

    static func version(_ s: RuleLibrary.PackInfo.Source) -> String {
        let tag = s.tag.count == 40 ? String(s.tag.prefix(7)) : s.tag
        let date = s.published.isEmpty ? "" : " от " + String(s.published.prefix(10))
        return tag.isEmpty ? s.version : tag + date
    }

    static func platforms(_ s: RuleLibrary.PackInfo.Source) -> String {
        guard let w = s.windows, let l = s.linux else { return "" }
        return l > 0 ? " (Windows \(w.formatted()), Linux \(l.formatted()))" : " (Windows \(w.formatted()))"
    }

    static func size(_ bytes: Int) -> String { ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file) }
}
