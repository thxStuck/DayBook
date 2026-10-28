import AppKit
import SwiftUI

/// Project addresses; the documentation opens in the interface language.
enum AppLinks {
    static let repo = URL(string: "https://github.com/thxStuck/DayBook")!
    static let newIssue = URL(string: "https://github.com/thxStuck/DayBook/issues/new")!
    static var docs: URL {
        let lang = Bundle.main.preferredLocalizations.first == "ru" ? "ru/" : "en/"
        return URL(string: "https://thxstuck.github.io/DayBook/" + lang)!
    }
}

/// The standard About panel with credits: what the app does, links and third-party licences.
enum AboutPanel {
    static func show() {
        NSApp.orderFrontStandardAboutPanel(options: [.credits: credits()])
        NSApp.activate()
    }

    private static func credits() -> NSAttributedString {
        let body = NSFont.systemFont(ofSize: NSFont.smallSystemFontSize)
        let bold = NSFont.boldSystemFont(ofSize: NSFont.smallSystemFontSize)
        let centered = NSMutableParagraphStyle()
        centered.alignment = .center
        let text = NSMutableAttributedString()
        func add(_ s: String, font: NSFont = body, link: URL? = nil) {
            var attributes: [NSAttributedString.Key: Any] = [.font: font, .paragraphStyle: centered,
                                                             .foregroundColor: NSColor.labelColor]
            if let link { attributes[.link] = link }
            text.append(NSAttributedString(string: s, attributes: attributes))
        }
        add(String(localized: "Анализ журналов Windows (.evtx) и сборов Linux (UAC) на macOS: поиск на языке DQL, таймлайн, хосты и пользователи, сеансы входа, деревья процессов и Sigma-детекты.") + "\n\n")
        add(String(localized: "Документация"), link: AppLinks.docs)
        add("  ·  ")
        add(String(localized: "Исходный код"), link: AppLinks.repo)
        add("  ·  ")
        add(String(localized: "Сообщить об ошибке"), link: AppLinks.newIssue)
        add("\n\n")
        add(String(localized: "Сторонние компоненты") + "\n", font: bold)
        add(String(localized: "Правила Sigma: SigmaHQ и Hayabusa — Detection Rule License 1.1. Автор каждого правила показывается рядом с каждым срабатыванием.") + "\n")
        add(String(localized: "Yams — лицензия MIT.") + "\n\n")
        add(String(localized: "Исходные журналы открываются только на чтение и никогда не изменяются."))
        return text
    }
}

/// Interface language chosen inside the app. It is the same per-app setting that System Settings →
/// Language & Region → Applications writes; macOS applies it when the app starts.
enum AppLanguage: String, CaseIterable, Identifiable {
    case system, russian, english

    var id: String { rawValue }

    private var code: String? {
        switch self {
        case .system: nil
        case .russian: "ru"
        case .english: "en"
        }
    }

    static var current: AppLanguage {
        let domain = UserDefaults.standard.persistentDomain(forName: Bundle.main.bundleIdentifier ?? "") ?? [:]
        switch (domain["AppleLanguages"] as? [String])?.first?.prefix(2) {
        case "ru"?: return .russian
        case "en"?: return .english
        default: return .system
        }
    }

    static func choose(_ language: AppLanguage, app: AppModel) {
        guard language != current else { return }
        if let code = language.code {
            UserDefaults.standard.set([code], forKey: "AppleLanguages")
        } else {
            UserDefaults.standard.removeObject(forKey: "AppleLanguages")
        }
        offerRestart(app: app)
    }

    private static func offerRestart(app: AppModel) {
        let alert = NSAlert()
        alert.messageText = String(localized: "Язык интерфейса изменится после перезапуска")
        if app.importState != nil {
            alert.informativeText = String(localized: "Сейчас идёт импорт. Перезапустите приложение, когда он закончится.")
            alert.addButton(withTitle: "OK")
            alert.runModal()
            return
        }
        var info = String(localized: "Перезапустить DayBookEvtxMacOS сейчас? Открытый кейс откроется снова.")
        if app.caseModel?.detectionProgress != nil {
            info += " " + String(localized: "Идущий прогон детектов будет прерван, прежние результаты сохранятся.")
        }
        alert.informativeText = info
        alert.addButton(withTitle: String(localized: "Перезапустить сейчас"))
        alert.addButton(withTitle: String(localized: "Позже"))
        if alert.runModal() == .alertFirstButtonReturn {
            relaunch(openCase: app.caseModel?.url)
        }
    }

    private static func relaunch(openCase: URL?) {
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.createsNewApplicationInstance = true
        if let openCase { configuration.arguments = ["-openCase", openCase.path] }
        NSWorkspace.shared.openApplication(at: Bundle.main.bundleURL, configuration: configuration) { _, error in
            Task { @MainActor in
                if let error { NSAlert(error: error).runModal() } else { NSApp.terminate(nil) }
            }
        }
    }
}

/// «Язык интерфейса» submenu in the app menu.
struct LanguageMenu: View {
    let app: AppModel

    var body: some View {
        Picker("Язык интерфейса", selection: Binding(get: { AppLanguage.current },
                                                     set: { AppLanguage.choose($0, app: app) })) {
            Text("Как в системе").tag(AppLanguage.system)
            Text(verbatim: "Русский").tag(AppLanguage.russian)
            Text(verbatim: "English").tag(AppLanguage.english)
        }
    }
}

/// Items after the standard «Справка DayBookEvtxMacOS» (the help book) in the Help menu.
struct HelpMenuItems: View {
    var body: some View {
        Button("Документация на сайте") { NSWorkspace.shared.open(AppLinks.docs) }
        Button("Язык запросов DQL на сайте") { NSWorkspace.shared.open(AppLinks.docs.appending(path: "dql.html")) }
        Divider()
        Button("Сообщить об ошибке…") { NSWorkspace.shared.open(AppLinks.newIssue) }
        Button("Страница проекта на GitHub") { NSWorkspace.shared.open(AppLinks.repo) }
    }
}
