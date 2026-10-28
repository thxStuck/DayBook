import DaybookSigma
import Foundation

/// Detection rules: the pack downloaded by "Update Sigma rules" (Application Support), else the
/// pack shipped with the app (SigmaHQ + Hayabusa, DRL 1.1); plus an optional folder of the
/// analyst's own rules.
nonisolated enum RuleLibrary {
    static let customFolderKey = "rules.customFolder"

    static var bundledPackURL: URL? {
        Bundle.main.url(forResource: "rules", withExtension: "json")
            ?? Bundle.main.url(forResource: "rules", withExtension: "json", subdirectory: "Rules")
    }

    /// `~/Library/Application Support/<app>/Rules/rules.json` (a temporary folder in snapshot runs,
    /// which must not change the analyst's rules).
    static var installedPackURL: URL {
        if ProcessInfo.processInfo.arguments.contains("-snapshot") {
            return FileManager.default.temporaryDirectory.appendingPathComponent("daybook-snapshot-rules/rules.json")
        }
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent(Bundle.main.bundleIdentifier ?? "DayBookEvtxMacOS")
            .appendingPathComponent("Rules/rules.json")
    }

    static var hasInstalledPack: Bool { FileManager.default.fileExists(atPath: installedPackURL.path) }

    /// The pack in use: the downloaded one when it is there, else the bundled one.
    static var packURL: URL? { hasInstalledPack ? installedPackURL : bundledPackURL }

    static var licenseText: String {
        let url = Bundle.main.url(forResource: "DRL-1.1", withExtension: "md")
            ?? Bundle.main.url(forResource: "DRL-1.1", withExtension: "md", subdirectory: "Rules")
        return url.flatMap { try? String(contentsOf: $0, encoding: .utf8) } ?? "https://github.com/SigmaHQ/Detection-Rule-License"
    }

    static func load(customFolder: String?) throws -> SigmaRuleSet {
        guard let url = packURL else {
            throw CocoaError(.fileNoSuchFile, userInfo: [NSLocalizedDescriptionKey: String(localized: "В приложении нет пакета правил rules.json")])
        }
        var set: SigmaRuleSet
        do {
            set = try SigmaRuleSet.pack(Data(contentsOf: url))
        } catch where url == installedPackURL {
            // A damaged download must not leave the app without rules.
            guard let bundled = bundledPackURL else { throw error }
            set = try SigmaRuleSet.pack(Data(contentsOf: bundled))
        }
        if let path = customFolder, !path.isEmpty {
            let folder = URL(fileURLWithPath: path)
            set.merge(.folder(folder, name: String(localized: "Свои: ") + folder.lastPathComponent))
        }
        return set
    }

    /// Versions recorded in a pack (without parsing its rules).
    struct PackInfo: Sendable {
        struct Source: Sendable {
            var name: String
            var tag: String
            var version: String
            var published: String
            var windows: Int?
            var linux: Int?
            var count: Int
        }
        var generated: String
        var sources: [Source]
        var installed: Bool

        func source(_ name: String) -> Source? { sources.first { $0.name == name } }
    }

    static func info(_ url: URL? = packURL) -> PackInfo? {
        guard let url, let data = try? Data(contentsOf: url),
              let doc = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return nil }
        let sources = (doc["sources"] as? [[String: Any]] ?? []).map { s in
            PackInfo.Source(name: s["name"] as? String ?? "?", tag: s["tag"] as? String ?? "",
                            version: s["version"] as? String ?? "", published: s["published"] as? String ?? "",
                            windows: s["windows"] as? Int, linux: s["linux"] as? Int, count: s["count"] as? Int ?? 0)
        }
        return PackInfo(generated: doc["generated"] as? String ?? "", sources: sources, installed: url == installedPackURL)
    }

    /// Back to the bundled rules (removes the downloaded pack).
    static func removeInstalledPack() throws {
        if hasInstalledPack { try FileManager.default.removeItem(at: installedPackURL) }
    }
}
