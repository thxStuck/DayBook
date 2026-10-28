import CryptoKit
import DaybookStore
import Foundation

/// Builds the rule pack (`rules.json`) from the SigmaHQ release archive and the Hayabusa rules
/// archive — what scripts/pack_rules.py did, now also inside the app for "Update Sigma rules".
/// Every rule keeps its original YAML and path; licences (DRL 1.1) and versions are recorded.
public enum SigmaPackBuilder {
    public struct Archive: Sendable {
        public var data: Data
        /// Release tag (SigmaHQ) or commit (Hayabusa) the archive was taken from.
        public var version: String
        /// Publication time of the release / commit (ISO 8601), when known.
        public var published: String?
        public var url: String

        public init(data: Data, version: String, published: String?, url: String) {
            self.data = data
            self.version = version
            self.published = published
            self.url = url
        }
    }

    public struct Summary: Sendable {
        public var sigmaWindows = 0, sigmaLinux = 0, hayabusa = 0, aliases = 0
        public var sigmaVersion = "", hayabusaVersion = ""
    }

    static func sha256(_ d: Data) -> String { SHA256.hash(data: d).map { String(format: "%02x", $0) }.joined() }

    /// Product of a rule from its folder or its `logsource: product:` line.
    static func product(_ path: String, _ text: String) -> String? {
        if path.hasPrefix("rules/windows/") { return "windows" }
        if path.hasPrefix("rules/linux/") { return "linux" }
        for line in text.split(separator: "\n") {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t == "product: windows" { return "windows" }
            if t == "product: linux" { return "linux" }
        }
        return nil
    }

    public static func build(sigma: Archive, hayabusa: Archive?) throws -> (json: Data, summary: Summary) {
        var summary = Summary()
        var rules: [[String: String]] = []
        let zip = try ZipReader(sigma.data)
        var picked: [(String, String, String)] = []   // path, yaml, product
        var label = sigma.version
        for e in zip.entries {
            if e.name == "version.txt" {
                let text = String(decoding: try zip.read(e), as: UTF8.self)
                label = text.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }.joined(separator: " · ")
                continue
            }
            guard e.name.hasPrefix("rules/") || e.name.hasPrefix("rules-emerging-threats/"),
                  e.name.hasSuffix(".yml") || e.name.hasSuffix(".yaml") else { continue }
            let text = String(decoding: try zip.read(e), as: UTF8.self)
            guard let p = product(e.name, text) else { continue }
            picked.append((e.name, text, p))
        }
        picked.sort { $0.0 < $1.0 }
        for (path, text, p) in picked {
            rules.append(["source": "SigmaHQ", "path": path, "yaml": text, "product": p])
            if p == "linux" { summary.sigmaLinux += 1 } else { summary.sigmaWindows += 1 }
        }
        var sources: [[String: Any]] = [[
            "name": "SigmaHQ", "url": "https://github.com/SigmaHQ/sigma", "version": label, "tag": sigma.version,
            "published": sigma.published ?? "", "archive": sigma.url, "sha256": sha256(sigma.data),
            "license": "Detection Rule License (DRL) 1.1", "licenseURL": "https://github.com/SigmaHQ/Detection-Rule-License",
            "count": picked.count, "windows": summary.sigmaWindows, "linux": summary.sigmaLinux,
        ]]
        summary.sigmaVersion = sigma.version
        var aliases: [String: String] = [:]
        if let hayabusa {
            let hz = try ZipReader(hayabusa.data)
            var hrules: [(String, String)] = []
            for e in hz.entries {
                // "hayabusa-rules-<sha>/hayabusa/…" → "hayabusa/…"
                let parts = e.name.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
                guard parts.count == 2 else { continue }
                let rel = String(parts[1])
                if rel == "config/eventkey_alias.txt" {
                    for line in String(decoding: try hz.read(e), as: UTF8.self).split(separator: "\n") {
                        let t = line.trimmingCharacters(in: .whitespaces)
                        guard !t.isEmpty, !t.hasPrefix("#"), let comma = t.firstIndex(of: ",") else { continue }
                        let alias = t[..<comma].trimmingCharacters(in: .whitespaces)
                        if alias.lowercased() != "alias" { aliases[alias] = t[t.index(after: comma)...].trimmingCharacters(in: .whitespaces) }
                    }
                } else if rel.hasPrefix("hayabusa/"), rel.hasSuffix(".yml") || rel.hasSuffix(".yaml") {
                    hrules.append((rel, String(decoding: try hz.read(e), as: UTF8.self)))
                }
            }
            hrules.sort { $0.0 < $1.0 }
            for (path, text) in hrules { rules.append(["source": "Hayabusa", "path": path, "yaml": text, "product": "windows"]) }
            summary.hayabusa = hrules.count
            summary.hayabusaVersion = hayabusa.version
            sources.append([
                "name": "Hayabusa", "url": "https://github.com/Yamato-Security/hayabusa-rules", "version": hayabusa.version,
                "tag": hayabusa.version, "published": hayabusa.published ?? "", "archive": hayabusa.url, "sha256": sha256(hayabusa.data),
                "license": "Detection Rule License (DRL) 1.1",
                "licenseURL": "https://github.com/Yamato-Security/hayabusa-rules/blob/main/LICENSE.md",
                "count": hrules.count, "windows": hrules.count, "linux": 0,
            ])
        }
        summary.aliases = aliases.count
        let doc: [String: Any] = [
            "generated": ISO8601DateFormatter().string(from: Date()),
            "sources": sources,
            "aliases": aliases,
            "aliasesSource": "Hayabusa config/eventkey_alias.txt (DRL 1.1)",
            "rules": rules,
        ]
        let json = try JSONSerialization.data(withJSONObject: doc, options: [.sortedKeys, .withoutEscapingSlashes])
        return (json, summary)
    }
}
