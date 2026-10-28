import EvtxCore
import DaybookStore
import Foundation
import Yams

/// A detection value as written in the rule (scalars are kept as their source text, so
/// `0x17` stays `0x17` instead of becoming the number 23).
public enum SigmaValue: Sendable, Equatable {
    case string(String)
    case null
}

/// `field|mod1|mod2: value(s)`, or a keyword list item when `field` is nil.
public struct SigmaItem: Sendable, Equatable {
    public let field: String?
    public let modifiers: [String]
    public let values: [SigmaValue]
}

/// A search identifier: a map (AND of items), a list of maps (OR), or keywords (OR).
public indirect enum SigmaSearch: Sendable, Equatable {
    case all([SigmaItem])
    case any([SigmaSearch])
    case keywords([SigmaValue])
}

extension SigmaRule {
    /// The system a rule is written for: its logsource product, Windows for Hayabusa rules.
    public var platform: CasePlatform? {
        switch logsource["product"]?.lowercased() {
        case "windows": return .windows
        case "linux": return .linux
        case nil: return source == "Hayabusa" ? .windows : nil
        default: return nil
        }
    }
}

public struct SigmaRule: Sendable, Identifiable {
    public let id: String
    public let title: String
    public let status: String?
    public let level: String?
    public let description: String?
    public let author: String?
    public let date: String?
    public let modified: String?
    public let references: [String]
    public let tags: [String]
    public let falsepositives: [String]
    public let logsource: [String: String]
    public let searches: [String: SigmaSearch]
    public let conditions: [String]
    /// Rule set name (SigmaHQ, Hayabusa, custom folder).
    public let source: String
    public let path: String
    public let yaml: String

    /// Sort weight of `level` (critical first).
    public var levelRank: Int {
        switch level?.lowercased() {
        case "critical": 5
        case "high": 4
        case "medium": 3
        case "low": 2
        case "informational": 1
        default: 0
        }
    }

    public var logsourceText: String {
        ["product", "category", "service"].compactMap { k in logsource[k].map { "\(k): \($0)" } }.joined(separator: ", ")
    }
}

/// A rule file that could not be turned into a rule (kept and shown, never dropped silently).
public struct SigmaParseError: Error, CustomStringConvertible, Sendable {
    public let source: String
    public let path: String
    public let message: String
    public let yaml: String
    /// Title, when the YAML was readable far enough.
    public let title: String?
    public var description: String { "\(path): \(message)" }
}

public enum SigmaParser {
    public static func parse(yaml: String, source: String, path: String) throws -> SigmaRule {
        func fail(_ message: String, title: String? = nil) -> SigmaParseError {
            SigmaParseError(source: source, path: path, message: message, yaml: yaml, title: title)
        }
        var docs: [Node] = []
        do {
            var seq = try Yams.compose_all(yaml: yaml, .basic)
            while let n = seq.next() { docs.append(n) }
            if let e = seq.error { throw e }
        } catch {
            throw fail(String(localized: "ошибка YAML: ") + "\(error)")
        }
        guard let root = docs.first, case let .mapping(map) = root else { throw fail(String(localized: "YAML не является словарём")) }
        func str(_ key: String) -> String? { map[key].flatMap(scalarText) }
        func list(_ key: String) -> [String] {
            guard let n = map[key] else { return [] }
            if case let .sequence(seq) = n { return seq.compactMap(scalarText) }
            return scalarText(n).map { [$0] } ?? []
        }
        let title = str("title")
        if docs.count > 1 {
            throw fail(String(localized: "несколько YAML-документов в файле (коллекция правил или корреляция Sigma) — не поддерживается"), title: title)
        }
        if map["correlation"] != nil {
            throw fail(String(localized: "корреляционное правило Sigma — не поддерживается"), title: title)
        }
        guard let title else { throw fail(String(localized: "нет title")) }
        var logsource: [String: String] = [:]
        if case let .mapping(ls)? = map["logsource"] {
            for (k, v) in ls { if let key = scalarText(k), let value = scalarText(v) { logsource[key] = value } }
        }
        guard case let .mapping(det)? = map["detection"] else { throw fail(String(localized: "нет detection"), title: title) }
        var searches: [String: SigmaSearch] = [:]
        var conditions: [String] = []
        for (k, v) in det {
            guard let name = scalarText(k) else { continue }
            if name == "condition" {
                if case let .sequence(seq) = v { conditions = seq.compactMap(scalarText) }
                else if let c = scalarText(v) { conditions = [c] }
            } else if name == "timeframe" {
                continue
            } else {
                guard let s = search(v) else {
                    throw fail(String(localized: "неподдерживаемая структура detection «\(name)»"), title: title)
                }
                searches[name] = s
            }
        }
        return SigmaRule(id: str("id") ?? path, title: title, status: str("status"), level: str("level"),
                         description: str("description"), author: str("author"), date: str("date"),
                         modified: str("modified"), references: list("references"), tags: list("tags"),
                         falsepositives: list("falsepositives"), logsource: logsource, searches: searches,
                         conditions: conditions, source: source, path: path, yaml: yaml)
    }

    static func scalarText(_ n: Node) -> String? {
        guard case let .scalar(s) = n else { return nil }
        return s.string
    }

    static func value(_ n: Node) -> SigmaValue {
        guard case let .scalar(s) = n else { return .string("") }
        if s.style == .plain, ["null", "~", ""].contains(s.string) { return .null }
        return .string(s.string)
    }

    static func values(_ n: Node) -> [SigmaValue] {
        if case let .sequence(seq) = n { return seq.map(value) }
        return [value(n)]
    }

    static func search(_ n: Node) -> SigmaSearch? {
        switch n {
        case let .mapping(m):
            var items: [SigmaItem] = []
            for (k, v) in m {
                guard let key = scalarText(k) else { return nil }
                if case .mapping = v { return nil }
                let parts = key.split(separator: "|", omittingEmptySubsequences: false).map(String.init)
                let field = parts[0].isEmpty ? nil : parts[0]
                items.append(SigmaItem(field: field, modifiers: parts.dropFirst().map { $0.lowercased() }, values: values(v)))
            }
            return .all(items)
        case let .sequence(seq):
            if seq.allSatisfy({ if case .scalar = $0 { return true } else { return false } }) {
                return .keywords(seq.map(value))
            }
            var out: [SigmaSearch] = []
            for x in seq {
                guard let s = search(x) else { return nil }
                out.append(s)
            }
            return .any(out)
        case .scalar:
            return .keywords([value(n)])
        default:
            return nil
        }
    }
}

/// Rules from the bundled pack and/or a custom folder, plus files that failed to load.
public struct SigmaRuleSet: Sendable {
    public struct Source: Sendable, Hashable {
        public let name: String
        public let url: String
        public let version: String
        public let license: String
        public let licenseURL: String
        public let count: Int
    }

    public var sources: [Source] = []
    public var rules: [SigmaRule] = []
    public var failures: [SigmaParseError] = []
    /// Field aliases (alias → XML path) shipped with Hayabusa rules.
    public var aliases: [String: String] = [:]
    public var generated: String?

    public init() {}

    /// Loads a pack built by `SigmaPackBuilder` (bundled, downloaded or `evtxdump pack-rules`).
    public static func pack(_ data: Data) throws -> SigmaRuleSet {
        guard let doc = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw SigmaParseError(source: "pack", path: "rules.json", message: "not a JSON object", yaml: "", title: nil)
        }
        var set = SigmaRuleSet()
        set.generated = doc["generated"] as? String
        for s in doc["sources"] as? [[String: Any]] ?? [] {
            set.sources.append(Source(name: s["name"] as? String ?? "?", url: s["url"] as? String ?? "",
                                      version: s["version"] as? String ?? "", license: s["license"] as? String ?? "",
                                      licenseURL: s["licenseURL"] as? String ?? "", count: s["count"] as? Int ?? 0))
        }
        set.aliases = doc["aliases"] as? [String: String] ?? [:]
        let items = doc["rules"] as? [[String: String]] ?? []
        let parsed = parallelMap(items.count) { i -> Result<SigmaRule, SigmaParseError> in
            let r = items[i]
            let source = r["source"] ?? "?", path = r["path"] ?? "?", yaml = r["yaml"] ?? ""
            do { return .success(try SigmaParser.parse(yaml: yaml, source: source, path: path)) }
            catch let e as SigmaParseError { return .failure(e) }
            catch { return .failure(SigmaParseError(source: source, path: path, message: "\(error)", yaml: yaml, title: nil)) }
        }
        for p in parsed {
            switch p {
            case let .success(r): set.rules.append(r)
            case let .failure(e): set.failures.append(e)
            }
        }
        return set
    }

    /// Loads every .yml / .yaml file under a folder (custom rules).
    public static func folder(_ url: URL, name: String) -> SigmaRuleSet {
        var set = SigmaRuleSet()
        let fm = FileManager.default
        var files: [URL] = []
        if let e = fm.enumerator(at: url, includingPropertiesForKeys: [.isRegularFileKey]) {
            for case let f as URL in e where ["yml", "yaml"].contains(f.pathExtension.lowercased()) { files.append(f) }
        }
        files.sort { $0.path < $1.path }
        let base = url.standardizedFileURL.path
        for f in files {
            let rel = f.standardizedFileURL.path.hasPrefix(base + "/") ? String(f.standardizedFileURL.path.dropFirst(base.count + 1)) : f.lastPathComponent
            guard let yaml = try? String(contentsOf: f, encoding: .utf8) else {
                set.failures.append(SigmaParseError(source: name, path: rel, message: String(localized: "не удалось прочитать файл как UTF-8"), yaml: "", title: nil))
                continue
            }
            do { set.rules.append(try SigmaParser.parse(yaml: yaml, source: name, path: rel)) }
            catch let e as SigmaParseError { set.failures.append(e) }
            catch { set.failures.append(SigmaParseError(source: name, path: rel, message: "\(error)", yaml: yaml, title: nil)) }
        }
        set.sources = [Source(name: name, url: url.path, version: "", license: String(localized: "(пользовательские правила)"),
                              licenseURL: "", count: set.rules.count + set.failures.count)]
        return set
    }

    public mutating func merge(_ other: SigmaRuleSet) {
        sources += other.sources
        rules += other.rules
        failures += other.failures
        aliases.merge(other.aliases) { a, _ in a }
    }
}
