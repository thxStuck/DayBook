import DaybookStore
import EvtxCore
import Foundation

/// A table row with its strings resolved.
struct DisplayRow {
    let row: EventRow
    let summary: String
    /// Human-readable description (EventDescriber), when the event is known.
    let description: String?
    /// The user the event is about (Target/Subject/Sysmon User), for the "user" column.
    let actor: String?
    /// First value per field key id.
    let values: [UInt32: String]

    /// What the description column shows.
    var text: String { description ?? summary }
}

/// Page cache between the result set and the table: rows are fetched 256 at a time
/// (one SQLite query + one string batch) and kept in a small LRU.
@MainActor
final class RowProvider {
    let store: CaseStore
    private(set) var result: ResultSet = .empty
    private(set) var ascending = true
    /// False for a custom (field) order: ids are not sorted, so no binary search.
    private(set) var ordered = true
    private var pages: [Int: [DisplayRow]] = [:]
    private var lru: [Int] = []
    private let pageSize = 256
    private let maxPages = 64

    init(store: CaseStore) { self.store = store }

    var count: Int { result.count }

    func reset(result: ResultSet, ascending: Bool, ordered: Bool = true) {
        self.result = result
        self.ascending = ascending
        self.ordered = ordered
        pages.removeAll()
        lru.removeAll()
    }

    /// Event id shown at table row `index`.
    func eventId(at index: Int) -> UInt32? {
        guard index >= 0, index < result.count else { return nil }
        return result.id(at: ascending ? index : result.count - 1 - index)
    }

    /// Table row index of event `id`, if it is in the result.
    func index(of id: UInt32) -> Int? {
        if !ordered {
            guard let i = (0..<result.count).first(where: { result.id(at: $0) == id }) else { return nil }
            return ascending ? i : result.count - 1 - i
        }
        let i = result.lowerBound(id)
        guard i < result.count, result.id(at: i) == id else { return nil }
        return ascending ? i : result.count - 1 - i
    }

    func row(at index: Int) -> DisplayRow? {
        guard index >= 0, index < result.count else { return nil }
        let p = index / pageSize
        if let page = pages[p] {
            touch(p)
            let k = index - p * pageSize
            return k < page.count ? page[k] : nil
        }
        let page = load(page: p)
        pages[p] = page
        touch(p)
        if lru.count > maxPages, let old = lru.first {
            lru.removeFirst()
            pages[old] = nil
        }
        let k = index - p * pageSize
        return k < page.count ? page[k] : nil
    }

    /// The user an event is about: Sysmon/LSM `User`, else Target, else Subject.
    static func actor(_ f: [String: String]) -> String? {
        func v(_ k: String) -> String? {
            guard let x = f[k]?.trimmingCharacters(in: .whitespaces), !x.isEmpty, x != "-" else { return nil }
            return x
        }
        if let u = v("User") { return u }
        for (n, d) in [("TargetUserName", "TargetDomainName"), ("SubjectUserName", "SubjectDomainName"), ("AccountName", "AccountDomain")] {
            if let name = v(n) { return v(d).map { $0 + "\\" + name } ?? name }
        }
        return v("Param1")
    }

    private func touch(_ p: Int) {
        if let i = lru.firstIndex(of: p) { lru.remove(at: i) }
        lru.append(p)
    }

    private func load(page p: Int) -> [DisplayRow] {
        let lo = p * pageSize, hi = min(lo + pageSize, result.count)
        guard lo < hi else { return [] }
        let ids = (lo..<hi).compactMap { eventId(at: $0) }
        guard let rows = try? store.rows(ids) else { return [] }
        let linux = store.platform == .linux
        var need = Set<UInt32>()
        for r in rows { for pair in r.pairs { need.insert(pair.key); need.insert(pair.value) } }
        let needList = Array(need)
        let strings = (try? store.strings(needList)) ?? []
        let dict = Dictionary(uniqueKeysWithValues: zip(needList, strings))
        return rows.map { r in
            var values: [UInt32: String] = [:]
            var byName: [String: String] = [:]
            var summary = ""
            for pair in r.pairs {
                let v = dict[pair.value] ?? ""
                let name = dict[pair.key] ?? ""
                if values[pair.key] == nil { values[pair.key] = v }
                if byName[name] == nil { byName[name] = v }
                if summary.utf8.count < 320, !v.isEmpty, v != "-" {
                    let short = v.count > 90 ? String(v.prefix(90)) + "…" : v
                    summary += (summary.isEmpty ? "" : "  ·  ") + name + ": " + short.replacingOccurrences(of: "\n", with: " ⏎ ")
                }
            }
            // Linux events carry their text in `Message`: show it as is, the parsed fields follow in the details.
            let description = linux ? byName["Message"].map { $0.replacingOccurrences(of: "\n", with: " ⏎ ") }
                : EventDescriber.describe(provider: r.provider, channel: r.channel, eventId: r.eventId) { byName[$0] }
            return DisplayRow(row: r, summary: EventDescriber.param(summary), description: description,
                              actor: Self.actor(byName) ?? r.user, values: values)
        }
    }
}
