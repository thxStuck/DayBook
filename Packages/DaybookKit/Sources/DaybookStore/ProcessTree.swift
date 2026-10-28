import Foundation

public enum ProcessSource: String, Sendable, CaseIterable {
    case sysmon      // Sysmon 1 / 5, linked by ProcessGuid (exact)
    case security    // Security 4688 / 4689, linked by PID (heuristic)
    case audit       // Linux auditd execve, linked by PPID (heuristic)
}

public final class ProcessNode: Identifiable, @unchecked Sendable {
    public let id: Int
    public let host: String
    public let image: String
    public let commandLine: String?
    public let pid: String?
    public let user: String?
    public let start: Int64?
    public var end: Int64?
    /// Event that created the process (nil for synthetic parents).
    public let event: UInt32?
    public let guid: String?
    /// Parent was never logged (process started before the log begins): built from the
    /// child's ParentImage / ParentProcessId.
    public let synthetic: Bool
    /// Parent found by PID (4688): the latest process with that PID that started earlier on
    /// the same host and boot and had not exited — a heuristic, not a recorded link.
    public var linkedByPID = false
    public var children: [ProcessNode]?
    public var extra: [String: String]

    init(id: Int, host: String, image: String, commandLine: String?, pid: String?, user: String?, start: Int64?,
         event: UInt32?, guid: String?, synthetic: Bool, extra: [String: String] = [:]) {
        self.id = id
        self.host = host
        self.image = image
        self.commandLine = commandLine
        self.pid = pid
        self.user = user
        self.start = start
        self.event = event
        self.guid = guid
        self.synthetic = synthetic
        self.extra = extra
    }

    public var name: String {
        if image == "?" || image.isEmpty { return String(localized: "(образ неизвестен)") }
        return image.split(whereSeparator: { $0 == "\\" || $0 == "/" }).last.map(String.init) ?? image
    }

    func add(_ child: ProcessNode) {
        if children == nil { children = [] }
        children!.append(child)
    }
}

public struct ProcessForest: Sendable {
    public let roots: [ProcessNode]
    public let processCount: Int
    public let syntheticCount: Int
    public let pidLinkedCount: Int
    /// Creation events whose ProcessGuid was already seen (kept out of the tree).
    public var repeatedGuidEvents = 0
}

public enum ProcessTreeBuilder {
    public static func build(_ store: CaseStore, source: ProcessSource) throws -> ProcessForest {
        switch source {
        case .sysmon: try sysmon(store)
        case .security: try security(store)
        case .audit: try audit(store)
        }
    }

    /// Linux: every execve auditd logged. exec keeps the PID, so a process that runs several
    /// programs appears once per program; a child hangs under the latest earlier exec of its PPID
    /// on the same host and boot (heuristic, flagged as linked by PID).
    private static func audit(_ store: CaseStore) throws -> ProcessForest {
        let created = try store.matching(key: "Action", value: "process_exec")
        let boots = try store.linuxBootTimes()
        let names: Set<String> = ["pid", "ppid", "exe", "comm", "CommandLine", "SubjectUserName", "SubjectDomainName", "cwd",
                                  "key", "success", "UidName", "EuidName", "tty", "ses"]
        func key(_ host: String, _ ts: Int64, _ pid: String) -> String {
            let h = EntityNames.hostKey(host) ?? host
            return "\(h)|\(bootSegment(boots[h], ts))|\(pid)"
        }
        var byPid: [String: [ProcessNode]] = [:]
        var roots: [ProcessNode] = []
        var nextId = 0, synthetic = 0, linked = 0, count = 0
        for e in try store.fieldEvents(created, names: names).sorted(by: { ($0.ts, $0.id) < ($1.ts, $1.id) }) {
            let user = [e.f("SubjectDomainName"), e.f("SubjectUserName")].compactMap { $0 }.joined(separator: "\\")
            var extra: [String: String] = [:]
            for k in ["cwd", "key", "success", "UidName", "EuidName", "tty", "ses"] { if let v = e.f(k) { extra[k] = v } }
            let n = ProcessNode(id: nextId, host: e.computer, image: e.f("exe") ?? e.f("comm") ?? "?", commandLine: e.f("CommandLine"),
                                pid: e.f("pid"), user: user.isEmpty ? nil : user, start: e.ts, event: e.id, guid: nil,
                                synthetic: false, extra: extra)
            nextId += 1
            count += 1
            if let ppid = e.f("ppid") {
                let k = key(e.computer, e.ts, ppid)
                if let parent = byPid[k]?.last(where: { ($0.start ?? .min) <= e.ts }) {
                    parent.add(n)
                    n.linkedByPID = true
                    linked += 1
                } else {
                    let p = ProcessNode(id: nextId, host: e.computer, image: "?", commandLine: nil, pid: ppid, user: nil,
                                        start: nil, event: nil, guid: nil, synthetic: true)
                    nextId += 1
                    synthetic += 1
                    p.add(n)
                    roots.append(p)
                    byPid[k, default: []].append(p)
                }
            } else {
                roots.append(n)
            }
            if let pid = e.f("pid") { byPid[key(e.computer, e.ts, pid), default: []].append(n) }
        }
        return ProcessForest(roots: sortTree(mergeSynthetic(roots)), processCount: count, syntheticCount: synthetic, pidLinkedCount: linked)
    }

    private static func sysmon(_ store: CaseStore) throws -> ProcessForest {
        let sysmonIds = try store.matching(key: CaseSchema.SystemKey.provider, value: "Microsoft-Windows-Sysmon")
        let created = IdSet.intersect(sysmonIds, try store.matching(key: CaseSchema.SystemKey.eventId, value: "1"))
        let ended = IdSet.intersect(sysmonIds, try store.matching(key: CaseSchema.SystemKey.eventId, value: "5"))
        let names: Set<String> = ["ProcessGuid", "ParentProcessGuid", "ProcessId", "ParentProcessId", "Image", "ParentImage",
                                  "CommandLine", "ParentCommandLine", "User", "IntegrityLevel", "Hashes", "CurrentDirectory"]
        var nodes: [String: ProcessNode] = [:]
        var all: [ProcessNode] = []
        var nextId = 0
        func node(_ e: FieldEvent) -> ProcessNode? {
            guard let guid = e.f("ProcessGuid")?.uppercased() else { return nil }
            let n = ProcessNode(id: nextId, host: e.computer, image: e.f("Image") ?? "?", commandLine: e.f("CommandLine"),
                                pid: e.f("ProcessId"), user: e.f("User"), start: e.ts, event: e.id, guid: guid, synthetic: false,
                                extra: ["IntegrityLevel": e.f("IntegrityLevel") ?? "", "Hashes": e.f("Hashes") ?? ""])
            nextId += 1
            return n
        }
        let createdEvents = try store.fieldEvents(created, names: names)
        var repeated = 0
        for e in createdEvents {
            guard let n = node(e) else { continue }
            guard nodes[n.guid!] == nil else { repeated += 1; continue }
            nodes[n.guid!] = n
            all.append(n)
        }
        for e in try store.fieldEvents(ended, names: ["ProcessGuid"]) {
            if let g = e.f("ProcessGuid")?.uppercased() { nodes[g]?.end = e.ts }
        }
        var roots: [ProcessNode] = []
        var synthetic = 0
        for e in createdEvents {
            guard let g = e.f("ProcessGuid")?.uppercased(), let child = nodes[g] else { continue }
            guard let pg = e.f("ParentProcessGuid")?.uppercased(), pg != g else { roots.append(child); continue }
            if let parent = nodes[pg] {
                parent.add(child)
            } else {
                let p = ProcessNode(id: nextId, host: e.computer, image: e.f("ParentImage") ?? "?",
                                    commandLine: e.f("ParentCommandLine"), pid: e.f("ParentProcessId"), user: nil,
                                    start: nil, event: nil, guid: pg, synthetic: true)
                nextId += 1
                synthetic += 1
                nodes[pg] = p
                p.add(child)
                roots.append(p)
            }
        }
        var forest = ProcessForest(roots: sortTree(roots), processCount: all.count, syntheticCount: synthetic, pidLinkedCount: 0)
        forest.repeatedGuidEvents = repeated
        return forest
    }

    private static func security(_ store: CaseStore) throws -> ProcessForest {
        let created = try store.events(CaseSchema.SystemKey.eventId, in: ["4688"], channel: "Security")
        let ended = try store.events(CaseSchema.SystemKey.eventId, in: ["4689"], channel: "Security")
        let boots = try store.bootTimes()
        let names: Set<String> = ["NewProcessId", "NewProcessName", "ProcessId", "ParentProcessName", "CommandLine",
                                  "SubjectUserName", "SubjectDomainName", "TargetUserName", "TargetDomainName",
                                  "TokenElevationType", "MandatoryLabel", "ProcessName"]
        func pidKey(_ host: String, _ ts: Int64, _ pid: String) -> String {
            let h = EntityNames.hostKey(host) ?? host
            let n = StringKey.number(pid).map(String.init) ?? pid.lowercased()
            return "\(h)|\(bootSegment(boots[h], ts))|\(n)"
        }
        // Exit times per (host, boot, pid), sorted.
        var exits: [String: [Int64]] = [:]
        for e in try store.fieldEvents(ended, names: ["ProcessId"]) {
            if let pid = e.f("ProcessId") { exits[pidKey(e.computer, e.ts, pid), default: []].append(e.ts) }
        }
        for k in exits.keys { exits[k]?.sort() }

        var byPid: [String: [ProcessNode]] = [:]   // creation order
        var all: [ProcessNode] = []
        var roots: [ProcessNode] = []
        var nextId = 0, synthetic = 0, linked = 0
        for e in try store.fieldEvents(created, names: names).sorted(by: { $0.ts < $1.ts }) {
            let user = [e.f("SubjectDomainName"), e.f("SubjectUserName")].compactMap { $0 }.joined(separator: "\\")
            let n = ProcessNode(id: nextId, host: e.computer, image: e.f("NewProcessName") ?? "?", commandLine: e.f("CommandLine"),
                                pid: e.f("NewProcessId"), user: user.isEmpty ? nil : user, start: e.ts, event: e.id, guid: nil,
                                synthetic: false, extra: ["TokenElevationType": e.f("TokenElevationType").map(EventDescriber.param) ?? "",
                                                          "MandatoryLabel": e.f("MandatoryLabel") ?? ""])
            nextId += 1
            all.append(n)
            if let ppid = e.f("ProcessId") {
                let key = pidKey(e.computer, e.ts, ppid)
                // Latest earlier process with this PID that had not exited before the child started.
                let candidate = byPid[key]?.last { p in
                    guard let s = p.start, s <= e.ts else { return false }
                    if let ex = exits[key]?.first(where: { $0 >= s }), ex < e.ts { return false }
                    return true
                }
                if let parent = candidate {
                    parent.add(n)
                    n.linkedByPID = true
                    linked += 1
                } else {
                    let p = ProcessNode(id: nextId, host: e.computer, image: e.f("ParentProcessName") ?? "?", commandLine: nil,
                                        pid: ppid, user: nil, start: nil, event: nil, guid: nil, synthetic: true)
                    nextId += 1
                    synthetic += 1
                    p.add(n)
                    roots.append(p)
                    byPid[key, default: []].append(p)
                }
            } else {
                roots.append(n)
            }
            if let pid = e.f("NewProcessId") { byPid[pidKey(e.computer, e.ts, pid), default: []].append(n) }
        }
        // Exit times on nodes.
        for (key, list) in byPid {
            for n in list {
                if let s = n.start, let ex = exits[key]?.first(where: { $0 >= s }) { n.end = ex }
            }
        }
        // Synthetic parents with the same image and PID on the same host+boot are one process.
        return ProcessForest(roots: sortTree(mergeSynthetic(roots)), processCount: all.count,
                             syntheticCount: synthetic, pidLinkedCount: linked)
    }

    private static func mergeSynthetic(_ roots: [ProcessNode]) -> [ProcessNode] {
        var seen: [String: ProcessNode] = [:]
        var out: [ProcessNode] = []
        for r in roots {
            guard r.synthetic else { out.append(r); continue }
            let key = "\(EntityNames.hostKey(r.host) ?? r.host)|\(r.image.lowercased())|\(r.pid ?? "")"
            if let existing = seen[key] {
                for c in r.children ?? [] { existing.add(c) }
            } else {
                seen[key] = r
                out.append(r)
            }
        }
        return out
    }

    private static func sortTree(_ nodes: [ProcessNode]) -> [ProcessNode] {
        func start(_ n: ProcessNode) -> Int64 { n.start ?? n.children?.compactMap(\.start).min() ?? 0 }
        for n in nodes { if let c = n.children { n.children = sortTree(c) } }
        return nodes.sorted { (start($0), $0.id) < (start($1), $1.id) }
    }
}
