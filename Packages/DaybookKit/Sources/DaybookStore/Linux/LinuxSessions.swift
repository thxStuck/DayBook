import EvtxCore
import Foundation

extension CaseStore {
    /// Boot times per host from wtmp `reboot` records (Linux).
    func linuxBootTimes() throws -> [String: [Int64]] {
        var out: [String: [Int64]] = [:]
        for r in try rows(try matching(key: "Action", value: "boot")) {
            guard let h = EntityNames.hostKey(r.computer) else { continue }
            out[h, default: []].append(r.ts)
        }
        for h in out.keys { out[h]?.sort() }
        return out
    }
}

/// Linux logon sessions from wtmp, as `last` shows them: a login (USER_PROCESS) ends with the next
/// logout (DEAD_PROCESS) on the same terminal, or with the next boot or shutdown of the host
/// (then the session was not closed by a logout).
public enum LinuxSessionBuilder {
    public static func build(_ store: CaseStore) throws -> SessionAnalysis {
        let wtmp = try store.matching(key: CaseSchema.SystemKey.channel, value: "wtmp")
        let ids = IdSet.intersect(wtmp, IdSet.union([
            try store.matching(key: "Action", value: "login"), try store.matching(key: "Action", value: "logout"),
            try store.matching(key: "Action", value: "boot"), try store.matching(key: "Action", value: "shutdown"),
        ], universe: store.eventCount))
        let events = try store.fieldEvents(ids, names: ["Action", "Terminal", "TargetUserName", "TargetDomainName",
                                                        "IpAddress", "WorkstationName", "ProcessId"])
            .sorted { ($0.ts, $0.id) < ($1.ts, $1.id) }
        let boots = try store.linuxBootTimes()
        var open: [String: FieldEvent] = [:]   // host|terminal → login
        var sessions: [LogonSession] = []
        var unmatched = 0
        func close(_ login: FieldEvent, end: FieldEvent?) {
            let host = EntityNames.hostKey(login.computer) ?? login.computer
            let user = [login.f("TargetDomainName"), login.f("TargetUserName")].compactMap { $0 }.joined(separator: "\\")
            let id = [login.f("Terminal"), login.f("ProcessId").map { "pid " + $0 }].compactMap { $0 }.joined(separator: " · ")
            sessions.append(LogonSession(
                id: sessions.count, host: login.computer, logonId: id.isEmpty ? "?" : id, user: user, userSid: nil, logonType: nil,
                workstation: login.f("WorkstationName"), ip: login.f("IpAddress"), authPackage: nil,
                logonProcess: end?.f("Action").flatMap { $0 == "logout" ? nil : $0 }, elevated: nil, linkedLogonId: nil,
                start: login.ts, end: end?.ts, startEvent: login.id, endEvent: end?.id,
                privileged: login.f("TargetUserName") == "root", bootSegment: bootSegment(boots[host], login.ts)))
        }
        for e in events {
            let host = EntityNames.hostKey(e.computer) ?? e.computer
            switch e.f("Action") {
            case "login":
                let k = host + "|" + (e.f("Terminal") ?? "?")
                if let previous = open.removeValue(forKey: k) { close(previous, end: nil) }
                open[k] = e
            case "logout":
                let k = host + "|" + (e.f("Terminal") ?? "?")
                if let login = open.removeValue(forKey: k) { close(login, end: e) } else { unmatched += 1 }
            default:   // boot / shutdown ends every open session of the host
                for k in open.keys.filter({ $0.hasPrefix(host + "|") }) { close(open.removeValue(forKey: k)!, end: e) }
            }
        }
        for login in open.values.sorted(by: { $0.ts < $1.ts }) { close(login, end: nil) }
        sessions.sort { ($0.start, $0.startEvent) < ($1.start, $1.startEvent) }
        let numbered = sessions.enumerated().map { i, s in
            LogonSession(id: i, host: s.host, logonId: s.logonId, user: s.user, userSid: nil, logonType: nil, workstation: s.workstation,
                         ip: s.ip, authPackage: nil, logonProcess: s.logonProcess, elevated: nil, linkedLogonId: nil, start: s.start,
                         end: s.end, startEvent: s.startEvent, endEvent: s.endEvent, privileged: s.privileged, bootSegment: s.bootSegment)
        }
        let hostsNoBoot = Set(numbered.map { EntityNames.hostKey($0.host) ?? $0.host }).filter { boots[$0] == nil }.sorted()
        return SessionAnalysis(sessions: numbered, unmatchedEnds: unmatched, hostsWithoutBootInfo: hostsNoBoot)
    }
}
