import EvtxCore
import Foundation

/// glibc `struct utmp` records of wtmp (logins, logouts, boots), btmp (failed logins) and utmp
/// (current sessions): 384 bytes, little-endian, time in seconds + microseconds (UTC).
struct UtmpRecord {
    static let size = 384
    static let typeNames = ["EMPTY", "RUN_LVL", "BOOT_TIME", "NEW_TIME", "OLD_TIME", "INIT_PROCESS",
                            "LOGIN_PROCESS", "USER_PROCESS", "DEAD_PROCESS", "ACCOUNTING"]

    var offset: Int
    var type: Int
    var pid: Int32
    var line: String
    var id: String
    var user: String
    var host: String
    var termination: Int16
    var exit: Int16
    var session: Int32
    var seconds: Int64
    var microseconds: Int32
    var address: String?

    var timestamp: Int64 { FileTime.fromUnixSeconds(seconds) + Int64(microseconds) * 10 }
    var typeName: String { type >= 0 && type < Self.typeNames.count ? Self.typeNames[type] : "TYPE_\(type)" }

    /// Records in file order. A trailing partial record and records with an impossible type or
    /// time are returned in `bad` (offsets) instead.
    static func parse(_ data: Data) -> (records: [UtmpRecord], bad: [Int], trailing: Int) {
        var out: [UtmpRecord] = []
        var bad: [Int] = []
        let count = data.count / size
        data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            for k in 0..<count {
                let o = k * size
                let r = UnsafeRawBufferPointer(rebasing: raw[o..<(o + size)])
                let type = Int(r.loadUnaligned(fromByteOffset: 0, as: Int16.self).littleEndian)
                let sec = r.loadUnaligned(fromByteOffset: 340, as: Int32.self).littleEndian
                let usec = r.loadUnaligned(fromByteOffset: 344, as: Int32.self).littleEndian
                guard (0...9).contains(type), usec >= 0, usec < 1_000_000 else { bad.append(o); continue }
                if type == 0 && sec == 0 { continue }   // unused slot
                var rec = UtmpRecord(offset: o, type: type, pid: r.loadUnaligned(fromByteOffset: 4, as: Int32.self).littleEndian,
                                     line: text(r, 8, 32), id: text(r, 40, 4), user: text(r, 44, 32), host: text(r, 76, 256),
                                     termination: r.loadUnaligned(fromByteOffset: 332, as: Int16.self).littleEndian,
                                     exit: r.loadUnaligned(fromByteOffset: 334, as: Int16.self).littleEndian,
                                     session: r.loadUnaligned(fromByteOffset: 336, as: Int32.self).littleEndian,
                                     seconds: Int64(UInt32(bitPattern: sec)), microseconds: usec, address: nil)
                rec.address = address(r)
                out.append(rec)
            }
        }
        return (out, bad, data.count - count * size)
    }

    static func text(_ r: UnsafeRawBufferPointer, _ at: Int, _ len: Int) -> String {
        let bytes = UnsafeRawBufferPointer(rebasing: r[at..<(at + len)])
        let end = bytes.firstIndex(of: 0) ?? len
        return LogLines.decode(UnsafeBufferPointer(rebasing: bytes.bindMemory(to: UInt8.self)[0..<end])).0
    }

    /// `ut_addr_v6`: IPv4 in the first word when the others are zero.
    static func address(_ r: UnsafeRawBufferPointer) -> String? {
        let words = (0..<4).map { r.loadUnaligned(fromByteOffset: 348 + $0 * 4, as: UInt32.self) }
        guard words.contains(where: { $0 != 0 }) else { return nil }
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        if words[1] == 0 && words[2] == 0 && words[3] == 0 {
            var a = in_addr(s_addr: words[0])
            return inet_ntop(AF_INET, &a, &buf, socklen_t(buf.count)).map { String(cString: $0) }
        }
        var a6 = in6_addr()
        withUnsafeMutableBytes(of: &a6) { dst in
            for (i, w) in words.enumerated() { dst.storeBytes(of: w, toByteOffset: i * 4, as: UInt32.self) }
        }
        return inet_ntop(AF_INET6, &a6, &buf, socklen_t(buf.count)).map { String(cString: $0) }
    }

    /// Fields of the record; `failed` for btmp (every record is a failed login).
    func fields(host machine: String, failed: Bool) -> [CaseField] {
        var f = LinuxFields(host: machine)
        let action: String
        switch type {
        case 1: action = user == "shutdown" ? "shutdown" : "runlevel"
        case 2: action = "boot"
        case 3: action = "clock_new"
        case 4: action = "clock_old"
        case 5: action = "init_process"
        case 6: action = "login_process"
        case 7: action = "login"
        case 8: action = "logout"
        default: action = typeName.lowercased()
        }
        var summary = [typeName]
        f.action(failed ? "login_failed" : action)
        f.add("Type", typeName)
        if type == 2 || type == 1 {
            // Boot and run-level records keep the kernel version in ut_host, the level in ut_pid.
            f.add("KernelVersion", host)
            if type == 1, let s = UnicodeScalar(UInt32(pid & 0xFF)), (32..<127).contains(s.value) { f.add("RunLevel", String(Character(s))) }
            summary += [user, host]
        } else {
            f.user("Target", user)
            if let address, address != "0.0.0.0" {
                f.add("IpAddress", address)
                if host != address { f.peer(host) }
            } else {
                f.peer(host)
            }
            summary += [user, line] + (host.isEmpty ? [] : ["from", host])
        }
        f.add("Terminal", line)
        f.add("TerminalId", id)
        if pid != 0 { f.add("ProcessId", String(pid)); summary += ["pid", String(pid)] }
        if session != 0 { f.add("SessionId", String(session)) }
        if type == 8, termination != 0 || exit != 0 { f.add("ExitStatus", "\(termination)/\(exit)") }
        f.list.insert(CaseField("Message", summary.filter { !$0.isEmpty }.joined(separator: " ")), at: 0)
        return f.list
    }
}

/// `/var/log/lastlog`: one 292-byte record per UID (time, terminal, host), sparse.
struct LastlogRecord {
    static let size = 292
    var uid: Int
    var offset: Int
    var seconds: Int64
    var line: String
    var host: String

    static func parse(_ data: Data) -> [LastlogRecord] {
        var out: [LastlogRecord] = []
        data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            for uid in 0..<(raw.count / size) {
                let o = uid * size
                let r = UnsafeRawBufferPointer(rebasing: raw[o..<(o + size)])
                let t = r.loadUnaligned(fromByteOffset: 0, as: UInt32.self).littleEndian
                guard t != 0 else { continue }
                out.append(LastlogRecord(uid: uid, offset: o, seconds: Int64(t), line: UtmpRecord.text(r, 4, 32),
                                         host: UtmpRecord.text(r, 36, 256)))
            }
        }
        return out
    }

    func fields(host machine: String, user: String?) -> [CaseField] {
        var f = LinuxFields(host: machine)
        f.action("last_login")
        f.user("Target", user)
        f.add("TargetUid", String(uid))
        f.add("Terminal", line)
        f.peer(host)
        let who = user.map { "\($0) (uid \(uid))" } ?? "uid \(uid)"
        let summary = ["last login", who, line] + (host.isEmpty ? [] : ["from", host])
        f.list.insert(CaseField("Message", summary.filter { !$0.isEmpty }.joined(separator: " ")), at: 0)
        return f.list
    }
}
