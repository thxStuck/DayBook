import EvtxCore
import Foundation

/// Linux audit log (`/var/log/audit/audit.log`): the records of one event share `msg=audit(time:serial)`
/// and are written one after another; they become one event with the fields of all records.
/// Values hex-encoded by auditd are decoded, the interpreted part after 0x1D (`AUID="alice"`) becomes
/// `AuidName` and so on. EXECVE arguments stay `a0`, `a1`, …; the raw syscall arguments of SYSCALL
/// are `syscall_a0` … `syscall_a3`.
struct AuditFormat: TextLogFormat {
    var name: String { "audit" }

    static let separateArguments = 10

    static func looksLike(_ line: String) -> Bool {
        (line.hasPrefix("type=") || line.hasPrefix("node=")) && line.contains(" msg=audit(")
    }

    static func auditId(_ line: String) -> Substring? {
        let s = Substring(line)
        guard let a = Bytes.find("msg=audit(", in: s), let b = s.utf8[a.upperBound...].firstIndex(of: 41) else { return nil }   // ')'
        return s[a.upperBound..<b]
    }

    func continues(_ line: LogLine, record first: LogLine) -> Bool {
        guard let a = Self.auditId(first.text), let b = Self.auditId(line.text) else { return false }
        return a == b
    }

    func stamp(_ record: TextRecord) -> (stamp: SyslogLine.Stamp?, host: Substring?) {
        let line = record.first.text
        var host: Substring?
        if line.hasPrefix("node="), let sp = line.firstIndex(of: " ") { host = line[line.index(line.startIndex, offsetBy: 5)..<sp] }
        return (Self.auditId(line).flatMap(Self.time).map { .iso(wall: $0, offset: 0) }, host)
    }

    /// `1790836506.761:108021` → FILETIME (UTC).
    static func time(_ id: Substring) -> Int64? {
        let t = id.split(separator: ":").first ?? id
        let parts = t.split(separator: ".")
        guard let secs = Int64(parts[0]) else { return nil }
        var frac: Int64 = 0
        if parts.count > 1 {
            var digits = parts[1].prefix(7)
            while digits.count < 7 { digits += "0" }
            frac = Int64(digits) ?? 0
        }
        return FileTime.fromUnixSeconds(secs) + frac
    }

    static let typeCodes: [String: UInt16] = [
        "USER_AUTH": 1100, "USER_ACCT": 1101, "USER_MGMT": 1102, "CRED_ACQ": 1103, "CRED_DISP": 1104, "USER_START": 1105,
        "USER_END": 1106, "USER_AVC": 1107, "USER_CHAUTHTOK": 1108, "USER_ERR": 1109, "CRED_REFR": 1110,
        "USYS_CONFIG": 1111, "USER_LOGIN": 1112, "USER_LOGOUT": 1113, "ADD_USER": 1114, "DEL_USER": 1115,
        "ADD_GROUP": 1116, "DEL_GROUP": 1117, "DAC_CHECK": 1118, "CHGRP_ID": 1119, "TEST": 1120, "TRUSTED_APP": 1121,
        "USER_SELINUX_ERR": 1122, "USER_CMD": 1123, "USER_TTY": 1124, "CHUSER_ID": 1125, "GRP_AUTH": 1126,
        "SYSTEM_BOOT": 1127, "SYSTEM_SHUTDOWN": 1128, "SYSTEM_RUNLEVEL": 1129, "SERVICE_START": 1130,
        "SERVICE_STOP": 1131, "GRP_MGMT": 1132, "GRP_CHAUTHTOK": 1133, "MAC_CHECK": 1134, "ACCT_LOCK": 1135,
        "ACCT_UNLOCK": 1136, "USER_DEVICE": 1137, "SOFTWARE_UPDATE": 1138,
        "DAEMON_START": 1200, "DAEMON_END": 1201, "DAEMON_ABORT": 1202, "DAEMON_CONFIG": 1203,
        "DAEMON_RECONFIG": 1204, "DAEMON_ROTATE": 1205, "DAEMON_RESUME": 1206, "DAEMON_ACCEPT": 1207,
        "DAEMON_CLOSE": 1208, "DAEMON_ERR": 1209,
        "SYSCALL": 1300, "PATH": 1302, "IPC": 1303, "SOCKETCALL": 1304, "CONFIG_CHANGE": 1305, "SOCKADDR": 1306,
        "CWD": 1307, "EXECVE": 1309, "IPC_SET_PERM": 1311, "MQ_OPEN": 1312, "MQ_SENDRECV": 1313, "MQ_NOTIFY": 1314,
        "MQ_GETSETATTR": 1315, "KERNEL_OTHER": 1316, "FD_PAIR": 1317, "OBJ_PID": 1318, "TTY": 1319, "EOE": 1320,
        "BPRM_FCAPS": 1321, "CAPSET": 1322, "MMAP": 1323, "NETFILTER_PKT": 1324, "NETFILTER_CFG": 1325,
        "SECCOMP": 1326, "PROCTITLE": 1327, "FEATURE_CHANGE": 1328, "REPLACE": 1329, "KERN_MODULE": 1330,
        "FANOTIFY": 1331, "TIME_INJOFFSET": 1332, "TIME_ADJNTPVAL": 1333, "BPF": 1334, "EVENT_LISTENER": 1335,
        "URINGOP": 1336, "OPENAT2": 1337, "AVC": 1400, "ANOM_PROMISCUOUS": 1700, "ANOM_ABEND": 1701,
        "ANOM_LINK": 1702, "ANOM_CREAT": 1703, "ANOM_LOGIN_FAILURES": 2100, "ANOM_LOGIN_TIME": 2101,
        "ANOM_LOGIN_SESSIONS": 2102, "ANOM_LOGIN_ACCT": 2103, "ANOM_LOGIN_LOCATION": 2104,
    ]

    /// Fields whose unquoted value auditd writes hex-encoded (it contains spaces, quotes or control bytes).
    static let encodable: Set<String> = ["name", "cwd", "comm", "exe", "acct", "path", "proctitle", "data", "cmd",
                                         "new_name", "old_name", "ocomm", "key", "root_dir", "watch", "vm", "new-name", "old-name"]

    static func decodeHex(_ v: Substring, nulAsSpace: Bool) -> String? {
        decodeHexBytes(v, nulAsSpace: nulAsSpace).map { bytes in bytes.withUnsafeBufferPointer { LogLines.decode($0).0 } }
    }

    static func decodeHexBytes(_ v: Substring, nulAsSpace: Bool) -> [UInt8]? {
        let u = v.utf8
        guard u.count >= 2, u.count % 2 == 0 else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(u.count / 2)
        var high: UInt8 = 0, odd = false
        for c in u {
            let d: UInt8
            switch c {
            case 48...57: d = c - 48
            case 65...70: d = c - 55
            case 97...102: d = c - 87
            default: return nil
            }
            if odd {
                let b = high << 4 | d
                bytes.append(b == 0 && nulAsSpace ? 32 : b)
            } else {
                high = d
            }
            odd.toggle()
        }
        while nulAsSpace, bytes.last == 32 { bytes.removeLast() }
        return bytes
    }

    /// `key=value key="value" key='value'` → pairs (quotes removed, `quoted` tells whether there were).
    static func pairs(_ s: Substring) -> [(key: Substring, value: Substring, quoted: Bool)] {
        var out: [(Substring, Substring, Bool)] = []
        let u = s.utf8
        var i = u.startIndex
        let end = u.endIndex
        while i < end {
            while i < end, u[i] == 32 { i = u.index(after: i) }
            guard i < end else { break }
            var j = i
            while j < end, u[j] != 61, u[j] != 32 { j = u.index(after: j) }   // '=' / ' '
            guard j < end, u[j] == 61 else { i = j; continue }
            let key = s[i..<j]
            var v = u.index(after: j)
            if v < end, u[v] == 34 || u[v] == 39 {
                let q = u[v]
                v = u.index(after: v)
                var e = v
                while e < end, u[e] != q { e = u.index(after: e) }
                out.append((key, s[v..<e], true))
                i = e < end ? u.index(after: e) : e
            } else {
                var e = v
                while e < end, u[e] != 32 { e = u.index(after: e) }
                out.append((key, s[v..<e], false))
                i = e
            }
        }
        return out
    }

    // swiftlint:disable:next function_body_length cyclomatic_complexity
    func parse(_ record: TextRecord, plan: LinuxSourcePlan) -> ParsedRecord {
        let (stamp, node) = stamp(record)
        var f = LinuxFields(host: node.map(String.init) ?? plan.host)
        var types: [String] = []
        var raw: [(String, String)] = []
        var interpreted: [String: String] = [:]
        var argv: [(Int, String)] = []
        var pieces: [Int: [(Int, [UInt8])]] = [:]   // long arguments: a1_len=… a1[0]=… a1[1]=…
        var msgText: String?
        var proctitle: String?
        var firstBody: Substring?
        for line in record.lines {
            let text = Substring(line.text)
            guard let typeStart = Bytes.find("type=", in: text), let close = Bytes.find("): ", in: text) else { continue }
            let typeEnd = text.utf8[typeStart.upperBound...].firstIndex(of: 32) ?? text.endIndex
            let typeName = String(text[typeStart.upperBound..<typeEnd])
            types.append(typeName)
            var body = text[close.upperBound...]
            defer { if firstBody == nil { firstBody = body } }
            if let gs = body.utf8.firstIndex(of: 0x1D) {
                for p in Self.pairs(body[body.utf8.index(after: gs)...]) {
                    let k = p.key.lowercased()
                    interpreted[k] = interpreted[k] ?? String(p.value)
                    raw.append((k.prefix(1).uppercased() + k.dropFirst() + "Name", String(p.value)))
                }
                body = body[..<gs]
            }
            for p in Self.pairs(body) {
                var key = String(p.key)
                var value = String(p.value)
                if key == "msg" {
                    // User-space records: `msg='op=… acct=… exe=… res=…'`, values decoded.
                    var decoded: [String] = []
                    for q in Self.pairs(p.value) {
                        let k = String(q.key)
                        let v = !q.quoted && Self.encodable.contains(k) ? Self.decodeHex(q.value, nulAsSpace: false) ?? String(q.value) : String(q.value)
                        raw.append((TextFormats.safeName(k), v))
                        decoded.append("\(k)=\(v)")
                    }
                    msgText = decoded.isEmpty ? value : decoded.joined(separator: " ")
                    continue
                }
                if typeName == "EXECVE", key.hasPrefix("a"), let open = key.firstIndex(of: "["), let n = Int(key[key.index(after: key.startIndex)..<open]),
                   let k = Int(key[key.index(after: open)...].dropLast()) {
                    let bytes = p.quoted ? Array(p.value.utf8) : Self.decodeHexBytes(p.value, nulAsSpace: false) ?? Array(p.value.utf8)
                    pieces[n, default: []].append((k, bytes))
                    continue
                } else if typeName == "EXECVE", key.hasPrefix("a"), key.hasSuffix("_len") {
                    continue
                } else if typeName == "EXECVE", key.hasPrefix("a"), let n = Int(key.dropFirst()) {
                    value = !p.quoted ? Self.decodeHex(p.value, nulAsSpace: false) ?? value : value
                    argv.append((n, value))
                    // a0…a9 stay separate fields (rules query them); the whole command is in CommandLine.
                    if n >= Self.separateArguments { continue }
                } else if typeName == "SYSCALL", ["a0", "a1", "a2", "a3"].contains(key) {
                    key = "syscall_" + key
                } else if typeName == "PROCTITLE", key == "proctitle" {
                    value = !p.quoted ? Self.decodeHex(p.value, nulAsSpace: true) ?? value : value
                    proctitle = value
                } else if !p.quoted, Self.encodable.contains(key) {
                    value = Self.decodeHex(p.value, nulAsSpace: false) ?? value
                }
                raw.append((TextFormats.safeName(key), value))
            }
        }
        for (n, parts) in pieces {
            let bytes = parts.sorted { $0.0 < $1.0 }.flatMap(\.1)
            let value = bytes.withUnsafeBufferPointer { LogLines.decode($0).0 }
            argv.append((n, value))
            if n < Self.separateArguments { raw.append(("a\(n)", value)) }
        }
        let first = types.first ?? ""
        let field = { (name: String) in raw.first { $0.0 == name }?.1 }
        // EXECVE arguments, or the command sudo logged (USER_CMD cmd=…).
        let commandLine = argv.isEmpty ? field("cmd") : argv.sorted { $0.0 < $1.0 }.map { Self.shellQuote($0.1) }.joined(separator: " ")
        let result = field("res") ?? field("success")
        let ok = result.map { ["success", "yes"].contains($0) }
        f.add("Message", commandLine ?? msgText ?? proctitle ?? firstBody.map(String.init) ?? record.first.text)
        if let a = Self.action(types: types, syscall: interpreted["syscall"], hasExec: !argv.isEmpty, ok: ok) { f.action(a) }
        for t in types { f.add("Type", t) }
        f.add("AuditId", Self.auditId(record.first.text))
        f.add("CommandLine", commandLine)
        if let auid = interpreted["auid"], auid != "unset" { f.user("Subject", auid) }
        else if let uid = interpreted["uid"] { f.user("Subject", uid) }
        if let acct = field("acct"), !acct.hasPrefix("("), acct != "?" { f.user("Target", acct) }
        if let addr = field("addr"), EntityNames.isIP(addr) { f.add("IpAddress", addr) }
        if let host = field("hostname"), host != "?", !EntityNames.isIP(host), host != (field("addr") ?? "") { f.add("WorkstationName", host) }
        for (k, v) in raw { f.add(k, v) }
        let comm = field("comm"), exe = field("exe")
        let provider = comm ?? exe.map { ($0 as NSString).lastPathComponent } ?? first.lowercased()
        return ParsedRecord(stamp: stamp, host: node.map(String.init), provider: provider, pid: field("pid").flatMap { UInt32($0) },
                            level: nil, eventId: Self.typeCodes[first] ?? 0, fields: f.list)
    }

    static func action(types: [String], syscall: String?, hasExec: Bool, ok: Bool?) -> String? {
        let t = Set(types)
        if hasExec || syscall == "execve" || syscall == "execveat" { return "process_exec" }
        let failed = ok == false
        if t.contains("USER_LOGIN") { return failed ? "login_failed" : "login" }
        if t.contains("USER_AUTH") { return failed ? "auth_failure" : "auth_success" }
        if t.contains("USER_START") { return "session_opened" }
        if t.contains("USER_END") { return "session_closed" }
        if t.contains("USER_LOGOUT") { return "logout" }
        if t.contains("ADD_USER") { return "user_added" }
        if t.contains("DEL_USER") { return "user_deleted" }
        if t.contains("ADD_GROUP") { return "group_added" }
        if t.contains("DEL_GROUP") { return "group_deleted" }
        if t.contains("USER_MGMT") || t.contains("GRP_MGMT") { return "user_modified" }
        if t.contains("USER_CHAUTHTOK") { return "password_changed" }
        if t.contains("USER_CMD") { return "sudo" }
        if t.contains("SERVICE_START") { return "service_start" }
        if t.contains("SERVICE_STOP") { return "service_stop" }
        if t.contains("SYSTEM_BOOT") { return "boot" }
        if t.contains("SYSTEM_SHUTDOWN") { return "shutdown" }
        if t.contains("CONFIG_CHANGE") { return "audit_config_change" }
        if t.contains("DAEMON_START") { return "audit_daemon_start" }
        if t.contains("DAEMON_END") { return "audit_daemon_end" }
        if t.contains("KERN_MODULE") { return "kernel_module" }
        if t.contains("ANOM_PROMISCUOUS") { return "promiscuous_mode" }
        if t.contains("ANOM_ABEND") { return "abnormal_end" }
        return nil
    }

    /// An argument as a shell would need it typed.
    static func shellQuote(_ s: String) -> String {
        guard !s.isEmpty else { return "''" }
        let plain = s.allSatisfy { $0.isLetter || $0.isNumber || "-_./=:,@%+".contains($0) }
        return plain ? s : "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
