import Foundation

/// Field extraction for syslog messages by program. Unknown programs keep only `Message`.
enum SyslogMessages {
    /// Adds the fields of `message`; returns a level when the text itself states one.
    static func extract(program: Substring, message: Substring, into f: inout LinuxFields) -> UInt8? {
        switch program {
        case "sshd", "sshd-session", "sshd-auth": return SshdMessages.extract(message, into: &f)
        case "sudo": SudoMessages.extract(message, into: &f)
        case "su": SuMessages.extract(message, into: &f)
        case "systemd-logind": LogindMessages.extract(message, into: &f)
        case "CRON", "cron", "crond": CronMessages.extract(message, into: &f)
        case "useradd", "groupadd", "usermod", "userdel", "groupdel", "groupmod", "passwd", "chpasswd",
             "gpasswd", "chage", "chfn", "chsh", "newusers":
            AccountMessages.extract(program: program, message, into: &f)
        case "kernel": KernelMessages.extract(message, into: &f)
        default: _ = PamMessages.extract(message, into: &f)
        }
        return nil
    }
}

/// `pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)` and the like.
enum PamMessages {
    static func extract(_ m: Substring, into f: inout LinuxFields) -> Bool {
        guard m.hasPrefix("pam_"), let open = m.firstIndex(of: "("), let close = m.range(of: "): ") else { return false }
        f.add("PamModule", m[..<open])
        let svc = m[m.index(after: open)..<close.lowerBound]
        if let colon = svc.firstIndex(of: ":") {
            f.add("PamService", svc[..<colon])
            f.add("PamType", svc[svc.index(after: colon)...])
        }
        let text = m[close.upperBound...]
        if let rest = text.after("session opened for user ") {
            f.action("session_opened")
            // "root(uid=0) by alice(uid=1000)", "root by (uid=0)", "root(uid=0) by (uid=0)"
            let parts = rest.components(separatedBy: " by ")
            f.user("Target", parts[0].components(separatedBy: "(")[0])
            if let uid = Substring(parts[0]).between("(uid=", ")") { f.add("TargetUid", uid) }
            if parts.count > 1 {
                let by = parts[1].components(separatedBy: "(")[0]
                f.user("Subject", by)
                if let uid = Substring(parts[1]).between("(uid=", ")") { f.add("SubjectUid", uid) }
            }
        } else if let rest = text.after("session closed for user ") {
            f.action("session_closed")
            f.user("Target", rest)
        } else if let rest = text.after("authentication failure; ") {
            f.action("auth_failure")
            keyValues(rest, into: &f)
        } else if let rest = text.after("password changed for ") {
            f.action("password_changed")
            f.user("Target", rest)
        } else if text.hasPrefix("check pass; user unknown") {
            f.action("auth_failure")
            f.add("UserStatus", "unknown")
        }
        return true
    }

    /// `logname= uid=0 euid=0 tty=ssh ruser= rhost=1.2.3.4  user=root`
    static func keyValues(_ s: Substring, into f: inout LinuxFields) {
        for (k, v) in s.keyValues() {
            switch k {
            case "user": f.user("Target", v)
            case "ruser": f.add("RemoteUser", v)
            case "rhost": f.peer(v)
            case "tty": f.add("Terminal", v)
            case "uid": f.add("Uid", v)
            case "euid": f.add("Euid", v)
            case "logname": f.add("LogName", v)
            default: break
            }
        }
    }
}

/// `alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id`
enum SudoMessages {
    static func extract(_ m: Substring, into f: inout LinuxFields) {
        if PamMessages.extract(m, into: &f) { return }
        guard let sep = m.range(of: " : ") else { return }
        f.user("Subject", m[..<sep.lowerBound])
        var rest = m[sep.upperBound...]
        if let c = rest.range(of: "COMMAND=") {   // the command is last and may itself contain " ; "
            f.add("CommandLine", rest[c.upperBound...])
            rest = rest[..<c.lowerBound]
        }
        var denied: Substring?
        for part in rest.components(separatedBy: " ; ") {
            let p = Substring(part.trimmingCharacters(in: .whitespaces))
            guard !p.isEmpty else { continue }
            guard let eq = p.firstIndex(of: "=") else { denied = p; continue }
            let v = p[p.index(after: eq)...]
            switch p[..<eq] {
            case "TTY": f.add("Terminal", v)
            case "PWD": f.add("CurrentDirectory", v)
            case "USER": f.user("Target", v)
            case "GROUP": f.add("TargetGroup", v)
            case "TSID": f.add("SessionId", v)
            case "ENV": f.add("Environment", v)
            default: break
            }
        }
        if let denied {
            f.action("sudo_denied")
            f.add("Reason", denied)
        } else {
            f.action("sudo")
        }
    }
}

/// `(to root) alice on pts/0`, `FAILED SU (to root) alice on pts/0`.
enum SuMessages {
    static func extract(_ m: Substring, into f: inout LinuxFields) {
        if PamMessages.extract(m, into: &f) { return }
        var s = m
        var failed = false
        if let rest = s.after("FAILED SU ") { s = rest; failed = true }
        guard let target = s.between("(to ", ") ") else { return }
        f.action(failed ? "su_failed" : "su")
        f.user("Target", target)
        let rest = s[s.range(of: ") ")!.upperBound...]
        if let on = rest.range(of: " on ") {
            f.user("Subject", rest[..<on.lowerBound])
            f.add("Terminal", rest[on.upperBound...])
        } else {
            f.user("Subject", rest)
        }
    }
}

/// `New session 12 of user alice.`, `Session 12 logged out. …`, `Removed session 12.`
enum LogindMessages {
    static func extract(_ m: Substring, into f: inout LinuxFields) {
        if let rest = m.after("New session ") {
            f.action("logind_session_new")
            if let of = rest.range(of: " of user ") {
                f.add("SessionId", rest[..<of.lowerBound])
                var user = rest[of.upperBound...]
                if user.hasSuffix(".") { user = user.dropLast() }
                f.user("Target", user)
            }
        } else if let rest = m.after("Session "), let r = rest.range(of: " logged out") {
            f.action("logind_session_logout")
            f.add("SessionId", rest[..<r.lowerBound])
        } else if let rest = m.after("Removed session ") {
            f.action("logind_session_removed")
            f.add("SessionId", rest.hasSuffix(".") ? rest.dropLast() : rest)
        }
    }
}

/// `(root) CMD (command)`.
enum CronMessages {
    static func extract(_ m: Substring, into f: inout LinuxFields) {
        if PamMessages.extract(m, into: &f) { return }
        guard m.hasPrefix("("), let close = m.range(of: ") ") else { return }
        let user = m[m.index(after: m.startIndex)..<close.lowerBound]
        let rest = m[close.upperBound...]
        if let cmd = rest.after("CMD (") {
            f.action("cron_command")
            f.user("Subject", user)
            f.add("CommandLine", cmd.hasSuffix(")") ? cmd.dropLast() : cmd)
        } else if user != "CRON" {
            f.user("Subject", user)
        }
    }
}

/// shadow-utils: useradd, groupadd, usermod, userdel, passwd, chpasswd, …
enum AccountMessages {
    static func extract(program: Substring, _ m: Substring, into f: inout LinuxFields) {
        if PamMessages.extract(m, into: &f) { return }
        if let rest = m.after("new user: ") {
            f.action("user_added")
            for (k, v) in rest.keyValues(separator: ",") {
                switch k {
                case "name": f.user("Target", v)
                case "UID": f.add("TargetUid", v)
                case "GID": f.add("Gid", v)
                case "home": f.add("HomeDirectory", v)
                case "shell": f.add("Shell", v)
                case "from": f.add("Terminal", v)
                default: break
                }
            }
        } else if let rest = m.after("new group: ") {
            f.action("group_added")
            for (k, v) in rest.keyValues(separator: ",") {
                if k == "name" { f.add("GroupName", v) } else if k == "GID" { f.add("Gid", v) }
            }
        } else if m.hasPrefix("add '"), let user = m.between("'", "'"),
                  let group = m.range(of: "group '").map({ m[$0.upperBound...] }) {
            f.action("group_member_added")
            f.user("Target", user)
            f.add("GroupName", group.hasSuffix("'") ? group.dropLast() : group)
        } else if m.hasPrefix("delete '"), let user = m.between("'", "'"),
                  let group = m.range(of: "group '").map({ m[$0.upperBound...] }) {
            f.action("group_member_removed")
            f.user("Target", user)
            f.add("GroupName", group.hasSuffix("'") ? group.dropLast() : group)
        } else if let rest = m.after("delete user '") {
            f.action("user_deleted")
            f.user("Target", rest.prefix { $0 != "'" })
        } else if m.hasPrefix("group '"), m.hasSuffix("' removed") || m.contains("' removed from") {
            f.action("group_deleted")
            f.add("GroupName", m.between("'", "'"))
        } else if let rest = m.after("password for '") {
            f.action("password_changed")
            f.user("Target", rest.prefix { $0 != "'" })
            f.user("Subject", rest.between("changed by '", "'"))
        } else if let user = m.between("user '", "'") {
            f.action("user_modified")
            f.user("Target", user)
        }
        if !f.has("Action"), program == "passwd" || program == "chpasswd", m.contains("password changed") {
            f.action("password_changed")
        }
    }
}

/// Netfilter LOG lines (`[UFW BLOCK] IN=eth0 OUT= … SRC=1.2.3.4 DST=… PROTO=TCP SPT=… DPT=22 …`).
enum KernelMessages {
    static func extract(_ m: Substring, into f: inout LinuxFields) {
        guard let inRange = m.range(of: "IN="), m.contains(" SRC="), m.contains(" DST=") else { return }
        f.action("firewall")
        var prefix = m[..<inRange.lowerBound]
        if prefix.hasPrefix("["), let close = prefix.firstIndex(of: "]") {   // "[ 1234.567890] " uptime stamp
            let inner = prefix[prefix.index(after: prefix.startIndex)..<close]
            if inner.allSatisfy({ $0 == " " || $0 == "." || $0.isNumber }) { prefix = prefix[prefix.index(after: close)...] }
        }
        let rule = prefix.trimmingCharacters(in: CharacterSet(charactersIn: " []"))
        f.add("FirewallRule", rule)
        for (k, v) in m[inRange.lowerBound...].keyValues() {
            switch k {
            case "IN": f.add("InInterface", v)
            case "OUT": f.add("OutInterface", v)
            case "SRC": f.add("SourceIp", v)
            case "DST": f.add("DestinationIp", v)
            case "PROTO": f.add("Protocol", v)
            case "SPT": f.add("SourcePort", v)
            case "DPT": f.add("DestinationPort", v)
            case "MAC": f.add("Mac", v)
            default: break
            }
        }
    }
}
