import Foundation

/// OpenSSH server messages (auth.log / secure). Recognised lines get an `Action`, the account and
/// the peer; every line keeps its text in `Message`.
enum SshdMessages {
    /// Account prefixes sshd writes before a user name.
    private static let userKinds = [("invalid user ", "invalid"), ("authenticating user ", "authenticating"), ("user ", "")]

    static func extract(_ message: Substring, into f: inout LinuxFields) -> UInt8? {
        var m = message
        if m.hasSuffix(" [preauth]") {
            m = m.dropLast(10)
            f.add("Stage", "preauth")
        }
        var level: UInt8?
        if let rest = m.after("error: ") { m = rest; level = 2 } else if let rest = m.after("fatal: ") { m = rest; level = 1 }

        if let rest = m.after("Accepted ") {
            if let key = rest.after("key ") {   // "Accepted key ED25519 SHA256:… found at /home/u/.ssh/authorized_keys:1"
                f.action("key_accepted")
                let parts = key.split(separator: " ", maxSplits: 2)
                if parts.count >= 2 { f.add("KeyType", parts[0]); f.add("KeyFingerprint", parts[1]) }
                f.add("KeyFile", key.range(of: " found at ").map { key[$0.upperBound...] })
            } else {
                f.action("auth_success")
                authAttempt(rest, into: &f)
            }
        } else if let rest = m.after("Failed ") {
            f.action("auth_failure")
            authAttempt(rest, into: &f)
        } else if let rest = m.after("Postponed ") {
            f.action("auth_postponed")
            authAttempt(rest, into: &f)
        } else if let rest = m.after("Invalid user ") {
            f.action("invalid_user")
            f.add("UserStatus", "invalid")
            if let p = fromPort(rest) { f.user("Target", p.who); f.peer(p.address); f.add("IpPort", p.port) }
        } else if let rest = m.after("User "), rest.contains(" not allowed because ") {
            f.action("user_not_allowed")
            let head = rest[..<rest.range(of: " not allowed because ")!.lowerBound]
            if let p = fromPort(head) { f.user("Target", p.who); f.peer(p.address) }
            f.add("Reason", rest.range(of: " not allowed because ").map { rest[$0.upperBound...] })
        } else if let rest = m.after("maximum authentication attempts exceeded for ") {
            f.action("too_many_auth_failures")
            if let p = fromPort(rest) { account(p.who, into: &f); f.peer(p.address); f.add("IpPort", p.port) }
        } else if let rest = m.after("Connection from ") {
            f.action("connection")
            if let p = addressPort(rest) { f.peer(p.address); f.add("IpPort", p.port) }
            if let local = rest.range(of: " on ").map({ rest[$0.upperBound...] }), let l = addressPort(local) {
                f.add("LocalAddress", l.address); f.add("LocalPort", l.port)
            }
        } else if let rest = m.after("Connection closed by ") ?? m.after("Connection reset by ") {
            f.action(m.hasPrefix("Connection closed") ? "connection_closed" : "connection_reset")
            byAccount(rest, into: &f)
        } else if let rest = m.after("Disconnected from ") {
            f.action("disconnected")
            byAccount(rest, into: &f)
        } else if let rest = m.after("Received disconnect from ") {
            f.action("disconnect_received")
            if let p = addressPort(rest) { f.peer(p.address); f.add("IpPort", p.port) }
            if let r = rest.range(of: ": ") { f.add("Reason", rest[r.upperBound...]) }
        } else if let rest = m.after("Starting session: ") {
            // "command on pts/0 for u from 1.2.3.4 port 5 id 0", "shell on pts/1 …", "subsystem 'sftp' for …"
            f.action("session_start")
            if let r = rest.range(of: " for ", options: .backwards) {
                var kind = rest[..<r.lowerBound]
                if let on = kind.range(of: " on ") { f.add("Terminal", kind[on.upperBound...]); kind = kind[..<on.lowerBound] }
                f.add("SessionType", kind)
                if let p = fromPort(rest[r.upperBound...]) { f.user("Target", p.who); f.peer(p.address); f.add("IpPort", p.port) }
            }
            f.add("SessionId", rest.range(of: " id ", options: .backwards).map { rest[$0.upperBound...] })
        } else if let rest = m.after("Close session: ") {
            f.action("session_end")
            if let p = fromPort(rest.after("user ") ?? rest) { f.user("Target", p.who); f.peer(p.address); f.add("IpPort", p.port) }
            f.add("SessionId", rest.range(of: " id ", options: .backwards).map { rest[$0.upperBound...] })
        } else if let rest = m.after("Timeout before authentication for ") {
            f.action("preauth_timeout")
            if let p = addressPort(rest) { f.peer(p.address); f.add("IpPort", p.port) }
        } else if let rest = m.after("Did not receive identification string from ") {
            f.action("no_identification")
            if let p = addressPort(rest) { f.peer(p.address); f.add("IpPort", p.port) }
        } else if let rest = m.after("Unable to negotiate with ") {
            f.action("negotiation_failed")
            if let p = addressPort(rest) { f.peer(p.address); f.add("IpPort", p.port) }
        } else if let rest = m.after("banner exchange: Connection from ") {
            f.action("bad_banner")
            if let p = addressPort(rest) { f.peer(p.address); f.add("IpPort", p.port) }
        } else if let rest = m.after("Server listening on ") {
            f.action("listening")
            if let p = addressPort(rest) { f.add("LocalAddress", p.address); f.add("LocalPort", p.port) }
        } else if m.hasPrefix("Received signal ") {
            f.action("signal")
        } else if PamMessages.extract(m, into: &f) {
            // pam_unix(sshd:…) lines
        } else if let rest = m.after("PAM "), rest.contains("more authentication failure") {
            f.action("auth_failure")
            PamMessages.keyValues(rest, into: &f)
        }
        return level
    }

    /// "<method> for [invalid user ]<user> from <addr> port <port> ssh2[: <key type> <fingerprint>]"
    private static func authAttempt(_ s: Substring, into f: inout LinuxFields) {
        guard let forRange = s.range(of: " for ") else { return }
        f.add("AuthMethod", s[..<forRange.lowerBound])
        var rest = s[forRange.upperBound...]
        if let colon = rest.range(of: ": ", options: .backwards), rest[..<colon.lowerBound].hasSuffix("ssh2") {
            let key = rest[colon.upperBound...].split(separator: " ", maxSplits: 1)
            if key.count == 2 { f.add("KeyType", key[0]); f.add("KeyFingerprint", key[1]) }
            rest = rest[..<colon.lowerBound]
        }
        guard let p = fromPort(rest) else { return }
        account(p.who, into: &f)
        f.peer(p.address)
        f.add("IpPort", p.port)
    }

    /// "[invalid user |authenticating user |user ]<name>"
    private static func account(_ who: Substring, into f: inout LinuxFields) {
        for (prefix, status) in userKinds {
            if let name = who.after(prefix) {
                if !status.isEmpty { f.add("UserStatus", status) }
                f.user("Target", name)
                return
            }
        }
        f.user("Target", who)
    }

    /// "[invalid user |authenticating user |user ]<name> <addr> port <port>" or "<addr> port <port>".
    private static func byAccount(_ s: Substring, into f: inout LinuxFields) {
        guard let portRange = s.range(of: " port ", options: .backwards) else { return }
        let head = s[..<portRange.lowerBound]
        let address = head.split(separator: " ").last.map { Substring($0) } ?? head
        if head.count > address.count {
            account(head.dropLast(address.count + 1), into: &f)
        }
        f.peer(address)
        f.add("IpPort", s[portRange.upperBound...].leadingDigits)
    }

    /// "<who> from <addr>[ port <port>]…" — the last " from " separates, since a user name can hold one.
    static func fromPort(_ s: Substring) -> (who: Substring, address: Substring, port: Substring)? {
        guard let r = s.range(of: " from ", options: .backwards) else { return nil }
        let rest = s[r.upperBound...]
        guard let p = addressPort(rest) else { return nil }
        return (s[..<r.lowerBound], p.address, p.port)
    }

    /// "<addr>[ port <port>]…"
    static func addressPort(_ s: Substring) -> (address: Substring, port: Substring)? {
        let address = s[..<(s.firstIndex(of: " ") ?? s.endIndex)]
        guard !address.isEmpty else { return nil }
        var port: Substring = ""
        if let r = s.range(of: " port ") { port = s[r.upperBound...].leadingDigits }
        return (address.hasSuffix(",") || address.hasSuffix(".") ? address.dropLast() : address, port)
    }
}
