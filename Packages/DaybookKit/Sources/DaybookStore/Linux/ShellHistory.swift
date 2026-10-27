import EvtxCore
import Foundation

/// Shell and REPL histories from home folders. bash keeps `#<epoch>` before each command when
/// HISTTIMEFORMAT is set, zsh's extended format `: <epoch>:<seconds>;command`, fish a YAML-like
/// `- cmd: …` / `  when: <epoch>`. Commands without a time get the file's modification time
/// (flag timeFromFile) or, next to timed ones, the time of the nearest timed command.
struct ShellHistoryFormat: TextLogFormat {
    let name: String

    /// History kind of a file, by its name; nil for other files.
    static func kind(of path: String) -> String? {
        let base = (path as NSString).lastPathComponent
        switch base {
        case ".bash_history", ".sh_history", ".ash_history", ".ksh_history", ".history", ".mysql_history",
             ".psql_history", ".python_history", ".sqlite_history", ".node_repl_history", ".rediscli_history":
            return "bash-history"
        case ".zsh_history", ".zhistory", ".histfile": return "zsh-history"
        case "fish_history": return "fish-history"
        default: return nil
        }
    }

    /// The program a history belongs to: `.mysql_history` → mysql, `.zsh_history` → zsh.
    static func shell(_ path: String) -> String {
        let base = (path as NSString).lastPathComponent
        if base == "fish_history" { return "fish" }
        if base == ".history" || base == ".histfile" { return "sh" }
        return String(base.dropFirst().split(separator: "_").first ?? "sh")
    }

    /// Owner of a home-folder file: `/root/…` → root, `/home/alice/…` → alice.
    static func owner(_ path: String) -> String? {
        let parts = path.split(separator: "/")
        if parts.first == "root" { return "root" }
        if parts.count > 1, parts[0] == "home" { return String(parts[1]) }
        return nil
    }

    static func epochLine(_ s: String) -> Int64? {
        guard s.hasPrefix("#"), s.count >= 10, s.count <= 12 else { return nil }
        return Int64(s.dropFirst())
    }

    /// `: 1790000000:0;command`
    static func zshEntry(_ s: String) -> (time: Int64, command: Substring)? {
        guard s.hasPrefix(": "), let colon = s.dropFirst(2).firstIndex(of: ":"), let semi = s.firstIndex(of: ";"),
              let t = Int64(s[s.index(s.startIndex, offsetBy: 2)..<colon]) else { return nil }
        return (t, s[s.index(after: semi)...])
    }

    func continues(_ line: LogLine, record first: LogLine) -> Bool {
        switch name {
        case "fish-history": return !line.text.hasPrefix("- cmd: ")
        case "zsh-history": return Self.zshEntry(first.text) != nil && Self.zshEntry(line.text) == nil && line.text.first != ":"
        default: return Self.epochLine(first.text) != nil && Self.epochLine(line.text) == nil
        }
    }

    func stamp(_ record: TextRecord) -> (stamp: SyslogLine.Stamp?, host: Substring?) {
        let t: Int64?
        switch name {
        case "fish-history":
            t = record.lines.first { $0.text.hasPrefix("  when: ") }.flatMap { Int64($0.text.dropFirst(8)) }
        case "zsh-history": t = Self.zshEntry(record.first.text)?.time
        default: t = Self.epochLine(record.first.text)
        }
        return (t.map { .iso(wall: FileTime.fromUnixSeconds($0), offset: 0) }, nil)
    }

    func parse(_ record: TextRecord, plan: LinuxSourcePlan) -> ParsedRecord {
        let command: String
        switch name {
        case "fish-history":
            command = record.first.text.hasPrefix("- cmd: ") ? String(record.first.text.dropFirst(7)) : record.text
        case "zsh-history":
            if let e = Self.zshEntry(record.first.text) {
                command = ([String(e.command)] + record.lines.dropFirst().map(\.text)).joined(separator: "\n")
            } else {
                command = record.text
            }
        default:
            command = Self.epochLine(record.first.text) != nil ? record.lines.dropFirst().map(\.text).joined(separator: "\n") : record.text
        }
        var f = LinuxFields(host: plan.host)
        let shell = Self.shell(plan.originalPath)
        f.add("Message", command)
        f.action("shell_command")
        f.add("CommandLine", command)
        f.add("Shell", shell)
        f.user("Subject", Self.owner(plan.originalPath))
        return ParsedRecord(stamp: stamp(record).stamp, provider: shell, fields: f.list)
    }
}
