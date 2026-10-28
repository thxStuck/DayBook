import Foundation

/// A file of a collection that becomes a source of the case, parsed or not.
struct LinuxSourcePlan {
    enum Kind: Equatable { case text, wtmp, btmp, utmp, lastlog, journal, bodyfile, unsupported(String) }

    var url: URL
    /// Path on the analysed system (`/var/log/auth.log.1`).
    var originalPath: String
    var collection: Int
    var host: String
    /// Log name shared by rotations (`auth.log`, `nginx/access.log`, `wtmp`).
    var channel: String
    var kind: Kind
    var size: Int
    /// Year inference: the file's modification time on the system (bodyfile), else the copy's.
    var reference: Date
    var referenceFromBodyfile: Bool
    /// Zone for times written without one; nil when the collection names none (UTC is used).
    var zone: TimeZone?
    var zoneName: String
}

enum LinuxPlan {
    static let rotationSuffix = try! NSRegularExpression(pattern: #"(\.\d+)?(-\d{8}(\d{2})?)?(\.(gz|xz|bz2|zst|lz4))?$"#)

    /// `auth.log.2.gz` → `auth.log`, `messages-20260927` → `messages`, `wtmp.1` → `wtmp`.
    static func logName(_ relative: String) -> String {
        let ns = relative as NSString
        let r = rotationSuffix.rangeOfFirstMatch(in: relative, range: NSRange(location: 0, length: ns.length))
        guard r.location != NSNotFound, r.length > 0, r.location > 0 else { return relative }
        return ns.substring(to: r.location)
    }

    static func kind(originalPath: String, channel: String) -> LinuxSourcePlan.Kind {
        let base = (channel as NSString).lastPathComponent
        if originalPath.hasSuffix(".journal") || originalPath.hasSuffix(".journal~") { return .journal }
        switch base {
        case "wtmp": return .wtmp
        case "btmp": return .btmp
        case "utmp": return .utmp
        case "lastlog": return .lastlog
        case "faillog", "tallylog", "sulog": return .unsupported(base)
        default: return .text
        }
    }

    /// Files of the collections that the case lists: everything under `/var/log` and the utmp files.
    static func sources(_ collections: [UacCollection]) -> [LinuxSourcePlan] {
        var out: [LinuxSourcePlan] = []
        for (ci, c) in collections.enumerated() {
            let root = c.rootFolder
            let host = c.host
            let zone = c.info.timeZone.flatMap(TimeZone.init(identifier:))
            let bodyTimes = c.bodyfileTimes(under: ["/var/", "/run/", "/home/", "/root/"])
            var files: [URL] = []
            let logDir = root.appendingPathComponent("var/log")
            if let e = FileManager.default.enumerator(at: logDir, includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey]) {
                for case let u as URL in e {
                    let v = try? u.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
                    guard v?.isRegularFile == true, v?.isSymbolicLink != true, u.lastPathComponent != ".DS_Store" else { continue }
                    files.append(u)
                }
            }
            // Shell and REPL histories of root and of every home folder.
            var homes = [root.appendingPathComponent("root")]
            if let users = try? FileManager.default.contentsOfDirectory(at: root.appendingPathComponent("home"),
                                                                        includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey]) {
                homes += users.filter {
                    let v = try? $0.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
                    return v?.isDirectory == true && v?.isSymbolicLink != true
                }
            }
            for home in homes {
                let candidates = ((try? FileManager.default.contentsOfDirectory(at: home, includingPropertiesForKeys: nil)) ?? [])
                    + [home.appendingPathComponent(".local/share/fish/fish_history")]
                for u in candidates where ShellHistoryFormat.kind(of: u.path) != nil {
                    let v = try? u.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
                    if v?.isRegularFile == true, v?.isSymbolicLink != true { files.append(u) }
                }
            }
            for extra in ["run/utmp", "var/run/utmp"] {
                let u = root.appendingPathComponent(extra)
                let v = try? u.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
                if v?.isRegularFile == true, v?.isSymbolicLink != true { files.append(u) }
            }
            // The file system timeline UAC built (outside [root]).
            let body = c.url.appendingPathComponent("bodyfile/bodyfile.txt")
            if (try? body.resourceValues(forKeys: [.isRegularFileKey]))?.isRegularFile == true {
                let v = try? body.resourceValues(forKeys: [.fileSizeKey, .contentModificationDateKey])
                out.append(LinuxSourcePlan(url: body, originalPath: "bodyfile/bodyfile.txt", collection: ci, host: host,
                                           channel: "bodyfile", kind: .bodyfile, size: v?.fileSize ?? 0,
                                           reference: v?.contentModificationDate ?? Date(), referenceFromBodyfile: false,
                                           zone: zone, zoneName: c.info.timeZone ?? "UTC"))
            }
            let rootPath = root.standardizedFileURL.path
            for u in files.sorted(by: { $0.path < $1.path }) {
                let full = u.standardizedFileURL.path
                guard full.hasPrefix(rootPath + "/") else { continue }
                let original = String(full.dropFirst(rootPath.count))
                let relative = original.hasPrefix("/var/log/") ? String(original.dropFirst("/var/log/".count))
                                                               : (original as NSString).lastPathComponent
                var channel = original.hasSuffix(".journal") || original.hasSuffix(".journal~")
                    ? JournalRecords.channel(original) : logName(relative)
                if ShellHistoryFormat.kind(of: original) != nil {
                    channel = channel.hasPrefix(".") ? String(channel.dropFirst()) : channel   // ".bash_history" → "bash_history"
                }
                let v = try? u.resourceValues(forKeys: [.fileSizeKey, .contentModificationDateKey])
                let body = bodyTimes[original]
                out.append(LinuxSourcePlan(
                    url: u, originalPath: original, collection: ci, host: host, channel: channel,
                    kind: kind(originalPath: original, channel: channel), size: v?.fileSize ?? 0,
                    reference: body.map { Date(timeIntervalSince1970: TimeInterval($0)) } ?? v?.contentModificationDate ?? Date(),
                    referenceFromBodyfile: body != nil, zone: zone, zoneName: c.info.timeZone ?? "UTC"))
            }
        }
        return out
    }
}
