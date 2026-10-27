import Foundation

/// What UAC wrote about the collection in `uac.log`.
public struct UacInfo: Sendable, Codable, Hashable {
    public var path: String = ""
    public var version: String?
    public var commandLine: String?
    public var os: String?
    public var arch: String?
    public var hostname: String?
    public var timeZone: String?
    public var mountPoint: String?
    public var runningAs: String?
    /// First and last lines of `uac.log`, as written (local time with offset).
    public var started: String?
    public var finished: String?
    public var errors = 0
}

/// An extracted UAC collection (https://github.com/tclahr/uac): `uac.log`, `[root]/` with copies of
/// the system's files under their original paths, `live_response/`, `bodyfile/`, …
public struct UacCollection: Sendable {
    public let url: URL
    public let info: UacInfo

    public var rootFolder: URL { url.appendingPathComponent("[root]") }

    /// The host name UAC recorded, else `/etc/hostname`, else the folder name.
    public var host: String {
        if let h = info.hostname, !h.isEmpty { return h }
        if let h = UacCollection.regularFileText(rootFolder.appendingPathComponent("etc/hostname"))?
            .trimmingCharacters(in: .whitespacesAndNewlines), !h.isEmpty { return h }
        return url.lastPathComponent
    }

    public static func isCollection(_ url: URL) -> Bool {
        let fm = FileManager.default
        var dir: ObjCBool = false
        guard fm.fileExists(atPath: url.appendingPathComponent("[root]").path, isDirectory: &dir), dir.boolValue else { return false }
        return ["uac.log", "live_response", "bodyfile"].contains { fm.fileExists(atPath: url.appendingPathComponent($0).path) }
    }

    /// Collections in the chosen folders (the folders themselves or up to three levels below).
    public static func find(in urls: [URL]) -> [UacCollection] {
        var found: [URL] = []
        func walk(_ url: URL, depth: Int) {
            if isCollection(url) { found.append(url); return }
            guard depth < 3, let items = try? FileManager.default.contentsOfDirectory(
                at: url, includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey], options: [.skipsHiddenFiles]) else { return }
            for item in items.sorted(by: { $0.path < $1.path }) {
                let v = try? item.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
                if v?.isDirectory == true, v?.isSymbolicLink != true { walk(item, depth: depth + 1) }
            }
        }
        for u in urls { walk(u.standardizedFileURL, depth: 0) }
        var seen = Set<String>()
        return found.filter { seen.insert($0.path).inserted }.map { UacCollection(url: $0, info: readInfo($0)) }
    }

    static func readInfo(_ url: URL) -> UacInfo {
        var info = UacInfo()
        info.path = url.path
        guard let text = regularFileText(url.appendingPathComponent("uac.log")) else { return info }
        var first: String?, last: String?
        for raw in text.split(separator: "\n", omittingEmptySubsequences: true) {
            // "2026-10-01 09:31:03 +0300 INF Hostname: web01"
            let parts = raw.split(separator: " ", maxSplits: 4, omittingEmptySubsequences: false)
            guard parts.count == 5 else { continue }
            let stamp = parts[0...2].joined(separator: " ")
            if first == nil { first = stamp }
            last = stamp
            if parts[3] == "ERR" { info.errors += 1 }
            guard parts[3] == "INF" else { continue }
            let msg = parts[4]
            func value(_ key: String) -> String? {
                msg.hasPrefix(key) ? String(msg.dropFirst(key.count)).trimmingCharacters(in: .whitespaces) : nil
            }
            if msg.hasPrefix("Unix-like Artifacts Collector ") { info.version = String(msg.dropFirst(30)) }
            else if let v = value("Command line:") { info.commandLine = v }
            else if let v = value("Operating system:") { info.os = v }
            else if let v = value("System architecture:") { info.arch = v }
            else if let v = value("Hostname:") { info.hostname = v }
            else if let v = value("Time zone:") { info.timeZone = v }
            else if let v = value("Mount point:") { info.mountPoint = v }
            else if let v = value("Running as:") { info.runningAs = v }
        }
        info.started = first
        info.finished = last
        return info
    }

    /// Text of a regular file (never through a symbolic link: a collection's links point into the
    /// analysed system, not this Mac).
    static func regularFileText(_ url: URL, limit: Int = 64 << 20) -> String? {
        guard let v = try? url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey]),
              v.isRegularFile == true, v.isSymbolicLink != true, (v.fileSize ?? 0) <= limit,
              let data = try? Data(contentsOf: url) else { return nil }
        return String(decoding: data, as: UTF8.self)
    }

    /// UID → name from the collected `/etc/passwd`.
    func users() -> [Int: String] {
        guard let text = Self.regularFileText(rootFolder.appendingPathComponent("etc/passwd")) else { return [:] }
        var out: [Int: String] = [:]
        for line in text.split(separator: "\n") {
            let p = line.split(separator: ":", omittingEmptySubsequences: false)
            if p.count >= 3, let uid = Int(p[2]), out[uid] == nil { out[uid] = String(p[0]) }
        }
        return out
    }

    /// Modification times (Unix seconds) the bodyfile recorded for paths under the prefixes.
    func bodyfileTimes(under prefixes: [String]) -> [String: Int64] {
        guard let text = Self.regularFileText(url.appendingPathComponent("bodyfile/bodyfile.txt"), limit: 2 << 30) else { return [:] }
        var out: [String: Int64] = [:]
        for line in text.split(separator: "\n") {
            // MD5|name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime — the name may hold '|'.
            let p = line.split(separator: "|", omittingEmptySubsequences: false)
            guard p.count >= 11 else { continue }
            let name = p[1..<(p.count - 9)].joined(separator: "|")
            guard prefixes.contains(where: { name.hasPrefix($0) }), let mtime = Int64(p[p.count - 3]) else { continue }
            out[name] = mtime
        }
        return out
    }
}
