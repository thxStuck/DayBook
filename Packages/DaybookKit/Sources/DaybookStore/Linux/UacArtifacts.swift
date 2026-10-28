import Foundation

/// A file of a UAC collection shown on the "System" screen: command output (live_response), the
/// collector's own lists, or a collected configuration file relevant to persistence.
public struct UacArtifact: Sendable, Hashable, Identifiable {
    public let group: String
    /// Name shown in the list (command output: the command; collected file: its original path).
    public let name: String
    public let url: URL
    public let size: Int
    public var id: String { url.path }
}

extension UacCollection {
    /// Groups in display order (folder of the collection → title).
    static let artifactGroups: [(folder: String, title: String)] = [
        ("live_response/system", String(localized: "Система")),
        ("live_response/process", String(localized: "Процессы")),
        ("live_response/network", String(localized: "Сеть")),
        ("live_response/packages", String(localized: "Пакеты")),
        ("live_response/storage", String(localized: "Диски и монтирование")),
        ("live_response/hardware", String(localized: "Оборудование")),
        ("live_response/containers", String(localized: "Контейнеры")),
        ("live_response/vms", String(localized: "Виртуальные машины")),
        ("live_response/modifiers", String(localized: "Модификаторы")),
        ("system", String(localized: "Списки UAC (suid, скрытые, доступные на запись…)")),
        ("hash_executables", String(localized: "Хеши исполняемых файлов")),
        ("chkrootkit", "chkrootkit"),
        ("ssh", "SSH"),
        ("osquery", "osquery"),
    ]

    /// Collected files that keep a system's configuration and its autostart (persistence).
    static let persistencePaths = [
        "etc/os-release", "etc/hostname", "etc/hosts", "etc/resolv.conf", "etc/passwd", "etc/group", "etc/sudoers",
        "etc/sudoers.d", "etc/crontab", "etc/cron.d", "etc/cron.hourly", "etc/cron.daily", "etc/cron.weekly", "etc/cron.monthly",
        "var/spool/cron/crontabs", "var/spool/cron", "etc/anacrontab", "etc/rc.local", "etc/ld.so.preload", "etc/environment",
        "etc/profile", "etc/profile.d", "etc/bash.bashrc", "etc/ssh/sshd_config", "etc/ssh/sshd_config.d", "root/.ssh/authorized_keys",
        "root/.bashrc", "root/.profile", "etc/systemd/system", "etc/udev/rules.d", "etc/modules", "etc/modules-load.d",
        "etc/pam.d", "etc/security/limits.conf", "etc/audit/rules.d", "etc/audit/audit.rules",
    ]

    /// Every artifact of the collection, grouped, without following symbolic links.
    public func artifacts(maxPerGroup: Int = 5000) -> [UacArtifact] {
        var out: [UacArtifact] = []
        func regular(_ u: URL) -> Int? {
            guard let v = try? u.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey]),
                  v.isRegularFile == true, v.isSymbolicLink != true else { return nil }
            return v.fileSize ?? 0
        }
        func walk(_ dir: URL, group: String, base: URL, prefix: String) {
            guard let e = FileManager.default.enumerator(at: dir, includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey],
                                                         options: [.skipsPackageDescendants]) else { return }
            var found: [UacArtifact] = []
            for case let u as URL in e {
                guard let size = regular(u), found.count < maxPerGroup else { continue }
                let rel = String(u.standardizedFileURL.path.dropFirst(base.standardizedFileURL.path.count + 1))
                found.append(UacArtifact(group: group, name: prefix + rel, url: u, size: size))
            }
            // Top-level files first, then subfolders; by name.
            out += found.sorted {
                let a = $0.name.filter { $0 == "/" }.count, b = $1.name.filter { $0 == "/" }.count
                return a != b ? a < b : $0.name.localizedStandardCompare($1.name) == .orderedAscending
            }
        }
        for (folder, title) in Self.artifactGroups {
            let dir = url.appendingPathComponent(folder)
            walk(dir, group: title, base: dir, prefix: "")
        }
        let title = String(localized: "Настройки и автозапуск (файлы из [root])")
        for path in Self.persistencePaths {
            let u = rootFolder.appendingPathComponent(path)
            if let size = regular(u) {
                out.append(UacArtifact(group: title, name: "/" + path, url: u, size: size))
            } else {
                walk(u, group: title, base: rootFolder, prefix: "/")
            }
        }
        // Users' own autostart and keys.
        for home in (try? FileManager.default.contentsOfDirectory(at: rootFolder.appendingPathComponent("home"), includingPropertiesForKeys: nil)) ?? [] {
            for rel in [".ssh/authorized_keys", ".bashrc", ".profile", ".bash_profile", ".config/autostart"] {
                let u = home.appendingPathComponent(rel)
                if let size = regular(u) {
                    out.append(UacArtifact(group: title, name: "/home/\(home.lastPathComponent)/\(rel)", url: u, size: size))
                } else {
                    walk(u, group: title, base: rootFolder, prefix: "/")
                }
            }
        }
        var seen = Set<String>()
        return out.filter { seen.insert($0.url.path).inserted }
    }

    /// Text of an artifact, at most `limit` bytes (and whether it was cut).
    public static func text(of a: UacArtifact, limit: Int = 4 << 20) -> (text: String, truncated: Bool)? {
        guard let h = try? FileHandle(forReadingFrom: a.url) else { return nil }
        defer { try? h.close() }
        let data = (try? h.read(upToCount: limit)) ?? Data()
        let (text, _) = data.withUnsafeBytes { LogLines.decode($0.bindMemory(to: UInt8.self)) }
        return (CaseStore.visibleControls(text), a.size > limit)
    }
}

extension CaseStore {
    /// The UAC collections a Linux case was built from (paths as they were at import).
    public var uacCollections: [UacInfo] {
        (try? JSONDecoder().decode([UacInfo].self, from: Data((meta["uac.collections"] ?? "[]").utf8))) ?? []
    }
}
