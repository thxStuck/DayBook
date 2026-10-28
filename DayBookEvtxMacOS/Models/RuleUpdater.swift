import CryptoKit
import DaybookSigma
import Foundation
import Observation

/// "Update Sigma rules": compares the installed rule pack with the latest SigmaHQ release and the
/// latest commit of the Hayabusa rules, downloads what is newer, checks the archives (SHA-256 that
/// GitHub publishes for release assets), builds a new pack and installs it in Application Support.
/// Nothing is downloaded without the analyst's click; the bundled pack stays as the fallback.
@MainActor @Observable
final class RuleUpdater {
    static let shared = RuleUpdater()

    struct Release: Sendable {
        var tag: String
        var published: String
        var url: URL
        var size: Int
        /// `sha256:…` as GitHub reports it for the asset.
        var digest: String?
    }

    struct Commit: Sendable {
        var sha: String
        var date: String
        var url: URL
    }

    struct Plan: Sendable {
        var sigma: Release
        var hayabusa: Commit
        var sigmaNewer: Bool
        var hayabusaNewer: Bool
        var anything: Bool { sigmaNewer || hayabusaNewer }
    }

    enum State: Equatable {
        case idle, checking, checked, downloading(String), building
        case installed(String)
        case failed(String)
    }

    private(set) var state: State = .idle
    private(set) var plan: Plan?
    private(set) var installed: RuleLibrary.PackInfo? = RuleLibrary.info()
    private(set) var lastCheck: Date?

    static let sigmaLatest = URL(string: "https://api.github.com/repos/SigmaHQ/sigma/releases/latest")!
    static let hayabusaHead = URL(string: "https://api.github.com/repos/Yamato-Security/hayabusa-rules/commits/main")!
    static let sigmaAsset = "sigma_all_rules.zip"

    var busy: Bool {
        switch state {
        case .checking, .downloading, .building: true
        default: false
        }
    }

    private static func request(_ url: URL) -> URLRequest {
        var r = URLRequest(url: url, timeoutInterval: 60)
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0"
        r.setValue("DayBookEvtxMacOS/\(version)", forHTTPHeaderField: "User-Agent")
        r.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        r.setValue("2022-11-28", forHTTPHeaderField: "X-GitHub-Api-Version")
        return r
    }

    private static func fetch(_ url: URL) async throws -> Data {
        let (data, response) = try await URLSession.shared.data(for: request(url))
        let code = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard code == 200 else {
            if code == 403 || code == 429 {
                throw UpdateError(String(localized: "GitHub временно ограничил число запросов без входа (60 в час). Попробуйте позже."))
            }
            throw UpdateError(String(localized: "GitHub ответил кодом \(code) на запрос \(url.absoluteString)"))
        }
        return data
    }

    struct UpdateError: LocalizedError {
        let message: String
        init(_ m: String) { message = m }
        var errorDescription: String? { message }
    }

    /// Latest versions on GitHub compared with the installed pack.
    func check() {
        guard !busy else { return }
        state = .checking
        installed = RuleLibrary.info()
        Task {
            do {
                async let sigmaData = Self.fetch(Self.sigmaLatest)
                async let hayabusaData = Self.fetch(Self.hayabusaHead)
                let s = try JSONSerialization.jsonObject(with: try await sigmaData) as? [String: Any] ?? [:]
                let h = try JSONSerialization.jsonObject(with: try await hayabusaData) as? [String: Any] ?? [:]
                guard let tag = s["tag_name"] as? String,
                      let asset = (s["assets"] as? [[String: Any]])?.first(where: { $0["name"] as? String == Self.sigmaAsset }),
                      let assetURL = (asset["browser_download_url"] as? String).flatMap(URL.init(string:)) else {
                    throw UpdateError(String(localized: "В последнем релизе SigmaHQ нет архива \(Self.sigmaAsset)"))
                }
                guard let sha = h["sha"] as? String,
                      let url = URL(string: "https://codeload.github.com/Yamato-Security/hayabusa-rules/zip/" + sha) else {
                    throw UpdateError(String(localized: "Не удалось узнать последнюю версию правил Hayabusa"))
                }
                let sigma = Release(tag: tag, published: s["published_at"] as? String ?? "", url: assetURL,
                                    size: asset["size"] as? Int ?? 0, digest: asset["digest"] as? String)
                let date = ((h["commit"] as? [String: Any])?["committer"] as? [String: Any])?["date"] as? String ?? ""
                let hayabusa = Commit(sha: sha, date: date, url: url)
                plan = Plan(sigma: sigma, hayabusa: hayabusa, sigmaNewer: Self.isNewer(sigma, than: installed?.source("SigmaHQ")),
                            hayabusaNewer: Self.isNewer(hayabusa, than: installed?.source("Hayabusa")))
                lastCheck = Date()
                state = .checked
            } catch {
                state = .failed(error.localizedDescription)
            }
        }
    }

    /// A release is newer unless the installed pack names the same tag (packs built before tags
    /// were recorded carry SigmaHQ's "Release Date: YYYY-MM-DD" instead).
    static func isNewer(_ r: Release, than s: RuleLibrary.PackInfo.Source?) -> Bool {
        guard let s else { return true }
        if !s.tag.isEmpty { return s.tag != r.tag }
        if let range = s.version.range(of: "Release Date: ") {
            return String(s.version[range.upperBound...].prefix(10)) != String(r.published.prefix(10))
        }
        return true
    }

    static func isNewer(_ c: Commit, than s: RuleLibrary.PackInfo.Source?) -> Bool {
        guard let s, !s.tag.isEmpty, s.tag != "main" else { return true }
        return s.tag != c.sha
    }

    /// Downloads both archives, builds the pack, checks it and installs it.
    func install() {
        guard let plan, !busy else { return }
        Task {
            do {
                state = .downloading("SigmaHQ \(plan.sigma.tag)")
                let sigmaZip = try await Self.fetch(plan.sigma.url)
                let sha = SHA256.hash(data: sigmaZip).map { String(format: "%02x", $0) }.joined()
                if let digest = plan.sigma.digest, digest.hasPrefix("sha256:"), digest.dropFirst(7).lowercased() != sha {
                    throw UpdateError(String(localized: "SHA-256 архива SigmaHQ не совпал с опубликованным на GitHub — архив не установлен"))
                }
                if plan.sigma.size > 0, sigmaZip.count != plan.sigma.size {
                    throw UpdateError(String(localized: "Размер архива SigmaHQ не совпал с опубликованным на GitHub — архив не установлен"))
                }
                state = .downloading("Hayabusa \(plan.hayabusa.sha.prefix(7))")
                let hayabusaZip = try await Self.fetch(plan.hayabusa.url)
                state = .building
                let sigma = SigmaPackBuilder.Archive(data: sigmaZip, version: plan.sigma.tag, published: plan.sigma.published,
                                                     url: plan.sigma.url.absoluteString)
                let hayabusa = SigmaPackBuilder.Archive(data: hayabusaZip, version: plan.hayabusa.sha, published: plan.hayabusa.date,
                                                        url: plan.hayabusa.url.absoluteString)
                let target = RuleLibrary.installedPackURL
                let message: String = try await Task.detached(priority: .userInitiated) {
                    let (json, s) = try SigmaPackBuilder.build(sigma: sigma, hayabusa: hayabusa)
                    // The new pack must load and hold a plausible number of rules before it replaces anything.
                    let set = try SigmaRuleSet.pack(json)
                    guard s.sigmaWindows >= 500, s.sigmaLinux >= 20, set.rules.count + set.failures.count == s.sigmaWindows + s.sigmaLinux + s.hayabusa else {
                        throw UpdateError(String(localized: "В скачанных архивах слишком мало правил — пакет не установлен"))
                    }
                    try FileManager.default.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: true)
                    try json.write(to: target, options: .atomic)
                    return String(localized: "Установлено: SigmaHQ \(s.sigmaVersion) (Windows \(s.sigmaWindows), Linux \(s.sigmaLinux)), Hayabusa \(String(s.hayabusaVersion.prefix(7))) (\(s.hayabusa)); не загрузилось \(set.failures.count)")
                }.value
                installed = RuleLibrary.info()
                self.plan = Plan(sigma: plan.sigma, hayabusa: plan.hayabusa, sigmaNewer: false, hayabusaNewer: false)
                state = .installed(message)
            } catch {
                state = .failed(error.localizedDescription)
            }
        }
    }

    /// Removes the downloaded pack: the rules shipped with the app are used again.
    func revertToBundled() {
        guard !busy else { return }
        do {
            try RuleLibrary.removeInstalledPack()
            installed = RuleLibrary.info()
            plan = nil
            state = .idle
        } catch {
            state = .failed(error.localizedDescription)
        }
    }
}
