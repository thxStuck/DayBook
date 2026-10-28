import AppKit
import DaybookStore
import EvtxCore
import SwiftUI

/// `-snapshot <dir>` (together with `-openCase <case>`): plays a fixed UI scenario, renders
/// the app's own window into PNG files after each step, writes a text report and quits.
/// Used for automated UI checks without screen recording or controlling the desktop.
@MainActor
enum SnapshotRunner {
    private static var started = false
    /// Keeps App Nap off: runs are launched in the background, where timers would be throttled.
    private static var activity: ActivityToken?
    /// The app was launched for automated snapshots (vibrant materials are not captured by the
    /// window snapshot, so some views use a solid background then).
    static let active = ProcessInfo.processInfo.arguments.contains("-snapshot")

    static func runIfRequested(app: AppModel) {
        let args = ProcessInfo.processInfo.arguments
        guard !started, let i = args.firstIndex(of: "-snapshot"), i + 1 < args.count else { return }
        started = true
        activity = ActivityToken("UI snapshots")
        let dir = URL(fileURLWithPath: args[i + 1])
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        Task { @MainActor in
            var report = ""
            @MainActor func log(_ s: String) { report += s + "\n" }
            func pause(_ s: Double) async { try? await Task.sleep(nanoseconds: UInt64(s * 1e9)) }
            /// Waits until the running query has finished (debug builds are slow).
            @MainActor func settle() async {
                try? await Task.sleep(nanoseconds: 200_000_000)
                for _ in 0..<200 where app.caseModel?.querying == true { try? await Task.sleep(nanoseconds: 100_000_000) }
            }
            await pause(1.0)
            if let w = NSApp.windows.first(where: { $0.isVisible }) {
                // Resizing must not overwrite the window frame and column widths that the user's
                // own launches restore (AppKit saves both into the standard settings by itself).
                w.setFrameAutosaveName("")
                func stopAutosave(_ v: NSView) {
                    if let split = v as? NSSplitView { split.autosaveName = nil }
                    v.subviews.forEach(stopAutosave)
                }
                if let root = w.contentView { stopAutosave(root) }
                w.setFrame(NSRect(x: 40, y: 40, width: 1700, height: 1000), display: true)
            }
            await pause(1.5)
            // `-importLogs … -snapshot …`: the scripted import runs first (the app's own import path).
            for _ in 0..<2400 where app.importState != nil && app.importState?.error == nil { await pause(0.25) }
            if let error = app.importState?.error { log("import failed: \(error)") }
            await pause(1.0)
            guard let model = app.caseModel else {
                log("no case opened")
                try? report.write(to: dir.appendingPathComponent("report.txt"), atomically: true, encoding: .utf8)
                NSApp.terminate(nil)
                return
            }
            // `-snapshotStress <rounds>`: switches sections, the details panel and the sidebar in
            // quick succession (the way a user clicks around); progress.txt names the last step,
            // so a crash points at the transition that caused it.
            if let s = ProcessInfo.processInfo.arguments.firstIndex(of: "-snapshotStress") {
                let args = ProcessInfo.processInfo.arguments
                let rounds = s + 1 < args.count ? Int(args[s + 1]) ?? 5 : 5
                model.mode = .events
                model.showDetails = true
                await settle()
                if let id = model.rows.eventId(at: 0) { model.select(id) }
                await pause(0.5)
                let order: [MainMode] = [.events, .users, .timeline, .hosts, .sessions, .detections, .processes, .logs, .ips, .events]
                for round in 0..<rounds {
                    for (i, mode) in order.enumerated() {
                        model.mode = mode
                        if (round + i) % 3 == 0 { model.showDetails.toggle() }
                        if (round + i) % 4 == 0 {
                            NSApp.sendAction(#selector(NSSplitViewController.toggleSidebar(_:)), to: nil, from: nil)
                        }
                        log("round \(round) step \(i): \(mode.rawValue) details=\(model.showDetails)")
                        try? report.write(to: dir.appendingPathComponent("progress.txt"), atomically: true, encoding: .utf8)
                        await pause(round % 2 == 0 ? 0.15 : 0.6)
                    }
                }
                log("stress OK: \(rounds) rounds")
                try? report.write(to: dir.appendingPathComponent("report.txt"), atomically: true, encoding: .utf8)
                NSApp.terminate(nil)
                return
            }
            // `-snapshotLayout`: every section at several window sizes; reports AppKit views that
            // extend beyond the window (content pushed off-screen by too-large minimum widths).
            if ProcessInfo.processInfo.arguments.contains("-snapshotLayout") {
                for size in [CGSize(width: 1100, height: 640), CGSize(width: 1280, height: 800), CGSize(width: 1700, height: 1000)] {
                    NSApp.windows.first(where: { $0.isVisible })?.setFrame(NSRect(x: 40, y: 40, width: size.width, height: size.height), display: true)
                    for mode in model.modes {
                        model.mode = mode
                        if mode == .events || mode == .timeline { model.showDetails = true }
                        await pause(mode == .logs ? 2.0 : 1.2)
                        if mode == .events, let id = model.rows.eventId(at: 0) { model.select(id) }
                        if mode == .logs, let id = model.logViewer.rows.eventId(at: 0) { model.logViewer.select(id) }
                        if mode == .events || mode == .logs { await pause(0.8) }
                        let name = "L\(Int(size.width))-\(mode.rawValue)"
                        log("== \(name): \(overflow())")
                        snap(dir, name)
                        if size.width == 1280, mode == .logs {
                            let logs = LogTreeSections.logs(model.store.sources)
                            let win = logs.filter { LogTreeSections.windowsLogs.contains($0.channel.lowercased()) }
                            log("   windows logs: " + win.map { "\($0.channel)=\($0.events)" }.joined(separator: ", "))
                            log("   other logs: \(logs.count - win.count), non-empty: \(logs.filter { $0.events > 0 }.count - win.filter { $0.events > 0 }.count); sample: "
                                + logs.filter { $0.events > 0 && !win.map(\.id).contains($0.id) }.prefix(6).map { "\(LogTreeSections.short($0.channel))=\($0.events)" }.joined(separator: ", "))
                            log("   viewer: log=\(model.logViewer.viewerLog ?? "-") rows=\(model.logViewer.result.count) ascending=\(model.logViewer.ascending) selected=\(model.logViewer.selectedId.map(String.init) ?? "-")")
                        }

                        try? report.write(to: dir.appendingPathComponent("progress.txt"), atomically: true, encoding: .utf8)
                    }
                    model.mode = .events
                    model.runQuery(text: "EventID = 4625 | group by IpAddress, TargetUserName")
                    await settle()
                    await pause(1.0)
                    let name = "L\(Int(size.width))-events-grouped"
                    log("== \(name): \(overflow())")
                    snap(dir, name)
                    model.runQuery(text: "")
                    await settle()
                }
                try? report.write(to: dir.appendingPathComponent("report.txt"), atomically: true, encoding: .utf8)
                NSApp.terminate(nil)
                return
            }
            @MainActor func state(_ step: String) {
                log("== \(step): result=\(model.result.count) query=\(String(format: "%.2f", model.lastQueryMs))ms filters=\(model.filters.map { "\($0.key)\($0.negated ? "!=" : "=")\($0.value)" })")
                for i in 0..<min(3, model.rows.count) {
                    if let r = model.rows.row(at: i) {
                        log("   [\(i)] \(model.formatter.string(r.row.ts)) \(r.row.computer) \(r.row.channel) \(r.row.eventId) | \(r.summary.prefix(120))")
                    }
                }
                snap(dir, step)
            }
            if model.isLinux {
                await linuxScenario(model, dir: dir, log: log, settle: settle, pause: pause)
                try? report.write(to: dir.appendingPathComponent("report.txt"), atomically: true, encoding: .utf8)
                NSApp.terminate(nil)
                return
            }
            state("1-open")
            log("   histogram bins=\(model.histogram?.bins.count ?? 0) outliers=\(model.histogram?.outliers ?? 0)")

            model.runQuery(text: "EventID = 4625 | group by IpAddress, TargetUserName")
            await pause(1.5)
            log("   groups=\(model.groups.count) top=\(model.groups.prefix(3).map { "\($0.values.joined(separator: "/")):\($0.count)" })")
            state("2-groups")
            if let g = model.groups.first { model.selectGroup(g) }
            await pause(1.0)
            state("3-group-selected")

            model.runQuery(text: "\"mimikatz\"")
            await pause(1.2)
            model.select(model.rows.eventId(at: 0))
            await pause(0.5)
            state("4-search")
            for _ in 0..<40 where model.detail?.row.id != model.selectedId { await pause(0.1) }
            if let d = model.detail { snapView(dir, "4-search-inspector", FieldsContent(model: model, detail: d), size: CGSize(width: 520, height: 900)) }
            for _ in 0..<30 where model.detail?.sourceState == .pending { await pause(0.1) }
            log("   detail fields=\(model.detail?.fields.count ?? -1) source=\(model.detail.map { "\($0.sourceState)" } ?? "-") xml=\(model.detail?.xml != nil) raw=\(model.detail?.raw?.count ?? 0)")

            if let preset = Presets.all.flatMap(\.items).first(where: { $0.query.contains("FromBase64String") }) {
                model.runQuery(text: preset.query)
                await pause(1.5)
                log("   preset '\(preset.title)': \(model.result.count) events, error=\(model.queryError ?? "-")")
            }
            model.runQuery(text: "")
            model.setTimeWindow(from: model.formatter.parse("2026-09-30 10:00"), to: model.formatter.parse("2026-09-30 12:00"))
            await pause(1.5)
            state("5-timewindow")

            // Phase 4: entity registry, descriptions and timeline.
            model.setTimeWindow(from: nil, to: nil)
            model.runQuery(text: "EventID in (4624, 4625, 4688, 4769, 4720, 7045, 4104)")
            await pause(1.5)
            for i in 0..<min(8, model.rows.count) {
                if let r = model.rows.row(at: i * max(1, model.rows.count / 8)) { log("   desc: \(r.row.eventId) \(r.text.prefix(150))") }
            }
            model.mode = .users
            await pause(1.5)
            // The busiest non-builtin account, whatever the case contains.
            let person = model.entities[.user]?.filter { !$0.builtin }.max { $0.events < $1.events }
            if let person { model.selectEntity(person) }
            await pause(1.0)
            log("   users=\(model.entities[.user]?.count ?? -1) links(\(person?.display ?? "-"))=\(model.entityLinks.count)")
            state("6-users")
            model.mode = .hosts
            await pause(1.0)
            state("7-hosts")
            // A jump to an entity's events is a new search: a query left from earlier work must
            // not narrow it (a rule query once hid every event of an IP).
            model.runQuery(text: "EventID = 4625")
            await settle()
            if let ip = model.entities[.ip]?.max(by: { $0.events < $1.events }) {
                model.showEvents(of: [ip])
                await settle()
                log("   pivot to IP \(ip.display): result=\(model.result.count) entity events=\(ip.events) query='\(model.queryText)' filters=\(model.filters.count)")
            }
            model.runQuery(text: "")
            model.clearFilters()
            // The least active host: a timeline scoped to one machine.
            if let host = model.entities[.host]?.min(by: { $0.events < $1.events }) {
                model.showEvents(of: [host], timeline: true)
            }
            await pause(1.5)
            state("8-timeline-host")
            model.clearFilters()
            await pause(1.0)
            state("9-timeline-all")
            if let id = model.rows.eventId(at: 0) {
                model.setTag(id, color: "red")
                model.setNote(id, "проверка закладки")
                model.runQuery(text: "tag = red")
                await pause(1.0)
                log("   bookmarks: tag=red -> \(model.result.count) event(s), note='\(model.tags[id]?.note ?? "")'")
                model.setTag(id, color: nil)
                model.runQuery(text: "")
            }

            // Phase 5: sessions and process trees.
            model.mode = .sessions
            for _ in 0..<40 where model.sessions == nil { await pause(0.25) }
            if let a = model.sessions {
                log("   sessions=\(a.sessions.count) open=\(a.sessions.filter { $0.end == nil }.count) unmatchedEnds=\(a.unmatchedEnds) rdp=\(model.rdpSessions?.count ?? -1)")
                state("10-sessions")
                if let s = a.sessions.first(where: { $0.end != nil && $0.logonType == 3 }) {
                    let q = model.sessionQuery(s)
                    model.showQuery(q)
                    await settle()
                    log("   session query: \(q.prefix(160)) -> \(model.result.count) events, error=\(model.queryError ?? "-")")
                }
            }
            model.processSource = .sysmon
            model.mode = .processes
            for _ in 0..<40 where model.forests[.sysmon] == nil { await pause(0.25) }
            if let f = model.forests[.sysmon] {
                log("   sysmon tree: processes=\(f.processCount) roots=\(f.roots.count) synthetic=\(f.syntheticCount) repeated=\(f.repeatedGuidEvents)")
                state("11-processes")
                if let n = f.roots.first?.children?.first, let q = model.processQuery(n) {
                    model.showQuery(q)
                    await settle()
                    log("   process query: \(q.prefix(160)) -> \(model.result.count) events, error=\(model.queryError ?? "-")")
                }
            }
            model.processSource = .security
            model.mode = .processes
            for _ in 0..<40 where model.forests[.security] == nil { await pause(0.25) }
            if let f = model.forests[.security] {
                log("   4688 tree: processes=\(f.processCount) roots=\(f.roots.count) synthetic=\(f.syntheticCount) byPID=\(f.pidLinkedCount)")
                state("12-processes-4688")
                if let n = f.roots.first(where: { !($0.children ?? []).isEmpty })?.children?.first, let q = model.processQuery(n) {
                    model.showQuery(q)
                    await settle()
                    log("   4688 process query: \(q.prefix(180)) -> \(model.result.count) events, error=\(model.queryError ?? "-")")
                }
            }
            // Phase 6: detections (optionally re-run from the app bundle's rule pack).
            if ProcessInfo.processInfo.arguments.contains("-snapshotRunDetections") {
                let t0 = Date()
                model.runDetections()
                for _ in 0..<1200 where model.detectionProgress != nil || model.detections == nil { await pause(0.25) }
                log("   detections run in app: \(String(format: "%.1f", Date().timeIntervalSince(t0)))s error=\(model.detectionError ?? "-") meta=\(model.detectionMeta.filter { ["rules_total", "evaluated", "unsupported", "failed", "errors", "with_hits", "hit_events"].contains($0.key) }.sorted { $0.key < $1.key })")
            }
            model.mode = .detections
            for _ in 0..<40 where model.detections == nil { await pause(0.25) }
            if let list = model.detections, let top = list.filter({ $0.hits > 0 }).max(by: { ($0.levelRank, $0.hits) < ($1.levelRank, $1.hits) }) {
                log("   detections: rules=\(list.count) withHits=\(list.filter { $0.hits > 0 }.count) top='\(top.title)' hits=\(top.hits)")
                model.selectedDetection = top.id
                await pause(1.2)   // the inspector closes with an animation
                state("13-detections")
                model.showDetection(top)
                await settle()
                log("   rule events: \(CaseModel.detectionQuery(top)) -> \(model.result.count) (stored hits \(top.hits)), error=\(model.queryError ?? "-")")
                if let id = model.rows.eventId(at: 0) {
                    model.select(id)
                    log("   event \(id): matched rules=\(model.eventDetections.map(\.title))")
                    for _ in 0..<40 where model.detail?.row.id != id { await pause(0.1) }
                    if let d = model.detail {
                        snapView(dir, "14-detection-event-inspector", FieldsContent(model: model, detail: d), size: CGSize(width: 520, height: 900))
                    }
                }
                state("14-detection-events")
                if let unsupported = list.first(where: { $0.unsupported != nil }) {
                    model.mode = .detections
                    model.selectedDetection = unsupported.id
                    await pause(0.5)
                    state("15-detection-unsupported")
                }
            }
            model.mode = .events

            // Export through the same code path as the toolbar, without the save panel.
            for format in ProcessInfo.processInfo.arguments.contains("-snapshotExport") ? [ExportFormat.csvExcel, .jsonl] : [] {
                let url = dir.appendingPathComponent("export.\(format == .jsonl ? "jsonl" : "csv")")
                let zone = model.timeZone
                let exporter = CaseExporter(store: model.store, format: format, fields: ["TargetUserName"],
                                            zoneLabel: zone.headerLabel(at: nil)) { TimeFormatter(zone: zone).string($0) }
                let n = (try? exporter.export(model.result, to: url)) ?? -1
                log("   export \(format.rawValue): \(n) rows")
            }
            try? report.write(to: dir.appendingPathComponent("report.txt"), atomically: true, encoding: .utf8)
            NSApp.terminate(nil)
        }
    }

    /// AppKit views (tables, lists, fields) whose frame leaves the window horizontally.
    /// Linux (UAC) case: sections, every Linux preset, a syslog line and a wtmp record in the
    /// details, the log viewer, entities and the case information.
    static func linuxScenario(_ model: CaseModel, dir: URL, log: (String) -> Void, settle: () async -> Void,
                              pause: (Double) async -> Void) async {
        func rows(_ m: CaseModel, _ n: Int = 3) {
            for i in 0..<min(n, m.rows.count) {
                if let r = m.rows.row(at: i) {
                    log("   [\(i)] \(m.formatter.string(r.row.ts)) \(r.row.computer) \(r.row.channel) \(r.row.provider) | \(r.text.prefix(120))")
                }
            }
        }
        func detail(_ m: CaseModel, _ name: String) async {
            m.select(m.rows.eventId(at: 0))
            for _ in 0..<40 where m.detail?.row.id != m.selectedId { await pause(0.1) }
            for _ in 0..<40 where m.detail?.sourceState == .pending { await pause(0.1) }
            let d = m.detail
            log("   \(name): fields=\(d?.fields.count ?? -1) source=\(d.map { "\($0.sourceState)" } ?? "-") raw=\(d?.raw?.count ?? 0) text=\(d?.text?.prefix(160).replacingOccurrences(of: "\n", with: " | ") ?? "-")")
            if let d { snapView(dir, name + "-fields", FieldsContent(model: m, detail: d), size: CGSize(width: 520, height: 900)) }
        }
        log("== L1-open: events=\(model.store.eventCount) modes=\(model.modes.map(\.rawValue)) facets=\(model.facets.map { "\($0.id)=\($0.total)" })")
        rows(model)
        snap(dir, "L1-open")
        for preset in Presets.linux.flatMap(\.items) {
            model.runQuery(text: preset.query)
            await settle()
            log("   preset '\(preset.title)': \(model.result.count) events, groups=\(model.groups.count), error=\(model.queryError ?? "-")")
        }
        model.runQuery(text: "Action in (auth_failure, invalid_user, user_not_allowed) | group by IpAddress | sort count desc")
        await settle()
        log("== L2-ssh-groups: groups=\(model.groups.count) top=\(model.groups.prefix(3).map { "\($0.values.joined(separator: "/")):\($0.count)" })")
        snap(dir, "L2-ssh-groups")
        model.runQuery(text: "Action = sudo")
        await settle()
        model.showDetails = true
        await detail(model, "L3-sudo")
        rows(model)
        snap(dir, "L3-sudo")
        model.runQuery(text: "channel = wtmp and Action = login")
        await settle()
        await detail(model, "L4-wtmp")
        snap(dir, "L4-wtmp")
        model.runQuery(text: "")
        await settle()
        model.mode = .logs
        await pause(2.0)
        let v = model.logViewer
        if let id = v.rows.eventId(at: 0) { v.select(id) }
        await pause(1.0)
        log("== L5-logs: viewer=\(v.viewerLog ?? "-") rows=\(v.result.count) columns=\(v.columns.map(\.id))")
        rows(v)
        snap(dir, "L5-logs")
        if let src = model.store.sources.first(where: { $0.format == "btmp" }) {
            v.showLog(src.name)
            await pause(1.5)
            log("   file viewer \(src.name): rows=\(v.result.count)")
            snap(dir, "L5b-logs-file")
        }
        for (mode, name) in [(MainMode.users, "L6-users"), (.ips, "L7-ips"), (.hosts, "L8-hosts"), (.system, "L8b-system"), (.timeline, "L9-timeline")] {
            model.mode = mode
            await pause(1.5)
            if let k = mode.kind {
                let top = model.entities[k]?.sorted { $0.events > $1.events }.prefix(5).map { "\($0.display):\($0.events)" } ?? []
                log("== \(name): \(model.entities[k]?.count ?? -1) top=\(top)")
            } else {
                log("== \(name): result=\(model.result.count)")
            }
            snap(dir, name)
        }
        snapView(dir, "L10-caseinfo", CaseInfoView(model: model, dismiss: {}), size: CGSize(width: 1700, height: 1000))
        log("== done")
    }

    static func overflow() -> String {
        guard let window = NSApp.windows.first(where: { $0.isVisible }), let root = window.contentView else { return "no window" }
        let width = root.bounds.width
        var bad: [String] = []
        func walk(_ v: NSView) {
            if !v.isHidden, v.alphaValue > 0, v.bounds.width > 4 {
                let f = v.convert(v.bounds, to: root)
                let isVisibleKind = v is NSScrollView || v is NSTextField || v is NSButton || v is NSSegmentedControl
                // Entirely right of the window = a collapsed inspector (hidden), not overflow.
                if isVisibleKind, f.minX < width, f.minX < -2 || f.maxX > width + 2 {
                    bad.append("\(type(of: v)) x=\(Int(f.minX))…\(Int(f.maxX))")
                }
            }
            // Content inside a scroll view (table cells scrolled sideways) is clipped, not overflow.
            if v is NSScrollView { return }
            v.subviews.forEach(walk)
        }
        walk(root)
        return bad.isEmpty ? "ok (width \(Int(width)))" : "OVERFLOW (width \(Int(width))): " + bad.prefix(6).joined(separator: "; ")
    }

    /// Renders the window's layer tree (SwiftUI and AppKit content) into a PNG.
    static func snap(_ dir: URL, _ name: String) {
        guard let window = NSApp.windows.first(where: { $0.isVisible && $0.contentView != nil }),
              let root = window.contentView?.superview ?? window.contentView else { return }
        root.layoutSubtreeIfNeeded()
        root.displayIfNeeded()
        let scale = window.backingScaleFactor
        let size = root.bounds.size
        guard let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(size.width * scale),
                                         pixelsHigh: Int(size.height * scale), bitsPerSample: 8,
                                         samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                                         colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0),
              let ctx = NSGraphicsContext(bitmapImageRep: rep) else { return }
        rep.size = size
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = ctx
        NSColor.windowBackgroundColor.setFill()
        NSRect(origin: .zero, size: size).fill()
        if let layer = root.layer {
            ctx.cgContext.saveGState()
            ctx.cgContext.scaleBy(x: scale, y: scale)
            layer.render(in: ctx.cgContext)
            ctx.cgContext.restoreGState()
        } else {
            root.cacheDisplay(in: root.bounds, to: rep)
        }
        NSGraphicsContext.restoreGraphicsState()
        try? rep.representation(using: .png, properties: [:])?.write(to: dir.appendingPathComponent(name + ".png"))
    }

    /// Pure SwiftUI views (the details inspector) rendered on their own: window layer
    /// rendering cannot draw the system glass materials around them.
    static func snapView<V: View>(_ dir: URL, _ name: String, _ view: V, size: CGSize) {
        let renderer = ImageRenderer(content: view.frame(width: size.width, height: size.height, alignment: .top)
            .background(Color(nsColor: .windowBackgroundColor)))
        renderer.scale = 2
        guard let image = renderer.nsImage, let tiff = image.tiffRepresentation,
              let rep = NSBitmapImageRep(data: tiff) else { return }
        try? rep.representation(using: .png, properties: [:])?.write(to: dir.appendingPathComponent(name + ".png"))
    }
}
