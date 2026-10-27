import AppKit
import DaybookStore
import EvtxCore
import SwiftUI

/// Main event grid: AppKit `NSTableView` (view-based, fixed row height, lazy paged data),
/// because SwiftUI `Table` does not stay smooth with millions of rows.
struct EventTable: NSViewRepresentable {
    let model: CaseModel
    let generation: Int
    let displayGeneration: Int
    let columns: [ColumnSpec]
    var timeline = false

    func makeCoordinator() -> EventTableCoordinator { EventTableCoordinator(model: model) }


    func makeNSView(context: Context) -> NSScrollView {
        let table = NSTableView()
        table.usesAlternatingRowBackgroundColors = true
        table.style = .fullWidth
        table.rowHeight = 20
        table.usesAutomaticRowHeights = false
        table.intercellSpacing = NSSize(width: 8, height: 2)
        table.allowsColumnReordering = true
        table.allowsColumnResizing = true
        table.allowsMultipleSelection = false
        table.columnAutoresizingStyle = .noColumnAutoresizing
        let c = context.coordinator
        table.dataSource = c
        table.delegate = c
        let menu = NSMenu()
        menu.delegate = c
        table.menu = menu
        c.table = table
        c.syncColumns(columns)

        let scroll = NSScrollView()
        scroll.documentView = table
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = true
        scroll.autohidesScrollers = true
        return scroll
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        let c = context.coordinator
        c.model = model
        if c.timeline != timeline {
            c.timeline = timeline
            c.table?.reloadData()
        }
        if c.columnIds != columns.map(\.id) { c.syncColumns(columns) }
        if c.generation != generation {
            c.generation = generation
            c.displayGeneration = displayGeneration
            c.updateTimeHeader()
            c.table?.reloadData()
            c.restoreSelection()
        } else if c.displayGeneration != displayGeneration {
            c.displayGeneration = displayGeneration
            c.updateTimeHeader()
            c.reloadVisible()
        }
        if let req = model.scrollRequest, req.token != c.scrollToken {
            c.scrollToken = req.token
            c.restoreSelection()
        }
    }
}

/// Target object for closure-based menu items (kept alive by `representedObject`,
/// because `NSMenuItem.target` is weak).
final class MenuAction: NSObject {
    private let handler: () -> Void
    init(_ handler: @escaping () -> Void) { self.handler = handler }
    @objc func fire() { handler() }
}

func actionItem(_ title: String, _ handler: @escaping () -> Void) -> NSMenuItem {
    let target = MenuAction(handler)
    let item = NSMenuItem(title: title, action: #selector(MenuAction.fire), keyEquivalent: "")
    item.target = target
    item.representedObject = target
    return item
}

final class EventTableCoordinator: NSObject, NSTableViewDataSource, NSTableViewDelegate, NSMenuDelegate {
    var model: CaseModel
    weak var table: NSTableView?
    var generation = -1
    var displayGeneration = -1
    var timeline = false
    var scrollToken = 0
    private(set) var columnIds: [String] = []
    private var specs: [String: ColumnSpec] = [:]
    private var applyingSelection = false

    private let regularFont = NSFont.systemFont(ofSize: 12)
    private let monoFont = NSFont.monospacedDigitSystemFont(ofSize: 12, weight: .regular)
    private let cellId = NSUserInterfaceItemIdentifier("cell")

    init(model: CaseModel) { self.model = model }

    // MARK: Columns

    /// Linux lines have a program where Windows events have a provider ("source").
    private func title(_ spec: ColumnSpec) -> String {
        model.isLinux && spec.kind == .provider ? String(localized: "Программа") : spec.title
    }

    func syncColumns(_ columns: [ColumnSpec]) {
        guard let table else { return }
        let wanted = Set(columns.map(\.id))
        for col in table.tableColumns where !wanted.contains(col.identifier.rawValue) { table.removeTableColumn(col) }
        for (i, spec) in columns.enumerated() {
            specs[spec.id] = spec
            if let existing = table.tableColumns.first(where: { $0.identifier.rawValue == spec.id }) {
                existing.title = title(spec)
                let from = table.column(withIdentifier: existing.identifier)
                if from != i, i < table.numberOfColumns { table.moveColumn(from, toColumn: i) }
            } else {
                let col = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(spec.id))
                col.title = title(spec)
                col.width = spec.width
                col.minWidth = 40
                col.resizingMask = .userResizingMask
                table.addTableColumn(col)
                let at = table.numberOfColumns - 1
                if at != i { table.moveColumn(at, toColumn: i) }
            }
        }
        columnIds = columns.map(\.id)
        updateTimeHeader()
    }

    func updateTimeHeader() {
        guard let col = table?.tableColumns.first(where: { $0.identifier.rawValue == "time" }) else { return }
        let first = model.rows.eventId(at: 0).map { model.store.timestamp($0) }
        let arrow = model.ascending ? "↑" : "↓"
        col.title = String(localized: "Время") + " (\(model.timeZone.headerLabel(at: first))) \(arrow)"
    }

    func reloadVisible() {
        guard let table else { return }
        let rows = table.rows(in: table.visibleRect)
        table.reloadData(forRowIndexes: IndexSet(integersIn: rows.location..<(rows.location + rows.length)),
                         columnIndexes: IndexSet(integersIn: 0..<table.numberOfColumns))
    }

    func restoreSelection() {
        guard let table else { return }
        applyingSelection = true
        defer { applyingSelection = false }
        if let id = model.selectedId, let index = model.rows.index(of: id) {
            table.selectRowIndexes(IndexSet(integer: index), byExtendingSelection: false)
            table.scrollRowToVisible(index)
        } else {
            table.deselectAll(nil)
            table.scrollRowToVisible(0)
        }
    }

    // MARK: Data

    func numberOfRows(in tableView: NSTableView) -> Int { model.rows.count }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard let col = tableColumn, let spec = specs[col.identifier.rawValue] else { return nil }
        let cell = (tableView.makeView(withIdentifier: cellId, owner: nil) as? NSTableCellView) ?? makeCell()
        guard let r = model.rows.row(at: row) else {
            cell.textField?.stringValue = ""
            return cell
        }
        let tf = cell.textField!
        if timeline, spec.kind == .channel {
            let dot = NSAttributedString(string: "● ", attributes: [.foregroundColor: Self.color(for: r.row.channel), .font: regularFont])
            let rest = NSAttributedString(string: r.row.channel, attributes: [.font: regularFont, .foregroundColor: NSColor.labelColor])
            let a = NSMutableAttributedString(attributedString: dot)
            a.append(rest)
            tf.attributedStringValue = a
            return cell
        }
        if timeline, spec.kind == .summary, let gap = gapBefore(row) {
            let a = NSMutableAttributedString(string: "⏸ \(gap)  ", attributes: [.foregroundColor: NSColor.systemOrange, .font: regularFont])
            a.append(NSAttributedString(string: Self.singleLine(r.text), attributes: [.font: regularFont, .foregroundColor: NSColor.labelColor]))
            tf.attributedStringValue = a
            return cell
        }
        tf.stringValue = Self.singleLine(text(r, spec))
        tf.font = spec.kind == .time ? monoFont : regularFont
        if spec.kind == .time {
            let f = r.row.flags
            if f.contains(.parseError) { tf.textColor = .systemRed }
            else if f.contains(.carved) || f.contains(.staleChunk) || f.contains(.afterGap) { tf.textColor = .systemOrange }
            else { tf.textColor = .labelColor }
        } else {
            tf.textColor = .labelColor
        }
        return cell
    }

    /// Table cells are one line: Windows values use CR LF, which a text field would draw as a
    /// line break over the next rows. Line breaks become a visible ⏎, tabs a space; the full
    /// value stays in the details panel.
    static func singleLine(_ s: String) -> String {
        guard s.contains(where: { $0 == "\r" || $0 == "\n" || $0 == "\t" || $0 == "\r\n" }) else { return s }
        var out = ""
        out.reserveCapacity(s.count)
        var lastWasBreak = false
        for ch in s {
            if ch == "\r\n" || ch == "\r" || ch == "\n" {
                if !lastWasBreak { out += " ⏎ " }
                lastWasBreak = true
            } else if ch == "\t" {
                if !lastWasBreak && out.last != " " { out += " " }
            } else {
                out.append(ch)
                lastWasBreak = false
            }
        }
        return out
    }

    private func makeCell() -> NSTableCellView {
        let cell = NSTableCellView()
        cell.identifier = cellId
        let tf = NSTextField(labelWithString: "")
        tf.lineBreakMode = .byTruncatingTail
        tf.cell?.truncatesLastVisibleLine = true
        tf.cell?.wraps = false
        tf.usesSingleLineMode = true
        tf.maximumNumberOfLines = 1
        tf.translatesAutoresizingMaskIntoConstraints = false
        cell.addSubview(tf)
        cell.textField = tf
        NSLayoutConstraint.activate([
            tf.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 2),
            tf.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -2),
            tf.centerYAnchor.constraint(equalTo: cell.centerYAnchor),
        ])
        return cell
    }

    func text(_ r: DisplayRow, _ spec: ColumnSpec) -> String {
        let e = r.row
        switch spec.kind {
        case .time: return model.formatter.string(e.ts)
        case .computer: return e.computer
        case .channel: return e.channel
        case .eventId: return String(e.eventId)
        case .level: return EventText.level(e.level, keywords: e.keywords)
        case .provider: return e.provider
        case .user: return e.user ?? ""
        case .source: return e.source < model.store.sources.count ? model.store.sources[e.source].name : ""
        case .recordId: return String(e.recordId)
        case .summary: return r.text
        case .actor: return r.actor ?? ""
        case let .field(name):
            guard let k = model.store.keyId(name) else { return "" }
            let v = r.values[k] ?? ""
            return v.count > 300 ? String(v.prefix(300)) + "…" : v.replacingOccurrences(of: "\n", with: " ⏎ ")
        }
    }

    /// Value used for `=` / `!=` filters (raw, not the display label).
    func filterValue(_ r: DisplayRow, _ spec: ColumnSpec) -> String? {
        let e = r.row
        switch spec.kind {
        case .computer: return e.computer
        case .channel: return e.channel
        case .eventId: return String(e.eventId)
        case .level: return e.level.map(String.init)
        case .provider: return e.provider
        case .user: return e.user
        case .source: return e.source < model.store.sources.count ? model.store.sources[e.source].name : nil
        case let .field(name): return model.store.keyId(name).flatMap { r.values[$0] }
        case .actor: return nil
        case .time, .recordId, .summary: return nil
        }
    }

    // MARK: Timeline decorations

    private static let palette: [NSColor] = [.systemBlue, .systemGreen, .systemOrange, .systemPurple, .systemPink,
                                             .systemTeal, .systemRed, .systemIndigo, .systemBrown, .systemYellow, .systemMint, .systemCyan]

    static func color(for channel: String) -> NSColor {
        var h: UInt64 = 1469598103934665603
        for b in channel.utf8 { h = (h ^ UInt64(b)) &* 1099511628211 }
        return palette[Int(h % UInt64(palette.count))]
    }

    private func timestamps(_ row: Int) -> (Int64, Int64)? {
        guard row > 0, let a = model.rows.eventId(at: row - 1), let b = model.rows.eventId(at: row) else { return nil }
        return (model.store.timestamp(a), model.store.timestamp(b))
    }

    /// "3 ч 12 мин" when more than an hour passed since the previous row.
    func gapBefore(_ row: Int) -> String? {
        guard let (a, b) = timestamps(row) else { return nil }
        let secs = abs(b - a) / FileTime.ticksPerSecond
        guard secs >= 3600 else { return nil }
        let d = secs / 86_400, h = secs / 3600 % 24, m = secs / 60 % 60
        return d > 0 ? String(localized: "пауза \(d) д \(h) ч \(m) мин") : String(localized: "пауза \(h) ч \(m) мин")
    }

    func dayChanges(_ row: Int) -> Bool {
        guard let (a, b) = timestamps(row) else { return false }
        let fa = model.formatter, day: (Int64) -> Int64 = { ($0 + Int64(fa.offset($0)) * FileTime.ticksPerSecond) / (86_400 * FileTime.ticksPerSecond) }
        return day(a) != day(b)
    }

    func tableView(_ tableView: NSTableView, rowViewForRow row: Int) -> NSTableRowView? {
        let v = (tableView.makeView(withIdentifier: TimelineRowView.id, owner: nil) as? TimelineRowView) ?? TimelineRowView()
        v.identifier = TimelineRowView.id
        v.marker = timeline ? (dayChanges(row) ? .day : (gapBefore(row) != nil ? .gap : .none)) : .none
        v.tagColor = model.rows.eventId(at: row).flatMap { model.tags[$0] }.map { Self.tagColor($0.color) }
        return v
    }

    static func tagColor(_ name: String) -> NSColor {
        switch name {
        case "red": .systemRed
        case "orange": .systemOrange
        case "yellow": .systemYellow
        case "green": .systemGreen
        case "blue": .systemBlue
        case "purple": .systemPurple
        default: .systemGray
        }
    }

    static func tagTitle(_ name: String) -> String {
        switch name {
        case "red": String(localized: "Красная")
        case "orange": String(localized: "Оранжевая")
        case "yellow": String(localized: "Жёлтая")
        case "green": String(localized: "Зелёная")
        case "blue": String(localized: "Синяя")
        case "purple": String(localized: "Фиолетовая")
        default: name
        }
    }

    private func bookmarkMenu(for id: UInt32) -> NSMenuItem {
        let item = NSMenuItem(title: String(localized: "Закладка"), action: nil, keyEquivalent: "")
        let sub = NSMenu()
        for c in CaseAnnotations.colors {
            let i = actionItem(Self.tagTitle(c)) { [weak self] in self?.model.setTag(id, color: c) }
            i.image = NSImage(systemSymbolName: "bookmark.fill", accessibilityDescription: nil)?
                .withSymbolConfiguration(.init(paletteColors: [Self.tagColor(c)]))
            i.state = model.tags[id]?.color == c ? .on : .off
            sub.addItem(i)
        }
        sub.addItem(.separator())
        sub.addItem(actionItem(String(localized: "Заметка…")) { [weak self] in self?.editNote(id) })
        if model.tags[id] != nil {
            sub.addItem(actionItem(String(localized: "Убрать закладку")) { [weak self] in self?.model.setTag(id, color: nil) })
        }
        item.submenu = sub
        return item
    }

    private func editNote(_ id: UInt32) {
        let alert = NSAlert()
        alert.messageText = String(localized: "Заметка к событию")
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 380, height: 24))
        field.stringValue = model.tags[id]?.note ?? ""
        alert.accessoryView = field
        alert.addButton(withTitle: String(localized: "Сохранить"))
        alert.addButton(withTitle: String(localized: "Отмена"))
        alert.window.initialFirstResponder = field
        if alert.runModal() == .alertFirstButtonReturn { model.setNote(id, field.stringValue) }
    }

    // MARK: Selection and sorting

    func tableViewSelectionDidChange(_ notification: Notification) {
        guard !applyingSelection, let table else { return }
        let id = table.selectedRow >= 0 ? model.rows.eventId(at: table.selectedRow) : nil
        model.select(id)
        // Clicking an event shows its details on the right even if the panel was closed.
        if id != nil, !model.showDetails { model.showDetails = true }
    }

    func tableView(_ tableView: NSTableView, didClick tableColumn: NSTableColumn) {
        if tableColumn.identifier.rawValue == "time" { model.ascending.toggle() }
    }

    // MARK: Context menu

    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        guard let table else { return }
        let row = table.clickedRow, column = table.clickedColumn
        guard row >= 0, let r = model.rows.row(at: row) else { return }
        if table.selectedRow != row { table.selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false) }
        let spec = column >= 0 ? specs[table.tableColumns[column].identifier.rawValue] : nil

        if let spec, spec.kind == .summary {
            for (key, value) in fieldPairs(r).prefix(40) where !value.isEmpty {
                let item = NSMenuItem(title: "\(key): \(Self.short(value))", action: nil, keyEquivalent: "")
                let sub = NSMenu()
                sub.addItem(actionItem(String(localized: "Фильтр  = значение")) { [weak self] in
                    self?.model.addFilter(key: key, value: value, negated: false)
                })
                sub.addItem(actionItem(String(localized: "Исключить  ≠ значение")) { [weak self] in
                    self?.model.addFilter(key: key, value: value, negated: true)
                })
                sub.addItem(actionItem(String(localized: "Добавить колонку «\(key)»")) { [weak self] in
                    self?.model.addColumn(field: key)
                })
                sub.addItem(actionItem(String(localized: "Копировать значение")) { Self.copy(value) })
                item.submenu = sub
                menu.addItem(item)
            }
        } else if let spec, let key = spec.filterKey, let value = filterValue(r, spec) {
            let title = model.keyTitle(key)
            menu.addItem(actionItem(String(localized: "Фильтр: \(title) = \(Self.short(value))")) { [weak self] in
                self?.model.addFilter(key: key, value: value, negated: false)
            })
            menu.addItem(actionItem(String(localized: "Исключить: \(title) ≠ \(Self.short(value))")) { [weak self] in
                self?.model.addFilter(key: key, value: value, negated: true)
            })
            menu.addItem(actionItem(String(localized: "Копировать значение")) { Self.copy(value) })
        }
        if menu.numberOfItems > 0 { menu.addItem(.separator()) }
        if let id = model.rows.eventId(at: row) { menu.addItem(bookmarkMenu(for: id)) }
        menu.addItem(actionItem(String(localized: "Копировать строку")) { [weak self] in
            guard let self else { return }
            Self.copy(self.model.columns.map { self.text(r, $0) }.joined(separator: "\t"))
        })
        let cols = NSMenuItem(title: String(localized: "Колонки"), action: nil, keyEquivalent: "")
        let sub = NSMenu()
        for kind in ColumnSpec.optional {
            let item = actionItem(ColumnSpec(kind: kind, width: 0).title) { [weak self] in self?.model.toggleColumn(kind) }
            item.state = model.columns.contains { $0.kind == kind } ? .on : .off
            sub.addItem(item)
        }
        if let spec, case .field = spec.kind {
            sub.addItem(.separator())
            sub.addItem(actionItem(String(localized: "Убрать колонку «\(spec.title)»")) { [weak self] in
                self?.model.removeColumn(id: spec.id)
            })
        }
        cols.submenu = sub
        menu.addItem(cols)
    }

    private func fieldPairs(_ r: DisplayRow) -> [(String, String)] {
        let keys = r.row.pairs.map(\.key), values = r.row.pairs.map(\.value)
        let names = (try? model.store.strings(keys)) ?? []
        let vals = (try? model.store.strings(values)) ?? []
        return Array(zip(names, vals))
    }

    static func short(_ s: String) -> String {
        let one = s.replacingOccurrences(of: "\n", with: " ")
        return one.count > 60 ? String(one.prefix(60)) + "…" : one
    }

    static func copy(_ s: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(s, forType: .string)
    }
}


/// Row view that draws a separator above the first event of a day (accent) or after a
/// long pause (dashed orange) in timeline mode.
final class TimelineRowView: NSTableRowView {
    static let id = NSUserInterfaceItemIdentifier("timelineRow")
    enum Marker { case none, day, gap }
    var marker = Marker.none { didSet { needsDisplay = true } }
    var tagColor: NSColor? { didSet { needsDisplay = true } }

    override func drawBackground(in dirtyRect: NSRect) {
        super.drawBackground(in: dirtyRect)
        if let tagColor {
            tagColor.withAlphaComponent(0.16).setFill()
            bounds.fill()
            tagColor.setFill()
            NSRect(x: 0, y: 0, width: 4, height: bounds.height).fill()
        }
        guard marker != .none else { return }
        let path = NSBezierPath()
        path.move(to: NSPoint(x: bounds.minX, y: bounds.minY + 0.5))
        path.line(to: NSPoint(x: bounds.maxX, y: bounds.minY + 0.5))
        path.lineWidth = marker == .day ? 2 : 1
        if marker == .gap { path.setLineDash([4, 3], count: 2, phase: 0) }
        (marker == .day ? NSColor.controlAccentColor : NSColor.systemOrange).setStroke()
        path.stroke()
    }
}
