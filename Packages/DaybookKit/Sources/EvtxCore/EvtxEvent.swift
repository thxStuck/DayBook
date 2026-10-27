import Foundation

public struct RecordFlags: OptionSet, Sendable, Hashable {
    public let rawValue: UInt32
    public init(rawValue: UInt32) { self.rawValue = rawValue }

    /// Chunk lies past the header's (stale) chunk count but holds newer records.
    public static let beyondHeader = RecordFlags(rawValue: 1 << 0)
    /// Chunk lies past the header's chunk count and holds older records (leftovers).
    public static let staleChunk = RecordFlags(rawValue: 1 << 1)
    public static let chunkHeaderCRC = RecordFlags(rawValue: 1 << 2)
    public static let chunkDataCRC = RecordFlags(rawValue: 1 << 3)
    /// Recovered from chunk slack space.
    public static let carved = RecordFlags(rawValue: 1 << 4)
    public static let parseError = RecordFlags(rawValue: 1 << 5)
    public static let sizeMismatch = RecordFlags(rawValue: 1 << 6)
    /// Template taken from another chunk (carved records).
    public static let foreignTemplate = RecordFlags(rawValue: 1 << 7)
    /// No template found; values emitted as `Value[n]`.
    public static let missingTemplate = RecordFlags(rawValue: 1 << 8)
    /// TimeCreated and the record's written time differ by more than the tolerance.
    public static let timeSkew = RecordFlags(rawValue: 1 << 9)
    /// Text contained unpaired UTF-16 surrogates (rendered as U+FFFD).
    public static let invalidText = RecordFlags(rawValue: 1 << 10)
    /// Identical copies of this event (same computer, channel, record id, time and event
    /// id) were found in other files or in slack and collapsed into it; their locations
    /// are kept in the case (`dup` table).
    public static let duplicate = RecordFlags(rawValue: 1 << 11)
    /// Live record found after skipping a corrupted stretch of its chunk (other parsers
    /// stop at the corruption and never show these).
    public static let afterGap = RecordFlags(rawValue: 1 << 12)
    /// Text logs: the line has no year (classic syslog), it was inferred from the file's dates.
    public static let yearInferred = RecordFlags(rawValue: 1 << 13)
    /// Text logs: the line has no time zone; the system's zone from the collection was assumed.
    public static let zoneAssumed = RecordFlags(rawValue: 1 << 14)
    /// The record has no time of its own (shell history without timestamps); the source file's
    /// modification time is used, and records keep their order in the file.
    public static let timeFromFile = RecordFlags(rawValue: 1 << 15)
    /// A compressed value could not be unpacked (for example zstd in a systemd journal).
    public static let notDecompressed = RecordFlags(rawValue: 1 << 16)
    /// The line matched no known format; it is kept whole in `Message`.
    public static let unparsed = RecordFlags(rawValue: 1 << 17)

    /// Names used in queries (`flag = …`), exports and the `@Flag` posting lists. The order is
    /// part of the case format: names are interned in this order.
    public static let names: [(RecordFlags, String)] = [
        (.carved, "carved"), (.beyondHeader, "beyondHeader"), (.staleChunk, "stale"), (.afterGap, "afterGap"),
        (.parseError, "parseError"), (.chunkDataCRC, "crcMismatch"), (.chunkHeaderCRC, "headerCrcMismatch"),
        (.timeSkew, "timeSkew"), (.foreignTemplate, "foreignTemplate"), (.missingTemplate, "missingTemplate"),
        (.invalidText, "invalidText"), (.sizeMismatch, "sizeMismatch"), (.duplicate, "hasCopies"),
        (.yearInferred, "yearInferred"), (.zoneAssumed, "zoneAssumed"), (.timeFromFile, "timeFromFile"),
        (.notDecompressed, "notDecompressed"), (.unparsed, "unparsed"),
    ]
}

public struct EvtxField: Sendable, Equatable {
    public var name: String
    public var value: String
    public var type: UInt8

    public init(name: String, value: String, type: UInt8) {
        self.name = name
        self.value = value
        self.type = type
    }
}

/// Structured form of one record: System properties plus flattened event data.
public struct EvtxEvent: Sendable {
    public var recordId: UInt64 = 0
    public var writtenTime: Int64 = 0
    public var timeCreated: Int64?
    public var eventRecordId: UInt64?
    public var provider = ""
    public var providerGuid: String?
    public var eventSourceName: String?
    public var eventId: UInt16 = 0
    public var qualifiers: UInt16?
    public var version: UInt8?
    public var level: UInt8?
    public var task: UInt16?
    public var opcode: UInt8?
    public var keywords: UInt64?
    public var channel = ""
    public var computer = ""
    public var userSid: String?
    public var processId: UInt32?
    public var threadId: UInt32?
    public var activityId: String?
    public var relatedActivityId: String?
    /// EventData / UserData / RenderingInfo / ProcessingErrorData items in document order.
    public var fields: [EvtxField] = []
    public var flags: RecordFlags = []

    public init() {}

    /// System/TimeCreated when present, else the record header's written time.
    public var timestamp: Int64 { timeCreated ?? writtenTime }

    public func field(_ name: String) -> String? {
        fields.first { $0.name.caseInsensitiveCompare(name) == .orderedSame }?.value
    }
}

/// Builds an `EvtxEvent` from the rendered document.
struct EventExtractor: BinXmlVisitor {
    var event = EvtxEvent()
    let systemOnly: Bool
    var invalidText = false

    private enum Section { case none, system, eventData, userData, other(String) }
    private var section = Section.none
    private var stack: [String] = []
    private var hasChild: [Bool] = []
    private var buffer = ""
    private var bufferType: UInt8 = ValueType.string
    private var dataName: String?

    init(systemOnly: Bool) { self.systemOnly = systemOnly }

    var wantsNestedContent: Bool { !systemOnly }

    mutating func startElement(_ name: String) {
        if !hasChild.isEmpty { hasChild[hasChild.count - 1] = true }
        stack.append(name)
        hasChild.append(false)
        buffer = ""
        bufferType = ValueType.string
        if stack.count == 2 {
            switch name {
            case "System": section = .system
            case "EventData": section = .eventData
            case "UserData": section = .userData
            default: section = .other(name)
            }
        }
        if stack.count == 3, case .eventData = section { dataName = nil }
    }

    mutating func attribute(_ name: String, _ value: AttributeValue) {
        guard stack.count >= 3 else { return }
        let element = stack[stack.count - 1]
        switch section {
        case .system where stack.count == 3:
            switch (element, name) {
            case ("Provider", "Name"): event.provider = string(value)
            case ("Provider", "Guid"): event.providerGuid = string(value)
            case ("Provider", "EventSourceName"): event.eventSourceName = string(value)
            case ("EventID", "Qualifiers"): event.qualifiers = integer(value).map { UInt16(truncatingIfNeeded: $0) }
            case ("TimeCreated", "SystemTime"):
                if case let .value(v) = value, let ft = v.fileTime { event.timeCreated = ft }
                else { event.timeCreated = Self.parseISO(string(value)) }
            case ("Correlation", "ActivityID"): event.activityId = string(value)
            case ("Correlation", "RelatedActivityID"): event.relatedActivityId = string(value)
            case ("Execution", "ProcessID"): event.processId = integer(value).map { UInt32(truncatingIfNeeded: $0) }
            case ("Execution", "ThreadID"): event.threadId = integer(value).map { UInt32(truncatingIfNeeded: $0) }
            case ("Security", "UserID"): event.userSid = string(value)
            default: break
            }
        case .eventData where stack.count == 3 && name == "Name":
            dataName = string(value)
        case .userData where stack.count >= 4 && name != "xmlns":
            append(path(dropFirst: 3) + "." + name, string(value), ValueType.string)
        default:
            break
        }
    }

    mutating func text(_ s: String) { buffer += s }

    mutating func value(_ v: EvtxValue) {
        if case .system = section, stack.count == 3, let n = v.integer {
            switch stack[2] {
            case "EventID": event.eventId = UInt16(truncatingIfNeeded: n)
            case "Version": event.version = UInt8(truncatingIfNeeded: n)
            case "Level": event.level = UInt8(truncatingIfNeeded: n)
            case "Task": event.task = UInt16(truncatingIfNeeded: n)
            case "Opcode": event.opcode = UInt8(truncatingIfNeeded: n)
            case "Keywords": event.keywords = n
            case "EventRecordID": event.eventRecordId = n
            default: break
            }
        }
        bufferType = v.type
        buffer += v.render(invalidText: &invalidText)
    }

    mutating func endElement(_ name: String) {
        let depth = stack.count
        let leaf = !(hasChild.last ?? false)
        switch section {
        case .system where depth == 3:
            switch name {
            case "Channel": event.channel = buffer
            case "Computer": event.computer = buffer
            case "EventID" where !buffer.isEmpty: event.eventId = UInt16(buffer) ?? event.eventId
            case "Level" where event.level == nil: event.level = UInt8(buffer)
            case "Version" where event.version == nil: event.version = UInt8(buffer)
            case "Task" where event.task == nil: event.task = UInt16(buffer)
            case "Opcode" where event.opcode == nil: event.opcode = UInt8(buffer)
            case "EventRecordID" where event.eventRecordId == nil: event.eventRecordId = UInt64(buffer)
            case "Keywords" where event.keywords == nil:
                event.keywords = UInt64(buffer.hasPrefix("0x") ? String(buffer.dropFirst(2)) : buffer,
                                        radix: buffer.hasPrefix("0x") ? 16 : 10)
            default: break
            }
        case .eventData where depth == 3:
            append(name == "Data" ? (dataName ?? "Data") : name, buffer, bufferType)
        case .userData where depth >= 4 && leaf:
            append(path(dropFirst: 3), buffer, bufferType)
        case let .other(sectionName) where depth >= 2 && leaf:
            append(depth == 2 ? sectionName : sectionName + "." + path(dropFirst: 2), buffer, bufferType)
        default:
            break
        }
        stack.removeLast()
        hasChild.removeLast()
        buffer = ""
        if depth == 2 { section = .none }
    }

    private mutating func append(_ name: String, _ value: String, _ type: UInt8) {
        event.fields.append(EvtxField(name: name, value: value, type: type))
    }

    private func path(dropFirst n: Int) -> String {
        stack.count > n ? stack[n...].joined(separator: ".") : (stack.last ?? "")
    }

    private mutating func string(_ v: AttributeValue) -> String {
        switch v {
        case let .value(x): x.render(invalidText: &invalidText)
        case let .text(s): s
        }
    }

    private mutating func integer(_ v: AttributeValue) -> UInt64? {
        switch v {
        case let .value(x): x.integer ?? UInt64(x.render(invalidText: &invalidText))
        case let .text(s): UInt64(s)
        }
    }

    /// Parses `YYYY-MM-DDTHH:MM:SS[.fffffff]Z` (used when TimeCreated is stored as text).
    static func parseISO(_ s: String) -> Int64? {
        let u = Array(s.utf8)
        guard u.count >= 19 else { return nil }
        func num(_ a: Int, _ n: Int) -> Int64? {
            var v: Int64 = 0
            for i in a..<(a + n) {
                let c = u[i]
                guard c >= 48 && c <= 57 else { return nil }
                v = v * 10 + Int64(c - 48)
            }
            return v
        }
        guard let y = num(0, 4), let mo = num(5, 2), let d = num(8, 2),
              let h = num(11, 2), let mi = num(14, 2), let se = num(17, 2) else { return nil }
        var frac: Int64 = 0
        if u.count > 20, u[19] == UInt8(ascii: ".") {
            var digits = 0
            var i = 20
            while i < u.count, u[i] >= 48, u[i] <= 57, digits < 7 {
                frac = frac * 10 + Int64(u[i] - 48); digits += 1; i += 1
            }
            for _ in digits..<7 { frac *= 10 }
        }
        let days = FileTime.days(fromCivil: y, Int(mo), Int(d))
        return FileTime.fromUnixSeconds(days * 86_400 + h * 3600 + mi * 60 + se) + frac
    }
}
