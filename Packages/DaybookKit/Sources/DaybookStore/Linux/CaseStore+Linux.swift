import EvtxCore
import Foundation

extension CaseStore {
    /// Re-reads a line (text logs) or a record (wtmp, lastlog) of a non-EVTX source. The line must
    /// start at the stored offset and be the stored line number, else the file changed after import.
    func readTextRecord(_ detail: EventDetail, at offset: Int) -> EventDetail {
        var d = detail
        let info = sources[detail.row.source]
        guard let data = textContent(detail.row.source, path: info.path, state: &d.sourceState) else { return d }
        guard offset >= 0, offset < data.count else {
            d.sourceState = .recordMismatch
            return d
        }
        switch info.format {
        case "wtmp", "btmp", "utmp":
            guard offset + UtmpRecord.size <= data.count,
                  let r = UtmpRecord.parse(data.subdata(in: offset..<(offset + UtmpRecord.size))).records.first,
                  r.timestamp == detail.row.ts else {
                d.sourceState = .recordMismatch
                return d
            }
            d.raw = Array(data[offset..<(offset + UtmpRecord.size)])
            d.text = r.fields(host: info.host ?? detail.row.computer, failed: info.format == "btmp")
                .map { "\($0.name): \($0.value)" }.joined(separator: "\n")
        case "lastlog":
            guard offset + LastlogRecord.size <= data.count else {
                d.sourceState = .recordMismatch
                return d
            }
            d.raw = Array(data[offset..<(offset + LastlogRecord.size)])
            let r = LastlogRecord.parse(Data(count: offset) + data[offset..<(offset + LastlogRecord.size)]).first
            guard let r, FileTime.fromUnixSeconds(r.seconds) == detail.row.ts else {
                d.sourceState = .recordMismatch
                return d
            }
            d.text = r.fields(host: info.host ?? detail.row.computer, user: nil).map { "\($0.name): \($0.value)" }.joined(separator: "\n")
        default:
            var lineNumber = 1
            var startsLine = true
            data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
                let b = raw.bindMemory(to: UInt8.self)
                startsLine = offset == 0 || b[offset - 1] == 0x0A
                guard let base = b.baseAddress else { return }
                var i = 0
                while i < offset, let p = memchr(base + i, 0x0A, offset - i) {
                    lineNumber += 1
                    i = UnsafeRawPointer(p) - UnsafeRawPointer(base) + 1
                }
            }
            guard startsLine, UInt64(lineNumber) == detail.row.recordId else {
                d.sourceState = .recordMismatch
                return d
            }
            var line: LogLine?
            LogLines.forEach(data, in: offset..<data.count, firstNumber: lineNumber) { l in line = l; return false }
            let end = data[offset...].firstIndex(of: 0x0A) ?? data.count
            d.raw = Array(data[offset..<end])
            d.text = line?.text ?? ""
        }
        d.sourceState = .loaded
        return d
    }

    /// Unpacked content of a source, cached for the last few files.
    private func textContent(_ id: Int, path: String, state: inout SourceRecordState) -> Data? {
        if let hit = fileLock.withLock({ textFiles.first { $0.id == id }?.data }) { return hit }
        let url = URL(fileURLWithPath: path)
        guard FileManager.default.fileExists(atPath: path) else { state = .missingFile; return nil }
        guard FileManager.default.isReadableFile(atPath: path) else { state = .noAccess; return nil }
        let read = LogBytes.read(url)
        guard let data = read.data else { state = .unreadable(read.error ?? path); return nil }
        fileLock.withLock {
            textFiles.removeAll { $0.id == id }
            textFiles.append((id, data))
            if textFiles.count > 3 { textFiles.removeFirst() }
        }
        return data
    }
}
