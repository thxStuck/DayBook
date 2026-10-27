import Compression
import Foundation
import zlib

/// Bytes of a log file as the system wrote it: plain, gzip (logrotate) or xz. Files are read
/// read-only; compressed files are unpacked in memory.
enum LogBytes {
    enum Compression: String, Sendable { case none, gzip, xz }

    static func compression(of url: URL) -> Compression {
        guard let h = try? FileHandle(forReadingFrom: url) else { return .none }
        defer { try? h.close() }
        let head = (try? h.read(upToCount: 6)) ?? Data()
        if head.starts(with: [0x1F, 0x8B]) { return .gzip }
        if head.starts(with: [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]) { return .xz }
        return .none
    }

    /// Whole content; nil when the file cannot be read or unpacked (the reason is returned).
    static func read(_ url: URL) -> (data: Data?, compression: Compression, error: String?) {
        let kind = compression(of: url)
        guard let raw = try? Data(contentsOf: url, options: .alwaysMapped) else {
            return (nil, kind, String(localized: "файл не читается"))
        }
        switch kind {
        case .none: return (raw, kind, nil)
        case .gzip:
            if let d = gunzip(raw) { return (d, kind, nil) }
            return (nil, kind, String(localized: "не удалось распаковать gzip"))
        case .xz:
            if let d = unxz(raw) { return (d, kind, nil) }
            return (nil, kind, String(localized: "не удалось распаковать xz"))
        }
    }

    /// gzip, including several concatenated members (logrotate with `delaycompress` and appends).
    static func gunzip(_ input: Data) -> Data? {
        var out = Data()
        var ok = false
        input.withUnsafeBytes { (src: UnsafeRawBufferPointer) in
            guard let base = src.bindMemory(to: UInt8.self).baseAddress else { return }
            var offset = 0
            let chunk = 1 << 18
            var buffer = [UInt8](repeating: 0, count: chunk)
            while offset < src.count {
                var s = z_stream()
                guard inflateInit2_(&s, 15 + 32, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size)) == Z_OK else { return }
                s.next_in = UnsafeMutablePointer(mutating: base + offset)
                s.avail_in = uInt(src.count - offset)
                var status: Int32 = Z_OK
                repeat {
                    status = buffer.withUnsafeMutableBufferPointer { b -> Int32 in
                        s.next_out = b.baseAddress
                        s.avail_out = uInt(chunk)
                        let r = inflate(&s, Z_NO_FLUSH)
                        out.append(b.baseAddress!, count: chunk - Int(s.avail_out))
                        return r
                    }
                } while status == Z_OK
                let consumed = src.count - offset - Int(s.avail_in)
                inflateEnd(&s)
                guard status == Z_STREAM_END else { ok = offset > 0; return }
                ok = true
                offset += consumed
                // Skip padding between members.
                while offset < src.count && base[offset] == 0 { offset += 1 }
            }
        }
        return ok ? out : nil
    }

    static func unxz(_ input: Data) -> Data? {
        let chunk = 1 << 18
        var out = Data()
        let dst = UnsafeMutablePointer<UInt8>.allocate(capacity: chunk)
        defer { dst.deallocate() }
        var stream = compression_stream(dst_ptr: dst, dst_size: 0, src_ptr: dst, src_size: 0, state: nil)
        guard compression_stream_init(&stream, COMPRESSION_STREAM_DECODE, COMPRESSION_LZMA) == COMPRESSION_STATUS_OK else { return nil }
        defer { compression_stream_destroy(&stream) }
        var result: compression_status = COMPRESSION_STATUS_OK
        input.withUnsafeBytes { (src: UnsafeRawBufferPointer) in
            stream.src_ptr = src.bindMemory(to: UInt8.self).baseAddress!
            stream.src_size = src.count
            repeat {
                stream.dst_ptr = dst
                stream.dst_size = chunk
                result = compression_stream_process(&stream, Int32(COMPRESSION_STREAM_FINALIZE.rawValue))
                out.append(dst, count: chunk - stream.dst_size)
            } while result == COMPRESSION_STATUS_OK
        }
        return result == COMPRESSION_STATUS_END ? out : nil
    }
}

/// One line of a text log: its text without the line break, where it starts in the (unpacked)
/// content, and its 1-based number.
struct LogLine {
    var text: String
    var offset: Int
    var number: Int
    /// The line held bytes that are not UTF-8 (replaced with U+FFFD) or NUL (removed).
    var invalidText: Bool
}

enum LogLines {
    /// Splits on LF (a trailing CR is dropped). NUL bytes are removed: SQLite text ends at NUL.
    static func split(_ data: Data, maxLines: Int = .max) -> [LogLine] {
        var lines: [LogLine] = []
        forEach(data, in: 0..<data.count, firstNumber: 1) { line in
            lines.append(line)
            return lines.count < maxLines
        }
        return lines
    }

    /// Calls `body` for every line that starts in `range` (offsets are absolute); `body` returns
    /// false to stop. A final line without LF is included unless it is empty.
    static func forEach(_ data: Data, in range: Range<Int>, firstNumber: Int, _ body: (LogLine) -> Bool) {
        data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            let bytes = raw.bindMemory(to: UInt8.self)
            guard let base = bytes.baseAddress else { return }
            var start = range.lowerBound
            var number = firstNumber
            let n = min(range.upperBound, bytes.count)
            while start < n {
                let rest = bytes.count - start
                let end = memchr(base + start, 0x0A, rest).map { UnsafeRawPointer($0) - UnsafeRawPointer(base) } ?? bytes.count
                var stop = end
                if stop > start && bytes[stop - 1] == 0x0D { stop -= 1 }
                if stop > start || end < bytes.count {
                    let (text, bad) = decode(UnsafeBufferPointer(rebasing: bytes[start..<stop]))
                    if !body(LogLine(text: text, offset: start, number: number, invalidText: bad)) { return }
                }
                number += 1
                start = end + 1
            }
        }
    }

    static func decode(_ bytes: UnsafeBufferPointer<UInt8>) -> (String, Bool) {
        var hasNul = false
        for b in bytes where b == 0 { hasNul = true; break }
        if !hasNul, isValidUTF8(bytes) { return (String(decoding: bytes, as: UTF8.self), false) }
        let clean = hasNul ? bytes.filter { $0 != 0 } : Array(bytes)
        return (String(decoding: clean, as: UTF8.self), true)
    }

    /// Strict UTF-8 check (no overlong forms, surrogates or values past U+10FFFF).
    static func isValidUTF8(_ b: UnsafeBufferPointer<UInt8>) -> Bool {
        var i = 0
        let n = b.count
        while i < n {
            let c = b[i]
            if c < 0x80 { i += 1; continue }
            let need: Int, minimum: UInt32
            var cp: UInt32
            if c & 0xE0 == 0xC0 { need = 1; cp = UInt32(c & 0x1F); minimum = 0x80 }
            else if c & 0xF0 == 0xE0 { need = 2; cp = UInt32(c & 0x0F); minimum = 0x800 }
            else if c & 0xF8 == 0xF0 { need = 3; cp = UInt32(c & 0x07); minimum = 0x10000 }
            else { return false }
            guard i + need < n else { return false }
            for k in 1...need {
                let d = b[i + k]
                guard d & 0xC0 == 0x80 else { return false }
                cp = cp << 6 | UInt32(d & 0x3F)
            }
            if cp < minimum || cp > 0x10FFFF || (0xD800...0xDFFF).contains(cp) { return false }
            i += need + 1
        }
        return true
    }
}
