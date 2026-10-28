import Foundation
import zlib

/// Minimal ZIP reader (stored and deflated entries, the central directory, ZIP64 not needed for
/// rule archives). Sizes are checked against limits so a hostile archive cannot exhaust memory.
public struct ZipReader {
    public struct Entry: Sendable {
        public let name: String
        let method: UInt16
        let compressedSize: Int
        public let size: Int
        let localHeader: Int
    }

    public struct ZipError: Error, CustomStringConvertible {
        public let description: String
    }

    public let data: Data
    public let entries: [Entry]

    public init(_ data: Data, maxEntrySize: Int = 64 << 20) throws {
        self.data = data
        // End of central directory: signature 0x06054b50 within the last 64 KB + 22 bytes.
        let n = data.count
        guard n >= 22 else { throw ZipError(description: "not a ZIP archive") }
        var eocd = -1
        var i = n - 22
        while i >= max(0, n - 65_557) {
            if data.u32(i) == 0x0605_4b50 { eocd = i; break }
            i -= 1
        }
        guard eocd >= 0 else { throw ZipError(description: "no end of central directory") }
        let count = Int(data.u16(eocd + 10)), cdOffset = Int(data.u32(eocd + 16))
        var out: [Entry] = []
        var p = cdOffset
        for _ in 0..<count {
            guard p + 46 <= n, data.u32(p) == 0x0201_4b50 else { throw ZipError(description: "bad central directory") }
            let method = data.u16(p + 10)
            let csize = Int(data.u32(p + 20)), usize = Int(data.u32(p + 24))
            let nameLen = Int(data.u16(p + 28)), extraLen = Int(data.u16(p + 30)), commentLen = Int(data.u16(p + 32))
            let local = Int(data.u32(p + 42))
            guard p + 46 + nameLen <= n else { throw ZipError(description: "bad entry name") }
            let name = String(decoding: data[(data.startIndex + p + 46)..<(data.startIndex + p + 46 + nameLen)], as: UTF8.self)
            guard usize <= maxEntrySize else { throw ZipError(description: "entry too large: \(name)") }
            out.append(Entry(name: name, method: method, compressedSize: csize, size: usize, localHeader: local))
            p += 46 + nameLen + extraLen + commentLen
        }
        entries = out
    }

    public func read(_ e: Entry) throws -> Data {
        let h = e.localHeader
        guard h + 30 <= data.count, data.u32(h) == 0x0403_4b50 else { throw ZipError(description: "bad local header: \(e.name)") }
        let start = h + 30 + Int(data.u16(h + 26)) + Int(data.u16(h + 28))
        guard start + e.compressedSize <= data.count else { throw ZipError(description: "truncated entry: \(e.name)") }
        let packed = data[(data.startIndex + start)..<(data.startIndex + start + e.compressedSize)]
        switch e.method {
        case 0: return Data(packed)
        case 8:
            var out = Data(count: e.size)
            var s = z_stream()
            guard inflateInit2_(&s, -15, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size)) == Z_OK else { throw ZipError(description: "zlib") }
            defer { inflateEnd(&s) }
            let status: Int32 = packed.withUnsafeBytes { src in
                out.withUnsafeMutableBytes { dst in
                    s.next_in = UnsafeMutablePointer(mutating: src.bindMemory(to: Bytef.self).baseAddress)
                    s.avail_in = uInt(src.count)
                    s.next_out = dst.bindMemory(to: Bytef.self).baseAddress
                    s.avail_out = uInt(dst.count)
                    return inflate(&s, Z_FINISH)
                }
            }
            guard status == Z_STREAM_END, Int(s.total_out) == e.size else { throw ZipError(description: "cannot inflate \(e.name)") }
            return out
        default:
            throw ZipError(description: "unsupported compression \(e.method): \(e.name)")
        }
    }
}

private extension Data {
    func u16(_ at: Int) -> UInt16 { UInt16(self[startIndex + at]) | UInt16(self[startIndex + at + 1]) << 8 }
    func u32(_ at: Int) -> UInt32 { UInt32(u16(at)) | UInt32(u16(at + 2)) << 16 }
}
