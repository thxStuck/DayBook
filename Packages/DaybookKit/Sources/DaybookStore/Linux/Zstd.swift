import Foundation

/// Zstandard decoder (RFC 8878) for compressed journald values; Apple's Compression has no zstd.
/// Decodes standard frames (raw, RLE and compressed blocks, Huffman literals, FSE sequences); no
/// dictionaries. Returns nil on any inconsistency rather than guessing.
enum Zstd {
    struct Corrupt: Error {}

    static func decompress(_ input: [UInt8]) -> [UInt8]? {
        try? input.withUnsafeBufferPointer { try decode($0) }
    }

    // MARK: Bit streams

    /// Forward little-endian bit reader (FSE table descriptions).
    struct ForwardBits {
        let b: UnsafeBufferPointer<UInt8>
        var bit: Int   // absolute bit position

        mutating func read(_ n: Int) throws -> Int {
            guard n > 0 else { return 0 }
            guard bit + n <= b.count * 8 else { throw Corrupt() }
            var v = 0
            for k in 0..<n {
                let p = bit + k
                v |= Int((b[p >> 3] >> UInt8(p & 7)) & 1) << k
            }
            bit += n
            return v
        }

        mutating func rewind(_ n: Int) { bit -= n }
        /// Byte offset after aligning to a whole byte.
        var alignedByte: Int { (bit + 7) >> 3 }
    }

    /// Backward bit reader (Huffman, FSE and sequence streams): starts after the final 1-bit of the
    /// last byte; reading past the start yields zeros (the format relies on it).
    struct BackwardBits {
        let b: UnsafeBufferPointer<UInt8>   // the stream's bytes
        var offset: Int                     // bits still unread

        init(_ b: UnsafeBufferPointer<UInt8>) throws {
            guard let last = b.last, last != 0 else { throw Corrupt() }
            self.b = b
            offset = (b.count - 1) * 8 + (7 - last.leadingZeroBitCount)
        }

        mutating func read(_ n: Int) -> UInt64 {
            guard n > 0 else { return 0 }
            offset -= n
            var start = offset, count = n
            if start < 0 { count += start; start = 0 }
            var v: UInt64 = 0
            if count > 0 {
                var k = 0
                while k < count {
                    let p = start + k
                    let byte = UInt64(b[p >> 3]) >> UInt64(p & 7)
                    let take = min(8 - (p & 7), count - k)
                    v |= (byte & ((1 << UInt64(take)) - 1)) << UInt64(k)
                    k += take
                }
            }
            if offset < 0 { v = -offset >= 64 ? 0 : v << UInt64(-offset) }
            return v
        }

        var overflowed: Bool { offset < 0 }
    }

    static func highBit(_ x: Int) -> Int { x <= 0 ? -1 : (Int.bitWidth - 1 - x.leadingZeroBitCount) }

    // MARK: FSE

    struct FSETable {
        var accuracy: Int
        var symbols: [UInt8]
        var bits: [UInt8]
        var base: [UInt16]

        static func rle(_ s: UInt8) -> FSETable { FSETable(accuracy: 0, symbols: [s], bits: [0], base: [0]) }

        init(accuracy: Int, symbols: [UInt8], bits: [UInt8], base: [UInt16]) {
            self.accuracy = accuracy
            self.symbols = symbols
            self.bits = bits
            self.base = base
        }

        /// Table from normalised counts (-1 = "less than 1").
        init(counts: [Int], accuracy: Int) throws {
            let size = 1 << accuracy
            var symbols = [UInt8](repeating: 0, count: size)
            var next = [Int](repeating: 0, count: counts.count)
            var high = size
            for (s, c) in counts.enumerated() where c == -1 {
                high -= 1
                symbols[high] = UInt8(s)
                next[s] = 1
            }
            var pos = 0
            let step = (size >> 1) + (size >> 3) + 3, mask = size - 1
            for (s, c) in counts.enumerated() where c > 0 {
                next[s] = c
                for _ in 0..<c {
                    symbols[pos] = UInt8(s)
                    repeat { pos = (pos + step) & mask } while pos >= high
                }
            }
            guard pos == 0 else { throw Corrupt() }
            var bits = [UInt8](repeating: 0, count: size), base = [UInt16](repeating: 0, count: size)
            for i in 0..<size {
                let s = Int(symbols[i])
                let d = next[s]
                next[s] += 1
                let nb = accuracy - Zstd.highBit(d)
                bits[i] = UInt8(nb)
                base[i] = UInt16(truncatingIfNeeded: (d << nb) - size)
            }
            self.init(accuracy: accuracy, symbols: symbols, bits: bits, base: base)
        }

        /// Reads a table description (forward bits); returns the table and the bytes used.
        static func read(_ b: UnsafeBufferPointer<UInt8>, maxAccuracy: Int, maxSymbols: Int) throws -> (FSETable, Int) {
            var r = ForwardBits(b: b, bit: 0)
            let accuracy = try r.read(4) + 5
            guard accuracy <= maxAccuracy else { throw Corrupt() }
            var remaining = 1 << accuracy
            var counts: [Int] = []
            while remaining > 0, counts.count <= maxSymbols {
                let nb = Zstd.highBit(remaining + 1) + 1
                var v = try r.read(nb)
                let lowMask = (1 << (nb - 1)) - 1
                let threshold = (1 << nb) - 1 - (remaining + 1)
                if v & lowMask < threshold {
                    r.rewind(1)
                    v &= lowMask
                } else if v > lowMask {
                    v -= threshold
                }
                let p = v - 1
                remaining -= abs(p)
                counts.append(p)
                if p == 0 {
                    var rep = try r.read(2)
                    while true {
                        for _ in 0..<rep where counts.count <= maxSymbols { counts.append(0) }
                        if rep == 3 { rep = try r.read(2) } else { break }
                    }
                }
            }
            guard remaining == 0, counts.count <= maxSymbols + 1 else { throw Corrupt() }
            return (try FSETable(counts: counts, accuracy: accuracy), r.alignedByte)
        }
    }

    struct FSEState {
        var state = 0
        mutating func start(_ t: FSETable, _ r: inout BackwardBits) { state = Int(r.read(t.accuracy)) }
        func peek(_ t: FSETable) -> UInt8 { t.symbols[state] }
        mutating func update(_ t: FSETable, _ r: inout BackwardBits) {
            state = Int(t.base[state]) + Int(r.read(Int(t.bits[state])))
        }
    }
}

// MARK: Huffman literals

extension Zstd {
    struct HuffmanTable {
        var maxBits: Int
        var symbols: [UInt8]
        var bits: [UInt8]

        /// Reads a Huffman tree description; returns the table and the bytes used.
        static func read(_ b: UnsafeBufferPointer<UInt8>) throws -> (HuffmanTable, Int) {
            guard let header = b.first else { throw Corrupt() }
            var weights: [Int] = []
            var used: Int
            if header >= 128 {
                let n = Int(header) - 127
                used = 1 + (n + 1) / 2
                guard used <= b.count else { throw Corrupt() }
                for i in 0..<n {
                    let byte = b[1 + i / 2]
                    weights.append(Int(i % 2 == 0 ? byte >> 4 : byte & 0x0F))
                }
            } else {
                used = 1 + Int(header)
                guard used <= b.count, header > 0 else { throw Corrupt() }
                let stream = UnsafeBufferPointer(rebasing: b[1..<used])
                let (table, headerBytes) = try FSETable.read(stream, maxAccuracy: 6, maxSymbols: 255)
                guard headerBytes < stream.count else { throw Corrupt() }
                var r = try BackwardBits(UnsafeBufferPointer(rebasing: stream[headerBytes...]))
                var s1 = FSEState(), s2 = FSEState()
                s1.start(table, &r)
                s2.start(table, &r)
                while weights.count < 255 {
                    weights.append(Int(s1.peek(table)))
                    s1.update(table, &r)
                    if r.overflowed { weights.append(Int(s2.peek(table))); break }
                    weights.append(Int(s2.peek(table)))
                    s2.update(table, &r)
                    if r.overflowed { weights.append(Int(s1.peek(table))); break }
                }
            }
            // The last symbol's weight is implied: it completes the sum to a power of two.
            var sum = 0
            for w in weights where w > 0 {
                guard w <= 12 else { throw Corrupt() }
                sum += 1 << (w - 1)
            }
            guard sum > 0 else { throw Corrupt() }
            let maxBits = highBit(sum) + 1
            let left = (1 << maxBits) - sum
            guard left > 0, left & (left - 1) == 0, maxBits <= 11 else { throw Corrupt() }
            weights.append(highBit(left) + 1)
            let nbits = weights.map { $0 > 0 ? maxBits + 1 - $0 : 0 }
            var rankCount = [Int](repeating: 0, count: maxBits + 2)
            for n in nbits where n > 0 { rankCount[n] += 1 }
            var rankIndex = [Int](repeating: 0, count: maxBits + 2)
            let size = 1 << maxBits
            var symbols = [UInt8](repeating: 0, count: size), bits = [UInt8](repeating: 0, count: size)
            var i = maxBits
            while i >= 1 {
                rankIndex[i - 1] = rankIndex[i] + rankCount[i] * (1 << (maxBits - i))
                for k in rankIndex[i]..<min(rankIndex[i - 1], size) { bits[k] = UInt8(i) }
                i -= 1
            }
            for (s, n) in nbits.enumerated() where n > 0 {
                let code = rankIndex[n], len = 1 << (maxBits - n)
                guard code + len <= size else { throw Corrupt() }
                for k in code..<(code + len) { symbols[k] = UInt8(s) }
                rankIndex[n] += len
            }
            return (HuffmanTable(maxBits: maxBits, symbols: symbols, bits: bits), used)
        }

        func decode(_ stream: UnsafeBufferPointer<UInt8>, count: Int, into out: inout [UInt8]) throws {
            var r = try BackwardBits(stream)
            let mask = (1 << maxBits) - 1
            var state = Int(r.read(maxBits))
            for _ in 0..<count {
                out.append(symbols[state])
                let n = Int(bits[state])
                state = ((state << n) + Int(r.read(n))) & mask
            }
            guard r.offset == -maxBits else { throw Corrupt() }
        }
    }

    /// Literals section of a compressed block; returns the literals and the bytes used.
    static func literals(_ b: UnsafeBufferPointer<UInt8>, huffman: inout HuffmanTable?) throws -> ([UInt8], Int) {
        guard let b0 = b.first.map(Int.init) else { throw Corrupt() }
        let type = b0 & 3, sizeFormat = (b0 >> 2) & 3
        func byte(_ i: Int) throws -> Int { guard i < b.count else { throw Corrupt() }; return Int(b[i]) }
        if type <= 1 {   // raw / RLE
            var size: Int, header: Int
            switch sizeFormat {
            case 0, 2: size = b0 >> 3; header = 1
            case 1: size = (b0 >> 4) + (try byte(1) << 4); header = 2
            default: size = (b0 >> 4) + (try byte(1) << 4) + (try byte(2) << 12); header = 3
            }
            if type == 0 {
                guard header + size <= b.count else { throw Corrupt() }
                return (Array(b[header..<(header + size)]), header + size)
            }
            return ([UInt8](repeating: UInt8(try byte(header)), count: size), header + 1)
        }
        // Compressed (2) or treeless (3, the previous table).
        var regenerated: Int, compressed: Int, header: Int, streams = 4
        switch sizeFormat {
        case 0, 1:
            streams = sizeFormat == 0 ? 1 : 4
            let v = (b0 >> 4) + (try byte(1) << 4) + (try byte(2) << 12)
            regenerated = v & 0x3FF; compressed = v >> 10; header = 3
        case 2:
            let v = (b0 >> 4) + (try byte(1) << 4) + (try byte(2) << 12) + (try byte(3) << 20)
            regenerated = v & 0x3FFF; compressed = v >> 14; header = 4
        default:
            let v = (b0 >> 4) + (try byte(1) << 4) + (try byte(2) << 12) + (try byte(3) << 20) + (try byte(4) << 28)
            regenerated = v & 0x3FFFF; compressed = v >> 18; header = 5
        }
        guard header + compressed <= b.count else { throw Corrupt() }
        var body = UnsafeBufferPointer(rebasing: b[header..<(header + compressed)])
        if type == 2 {
            let (t, used) = try HuffmanTable.read(body)
            huffman = t
            body = UnsafeBufferPointer(rebasing: body[used...])
        }
        guard let table = huffman else { throw Corrupt() }
        var out: [UInt8] = []
        out.reserveCapacity(regenerated)
        if streams == 1 {
            try table.decode(body, count: regenerated, into: &out)
        } else {
            guard body.count >= 6 else { throw Corrupt() }
            let s1 = Int(body[0]) | Int(body[1]) << 8, s2 = Int(body[2]) | Int(body[3]) << 8, s3 = Int(body[4]) | Int(body[5]) << 8
            let total = body.count - 6
            guard s1 + s2 + s3 <= total else { throw Corrupt() }
            let sizes = [s1, s2, s3, total - s1 - s2 - s3]
            let per = (regenerated + 3) / 4
            var start = 6
            for (k, size) in sizes.enumerated() {
                let count = k < 3 ? per : regenerated - 3 * per
                guard count >= 0 else { throw Corrupt() }
                try table.decode(UnsafeBufferPointer(rebasing: body[start..<(start + size)]), count: count, into: &out)
                start += size
            }
        }
        return (out, header + compressed)
    }
}

// MARK: Sequences, blocks, frames

extension Zstd {
    static let llBase: [Int] = Array(0...15) + [16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]
    static let llBits: [Int] = Array(repeating: 0, count: 16) + [1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    static let mlBase: [Int] = Array(3...34) + [35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051, 4099, 8195, 16387, 32771, 65539]
    static let mlBits: [Int] = Array(repeating: 0, count: 32) + [1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    static let llDefault = [4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, -1, -1, -1, -1]
    static let mlDefault = [1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                            1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1]
    static let ofDefault = [1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1]

    /// Tables kept between the blocks of a frame (repeat modes, treeless literals).
    struct FrameState {
        var huffman: HuffmanTable?
        var ll: FSETable?, of: FSETable?, ml: FSETable?
        var offsets = [1, 4, 8]
    }

    static func table(_ mode: Int, _ b: UnsafeBufferPointer<UInt8>, at: inout Int, previous: FSETable?,
                      defaults: [Int], defaultAccuracy: Int, maxAccuracy: Int, maxSymbol: Int) throws -> FSETable {
        switch mode {
        case 0: return try FSETable(counts: defaults, accuracy: defaultAccuracy)
        case 1:
            guard at < b.count, Int(b[at]) <= maxSymbol else { throw Corrupt() }
            defer { at += 1 }
            return .rle(b[at])
        case 2:
            let (t, used) = try FSETable.read(UnsafeBufferPointer(rebasing: b[at...]), maxAccuracy: maxAccuracy, maxSymbols: maxSymbol)
            at += used
            return t
        default:
            guard let p = previous else { throw Corrupt() }
            return p
        }
    }

    static func block(_ b: UnsafeBufferPointer<UInt8>, state: inout FrameState, out: inout [UInt8]) throws {
        let (lits, litBytes) = try literals(b, huffman: &state.huffman)
        var at = litBytes
        guard at < b.count else { throw Corrupt() }
        var count = Int(b[at])
        at += 1
        if count >= 128 {
            guard at < b.count else { throw Corrupt() }
            if count < 255 {
                count = ((count - 128) << 8) + Int(b[at]); at += 1
            } else {
                guard at + 1 < b.count else { throw Corrupt() }
                count = Int(b[at]) + (Int(b[at + 1]) << 8) + 0x7F00; at += 2
            }
        }
        if count == 0 { out += lits; return }
        guard at < b.count else { throw Corrupt() }
        let modes = Int(b[at])
        at += 1
        let ll = try table(modes >> 6, b, at: &at, previous: state.ll, defaults: llDefault, defaultAccuracy: 6, maxAccuracy: 9, maxSymbol: 35)
        let of = try table((modes >> 4) & 3, b, at: &at, previous: state.of, defaults: ofDefault, defaultAccuracy: 5, maxAccuracy: 8, maxSymbol: 31)
        let ml = try table((modes >> 2) & 3, b, at: &at, previous: state.ml, defaults: mlDefault, defaultAccuracy: 6, maxAccuracy: 9, maxSymbol: 52)
        state.ll = ll; state.of = of; state.ml = ml
        guard at < b.count else { throw Corrupt() }
        var r = try BackwardBits(UnsafeBufferPointer(rebasing: b[at...]))
        var sl = FSEState(), so = FSEState(), sm = FSEState()
        sl.start(ll, &r); so.start(of, &r); sm.start(ml, &r)
        var litPos = 0
        for i in 0..<count {
            let ofCode = Int(so.peek(of)), llCode = Int(sl.peek(ll)), mlCode = Int(sm.peek(ml))
            guard ofCode <= 31, llCode < llBase.count, mlCode < mlBase.count else { throw Corrupt() }
            let offsetValue = (1 << ofCode) + Int(r.read(ofCode))
            let matchLength = mlBase[mlCode] + Int(r.read(mlBits[mlCode]))
            let literalLength = llBase[llCode] + Int(r.read(llBits[llCode]))
            if i < count - 1 { sl.update(ll, &r); sm.update(ml, &r); so.update(of, &r) }
            // Repeat offsets (RFC 8878 §3.1.1.5).
            var offset: Int
            if offsetValue > 3 {
                offset = offsetValue - 3
                state.offsets = [offset, state.offsets[0], state.offsets[1]]
            } else {
                let idx = offsetValue - 1 + (literalLength == 0 ? 1 : 0)
                if idx == 0 {
                    offset = state.offsets[0]
                } else {
                    offset = idx < 3 ? state.offsets[idx] : state.offsets[0] - 1
                    if idx > 1 { state.offsets[2] = state.offsets[1] }
                    state.offsets[1] = state.offsets[0]
                    state.offsets[0] = offset
                }
            }
            guard litPos + literalLength <= lits.count else { throw Corrupt() }
            out += lits[litPos..<(litPos + literalLength)]
            litPos += literalLength
            guard offset > 0, offset <= out.count else { throw Corrupt() }
            let from = out.count - offset
            for k in 0..<matchLength { out.append(out[from + k]) }
        }
        guard !r.overflowed || r.offset == 0 else { throw Corrupt() }
        out += lits[litPos...]
    }

    static func decode(_ b: UnsafeBufferPointer<UInt8>) throws -> [UInt8] {
        var out: [UInt8] = []
        var p = 0
        while p + 4 <= b.count {
            let magic = UInt32(b[p]) | UInt32(b[p + 1]) << 8 | UInt32(b[p + 2]) << 16 | UInt32(b[p + 3]) << 24
            p += 4
            if magic & 0xFFFF_FFF0 == 0x184D_2A50 {   // skippable frame
                guard p + 4 <= b.count else { throw Corrupt() }
                let n = Int(b[p]) | Int(b[p + 1]) << 8 | Int(b[p + 2]) << 16 | Int(b[p + 3]) << 24
                p += 4 + n
                continue
            }
            guard magic == 0xFD2F_B528, p < b.count else { throw Corrupt() }
            let fhd = Int(b[p]); p += 1
            let fcsFlag = fhd >> 6, single = fhd & 0x20 != 0, checksum = fhd & 0x04 != 0, dictFlag = fhd & 3
            guard fhd & 0x08 == 0 else { throw Corrupt() }
            if !single { p += 1 }                                     // window descriptor
            guard dictFlag == 0 else { throw Corrupt() }               // dictionaries are not supported
            p += [single ? 1 : 0, 2, 4, 8][fcsFlag]                   // frame content size (not needed)
            var state = FrameState()
            var last = false
            while !last {
                guard p + 3 <= b.count else { throw Corrupt() }
                let h = Int(b[p]) | Int(b[p + 1]) << 8 | Int(b[p + 2]) << 16
                p += 3
                last = h & 1 != 0
                let type = (h >> 1) & 3, size = h >> 3
                switch type {
                case 0:
                    guard p + size <= b.count else { throw Corrupt() }
                    out += b[p..<(p + size)]; p += size
                case 1:
                    guard p < b.count else { throw Corrupt() }
                    out += repeatElement(b[p], count: size); p += 1
                case 2:
                    guard p + size <= b.count else { throw Corrupt() }
                    try block(UnsafeBufferPointer(rebasing: b[p..<(p + size)]), state: &state, out: &out)
                    p += size
                default: throw Corrupt()
                }
                guard out.count <= 1 << 28 else { throw Corrupt() }
            }
            if checksum { p += 4 }
        }
        guard p == b.count else { throw Corrupt() }
        return out
    }
}
