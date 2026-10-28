import EvtxCore
import Foundation

/// The file system timeline UAC writes (`bodyfile/bodyfile.txt`, Sleuth Kit body format:
/// `MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime`, Unix seconds). As in `mactime`,
/// the times of a file that coincide become one event with a `MACB` mark (`m.c.`); a time of 0 is
/// "unknown" and makes no event.
enum Bodyfile {
    struct Line {
        var md5: Substring, name: String, inode: Substring, mode: Substring
        var uid: Substring, gid: Substring, size: Substring
        /// m, a, c, b
        var times: [Int64]
    }

    static func split(_ text: String) -> Line? {
        let p = text.split(separator: "|", omittingEmptySubsequences: false)
        guard p.count >= 11 else { return nil }
        let n = p.count
        let times = [p[n - 3], p[n - 4], p[n - 2], p[n - 1]].map { Int64($0) ?? 0 }   // m a c b
        return Line(md5: p[0], name: p[1..<(n - 9)].joined(separator: "|"), inode: p[n - 9], mode: p[n - 8],
                    uid: p[n - 7], gid: p[n - 6], size: p[n - 5], times: times)
    }

    /// Distinct times of a line with their MACB mark and the index of their first letter.
    static func events(_ l: Line) -> [(seconds: Int64, macb: String, index: Int)] {
        var out: [(Int64, String, Int)] = []
        let letters: [Character] = ["m", "a", "c", "b"]
        for (i, t) in l.times.enumerated() where t > 0 && !l.times[..<i].contains(t) {
            let mark = String(letters.enumerated().map { l.times[$0.offset] == t ? $0.element : "." })
            out.append((t, mark, i))
        }
        return out
    }

    /// Pass 1: keys (one per distinct time of each line), jobs of whole lines.
    static func plan(_ p: LinuxSourcePlan, data: Data, src: Int) -> (jobs: [LinuxJob], keys: [[RecordKey]], skipped: Int) {
        var jobs: [LinuxJob] = [], keys: [[RecordKey]] = [], current: [RecordKey] = []
        var job = LinuxJob(source: src, bytes: 0..<data.count, firstLine: 1, formatName: "bodyfile")
        var skipped = 0
        LogLines.forEach(data, in: 0..<data.count, firstNumber: 1) { line in
            if current.count >= LinuxText.recordsPerJob {
                job.bytes = job.bytes.lowerBound..<line.offset
                jobs.append(job)
                keys.append(current)
                current = []
                job = LinuxJob(source: src, bytes: line.offset..<data.count, firstLine: line.number, formatName: "bodyfile")
            }
            guard let l = split(line.text) else { skipped += 1; return true }
            let evs = events(l)
            if evs.isEmpty { skipped += 1 }
            for e in evs {
                current.append(RecordKey(ts: FileTime.fromUnixSeconds(e.seconds), computer: p.host, channel: p.channel,
                                         rid: UInt64(line.number), eid: 0, src: src, chunk: e.index, off: line.offset, flags: []))
            }
            return true
        }
        jobs.append(job)
        keys.append(current)
        return (jobs, keys, skipped)
    }

    /// Pass 2: the records of a job, in the order of pass 1.
    static func records(_ p: LinuxSourcePlan, data: Data, job: LinuxJob, users: [Int: String]) -> [CaseRecord] {
        var out: [CaseRecord] = []
        LogLines.forEach(data, in: job.bytes, firstNumber: job.firstLine) { line in
            guard line.offset < job.bytes.upperBound else { return false }
            guard let l = split(line.text) else { return true }
            for e in events(l) {
                var f = LinuxFields(host: p.host)
                f.add("Message", "\(e.macb) \(l.name)")
                f.action("file_time")
                f.add("MACB", e.macb)
                f.add("FilePath", l.name)
                f.add("FileName", (l.name as NSString).lastPathComponent)
                f.add("Inode", l.inode)
                f.add("Mode", l.mode)
                f.add("Uid", l.uid)
                if let uid = Int(l.uid), let name = users[uid] { f.add("FileOwner", name) }
                f.add("Gid", l.gid)
                f.add("Size", l.size)
                if l.md5 != "0" { f.add("Md5", l.md5) }
                let ts = FileTime.fromUnixSeconds(e.seconds)
                out.append(CaseRecord(timestamp: ts, writtenTime: ts, recordId: UInt64(line.number), provider: "bodyfile",
                                      channel: p.channel, computer: p.host, flags: [], fields: f.list))
            }
            return true
        }
        return out
    }
}
