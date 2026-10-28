---
title: How it works
parent: English
nav_order: 10
---

# How it works
{: .no_toc }

[Русская версия](../ru/internals.html)

1. TOC
{:toc}

## Principles

- **Source data is only read.** Logs are opened read-only and mapped into memory read-only. The app
  opens the case database for reading; only bookmarks and detection results are written, over a
  separate connection.
- **Nothing is hidden.** Recovered records, chunks beyond the header, checksum errors, heuristic
  links, unsupported rules, limits and skips are all marked and explained in the interface.
- **Queries are not SQL.** User text never becomes an SQL statement.

## Components

| Module | Does |
|---|---|
| App | SwiftUI and AppKit. The event table is an `NSTableView`: a SwiftUI table does not stay smooth with millions of rows |
| `EvtxCore` | Own EVTX and BinXML parser in Swift, no external libraries |
| `DaybookStore` | Import, the SQLite case store, the DQL engine, entities, sessions, processes, export |
| `DaybookSigma` | Sigma rule parsing, translation to DQL, runs, engine check |
| `evtxdump` | Command-line tool on the same core |

The only external dependency is [Yams](https://github.com/jpsim/Yams) (MIT) for Sigma YAML.

## EVTX parser

- The file is memory-mapped. The format is recognised by the `ElfFile\0` signature, not the extension.
- 64 KiB chunks are independent, so they are parsed in parallel on all cores.
- **Every physical chunk** is read, not only those listed in the header. In live logs the header's
  chunk count is stale, and the newest events sit in chunks beyond it.
- The CRC32 of each chunk header and data is checked. A mismatch does not stop parsing; it flags the
  records.
- BinXML templates are parsed once per chunk and cached; nested BinXML is supported.
- Every value type of the format is supported: strings, numbers, GUIDs, SIDs, FILETIME, SYSTEMTIME,
  binary data, arrays.
- A record with a parse error is not lost: everything read is kept and the record is flagged.
- The slack space of chunks is scanned for remnants of old records (see
  [Recovering records](cases-import.html#recovering-records-from-slack)).

## Import

1. A parallel pass over all chunks: system fields, time, record location; the template library of all
   files is collected on the way.
2. Recovering records from slack with the templates of the whole case.
3. Sorting by time. Events are numbered in time order, so any list of event numbers is already sorted
   by time. Identical copies are merged.
4. A second parallel parse writes events to the database in batches of 256 chunks.
5. Indexes: posting lists, database indexes, full-text index, entity registry.

## Case store

- **String dictionary.** Every unique value or field name is stored once, with a hash of its
  lower-cased form and its numeric value if it is a number.
- **Events.** One row per event: time, system fields and packed "field → value" pairs. The table and
  the details are shown without joins.
- **Posting lists.** For every "field = value" pair, a sorted, compressed list of event numbers.
  System properties are the same pairs with keys `@EventID`, `@Channel` and so on.
- **Full-text index** — trigram FTS5 over the dictionary for substring search.
- **`ts.bin`** — event times in a row; a time range is a binary search.
- **XML and raw bytes** are not stored: when the details open, the record is re-read from the source
  file at its stored location (chunk and offset). The record number is compared to notice a changed
  file. The exception is records with a foreign or missing template: their XML is saved at import.

## Query execution

A query is parsed into a tree. Each condition becomes a set of event numbers through the dictionary
and posting lists; `and`, `or`, `not` are intersection, union and difference of sorted sets. More in
[DQL](dql.html#how-a-query-runs).

## Event details

The event fields come from the case and appear at once. The XML and bytes of the record are read from
the source file separately, on a background thread and without holding the database lock, so a slow or
unavailable file does not stall the interface. While the file is being read, the XML and Hex tabs show
the state: reading, the file is not responding (over 3 seconds), not found, no access, or the file
changed after import.

## Performance

Measured on a Mac with an Apple M5 Pro; the test set is 108 logs of a domain controller (906 MB,
632,872 events):

| Operation | Time |
|---|---|
| Import | about 13 s |
| Typical queries | 1–380 ms |
| All 2,748 Sigma rules | about 8 s |
| Import of 10 copies of the set (6.4 million events) | 67 s, peak memory 2.2 GB |
| Sigma rules on 6.4 million events | 24.5 s |

## Limitations

| Limitation | Details |
|---|---|
| Number of events | Fewer than 2³¹ per case |
| Number of files | Fewer than 65,535 per case |
| Memory during import | About 64 bytes per record plus the whole "field = value" index in memory until the import ends |
| `.evt` format | Windows XP/2003 is not supported |
| Incomplete last chunk | Not parsed; its size is shown in Case Information |
| File header CRC | Computed but not shown yet |
| Event description | Built for display: not searchable and not exported |
| EventRecordID, ProcessID, ThreadID | Shown in the details and exports, but not queryable yet |
| New location of sources | Moved logs cannot be re-linked to a case yet |
| Intel Macs | Not tested |
