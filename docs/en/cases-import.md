---
title: Cases and import
parent: English
nav_order: 3
---

# Cases and import
{: .no_toc }

[Русская версия](../ru/cases-import.html)

1. TOC
{:toc}

## What a case is

A case is a `<name>.daybook` folder into which the app parses the logs once. Everything else —
search, timeline, entities, detections — works on the case.

| File in the case folder | Contents |
|---|---|
| `case.sqlite` | The case database: events, value dictionary, indexes, entities, bookmarks, detection results. `case.sqlite-wal` and `case.sqlite-shm` may sit next to it |
| `ts.bin` | The time of every event (FILETIME, UTC), 8 bytes each, in time order. Time-range bounds are found in it instantly |
| `manifest.json` | Import summary: schema version, date, chosen sources, totals (files, events, copies, recovered records, errors, duration) |

- Source logs are **not copied** into the case. The case stores the absolute path of every file, its
  size, its SHA-256 (if enabled) and parsing statistics.
- All event fields live in the case. Only the XML and the raw bytes of a record (the XML and Hex tabs
  in the details) are read from the source file on demand.
- The case folder can be moved. If the source logs are moved, everything keeps working except the
  XML and Hex tabs, which then say that the source file was not found and show the path where it
  was expected. There is no way to point a case at a new location of its sources yet.

Open a case with File → Open Case… (⌘O) and choose the `.daybook` folder. Recent cases are listed on
the start screen. Close it with File → Close Case (⇧⌘W).

## Creating a case

1. File → New Case from Logs… (⌘N).
2. Choose one or more folders with logs and/or individual `.evtx` files — or an extracted UAC
   collection of a Linux system.
3. Choose where to save the case. The default is `~/Documents/DayBook/<source name>.daybook`.
   If a case with that name exists, macOS asks whether to replace it.
4. In the import options choose the system: **Windows — .evtx logs** or **Linux — UAC collection**. It
   is preselected from the folders' content; the sheet shows how many `.evtx` files and which UAC
   collections were found. Linux has its own page: [Linux (UAC collections)](linux.html).
5. Check the import options and click Start Import.

### Import options

All options are on by default and remembered for the next imports.

| Option | What it does |
|---|---|
| Recover records from chunk slack space | Looks for remnants of old records in the free part of chunks. Every recovered record gets the `carved` flag |
| Merge identical records | The same record from the live log, a shadow copy and slack is shown as one event with the `hasCopies` flag. Off: every copy is its own row |
| Compute SHA-256 of source files | Fixes the source data: the hash is shown in Case Information and goes into exports |
| Run Sigma detections after import | After the case opens, the bundled rules and your rules folder run in the background. Results are saved in the case |

## Which files are included

- Folders are walked recursively; hidden files are skipped.
- Inside folders the app takes `*.evtx` files (extension in any case) and files without an extension
  that start with the `ElfFile\0` signature.
- Files you choose explicitly are taken regardless of extension — the format is checked by signature.
- Symbolic links: a chosen link is resolved; links to files inside folders are followed; links to
  folders are not entered (to avoid cycles).
- The old `.evt` format (Windows XP/2003) is recognised but not supported.
- A file that cannot be opened is listed under failed files in Case Information; the other files are
  still imported.

## Import phases

1. Finding log files.
2. SHA-256 of source files.
3. Parsing records (in parallel by chunk, collecting templates from all files).
4. Recovering records from slack.
5. Sorting by time and merging copies.
6. Writing events to the case database — the only phase with a percentage.
7. Field index.
8. Database indexes.
9. Full-text index.
10. Registry of hosts, users and IPs.

During the import you see the current phase, how many events are written and the elapsed time.
Cancel stops the import and removes the unfinished case folder. The case opens by itself when the
import is done.

## How files are parsed

The app uses its own EVTX parser and does not depend on the Windows API.

- **Every physical chunk.** The number of chunks comes from the file size, not from the counter in
  the header: in live (dirty) logs that counter is stale, and the newest events sit in chunks beyond
  it. Such events get the `beyondHeader` flag.
- **An incomplete last chunk** (shorter than 64 KiB) is not parsed. Its size is shown as
  "Tail, bytes" in Case Information.
- **Checksums.** The CRC32 of each chunk header and of its records area are checked. On a mismatch
  parsing continues and the records of that chunk are flagged.
- **A damaged area** inside a chunk is skipped up to the next valid record. Records after the gap get
  the `afterGap` flag.
- **A parse error** does not drop the record: everything read so far is kept, the record gets the
  `parseError` flag, and the XML gets a comment where parsing stopped.
- **BinXML templates** come from the same chunk. If the template is not there (as with recovered
  records), it is looked up in every file of the case — `foreignTemplate` flag. If it is found nowhere,
  values are shown as `Value[n]` — `missingTemplate` flag.

## Recovering records from slack

Slack is the free part of a chunk after its last live record. Old records often remain there.

- The area after `freeSpaceOffset` (in a chunk without a valid header — the whole chunk from byte 512)
  is scanned in 8-byte steps.
- A candidate is accepted only if everything matches: the record marker `0x00002A2A`, a size of at
  least 28 bytes that fits the chunk, the copy of the size at the end of the record, a valid BinXML
  start, and a write time between 1990 and 2100.
- Recovered records get the `carved` flag; their time is shown in orange.
- If the same record exists among live records and merging is on, the live record stays and the
  recovered one becomes its copy.

## Merging copies

Records are copies when all four of these match:

- TimeCreated to 100 ns (or the write time if there is none);
- computer and log (case-insensitive);
- RecordID;
- EventID.

A live record wins over a recovered one; then the file whose path sorts first, then the lower chunk
and offset. The event gets the `hasCopies` flag, and the details get a Copies of this record section
listing every location: file, chunk, offset.

{: .note }
The file filter and per-file counts consider only the main copy of an event. How many copies from a
file went into other events is shown in the "Copies merged" column of Case Information.

## Record flags

| Flag (for `flag = …`) | Meaning |
|---|---|
| `beyondHeader` | The record is in a chunk beyond the chunk count in the file header (usually the newest data) |
| `stale` | Such a chunk whose record numbers are not newer than the live ones — remnants of old data |
| `crcMismatch` | The CRC of the chunk data does not match |
| `headerCrcMismatch` | The CRC of the chunk header does not match |
| `carved` | Recovered from slack |
| `parseError` | The record was parsed only partly |
| `sizeMismatch` | The copy of the size at the end of the record differs from the size at the start |
| `foreignTemplate` | The template was taken from another chunk or file |
| `missingTemplate` | No template was found; values are shown as `Value[n]` |
| `timeSkew` | TimeCreated and the time the record was written differ by more than 60 seconds |
| `invalidText` | Invalid UTF-16; characters were replaced with U+FFFD |
| `hasCopies` | Copies from other places were merged into this event |
| `afterGap` | A live record after a damaged area of the chunk |
| `yearInferred` | Linux: no year in the line, inferred from the file's date |
| `zoneAssumed` | Linux: no zone in the line, the system's zone from `uac.log` assumed |
| `timeCarried` | Linux: no time of its own — the time of a neighbouring record |
| `timeFromFile` | Linux: no time of its own — the file's modification time |
| `unparsed` | Linux: the line matched no format and is kept whole in `Message` |
| `notDecompressed` | Linux: a compressed value (journald) could not be unpacked |

Where flags are visible:

- the Flags line in the event details;
- the time colour in the table: red for `parseError`, orange for `carved`, `stale` and `afterGap`;
- the Record flags section of the Events sidebar — a click adds a filter;
- queries such as `flag = carved` or `flag = timeSkew` and the log-artefact presets;
- the Record flags column in Case Information;
- the `Flags` column in exports.

## Case Information

The ⓘ button on the toolbar. At the top there is a summary:

- events, files, creation date, schema version;
- how many records were recovered from slack (found and unique), how many copies were merged, how
  many parse errors there were;
- import options;
- files that could not be opened, in red.

Below is a table with one row per file:

| Column | Shows |
|---|---|
| File, Size, SHA-256, Version | Name (full path in the tooltip), size, hash, format version |
| Dirty | The file was not closed cleanly by the system |
| Chunks (header / physical) | How many chunks the header lists and how many physically exist |
| Empty | Chunks without records |
| Beyond header: new / stale | Chunks beyond the header count with new data and with stale data |
| CRC header / data | Chunks with a wrong header or data checksum |
| Tail, bytes | Size of the incomplete last chunk, which is not parsed |
| Events, Recovered, Copies merged | Events from the file, how many came from slack, how many copies went into other events |
| First, Last | Time of the first and last event |
| Record flags | How many records have each flag |

Deviations are highlighted in orange. Copy table (TSV) copies the table with full paths, ready for a
report.
