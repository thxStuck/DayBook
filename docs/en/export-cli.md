---
title: Export and command line
parent: English
nav_order: 9
---

# Export and command line
{: .no_toc }

[Русская версия](../ru/export-cli.html)

1. TOC
{:toc}

## Exporting events

The Export menu on the toolbar exports the **current result**: query, filters, time range, and only
the selected group if one is selected. Rows keep the on-screen order. The file is revealed in Finder
afterwards.

| Format | Details |
|---|---|
| CSV | Comma, UTF-8 without BOM, CRLF line ends, RFC 4180 quoting. Values are unchanged |
| CSV for Excel (;) | Semicolon and BOM. Values starting with `=`, `+`, `-`, `@`, a tab or CR get a leading apostrophe so Excel does not run them as formulas |
| JSON Lines | One event per line. `source_file` is the full path. Repeated fields in `data` become arrays |
| Excel (XLSX) | An events sheet with a frozen header and autofilter; an information sheet with the export parameters |

### Columns

| Column | Contents |
|---|---|
| `Time (<zone>)` | Time in the chosen zone, to milliseconds |
| `TimeUTC` | Time in UTC, 7 fraction digits and `Z` |
| `Computer`, `Channel`, `Provider`, `EventID` | System fields |
| `Level` | Level as a number |
| `UserSID`, `RecordID` | The user SID from System and the record number |
| `SourceFile`, `SourceSHA256` | Source file name and its SHA-256 |
| `Flags` | Record flags |
| Your columns | Fields you added to the table |
| `EventData` | Every event field as "name: value \| …" |

### XLSX details

- EventID, Level and RecordID are written as numbers; everything else as text, never as formulas.
- Up to 1,048,575 rows (the Excel limit). A larger result asks you to narrow the query.
- Cells longer than 32,767 characters are cut and end with "…[cut: full length N characters]"; their
  number is on the information sheet.
- The information sheet: case path, export time (UTC), time zone, query, filters, time range, row
  order, number of events, source files with SHA-256 and record counts.

{: .note }
The event description (the Description / event data column in the table) is built for display and is
not exported. All event data is in the `EventData` column.

## Exporting detections

On the Detections screen the matched rules can be saved as CSV — plain or for Excel (with the same
formula protection). Columns: `Level`, `Rule`, `Events`, `Hosts`, first and last match in the chosen
zone and in UTC, `Author`, `RuleSet` (SigmaHQ, Hayabusa or your folder), `RulePath`, `RuleID`,
`Status`, `Tags` (including MITRE ATT&CK techniques), `References`, `License` and `DQL` — the query
the rule became.

## The evtxdump command-line tool

Built with the app by `scripts/build.sh`: `Packages/DaybookKit/.build/release/evtxdump`. It uses the
same core as the app.

| Command | Syntax | Purpose |
|---|---|---|
| `ingest` | `<case.daybook> <files/folders>… [--no-merge] [--no-carve] [--no-hash]` | Create a case. The case folder must not exist. Detections are not run |
| `dql` | `<case> "<query>"` | Run a DQL query. Times are printed in UTC |
| `query` | `<case> [key=value \| key!=value]… [--facet key]` | Filters like in the app: first rows of the result and timings |
| `entities` | `<case> [--rebuild]` | Show or rebuild the registry of hosts, users and IPs |
| `sessions` | `<case>` | Logon and RDP sessions |
| `processes` | `<case>` | Process trees |
| `sigma` | `<case> --pack rules.json [--dir folder] [--rule id\|path] [--compile-only] [--verify] [--top N]` | Run Sigma rules. Results are written to the case |
| `export` | `<case> <out.csv\|out.jsonl\|out.xlsx> ["DQL"] [--fields a,b]` | Export; the format comes from the extension |
| `stats` | `<files/folders>…` | State of files and chunks without creating a case |
| `carve` | `<files/folders>…` | Slack recovery statistics |
| `xml` | `<file> [--limit N] [--jsonl]` | XML of a file's live records |
| `json` | `<file> [--limit N]` | A file's records, one JSON line each |

### Examples

```bash
evtxdump ingest case.daybook /path/to/winevt/logs
evtxdump dql case.daybook 'EventID = 4625 | group by IpAddress'
evtxdump sigma case.daybook --pack DayBookEvtxMacOS/Resources/Rules/rules.json --top 20
evtxdump export case.daybook out.xlsx 'EventID = 4688'
evtxdump stats /path/to/logs
```

### Differences from the app

- `export` cannot write CSV for Excel and prints times in UTC only.
- In `dql`, times in a query are UTC and only in the form `YYYY-MM-DD[ HH:MM[:SS]]`: no fractions,
  no `Z` suffix, no offsets.
- In `export`, time conditions in the query are not supported and return an error. Use `dql` to find
  what you need, or export from the app.
