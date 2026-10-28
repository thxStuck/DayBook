---
title: FAQ and troubleshooting
parent: English
nav_order: 11
---

# FAQ and troubleshooting
{: .no_toc }

[Русская версия](../ru/faq.html)

1. TOC
{:toc}

## macOS will not open the app

The app is not notarized by Apple. Open System Settings → Privacy & Security and click Open Anyway, or
run in Terminal:

```bash
xattr -dr com.apple.quarantine /Applications/DayBookEvtxMacOS.app
```

More in [Installation](install.html#first-launch).

## A prompt asks for access to Documents (or Desktop, Downloads)

macOS protects these folders separately. Allow access, or the app cannot read the logs during import
or the XML and bytes of a record in the details. If you denied it, turn it on in System Settings →
Privacy & Security → Files and Folders → DayBookEvtxMacOS.

## A query finds nothing

1. Look at the filter bar under the query: filter chips and the orange time chip narrow the result.
   Click Reset All (⌘K).
2. `=` matches the whole value. For part of a value use `contains`, `startswith`, `endswith` or a `*`
   mask.
3. `=` compares text: `0x17` and `23` are different values. Use `<`, `>`, `between` for numbers.
4. `time` is read in the chosen time zone. Add `Z` to give a time in UTC.
5. If a field does not exist, the app shows an error with similar field names.

## The XML or Hex tab says "Source file not found"

Event fields are stored in the case; the XML and raw bytes are re-read from the source log. If the
logs were moved or deleted after import, these tabs are unavailable and everything else works. Put
the files back at the path shown on the tab.

## "The file has not responded for more than 3 seconds"

The source file takes too long to open: a network share is unavailable, an external disk is asleep, or
macOS is waiting for an answer to a folder access prompt. The interface keeps working and the Fields
tab is available.

## An event has no readable description

Readable descriptions in English and Russian exist for events common in investigations: logons,
Kerberos, processes, services, tasks, PowerShell, Sysmon, RDP, Defender and more. Other events show
their data as "Field: value" in the description column. Every field is always on the Fields tab of the
details.

## How to find an event by record number (EventRecordID)

Not yet: the record number is shown in the details and in exports, but cannot be queried.

## How to switch the interface language

DayBookEvtxMacOS menu → Interface Language, then restart. More in
[Interface language](install.html#interface-language).

## Can a case be moved to another Mac

Yes, the `.daybook` folder can be copied. For the XML and Hex tabs to work there, the logs must be at
the same paths as during import.

## Does it run on Intel Macs

An Intel build has not been tested; the release archive is for Apple Silicon only.

## How to report a bug or suggest an improvement

Open an [issue on GitHub](https://github.com/thxStuck/DayBook/issues). Include the app and
macOS versions, the steps, what you expected and what happened. Do not attach logs with personal or
confidential data.
