---
title: Sigma detections
parent: English
nav_order: 8
---

# Sigma detections
{: .no_toc }

[Русская версия](../ru/detections.html)

1. TOC
{:toc}

## What it is

[Sigma](https://sigmahq.io) is an open format for detection rules. The app turns every rule into a
[DQL](dql.html) query, runs it against the case and stores the result. The translation is visible in
the rule card; you can copy it and run it by hand.

## Bundled rules

| Set | Rules | Version | Licence |
|---|---|---|---|
| [SigmaHQ](https://github.com/SigmaHQ/sigma) | 2,554 | Release 2026-07-09, r2026-04-01-50-g552f3fee4 | Detection Rule License 1.1 |
| [Hayabusa rules](https://github.com/Yamato-Security/hayabusa-rules) | 194 | main branch | Detection Rule License 1.1 |

- From SigmaHQ: `rules/windows/**` plus rules with `product: windows` from `rules/` and
  `rules-emerging-threats/`. From Hayabusa: `hayabusa/**` (its copies of SigmaHQ rules in `sigma/`
  are not taken).
- The 248 Hayabusa field aliases ship with the Hayabusa rules.
- The author of every rule is shown next to each match. The sets, versions and the full DRL 1.1 text
  are under Rules → Rule sets and licenses….

### Your own rules folder

- Rules → Choose custom rules folder…. Every `.yml` and `.yaml` file is read, including subfolders.
- The set is called "Custom: <folder name>". Changes in the folder are picked up on the next run.
- Turn it off with Stop using folder “…”.

## Running

- Automatically after import when Run Sigma detections after import is on (the default).
- By hand with Run Detections / Run Again on the Detections screen.
- The run is in the background. All rules are compiled first, then the substrings and masks of all
  rules are evaluated in one pass per field (Aho–Corasick), then the rules themselves run.
- Results are stored in the case and replaced by the next run. Stop keeps the previous results.

## How a rule becomes a query

### logsource

| logsource | Events |
|---|---|
| `category: process_creation` | Sysmon 1 **and** Security 4688 |
| other Sysmon categories (`network_connection`, `file_event`, `registry_*`, `dns_query`, `image_load` and more) | the matching Sysmon events |
| `ps_module`, `ps_script`, `ps_classic_*` | PowerShell 4103, 4104, 400/600/800 |
| `service: security`, `system`, … | the log from a table of 42 services |
| only `product: windows` | all logs; the rule sets the channels and EventIDs itself |

For the Security 4688 variant fields are renamed: `Image` → `NewProcessName`,
`ParentImage` → `ParentProcessName`, `IntegrityLevel` → `MandatoryLabel` (integrity levels become
`S-1-16-…` SIDs).

Rules with a `product` other than `windows` are not supported.

### Fields

- `EventID`, `Channel`, `Provider_Name`, `Computer`, `Level`, `Keywords` and the like are system fields.
- Other names are matched exactly, case-sensitively.
- If a field does not exist in the case, a condition on it is false and `null` is true. Such fields are
  listed in the rule card under Fields absent from this case.
- Hayabusa aliases (`Event.EventData.X` and so on) apply only to Hayabusa rules.

### Modifiers

| Supported | Not supported |
|---|---|
| `contains`, `startswith`, `endswith`, `all`, `re` (flags `i`, `m`, `s`), `cidr`, `gt`, `gte`, `lt`, `lte`, `exists`, `cased`, `fieldref`, `base64`, `base64offset`, `windash`, `wide`/`utf16le` (with `base64`) | `utf16`, `utf16be`, `expand`, unknown modifiers |

- `*` and `?` in values are masks; `\` escapes `*`, `?` and `\`.
- Matching is case-insensitive; `|cased` makes it case-sensitive. `re` is case-sensitive unless the
  `i` flag is set.
- Keywords are substrings in any field.

### condition

- `and`, `or`, `not`, parentheses.
- `1 of …` and `all of …` — by name, by a `*` pattern or `them`.
- A list of conditions is combined with `or`.
- Not supported: `N of` with N ≠ 1, aggregations with `|` (`count()` and the like), correlation and
  multi-document rules. `timeframe` is ignored.

### When a rule did not run

No rule disappears silently. A mark next to the title in the table, with the reason in the tooltip
and the card:

| Mark | Meaning |
|---|---|
| Grey ⊘ | Not evaluated (unsupported logsource, modifier, aggregation…) |
| Red octagon | Evaluation error |
| Orange triangle | Notes — for example, the regular expression limit |

The Not evaluated / with notes filter collects all such rules. With the bundled set, 2,734 rules are
evaluated, 11 are not supported (six `file_access`, one `file_rename`, three with `count()`
aggregation, one without a condition) and 3 Hayabusa correlation files are not loaded.

### Regular expression limit

A regular expression gets 2 seconds of CPU time per field value. Values that do not fit the limit
count as unchecked, and the rule gets a note saying how many values on which field were not checked.

## The Detections screen

**Toolbar:** Matched / All evaluated / Not evaluated / with notes / All rules, minimum level, search
by title, author, tag, path or id, the Rules menu, and starting or stopping a run with progress.

**Table:** Level, Rule, Events, Hosts, Author, First and Last match, Rule set, Status. Double-click
shows the rule's events. Context menu: Rule events, Rule events in timeline, Copy rule DQL, Copy
events query (`rule = "<id>"`).

**Rule card:**

- title, level, status, rule set, author, path and id, created and modified dates;
- notes and reasons, if any;
- "Matched events: N · hosts: M", the period, Events and In timeline buttons;
- description;
- How it was evaluated: logsource, variants with renamed fields, the final DQL with Run this DQL and
  Copy, evaluation time;
- tags — MITRE ATT&CK techniques linking to attack.mitre.org;
- False positives (according to the author), references from the rule, the source YAML.

**Footer:** run time, how many rules were evaluated, not supported, not loaded, failed and have
notes, how many matched on how many events, duration.

## Where else matches show up

- In the event details — the Matched rules block with level, title, author and rule set. A click opens
  the rule card.
- In the Events sidebar — rule levels with counts and All matched rules….
- In queries — the `rule` and `rulelevel` fields: `rule = "<id or title>"`, `rulelevel >= high`.
- Export of matched rules to CSV — see [Export](export-cli.html#exporting-detections).

## Engine check

`evtxdump sigma <case> --pack rules.json --verify` re-checks every matched rule with an independent
simplified evaluator that reads the original rule directly, and reports differences in both
directions. It checks the engine itself, not the data; the app does not have it.
