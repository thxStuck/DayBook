---
title: Installation
parent: English
nav_order: 2
---

# Installation
{: .no_toc }

[Русская версия](../ru/install.html)

1. TOC
{:toc}

## Requirements

- macOS 14 or later.
- A Mac with Apple Silicon. An Intel build has not been tested.
- To build from source: Xcode with Swift 6. Tested with Xcode 27 on macOS 26.

## Installing a release

1. Open the [latest release](https://github.com/thxStuck/DayBook/releases/latest) and
   download `DayBookEvtxMacOS-<version>-arm64.zip`.
2. Unzip it and move `DayBookEvtxMacOS.app` to Applications.
3. To verify the download, compare its SHA-256 with the value in the release notes:

   ```bash
   shasum -a 256 ~/Downloads/DayBookEvtxMacOS-*-arm64.zip
   ```

### First launch

The app is signed locally (ad hoc) and is not notarized by Apple, which requires a paid Developer ID.
macOS therefore refuses to open it the first time.

1. Close the warning.
2. Open System Settings → Privacy & Security.
3. Next to the message about DayBookEvtxMacOS, click Open Anyway and enter an administrator password.

The same in Terminal — the command removes the "downloaded from the internet" mark:

```bash
xattr -dr com.apple.quarantine /Applications/DayBookEvtxMacOS.app
```

### Folder access

The app is not sandboxed: a forensic tool has to read files wherever they are. macOS still protects
Documents, Desktop, Downloads, external and network volumes separately and asks for permission the
first time the app reads from them.

- Allow access, or the app cannot read the logs during import or the XML and Hex tabs of an event.
- If access was denied, turn it on in System Settings → Privacy & Security → Files and Folders →
  DayBookEvtxMacOS.
- Every locally signed build is a new app to macOS, so the prompt may appear again after an update.

## Interface language

The interface is available in Russian and English. By default macOS picks it from the system: Russian
if Russian comes first in the system languages, English otherwise.

To change it in the app: **DayBookEvtxMacOS → Interface Language** → System Language, Русский or
English. The language applies at launch, so the app offers to restart; the open case opens again.

It is the same setting as System Settings → General → Language & Region → Applications. It can also
be set in Terminal:

```bash
defaults write app.daybook.evtx AppleLanguages -array en
```

Back to the system language:

```bash
defaults delete app.daybook.evtx AppleLanguages
```

## Help and About

- **Help → DayBookEvtxMacOS Help** (⌘?) opens this documentation in the system help window, without
  internet access. The search field of the Help menu searches it too.
- The same menu has the documentation and the DQL reference online, Report a Bug… and the project
  page on GitHub.
- **DayBookEvtxMacOS → About DayBookEvtxMacOS** shows the version, links and third-party components
  with their licences.

## Building from source

```bash
git clone https://github.com/thxStuck/DayBook.git
cd DayBook
scripts/build.sh
open build/DayBookEvtxMacOS.app
```

The script builds:

- the app in Release configuration — `build/DayBookEvtxMacOS.app`;
- the command-line tool — `Packages/DaybookKit/.build/release/evtxdump`
  (see [Export and command line](export-cli.html)).

If `xcode-select` points to the Command Line Tools, the script uses
`DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer` by itself. You can also open
`DayBookEvtxMacOS.xcodeproj` in Xcode and press ⌘R.

The only external dependency is [Yams](https://github.com/jpsim/Yams) (MIT) for reading Sigma YAML.
Swift Package Manager downloads it on the first build.

## Where things are kept

| What | Where |
|---|---|
| A case | The `<name>.daybook` folder wherever you saved it during import |
| Source logs | Stay where they are; the case stores their absolute paths |
| App settings | The `app.daybook.evtx` domain (`defaults read app.daybook.evtx`) |
| Bundled Sigma rules | Inside the app: `Contents/Resources/rules.json` |
