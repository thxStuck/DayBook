#!/bin/zsh
# Builds DayBookEvtxMacOS (Release) into build/DayBookEvtxMacOS.app and the evtxdump CLI.
#   scripts/build.sh            # app + CLI
#   open build/DayBookEvtxMacOS.app
set -euo pipefail
cd "${0:A:h}/.."
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"

log=build/xcodebuild.log
mkdir -p build
if ! xcodebuild -project DayBookEvtxMacOS.xcodeproj -scheme DayBookEvtxMacOS -configuration Release \
        -derivedDataPath build/DerivedData.noindex build > "$log" 2>&1; then
    grep -E "error:" "$log" | head -20
    echo "App build failed, full log: $log"
    exit 1
fi
rm -rf build/DayBookEvtxMacOS.app
ditto build/DerivedData.noindex/Build/Products/Release/DayBookEvtxMacOS.app build/DayBookEvtxMacOS.app

# The linker's debug map lists every object file with its absolute path on this machine (user
# name, folders). The distributed binary must not carry it: strip it (the symbols stay in the
# dSYM next to the build products), sign again (ad hoc, hardened runtime, no debugger entitlement)
# and refuse the build if any path of this machine is still inside.
bin=build/DayBookEvtxMacOS.app/Contents/MacOS/DayBookEvtxMacOS
strip -S -x "$bin"
codesign --force --sign - --options runtime build/DayBookEvtxMacOS.app
for leak in "$PWD" "$HOME" "/Users/$USER" "-Users-$USER" "$USER"; do
    if /usr/bin/grep -a -q -F -- "$leak" "$bin"; then
        echo "The app binary still contains \"$leak\" (a path or name of this machine) — not usable for a release"
        exit 1
    fi
done
echo "App: $PWD/build/DayBookEvtxMacOS.app"

(cd Packages/DaybookKit && swift build -c release > ../../build/swiftbuild.log 2>&1) || {
    echo "CLI build failed, log: build/swiftbuild.log"
    exit 1
}
echo "CLI: $PWD/Packages/DaybookKit/.build/release/evtxdump"
