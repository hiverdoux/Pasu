#!/bin/zsh
# Optional signed integration diagnostic. Only UUID-scoped synthetic items.
set -euo pipefail
cd "${0:a:h}/.."
export PATH="/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/go/bin:/usr/local/bin"
# The v2.1.1 bridge applies only to the existing official identity.
PASU_RELEASE_MODE=migration go run ./scripts/signing-config
settings=".build/signing/settings.plist"
profile=$(/usr/libexec/PlistBuddy -c 'Print :Profile' "$settings")
identity=$(/usr/libexec/PlistBuddy -c 'Print :Identity' "$settings")
[[ -f "$profile" ]] || { echo "오류: profile에 실제 프로파일 파일을 지정하세요" >&2; exit 1; }
source ./scripts/signing-common.sh
team=$(/usr/libexec/PlistBuddy -c 'Print :TeamID' "$settings")
identity=$(select_pasu_identity "$team" "$identity" "$(security find-identity -v -p codesigning)")
work=$(mktemp -d "${TMPDIR:-/tmp}/pasu-group-diagnostic.XXXXXX")
trap 'rm -rf "$work"' EXIT
app="$work/GroupDiagnostic.app"
mkdir -p "$app/Contents/MacOS"
cp .build/signing/Agent-Info.plist "$app/Contents/Info.plist"
cp "$profile" "$app/Contents/embedded.provisionprofile"
cp .build/signing/Pasu.entitlements "$work/entitlements.plist"
/usr/libexec/PlistBuddy -c 'Add :keychain-access-groups:1 string AYTVXW6P5Q.com.dennis.pasu' "$work/entitlements.plist"
xcrun swiftc experiments/keychain-group/main.swift -o "$app/Contents/MacOS/pasu"
codesign --force --timestamp --options runtime --entitlements "$work/entitlements.plist" \
 --sign "$identity" "$app"
"$app/Contents/MacOS/pasu"
