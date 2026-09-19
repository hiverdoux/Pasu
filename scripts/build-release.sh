#!/bin/zsh
# Developer ID + provisioning profile로 배포용 Pasu.app을 만든다.
# 일반 사용자 권한으로 실행한다. 결과는 final이면 dist/Pasu.app,
# migration이면 dist/migration/Pasu.app에 저장한다.
set -euo pipefail
export PATH="/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/go/bin:/usr/local/bin"

REPO="${0:a:h:h}"
cd "$REPO"

source "$REPO/scripts/signing-common.sh"
go run ./scripts/signing-config
GENERATED="$REPO/.build/signing"
settings="$GENERATED/settings.plist"
TEAM_ID=$(/usr/libexec/PlistBuddy -c 'Print :TeamID' "$settings")
AGENT_BUNDLE_ID=$(/usr/libexec/PlistBuddy -c 'Print :AgentBundleID' "$settings")
GUI_BUNDLE_ID=$(/usr/libexec/PlistBuddy -c 'Print :GUIBundleID' "$settings")
APP_ID="$TEAM_ID.$AGENT_BUNDLE_ID"
ACCESS_GROUP="$APP_ID"
IDENTITY=$(/usr/libexec/PlistBuddy -c 'Print :Identity' "$settings")
PROFILE=$(/usr/libexec/PlistBuddy -c 'Print :Profile' "$settings")
MODE="${PASU_RELEASE_MODE:-final}"
case "$MODE" in
 final) APP="$REPO/dist/Pasu.app" ;;
 migration) APP="$REPO/dist/migration/Pasu.app" ;;
 *) echo "오류: PASU_RELEASE_MODE는 final 또는 migration" >&2; exit 1 ;;
esac
AGENT_APP="$APP/Contents/Library/LoginItems/PasuAgent.app"
AGENT_BIN="$AGENT_APP/Contents/MacOS/pasu"
GUI_BIN="$APP/Contents/MacOS/Pasu"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/pasu-release.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

if [[ -z "$PROFILE" ]]; then
	echo "오류: 프로파일을 설정하지 않았습니다. signing.local.json의 profile 또는 PASU_PROFILE에 agent용 Developer ID 프로파일 경로를 지정하세요. docs/BUILDING.md를 참고하세요" >&2
	exit 1
fi
if [[ ! -f "$PROFILE" ]]; then
	echo "오류: Developer ID provisioning profile 없음: $PROFILE" >&2
	exit 1
fi
identities=$(security find-identity -v -p codesigning)
identity_sha=$(select_pasu_identity "$TEAM_ID" "$IDENTITY" "$identities")
IDENTITY="${IDENTITY:-$identity_sha}"
security cms -D -i "$PROFILE" > "$WORK/profile.plist"
assert_pasu_profile "$WORK/profile.plist" "$TEAM_ID" "$AGENT_BUNDLE_ID"
assert_profile_certificate "$WORK/profile.plist" "$identity_sha" "$WORK"

./build.sh
V=$(<VERSION)
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$AGENT_APP/Contents/MacOS"
cp "$GENERATED/Info.plist" "$APP/Contents/Info.plist"
cp PasuGUI "$GUI_BIN"
cp "$GENERATED/Agent-Info.plist" "$AGENT_APP/Contents/Info.plist"
cp "$PROFILE" "$AGENT_APP/Contents/embedded.provisionprofile"
chmod 644 "$AGENT_APP/Contents/embedded.provisionprofile"
mkdir -p "$APP/Contents/Library/LaunchAgents"
cp "$GENERATED/PasuAgent.plist" "$APP/Contents/Library/LaunchAgents/$AGENT_BUNDLE_ID.plist"
cp "$GENERATED/Pasu.entitlements" "$WORK/agent.entitlements"
if [[ "$MODE" == migration ]]; then
 /usr/libexec/PlistBuddy -c "Add :keychain-access-groups:1 string $TEAM_ID.com.dennis.pasu" "$WORK/agent.entitlements"
fi
cp pasu "$AGENT_BIN"
plutil -replace CFBundleShortVersionString -string "$V" "$APP/Contents/Info.plist"
plutil -replace CFBundleVersion -string "$V" "$APP/Contents/Info.plist"
plutil -replace CFBundleShortVersionString -string "$V" "$AGENT_APP/Contents/Info.plist"
plutil -replace CFBundleVersion -string "$V" "$AGENT_APP/Contents/Info.plist"

codesign --force --timestamp --options runtime \
	--entitlements "$WORK/agent.entitlements" \
	--sign "$identity_sha" "$AGENT_APP"
plutil -insert PasuKeychainMigration -bool "$([[ "$MODE" == migration ]] && echo true || echo false)" "$APP/Contents/Info.plist"
codesign --force --timestamp --options runtime --sign "$identity_sha" "$APP"
codesign --verify --deep --strict --verbose=2 "$APP"

GUI_SIG_INFO=$(codesign --display --verbose=4 "$APP" 2>&1)
[[ "$GUI_SIG_INFO" == *"Identifier=$GUI_BUNDLE_ID"* ]] || { echo "오류: GUI Bundle ID 서명 불일치" >&2; exit 1; }
[[ "$GUI_SIG_INFO" == *"TeamIdentifier=$TEAM_ID"* ]] || { echo "오류: GUI Team ID 서명 불일치" >&2; exit 1; }
has_hardened_runtime "$GUI_SIG_INFO" || { echo "오류: GUI hardened runtime 없음" >&2; exit 1; }
AGENT_SIG_INFO=$(codesign --display --verbose=4 "$AGENT_APP" 2>&1)
[[ "$AGENT_SIG_INFO" == *"Identifier=$AGENT_BUNDLE_ID"* ]] || { echo "오류: agent Bundle ID 서명 불일치" >&2; exit 1; }
[[ "$AGENT_SIG_INFO" == *"TeamIdentifier=$TEAM_ID"* ]] || { echo "오류: agent Team ID 서명 불일치" >&2; exit 1; }
has_hardened_runtime "$AGENT_SIG_INFO" || { echo "오류: agent hardened runtime 없음" >&2; exit 1; }

codesign --display --entitlements :- "$AGENT_APP" > "$WORK/entitlements.plist" 2>/dev/null
codesign --display --entitlements :- "$APP" > "$WORK/gui-entitlements.plist" 2>/dev/null || true
security cms -D -i "$AGENT_APP/Contents/embedded.provisionprofile" > "$WORK/final-profile.plist"
ent_app=$(/usr/libexec/PlistBuddy -c 'Print :com.apple.application-identifier' "$WORK/entitlements.plist")
ent_team=$(/usr/libexec/PlistBuddy -c 'Print :com.apple.developer.team-identifier' "$WORK/entitlements.plist")
ent_group=$(/usr/libexec/PlistBuddy -c 'Print :keychain-access-groups:0' "$WORK/entitlements.plist")
if [[ "$ent_app" != "$APP_ID" || "$ent_team" != "$TEAM_ID" || "$ent_group" != "$ACCESS_GROUP" ]]; then
	echo "오류: 최종 앱 entitlement 불일치" >&2
	exit 1
fi
assert_pasu_profile "$WORK/final-profile.plist" "$TEAM_ID" "$AGENT_BUNDLE_ID"
if /usr/libexec/PlistBuddy -c 'Print :com.apple.security.get-task-allow' "$WORK/entitlements.plist" >/dev/null 2>&1; then
	echo "오류: 배포본에 get-task-allow가 포함됨" >&2
	exit 1
fi
if [[ -s "$WORK/gui-entitlements.plist" || -e "$APP/Contents/embedded.provisionprofile" ]]; then
 echo "오류: GUI는 entitlement/profile이 없어야 합니다" >&2; exit 1
fi
PASU_CANDIDATE_APP="$APP" PASU_RELEASE_MODE="$MODE" ./scripts/launchd.sh verify-app
if [[ "$("$AGENT_BIN" -version)" != "pasu $V" ]]; then
	echo "오류: 앱 실행 파일과 VERSION 불일치" >&2
	exit 1
fi

echo "배포 앱 빌드 완료: $APP"
echo "  identity: $IDENTITY"
echo "  gui-id:   $TEAM_ID.$GUI_BUNDLE_ID"
echo "  agent-id: $APP_ID"
echo "  group:    $ACCESS_GROUP"
echo "  version:  $V"
