#!/bin/zsh
# Developer ID 앱 결속과 가짜 ad-hoc 교체본의 Keychain 차단을 검증한다.
# 실제 비밀은 읽지 않고 interactionNotAllowed 기반 보호 상태만 조회한다.
# 해당 계정에 registry-v2 항목이 있어야 한다. 최초 설치용 검사가 아니다.
set -euo pipefail
export PATH="/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/go/bin:/usr/local/bin"
cd "${0:a:h}/.."

APP="dist/Pasu.app"
BIN="$APP/Contents/Library/LoginItems/PasuAgent.app/Contents/MacOS/pasu"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/pasu-release-verify.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

[[ -x "$BIN" ]] || { echo "오류: $APP 없음 — scripts/build-release.sh 먼저" >&2; exit 1; }
./scripts/launchd.sh verify-app
[[ "$(./pasu -build-identity)" == "$("$BIN" -build-identity)" ]] || { echo "오류: 개발용 빌드와 서명 앱의 신원이 다릅니다" >&2; exit 1; }

signed_state=$($BIN -keychain-status)
[[ "$signed_state" == *"registry-v2=0"* ]] || {
	echo "오류: 서명된 agent가 v2 registry Keychain을 읽지 못함: $signed_state" >&2; exit 1
}
[[ "$signed_state" == *"legacy=protected"* || "$signed_state" == *"legacy=missing"* ]] || {
	echo "오류: 서명된 agent의 legacy Keychain 상태가 protected/missing이 아님: $signed_state" >&2; exit 1
}

dev_state=$(./pasu -keychain-status)
[[ "$dev_state" == *"legacy=unavailable"* && "$dev_state" == *"registry-v2=-34018"* ]] || {
	echo "오류: ad-hoc 개발 빌드가 production access group을 봄: $dev_state" >&2; exit 1
}

# 정식 앱을 통째로 복사한 뒤 같은 entitlement 문자열을 넣어 ad-hoc 재서명한다.
# 프로파일·Bundle ID·파일 경로를 흉내 내도 Apple Team 서명이 없으므로 production
# access group은 protected로 보이면 안 된다(실행 자체가 AMFI에서 막혀도 통과).
FAKE="$WORK/FakePasu.app"
ditto "$APP" "$FAKE"
FAKE_AGENT="$FAKE/Contents/Library/LoginItems/PasuAgent.app"
codesign --display --entitlements :- "$FAKE_AGENT" > "$WORK/agent.entitlements" 2>/dev/null
codesign --force --sign - --options runtime \
	--entitlements "$WORK/agent.entitlements" "$FAKE_AGENT" >/dev/null
codesign --force --sign - --options runtime "$FAKE" >/dev/null
set +e
fake_out=$("$FAKE_AGENT/Contents/MacOS/pasu" -keychain-status 2>&1)
fake_rc=$?
set -e
if [[ "$fake_rc" -eq 0 && ("$fake_out" == *"legacy=protected"* || "$fake_out" == *"registry-v2=0"*) ]]; then
	echo "오류: ad-hoc 가짜 앱이 production Keychain 항목을 봄" >&2
	exit 1
fi

set +e
override_out=$($BIN -dir "$WORK/evil" -check 2>&1)
override_rc=$?
set -e
if [[ "$override_rc" -eq 0 || ("$override_out" != *"보안 경로를 고정"* && "$override_out" != *"flag provided but not defined"*) ]]; then
	echo "오류: 서명된 앱이 임의 보안 경로 옵션을 거부하지 않음" >&2; exit 1
fi

mkdir -p "$WORK/attacker-home/.ssh/pasu"
injected_home=$(HOME="$WORK/attacker-home" "$BIN" -check 2>&1)
[[ "$injected_home" == *"CHECK v2"* ]] || {
	echo "오류: 서명된 앱의 보안 경로가 HOME 환경 변수에 영향받음" >&2; exit 1
}

echo "Developer ID Keychain 경계 검증 통과"
echo "  서명된 앱: $signed_state"
echo "  ad-hoc 개발 빌드: $dev_state"
echo "  ad-hoc 가짜 앱: rc=$fake_rc ${fake_out:-실행 차단}"
echo "  서명된 앱 임의 경로: 거부"
echo "  서명된 앱 HOME 주입: 시스템 UID 홈 유지"
