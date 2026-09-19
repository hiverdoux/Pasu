#!/bin/zsh
# Pasu v2의 다중 키·정확 사슬·GUI/control 경계를 로컬에서 검증한다.
# production Keychain과 실사용 파일은 변경하지 않는다.
set -euo pipefail
cd "${0:a:h}/.."
export PATH="/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/go/bin:/usr/local/bin"
export GOCACHE="${TMPDIR:-/tmp}/pasu-v2-verify-gocache"

echo "== 1. agent와 GUI 빌드"
./build.sh
[[ -x ./pasu && -x ./PasuGUI ]]
codesign --verify --strict ./pasu
codesign --verify --strict ./PasuGUI
settings=".build/signing/settings.plist"
team=$(/usr/libexec/PlistBuddy -c 'Print :TeamID' "$settings")
gui=$(/usr/libexec/PlistBuddy -c 'Print :GUIBundleID' "$settings")
agent=$(/usr/libexec/PlistBuddy -c 'Print :AgentBundleID' "$settings")
expected="$team $gui $agent"
[[ "$(./pasu -build-identity)" == "$expected" ]]
[[ "$(./pasu -data-layout)" == 1 ]]
[[ "$(./PasuGUI --build-identity)" == "$expected" ]]
[[ "$(PASU_SIGNING_CONFIG=/nonexistent/example.json PASU_PROFILE=/nonexistent/example.provisionprofile ./pasu -build-identity)" == "$expected" ]]
[[ "$(PASU_SIGNING_CONFIG=/nonexistent/example.json ./PasuGUI --build-identity)" == "$expected" ]]

echo "== 2. v2 핵심 단위·통합 테스트"
go test -run '^(TestV2|TestStable|TestChain|TestMigrateV1|TestAskAlert|TestMacV2|TestConcise|TestProductionData|TestDataDirectory)' .

echo "== 3. 패키징·스크립트 정적 검사"
plutil -lint .build/signing/Info.plist .build/signing/Agent-Info.plist .build/signing/Pasu.entitlements .build/signing/PasuAgent.plist >/dev/null
for script in build.sh scripts/*.sh .githooks/pre-commit; do
  zsh -n "$script"
done

echo "== 4. 그룹 이전 결정 검증 (합성 데이터)"
work=$(mktemp -d "${TMPDIR:-/tmp}/pasu-group-tests.XXXXXX")
trap 'rm -rf "$work"' EXIT
xcrun swiftc -parse-as-library keychain_group_darwin.swift tests/keychain-group-tests.swift -o "$work/group-tests"
"$work/group-tests"

echo "== 5. ad-hoc 경계"
version=$(./pasu -version)
[[ "$version" == "pasu "* ]]
state=$(./pasu -keychain-status)
[[ "$state" == *"legacy=unavailable"* ]]

echo "Pasu v2 로컬 검증 통과"
echo "  $version"
echo "  $state"
