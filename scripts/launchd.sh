#!/bin/zsh
# root-owned bundle, user-domain SMAppService registration. No root SSH agent.
set -euo pipefail
export PATH="/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/go/bin:/usr/local/bin"
SELF="${0:a}"
REPO="${0:a:h:h}"
source "$REPO/scripts/signing-common.sh"
source "$REPO/scripts/data-layout.sh"
CURRENT_UID=$(id -u)
[[ "$CURRENT_UID" -ne 0 ]] || { echo "오류: 스크립트 자체를 sudo로 실행하지 마세요" >&2; exit 1; }
USER_HOME=$(dscacheutil -q user -a uid "$CURRENT_UID" | awk '/^dir: / { sub(/^dir: /, ""); print; exit }')
[[ "$USER_HOME" == /* ]] || exit 1
PASU_ROOT="$USER_HOME/.ssh/pasu"
PASU_DIR="$PASU_ROOT"
CANDIDATE_APP="${PASU_CANDIDATE_APP:-$REPO/dist/Pasu.app}"
BRIDGE_APP="$REPO/dist/migration/Pasu.app"
AGENT_REL="Contents/Library/LoginItems/PasuAgent.app/Contents/MacOS/pasu"
INSTALL_APP="/Applications/Pasu.app"
INSTALL_GUI="$INSTALL_APP/Contents/MacOS/Pasu"
INSTALL_BIN="$INSTALL_APP/$AGENT_REL"
OLD_PLIST="/Library/LaunchAgents/com.dennis.pasu.plist"
OLD_TARGET="gui/$CURRENT_UID/com.dennis.pasu"
SOCK="$PASU_ROOT/agent.sock"
SERVICE_STOP_WAIT_TENTHS=900
SERVICE_STOP_NOTICE_TENTHS=100

identity_source="$INSTALL_APP"
case "${1:-}" in
 install|verify-app) identity_source="$CANDIDATE_APP" ;;
 rollback) identity_source="$INSTALL_APP.rollback" ;;
 status|start|stop|restart|finalize|uninstall|cleanup) ;;
 *) echo "사용법: $SELF {install [--migrate|--switch-developer]|status|start|stop|restart|rollback|finalize|uninstall|cleanup|verify-app}" >&2; exit 2 ;;
esac
if [[ "${1:-}" != cleanup ]]; then
 load_app_identity "$identity_source" "$REPO/packaging/signing.json" "$([[ "${1:-}" == rollback ]] && echo true || echo false)"
 TARGET="gui/$CURRENT_UID/$LABEL"
 layout=$(/usr/libexec/PlistBuddy -c 'Print :PasuDataLayout' "$identity_source/Contents/Info.plist" 2>/dev/null || echo 0)
 if [[ "$layout" == 1 ]]; then PASU_DIR=$(profile_directory "$PASU_ROOT" "$TEAM_ID" "$GUI_BUNDLE_ID"); fi
fi
OFFICIAL_TEAM=$(plutil -extract team_id raw -o - "$REPO/packaging/signing.json")
OFFICIAL_GUI=$(plutil -extract bundle_id raw -o - "$REPO/packaging/signing.json")
is_official_identity() { [[ "$TEAM_ID" == "$OFFICIAL_TEAM" && "$GUI_BUNDLE_ID" == "$OFFICIAL_GUI" ]]; }

TRAPEXIT() {
 local rc=$?
 if [[ "$rc" != 0 && "$rc" != 3 && -e "$INSTALL_APP.new" ]]; then
  if [[ -e "$INSTALL_APP.rollback" ]]; then
   echo "설치 준비 파일과 백업을 보존했습니다. $SELF rollback으로 복원하세요." >&2
  else
   echo "백업 없이 설치 준비 파일이 남았습니다. $SELF cleanup 후 다시 설치하세요." >&2
  fi
 fi
 return "$rc"
}

assert_legacy_app() {
 is_official_identity || { echo "오류: 구버전 이전은 기존 공식 Pasu 신원에서만 지원합니다" >&2; return 1; }
 codesign --verify --deep --strict "$1" || return 1
 assert_developer_signature "$1" "$TEAM_ID" "$GUI_BUNDLE_ID.gui" || return 1
 assert_developer_signature "$1/Contents/Library/LoginItems/PasuAgent.app" "$TEAM_ID" "$GUI_BUNDLE_ID"
}

assert_release_app() {
	local app="$1" mode="${2:-final}" freshness="${3:-existing}" agent work ent gui_ent profile
	agent="$app/Contents/Library/LoginItems/PasuAgent.app"
	[[ -d "$app" && -x "$app/Contents/MacOS/Pasu" && -x "$agent/Contents/MacOS/pasu" ]] || {
		echo "오류: Pasu.app 구조가 아님: $app" >&2; return 1
	}
	codesign --verify --deep --strict "$app" || return 1
	assert_developer_signature "$app" "$TEAM_ID" "$GUI_BUNDLE_ID" || return 1
	assert_developer_signature "$agent" "$TEAM_ID" "$AGENT_BUNDLE_ID" || return 1
	work=$(mktemp -d "${TMPDIR:-/tmp}/pasu-app-check.XXXXXX") || return 1
	ent="$work/entitlements.plist"
	gui_ent="$work/gui-entitlements.plist"
	profile="$work/profile.plist"
	if ! codesign --display --entitlements :- "$agent" > "$ent" 2>/dev/null ||
		! security cms -D -i "$agent/Contents/embedded.provisionprofile" > "$profile"; then
		echo "오류: entitlement 또는 provisioning profile 읽기 실패: $app" >&2
		rm -rf -- "$work"
		return 1
	fi
	codesign --display --entitlements :- "$app" > "$gui_ent" 2>/dev/null || true
	if ! assert_pasu_profile "$profile" "$TEAM_ID" "$AGENT_BUNDLE_ID" "$freshness"; then rm -rf -- "$work"; return 1; fi
	if [[ "$(/usr/libexec/PlistBuddy -c 'Print :com.apple.application-identifier' "$ent" 2>/dev/null)" != "$APP_ID" ||
		"$(/usr/libexec/PlistBuddy -c 'Print :com.apple.developer.team-identifier' "$ent" 2>/dev/null)" != "$TEAM_ID" ||
		"$(/usr/libexec/PlistBuddy -c 'Print :keychain-access-groups:0' "$ent" 2>/dev/null)" != "$ACCESS_GROUP" ]]; then
		echo "오류: entitlement 또는 provisioning profile 내용 불일치: $app" >&2
		rm -rf -- "$work"
		return 1
	fi
	if /usr/libexec/PlistBuddy -c 'Print :com.apple.security.get-task-allow' "$ent" >/dev/null 2>&1; then
		echo "오류: 배포 앱에 get-task-allow가 포함됨" >&2
		rm -rf -- "$work"
		return 1
	fi
	if [[ -s "$gui_ent" || -e "$app/Contents/embedded.provisionprofile" ]]; then
		echo "오류: GUI에 Keychain access group 또는 get-task-allow가 포함됨" >&2
		rm -rf -- "$work"
		return 1
	fi
	local second third marker
 second=$(/usr/libexec/PlistBuddy -c 'Print :keychain-access-groups:1' "$ent" 2>/dev/null || true)
 third=$(/usr/libexec/PlistBuddy -c 'Print :keychain-access-groups:2' "$ent" 2>/dev/null || true)
 marker=$(/usr/libexec/PlistBuddy -c 'Print :PasuKeychainMigration' "$app/Contents/Info.plist" 2>/dev/null || true)
 if [[ -n "$third" || ( "$mode" == final && ( -n "$second" || "$marker" != false ) ) ||
       ( "$mode" == migration && ( "$second" != "$TEAM_ID.com.dennis.pasu" || "$marker" != true ) ) ]]; then
  echo "오류: final/migration 권한 경계 불일치" >&2; rm -rf -- "$work"; return 1
 fi
 local actual_mode
 if ! actual_mode=$("$agent/Contents/MacOS/pasu" -build-mode); then
  echo "오류: agent를 실행할 수 없습니다. 서명·프로파일과 macOS 진단 기록을 확인하세요: $app" >&2
  rm -rf -- "$work"; return 1
 fi
 if [[ "$actual_mode" != "$mode" ]]; then
  echo "오류: 실제 실행 파일과 서명 권한의 final/migration 모드 불일치" >&2
  rm -rf -- "$work"; return 1
 fi
 local marker_team
 marker_team=$(/usr/libexec/PlistBuddy -c 'Print :PasuSigningTeam' "$app/Contents/Info.plist" 2>/dev/null || true)
 if [[ -n "$marker_team" ]]; then
  if [[ "$marker_team" != "$TEAM_ID" ||
        "$("$agent/Contents/MacOS/pasu" -build-identity)" != "$TEAM_ID $GUI_BUNDLE_ID $AGENT_BUNDLE_ID" ||
        "$("$app/Contents/MacOS/Pasu" --build-identity)" != "$TEAM_ID $GUI_BUNDLE_ID $AGENT_BUNDLE_ID" ]]; then
   echo "오류: 앱 메타데이터와 실행 파일의 서명 설정이 다릅니다" >&2; rm -rf -- "$work"; return 1
  fi
 elif ! is_official_identity; then
  echo "오류: 앱에 빌드 신원 정보가 없습니다" >&2; rm -rf -- "$work"; return 1
 fi
 local data_layout
 data_layout=$(app_layout "$app")
 if [[ "$data_layout" != 0 && "$data_layout" != 1 ]]; then
  echo "오류: 지원하지 않는 자료 폴더 형식입니다: $data_layout" >&2; rm -rf -- "$work"; return 1
 fi
 if [[ "$data_layout" == 1 && "$("$agent/Contents/MacOS/pasu" -data-layout)" != 1 ]]; then
  echo "오류: 앱 메타데이터와 실행 파일의 자료 폴더 형식이 다릅니다" >&2; rm -rf -- "$work"; return 1
 fi
 local service="$app/Contents/Library/LaunchAgents/$LABEL.plist"
 if ! assert_service_plist "$service" "$LABEL"; then
  echo "오류: bundled LaunchAgent 설정 불일치" >&2; rm -rf -- "$work"; return 1
 fi
 rm -rf -- "$work" || return 1
}

wait_live() {
	local i out rc
	for i in {1..80}; do
		if [[ -S "$SOCK" ]]; then
			set +e
			out=$(SSH_AUTH_SOCK="$SOCK" /usr/bin/ssh-add -l 2>&1)
			rc=$?
			set -e
			if [[ "$rc" -eq 0 || "$out" == *"no identities"* || "$out" == *"식별자가 없습니다"* ]]; then
				return 0
			fi
		fi
		sleep 0.1
	done
	echo "오류: pasu 소켓이 8초 안에 List 응답을 하지 않음: $SOCK" >&2
	return 1
}

wait_for_service_exit() {
	local old_pid="$1" i
	[[ -n "$old_pid" ]] || return 0
	for (( i = 1; i <= SERVICE_STOP_WAIT_TENTHS; i++ )); do
		kill -0 "$old_pid" 2>/dev/null || return 0
		if (( i == SERVICE_STOP_NOTICE_TENTHS )); then
			echo "안내: 진행 중 서명·Touch ID·승인 창을 마무리하는 중일 수 있어 최대 $((SERVICE_STOP_WAIT_TENTHS / 10))초까지 기다립니다"
		fi
		sleep 0.1
	done
	echo "오류: 기존 pasu(pid $old_pid)가 $((SERVICE_STOP_WAIT_TENTHS / 10))초 안에 종료되지 않음" >&2
	return 1
}


stop_target() {
 local target="$1" old_pid=""
 old_pid=$(launchctl print "$target" 2>/dev/null | awk '/pid =/ { print $3; exit }') || true
 if [[ -n "$old_pid" ]]; then
  launchctl kill TERM "$target"
  wait_for_service_exit "$old_pid"
 fi
}

assert_root_bundle() {
 local app="$1" ownership unsafe
 ownership=$(stat -f '%Su:%Sg' "$app") || { echo "오류: 앱 소유권을 읽을 수 없습니다: $app" >&2; return 1; }
 unsafe=$(find "$app" \( ! -user root -o ! -group wheel -o -perm -020 -o -perm -002 \) -print -quit) || {
  echo "오류: 앱 파일 권한을 검사할 수 없습니다: $app" >&2; return 1
 }
 if [[ -L "$app" || "$ownership" != root:wheel || -n "$unsafe" ]]; then
  echo "오류: 앱은 root:wheel 소유이며 일반 사용자가 수정할 수 없어야 합니다: $app" >&2; return 1
 fi
}

require_gui_closed() {
 local processes
 processes=$(ps -axo comm=) || return 1
 if echo "$processes" | grep -Fx "$INSTALL_GUI" >/dev/null; then
  echo "Pasu 관리 GUI를 종료한 뒤 다시 실행하세요. agent는 스크립트가 정상 종료합니다." >&2
  return 1
 fi
}

register_service() {
 local state
 # A denied registration can still have transitioned to requiresApproval.
 "$INSTALL_GUI" --service register || true
 state=$("$INSTALL_GUI" --service status) || return 1
 if [[ "$state" == requiresApproval ]]; then
  echo "승인 대기: 시스템 설정 → 일반 → 로그인 항목 및 확장 프로그램에서 Pasu의 백그라운드 활동을 허용하세요."
  echo "승인 후: $SELF start"
  return 3
 fi
 [[ "$state" == enabled ]] || { echo "서비스 등록 실패: $state" >&2; return 1; }
 return 0
}

cmd_status() {
 assert_release_app "$INSTALL_APP"
 assert_root_bundle "$INSTALL_APP"
 local state launch_text repo_version installed_version log_version
 echo "제작자: $TEAM_ID / $GUI_BUNDLE_ID"
 echo "자료 폴더: $PASU_DIR"
 state=$("$INSTALL_GUI" --service status)
 echo "SMAppService: $state"
 if [[ "$state" == requiresApproval ]]; then
  echo "시스템 설정 → 일반 → 로그인 항목 및 확장 프로그램에서 Pasu를 허용한 뒤 $SELF start를 실행하세요."
  return 3
 fi
 [[ "$state" == enabled ]] || { echo "서비스가 실행되지 않습니다. $SELF start로 시작하세요." >&2; return 1; }
 local logs=()
 [[ -f "$PASU_DIR/pasu.log.old" ]] && logs+=("$PASU_DIR/pasu.log.old")
 [[ -f "$PASU_DIR/pasu.log" ]] && logs+=("$PASU_DIR/pasu.log")
 (( ${#logs[@]} > 0 )) || { echo "감사 로그 없음" >&2; return 1; }
 launch_text=$(launchctl print "$TARGET")
 echo "$launch_text" | grep -E 'state = |pid = |last exit code' || true
 echo "$launch_text" | grep -q 'state = running' || return 1
 "$INSTALL_BIN" -check
 repo_version=$(<"$REPO/VERSION")
 installed_version=$("$INSTALL_BIN" -version | awk '{print $2}')
 log_version=$(awk '/ START / { for(i=1;i<=NF;i++) if($i ~ /^version=/) { v=$i; sub(/^version=/,"",v) } } END {print v}' "${logs[@]}")
 echo "버전 repository=$repo_version installed=$installed_version START=$log_version"
 [[ "$repo_version" == "$installed_version" && "$installed_version" == "$log_version" ]] || return 1
 wait_live
 local deny_count
 deny_count=$(awk '
  / START / { full=0; suppressed=0; active=1; next }
  active && index($0, " DENY ") { full++ }
  active && index($0, " DENY-SUMMARY ") {
   if (match($0, /suppressed=[0-9]+/)) { suppressed+=substr($0, RSTART+11, RLENGTH-11) }
  }
  END { print full+suppressed }
 ' "${logs[@]}")
 echo "마지막 START 이후 DENY: $deny_count"
 echo "root 소유권·서명·registry·실제 List 확인 완료"
}

app_layout() { /usr/libexec/PlistBuddy -c 'Print :PasuDataLayout' "$1/Contents/Info.plist" 2>/dev/null || echo 0; }

assert_known_app() (
 local app="$1" actual_gui
 load_app_identity "$app" "$REPO/packaging/signing.json" true || return 1
 actual_gui=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app/Contents/Info.plist") || return 1
 if [[ "$actual_gui" == "$OFFICIAL_GUI.gui" && "$TEAM_ID" == "$OFFICIAL_TEAM" ]]; then
  assert_legacy_app "$app"
 else
  assert_release_app "$app"
 fi
)

stop_installed_service() (
 [[ -d "$INSTALL_APP" ]] || return 0
 load_app_identity "$INSTALL_APP" "$REPO/packaging/signing.json" true || return 1
 local actual_gui
 actual_gui=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$INSTALL_APP/Contents/Info.plist") || return 1
 if [[ "$actual_gui" == "$OFFICIAL_GUI.gui" && "$TEAM_ID" == "$OFFICIAL_TEAM" ]]; then
  stop_target "$OLD_TARGET" || return 1
  if launchctl print "$OLD_TARGET" >/dev/null 2>&1; then launchctl bootout "$OLD_TARGET" || return 1; fi
 else
  stop_target "gui/$CURRENT_UID/$LABEL" || return 1
  "$INSTALL_GUI" --service unregister || return 1
 fi
)

cmd_install() {
 local option="${1:-}" stage="$INSTALL_APP.new" fresh=0 old_team="" old_gui="" old_label="" old_layout=1 old_fields old_actual_gui=""
 [[ -z "$option" || "$option" == --migrate || "$option" == --switch-developer ]] || { echo "install: --migrate 또는 --switch-developer 중 하나를 사용하세요" >&2; return 2; }
 assert_release_app "$CANDIDATE_APP" final current
 [[ "$(app_layout "$CANDIDATE_APP")" == 1 ]] || { echo "오류: 이 설치 스크립트에는 제작자별 자료 폴더를 지원하는 앱이 필요합니다" >&2; return 1; }
 assert_profile_location "$PASU_ROOT" "$TEAM_ID" "$GUI_BUNDLE_ID"
 require_gui_closed
 [[ ! -e "$INSTALL_APP.rollback" && ! -e "$OLD_PLIST.rollback" && ! -e "$stage" && ! -e "$PASU_ROOT/.legacy-layout" ]] || {
  echo "이전 설치 준비나 백업이 남아 있습니다. rollback/finalize를 실행하세요. 백업 없는 .new만 남았다면 cleanup으로 정리합니다." >&2; return 1
 }
 if [[ -e "$INSTALL_APP" ]]; then
  assert_root_bundle "$INSTALL_APP"
  assert_known_app "$INSTALL_APP" || { echo "오류: 기존 앱 검증에 실패했습니다. 위 오류를 확인하세요" >&2; return 1; }
  old_fields=$( (load_app_identity "$INSTALL_APP" "$REPO/packaging/signing.json" true; print -r -- "$TEAM_ID $GUI_BUNDLE_ID $LABEL") )
  read -r old_team old_gui old_label <<< "$old_fields"
  old_layout=$(app_layout "$INSTALL_APP")
  old_actual_gui=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$INSTALL_APP/Contents/Info.plist")
  if [[ "$old_team $old_gui" != "$TEAM_ID $GUI_BUNDLE_ID" && "$option" != --switch-developer ]]; then
   echo "오류: 제작자가 다릅니다. 자료를 분리 보존하고 전환하려면 install --switch-developer를 실행하세요" >&2; return 1
  fi
 else
  fresh=1
  [[ "$option" != --migrate ]] || { echo "--migrate에는 기존 설치본이 필요합니다" >&2; return 1; }
  legacy_data_entries "$PASU_ROOT"
  (( ${#LAYOUT_ENTRIES} == 0 )) || { echo "오류: 구형 자료의 제작자를 확인할 설치본이 없습니다. 기존 제작자의 구형 앱을 복원한 뒤 업데이트하세요" >&2; return 1; }
 fi
 if [[ "$option" == --migrate ]]; then
  is_official_identity && [[ "$old_actual_gui" == "$OFFICIAL_GUI.gui" ]] || { echo "오류: --migrate는 공식 v2.1.1에서 이전할 때만 사용합니다" >&2; return 1; }
  assert_release_app "$BRIDGE_APP" migration current
  "$BRIDGE_APP/$AGENT_REL" -keychain-group-status
  [[ -f "$OLD_PLIST" && ! -L "$OLD_PLIST" ]] || { echo "기존 LaunchAgent 설정이 없습니다" >&2; return 1; }
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' "$OLD_PLIST")" == "$INSTALL_BIN" ]] || return 1
 else
  [[ ( "$old_actual_gui" != "$OFFICIAL_GUI.gui" || "$old_team" != "$OFFICIAL_TEAM" ) && ! -e "$OLD_PLIST" ]] || { echo "오류: 먼저 기존 공식 제작자의 앱으로 install --migrate를 완료하세요" >&2; return 1; }
  if [[ "$old_layout" == 0 && "$old_team $old_gui" == "$TEAM_ID $GUI_BUNDLE_ID" ]]; then
   "$CANDIDATE_APP/$AGENT_REL" -check-legacy-data
  else
   "$CANDIDATE_APP/$AGENT_REL" -check
  fi
 fi
 if [[ "$fresh" == 0 && "$old_layout" == 0 ]]; then
  legacy_data_entries "$PASU_ROOT"
  if (( ${#LAYOUT_ENTRIES} > 0 )) && [[ -e "$(profile_directory "$PASU_ROOT" "$old_team" "$old_gui")" ]]; then
   echo "오류: 구형 자료와 제작자별 자료가 모두 존재합니다. 자동으로 병합하지 않습니다" >&2; return 1
  fi
 fi
 echo "설치할 제작자: $TEAM_ID / $GUI_BUNDLE_ID"
 echo "사용할 자료: $PASU_DIR"
 echo "기존 서비스를 중지하고 앱을 교체합니다. 다른 제작자의 키·규칙·Keychain 항목은 보존합니다."
 sudo -v
 sudo ditto "$CANDIDATE_APP" "$stage"
 sudo chown -R root:wheel "$stage"
 sudo chmod -R go-w "$stage"
 assert_root_bundle "$stage"
 assert_release_app "$stage" final current
 if [[ "$fresh" == 0 ]]; then sudo ditto "$INSTALL_APP" "$INSTALL_APP.rollback"; fi
 if [[ -f "$OLD_PLIST" ]]; then sudo cp -p "$OLD_PLIST" "$OLD_PLIST.rollback"; fi
 stop_installed_service
 if [[ "$fresh" == 0 && "$old_layout" == 0 ]]; then move_legacy_data "$PASU_ROOT" "$old_team" "$old_gui"; fi
 if [[ "$option" == --migrate ]]; then
  "$BRIDGE_APP/$AGENT_REL" -migrate-keychain-group || { echo "그룹 이전이 중단되었습니다. $SELF rollback으로 복원하세요" >&2; return 1; }
 fi
 "$stage/$AGENT_REL" -check || { echo "자료 검사 실패. $SELF rollback이 필요합니다" >&2; return 1; }
 sudo rm -rf "$INSTALL_APP"
 sudo mv "$stage" "$INSTALL_APP"
 if [[ -f "$OLD_PLIST" ]]; then sudo rm "$OLD_PLIST"; fi
 assert_release_app "$INSTALL_APP"
 if register_service; then
  wait_live
  cmd_status
  echo "설치 검증 완료. 키·규칙·인증·SSH 연결을 확인한 뒤 $SELF finalize로 이전 앱 백업을 정리하세요."
 else
  local rc=$?
  [[ "$rc" == 3 ]] && return 3
  echo "서비스 확인 실패. 이전 앱 백업이 있으면 $SELF rollback으로 복원할 수 있습니다." >&2
  return 1
 fi
}

cmd_rollback() {
 local backup="$INSTALL_APP.rollback" previous_gui
 [[ -d "$backup" && ! -L "$backup" ]] || { echo "복원할 설치본 없음" >&2; return 1; }
 require_gui_closed
 assert_root_bundle "$backup"
 assert_known_app "$backup"
 previous_gui=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$backup/Contents/Info.plist")
 if [[ -e "$INSTALL_APP" ]]; then
  assert_root_bundle "$INSTALL_APP"
  assert_known_app "$INSTALL_APP"
 fi
 if [[ -e "$PASU_ROOT/.legacy-layout" ]]; then
  read_layout_journal "$PASU_ROOT"
  [[ "$LAYOUT_ID" == "$TEAM_ID.$GUI_BUNDLE_ID" ]] || { echo "오류: 백업 앱과 자료 이전 기록의 제작자가 다릅니다" >&2; return 1; }
 fi
 stop_installed_service
 if [[ "$previous_gui" == "$OFFICIAL_GUI.gui" && "$TEAM_ID" == "$OFFICIAL_TEAM" ]]; then
  assert_release_app "$BRIDGE_APP" migration current
  "$BRIDGE_APP/$AGENT_REL" -rollback-keychain-group
 fi
 restore_legacy_data "$PASU_ROOT"
 "$backup/$AGENT_REL" -check
 sudo -v
 sudo rm -rf "$INSTALL_APP"
 sudo mv "$backup" "$INSTALL_APP"
 if [[ -f "$OLD_PLIST.rollback" ]]; then sudo mv "$OLD_PLIST.rollback" "$OLD_PLIST"; fi
 if [[ -d "$INSTALL_APP.new" ]]; then assert_root_bundle "$INSTALL_APP.new"; sudo rm -rf "$INSTALL_APP.new"; fi
 if [[ "$previous_gui" == "$OFFICIAL_GUI.gui" && "$TEAM_ID" == "$OFFICIAL_TEAM" ]]; then
  launchctl bootout "$OLD_TARGET" 2>/dev/null || true
  launchctl bootstrap "gui/$CURRENT_UID" "$OLD_PLIST"
 else
  register_service
 fi
 wait_live
 "$INSTALL_BIN" -check
 echo "기존 설치본과 자료 경로 복원 완료. 다른 제작자의 자료도 보존했습니다."
}

cmd_finalize() {
 cmd_status
 finalize_data_layout "$PASU_ROOT" check
 [[ ! -e "$OLD_PLIST" ]] || { echo "기존 LaunchAgent 파일이 남아 있음" >&2; return 1; }
 if [[ -d "$INSTALL_APP.rollback" ]]; then
  assert_root_bundle "$INSTALL_APP.rollback"
  sudo rm -rf "$INSTALL_APP.rollback"
 fi
 if [[ -f "$OLD_PLIST.rollback" ]]; then sudo rm "$OLD_PLIST.rollback"; fi
 finalize_data_layout "$PASU_ROOT"
 echo "이전 설치 백업 정리 완료. 키체인 항목은 삭제하지 않았습니다."
}

case "${1:-}" in
 install) cmd_install "${2:-}" ;;
 status) cmd_status ;;
 start)
  assert_release_app "$INSTALL_APP"
  assert_root_bundle "$INSTALL_APP"
  "$INSTALL_BIN" -check
  register_service
  launchctl kickstart "$TARGET"
  wait_live
  cmd_status ;;
 stop) assert_release_app "$INSTALL_APP"; assert_root_bundle "$INSTALL_APP"; stop_target "$TARGET" ;;
 restart)
  assert_release_app "$INSTALL_APP"
  assert_root_bundle "$INSTALL_APP"
  "$INSTALL_BIN" -check
  stop_target "$TARGET"
  launchctl kickstart "$TARGET"
  wait_live
  cmd_status ;;
 rollback) cmd_rollback ;;
 finalize) cmd_finalize ;;
 uninstall)
  assert_root_bundle "$INSTALL_APP"
  require_gui_closed
  assert_release_app "$INSTALL_APP"
  stop_target "$TARGET"
  "$INSTALL_GUI" --service unregister
  sudo rm -rf "$INSTALL_APP"
  echo "앱 제거 완료. Keychain·SSH 키·설정·로그는 보존했습니다." ;;
 cleanup)
  [[ ! -e "$INSTALL_APP.rollback" && ! -e "$OLD_PLIST.rollback" && ! -e "$PASU_ROOT/.legacy-layout" ]] || { echo "백업이나 자료 이전 기록이 있습니다. rollback/finalize를 사용하세요" >&2; exit 1; }
  if [[ -e "$INSTALL_APP" ]]; then assert_root_bundle "$INSTALL_APP"; assert_known_app "$INSTALL_APP"; fi
  if [[ -e "$INSTALL_APP.new" || -L "$INSTALL_APP.new" ]]; then
   [[ -d "$INSTALL_APP.new" && ! -L "$INSTALL_APP.new" ]] || { echo "오류: 설치 준비 경로가 일반 앱 폴더가 아닙니다" >&2; exit 1; }
   sudo rm -rf "$INSTALL_APP.new"
  fi
  echo "실패한 앱 준비 파일을 정리했습니다. 사용자 자료는 유지했습니다." ;;
 verify-app) assert_release_app "$CANDIDATE_APP" "${PASU_RELEASE_MODE:-final}" current; echo "후보 앱 검증 통과: $CANDIDATE_APP"; echo "서명 팀: $TEAM_ID / 앱 식별자: $GUI_BUNDLE_ID" ;;
 *) echo "사용법: $SELF {install [--migrate|--switch-developer]|status|start|stop|restart|rollback|finalize|uninstall|cleanup|verify-app}" >&2; exit 2 ;;
esac
