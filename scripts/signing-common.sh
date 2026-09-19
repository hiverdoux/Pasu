#!/bin/zsh
# Build and installer checks share the same identity and profile rules.

valid_pasu_identity() {
 local team="$1" bundle="$2"
 [[ "$team" =~ '^[A-Z0-9]{10}$' && "$bundle" =~ '^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$' && ${#bundle} -le 206 ]]
}

developer_requirement() {
 valid_pasu_identity "$1" "$2" || return 1
 print -r -- "anchor apple generic and identifier \"$2\" and certificate 1[field.1.2.840.113635.100.6.2.6] and certificate leaf[field.1.2.840.113635.100.6.1.13] and certificate leaf[subject.OU] = \"$1\""
}

select_pasu_identity() {
 local team="$1" requested="$2" inventory="$3" line sha name
 local -aU matches=()
 local pattern='^[[:space:]]*[0-9]+\)[[:space:]]+([A-Fa-f0-9]{40})[[:space:]]+"(.*)"$'
 for line in "${(@f)inventory}"; do
  [[ "$line" =~ "$pattern" ]] || continue
  sha="${(U)match[1]}"; name="$match[2]"
  [[ "$name" == "Developer ID Application: "*" ($team)" ]] || continue
  if [[ -z "$requested" || "$requested" == "$name" || "${(U)requested}" == "$sha" ]]; then
   matches+=("$sha")
  fi
 done
 (( ${#matches[@]} > 0 )) || { echo "오류: 지정한 팀·이름·지문에 맞는 Developer ID Application 인증서와 개인키가 없습니다. security find-identity -v -p codesigning으로 확인하세요" >&2; return 1; }
 [[ ${#matches[@]} -eq 1 ]] || { echo "오류: 같은 팀의 인증서가 여러 개입니다. sign_identity에 사용할 인증서의 40자리 지문을 지정하세요" >&2; return 1; }
 print -r -- "$matches[1]"
}

assert_developer_signature() {
 local app="$1" team="$2" bundle="$3" requirement info
 requirement=$(developer_requirement "$team" "$bundle") || return 1
 codesign --verify --strict -R "=$requirement" "$app" || return 1
 info=$(codesign --display --verbose=4 "$app" 2>&1) || return 1
 print -r -- "$info" | grep -Fx "Identifier=$bundle" >/dev/null || return 1
 print -r -- "$info" | grep -Fx "TeamIdentifier=$team" >/dev/null || return 1
 has_hardened_runtime "$info" || { echo "오류: Hardened Runtime이 활성화되지 않았습니다: $app" >&2; return 1; }
}

has_hardened_runtime() {
 local line flags
 for line in "${(@f)1}"; do
  if [[ "$line" =~ '(^CodeDirectory .*|^)flags=0x([A-Fa-f0-9]+)\(' ]]; then
   flags="$match[2]"
   (( (16#$flags & 0x10000) != 0 )) && return 0
  fi
 done
 return 1
}

assert_service_plist() {
 local file="$1" label="$2"
 plutil -lint "$file" >/dev/null || return 1
 [[ "$(/usr/libexec/PlistBuddy -c 'Print :Label' "$file")" == "$label" &&
    "$(/usr/libexec/PlistBuddy -c 'Print :BundleProgram' "$file")" == Contents/Library/LoginItems/PasuAgent.app/Contents/MacOS/pasu &&
    "$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' "$file")" == pasu &&
    "$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments:1' "$file")" == -service &&
    "$(/usr/libexec/PlistBuddy -c 'Print :RunAtLoad' "$file")" == true &&
    "$(/usr/libexec/PlistBuddy -c 'Print :KeepAlive:Crashed' "$file")" == true &&
    "$(/usr/libexec/PlistBuddy -c 'Print :LimitLoadToSessionType' "$file")" == Aqua ]] || return 1
 ! /usr/libexec/PlistBuddy -c 'Print :ProgramArguments:2' "$file" >/dev/null 2>&1 || return 1
 ! /usr/libexec/PlistBuddy -c 'Print :Program' "$file" >/dev/null 2>&1 || return 1
}

assert_pasu_profile() {
 local profile="$1" team="$2" agent="$3" freshness="${4:-current}" group i=0 found=0 expiry expires
 valid_pasu_identity "$team" "$agent" || return 1
 [[ "$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:com.apple.application-identifier' "$profile" 2>/dev/null)" == "$team.$agent" &&
    "$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:com.apple.developer.team-identifier' "$profile" 2>/dev/null)" == "$team" &&
    "$(/usr/libexec/PlistBuddy -c 'Print :Platform:0' "$profile" 2>/dev/null)" == OSX &&
    "$(/usr/libexec/PlistBuddy -c 'Print :ProvisionsAllDevices' "$profile" 2>/dev/null)" == true ]] || {
  echo "오류: Developer ID 프로파일의 팀·앱·배포 범위가 일치하지 않습니다" >&2; return 1
 }
 while group=$(/usr/libexec/PlistBuddy -c "Print :Entitlements:keychain-access-groups:$i" "$profile" 2>/dev/null); do
  [[ "$group" == "$team.*" || "$group" == "$team.$agent" ]] && found=1
  (( i += 1 ))
 done
 [[ "$found" == 1 ]] || { echo "오류: 프로파일이 agent의 Keychain 접근 그룹을 허용하지 않습니다" >&2; return 1; }
 [[ "$freshness" == existing ]] && return 0
 expiry=$(plutil -extract ExpirationDate raw -o - "$profile") || return 1
 expires=$(LC_ALL=C date -j -u -f '%Y-%m-%dT%H:%M:%SZ' "$expiry" '+%s' 2>/dev/null) || return 1
 [[ "$expires" -gt "$(date '+%s')" ]] || { echo "오류: 프로파일이 만료되었습니다" >&2; return 1; }
}

assert_profile_certificate() {
 local profile="$1" identity_sha="$2" work="$3" cert_sha i=0
 [[ "$identity_sha" =~ '^[A-Fa-f0-9]{40}$' ]] || return 1
 while plutil -extract "DeveloperCertificates.$i" raw -o "$work/certificate.base64" "$profile" 2>/dev/null; do
  base64 -D < "$work/certificate.base64" > "$work/certificate.der" || return 1
  cert_sha=$(openssl x509 -inform DER -in "$work/certificate.der" -noout -fingerprint -sha1 |
   sed 's/.*=//; s/://g' | tr '[:lower:]' '[:upper:]') || return 1
  [[ "$cert_sha" == "${(U)identity_sha}" ]] && return 0
  (( i += 1 ))
 done
 echo "오류: 프로파일에 선택한 서명 인증서가 없습니다" >&2
 return 1
}

load_app_identity() {
 local app="$1" defaults="$2" allow_legacy="${3:-false}" legacy_identity=false
 [[ -d "$app" && -f "$app/Contents/Info.plist" ]] || { echo "오류: 앱을 찾을 수 없습니다: $app" >&2; return 1; }
 codesign --verify --deep --strict "$app" || return 1
 GUI_BUNDLE_ID=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app/Contents/Info.plist") || return 1
 TEAM_ID=$(/usr/libexec/PlistBuddy -c 'Print :PasuSigningTeam' "$app/Contents/Info.plist" 2>/dev/null) || {
  # Older official releases predate the signed identity field.
  TEAM_ID=$(plutil -extract team_id raw -o - "$defaults") || return 1
  local official_gui
  official_gui=$(plutil -extract bundle_id raw -o - "$defaults") || return 1
  [[ "$GUI_BUNDLE_ID" == "$official_gui" || ( "$allow_legacy" == true && "$GUI_BUNDLE_ID" == "$official_gui.gui" ) ]] || {
   echo "오류: 이 앱에는 필요한 서명 신원 정보가 없습니다: $app" >&2; return 1
  }
  if [[ "$GUI_BUNDLE_ID" == "$official_gui.gui" ]]; then legacy_identity=true; fi
 }
 [[ ${#GUI_BUNDLE_ID} -le 200 ]] && valid_pasu_identity "$TEAM_ID" "$GUI_BUNDLE_ID" || { echo "오류: 앱 서명 식별자 형식이 잘못되었습니다" >&2; return 1; }
 assert_developer_signature "$app" "$TEAM_ID" "$GUI_BUNDLE_ID" || return 1
 if [[ "$legacy_identity" == true ]]; then
  GUI_BUNDLE_ID="${GUI_BUNDLE_ID%.gui}"
 fi
 AGENT_BUNDLE_ID="$GUI_BUNDLE_ID.agent"
 LABEL="$AGENT_BUNDLE_ID"
 APP_ID="$TEAM_ID.$AGENT_BUNDLE_ID"
 ACCESS_GROUP="$APP_ID"
 return 0
}
