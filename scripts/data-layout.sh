#!/bin/zsh
# Move legacy files only after stopping the old service. Keep an inverse journal
# until finalize so interrupted moves and app rollback can restore the old layout.

profile_directory() { print -r -- "$1/profiles/$2.$3"; }

assert_profile_location() {
 local root="$1" item
 for item in "$root" "$root/profiles" "$(profile_directory "$root" "$2" "$3")"; do
  if [[ -e "$item" || -L "$item" ]]; then assert_user_directory "$item" || return 1; fi
 done
}

assert_user_directory() {
 [[ -d "$1" && ! -L "$1" && "$(stat -f '%u:%Lp' "$1")" == "$CURRENT_UID:700" ]] || {
  echo "오류: 사용자 소유의 권한 700 폴더가 필요합니다: $1" >&2; return 1
 }
}

# Finder metadata is not Pasu data. Reject links or directories with that name.
assert_finder_metadata() {
 [[ -e "$1" || -L "$1" ]] || return 0
 [[ -f "$1" && ! -L "$1" && "$(stat -f '%u' "$1")" == "$CURRENT_UID" ]] || {
  echo "오류: 일반 사용자 파일이 아닌 Finder 보기 설정입니다: $1" >&2; return 1
 }
}

legacy_data_entries() {
 local root="$1" entry name
 LAYOUT_ENTRIES=()
 [[ -e "$root" ]] || return 0
 assert_user_directory "$root" || return 1
 for entry in "$root"/*(DN); do
  name="${entry:t}"
  case "$name" in
   .DS_Store) assert_finder_metadata "$entry" || return 1; continue ;;
   profiles|agent.sock|agent.sock.lock|control.sock|control.sock.lock|.legacy-layout) continue ;;
  esac
  [[ "$name" != *$'\n'* && "$name" != *$'\r'* ]] || { echo "오류: 이전할 수 없는 자료 이름: $entry" >&2; return 1; }
  [[ -z "$(find "$entry" \( ! -user "$CURRENT_UID" -o -type l -o \( ! -type d ! -type f \) \) -print -quit)" ]] || {
   echo "오류: 자료에 다른 소유자·심볼릭 링크·특수 파일이 있습니다: $entry" >&2; return 1
  }
  LAYOUT_ENTRIES+=("$name")
 done
}

read_layout_journal() {
 local root="$1" name
 local journal="$root/.legacy-layout"
 [[ -f "$journal" && ! -L "$journal" && "$(stat -f '%u:%Lp' "$journal")" == "$CURRENT_UID:600" ]] || {
  echo "오류: 자료 이전 기록의 소유권·권한을 확인하세요: $journal" >&2; return 1
 }
 local lines=("${(@f)$(<"$journal")}")
 LAYOUT_ID="$lines[1]"
 [[ "$LAYOUT_ID" =~ '^[A-Z0-9]{10}\.[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$' && ${#LAYOUT_ID} -le 211 ]] || return 1
 LAYOUT_ENTRIES=("${(@)lines[2,-1]}")
 (( ${#LAYOUT_ENTRIES} > 0 )) || return 1
 for name in "${LAYOUT_ENTRIES[@]}"; do
  [[ -n "$name" && "$name" != */* && "$name" != . && "$name" != .. ]] || return 1
  case "$name" in profiles|agent.sock*|control.sock*|.legacy-layout) return 1 ;; esac
 done
}

move_legacy_data() {
 local root="$1" team="$2" bundle="$3" target name journal
 valid_pasu_identity "$team" "$bundle" || return 1
 target=$(profile_directory "$root" "$team" "$bundle")
 journal="$root/.legacy-layout"
 if [[ ! -e "$journal" ]]; then
  legacy_data_entries "$root" || return 1
  (( ${#LAYOUT_ENTRIES} > 0 )) || return 0
  [[ ! -e "$target" && ! -L "$target" ]] || { echo "오류: 이전 자료와 제작자 폴더를 병합하지 않습니다: $target" >&2; return 1; }
  if [[ ! -e "$root/profiles" ]]; then mkdir -m 700 "$root/profiles" || return 1; fi
  assert_user_directory "$root/profiles" || return 1
  # noclobber prevents replacing an earlier interrupted transaction.
  (umask 077; setopt noclobber; printf '%s\n' "$team.$bundle" "${LAYOUT_ENTRIES[@]}" > "$journal") || return 1
 fi
 read_layout_journal "$root" || return 1
 [[ "$LAYOUT_ID" == "$team.$bundle" ]] || { echo "오류: 다른 제작자의 자료 이전이 미완료입니다. rollback을 실행하세요" >&2; return 1; }
 if [[ ! -e "$target" ]]; then mkdir -m 700 "$target" || return 1; fi
 assert_user_directory "$root/profiles" && assert_user_directory "$target" || return 1
 for name in "${LAYOUT_ENTRIES[@]}"; do
  # Older journals may include metadata that Finder has since recreated or removed.
  if [[ "$name" == .DS_Store ]]; then
   assert_finder_metadata "$root/$name" && assert_finder_metadata "$target/$name" || return 1
   continue
  fi
  if [[ -e "$root/$name" || -L "$root/$name" ]]; then
   [[ ! -e "$target/$name" && ! -L "$target/$name" ]] || { echo "오류: 자료 이전 대상이 이미 있습니다: $target/$name" >&2; return 1; }
   mv "$root/$name" "$target/$name" || return 1
  else
   [[ -e "$target/$name" && ! -L "$target/$name" ]] || { echo "오류: 이전 자료를 찾을 수 없습니다: $name" >&2; return 1; }
  fi
 done
 echo "자료 폴더 이전 완료: $target"
 echo "SSH 설정의 IdentityFile을 관리 앱의 폴더 버튼으로 확인한 새 공개키 경로로 변경하세요."
}

restore_legacy_data() {
 local root="$1" target name
 [[ -e "$root/.legacy-layout" ]] || return 0
 assert_user_directory "$root" && read_layout_journal "$root" || return 1
 target="$root/profiles/$LAYOUT_ID"
 assert_user_directory "$root/profiles" || return 1
 if [[ -e "$target" ]]; then assert_user_directory "$target" || return 1; fi
 for name in "${LAYOUT_ENTRIES[@]}"; do
  [[ "$name" != .DS_Store ]] || continue
  [[ -e "$root/$name" || -e "$target/$name" ]] || { echo "오류: 복원할 자료가 없습니다: $name" >&2; return 1; }
 done
 assert_finder_metadata "$root/.DS_Store" && assert_finder_metadata "$target/.DS_Store" || return 1
 # Include files created after the upgrade (for example new keys or rotated logs).
 local entries=() entry
 for entry in "$target"/*(DN); do
  [[ "${entry:t}" != .DS_Store ]] || continue
  entries+=("$entry")
 done
 for name in "${entries[@]}"; do
  name="${name:t}"
  [[ ! -e "$root/$name" && ! -L "$root/$name" && "$name" != profiles && "$name" != .legacy-layout && "$name" != agent.sock* && "$name" != control.sock* ]] || {
   echo "오류: 복원 자료가 기존 파일과 충돌합니다: $root/$name" >&2; return 1
  }
 done
 for name in "${entries[@]}"; do mv "$name" "$root/${name:t}" || return 1; done
 # Only disposable Finder metadata may remain in the restored profile directory.
 if [[ -e "$target/.DS_Store" ]]; then rm -- "$target/.DS_Store" || return 1; fi
 [[ ! -d "$target" ]] || rmdir "$target" || return 1
 rm "$root/.legacy-layout"
}

finalize_data_layout() {
 local root="$1" mode="${2:-commit}"
 [[ -e "$root/.legacy-layout" ]] || return 0
 assert_user_directory "$root" && read_layout_journal "$root" || return 1
 local name
 for name in "${LAYOUT_ENTRIES[@]}"; do
  [[ "$name" != .DS_Store ]] || continue
  [[ ! -e "$root/$name" ]] || { echo "오류: 자료 이전이 미완료입니다. rollback으로 복원하세요" >&2; return 1; }
 done
 [[ "$mode" == check ]] || rm "$root/.legacy-layout"
}
