#!/bin/zsh
# Pasu v2 SSH 별칭이 한 키만 명시하고 forwarding을 끄는지 읽기 전용으로 검사한다.
set -uo pipefail
export PATH="/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/go/bin:/usr/local/bin"

HOST="${1:-example-pasu}"
EXPECTED_KEY="${2:-}"
PASU_AGENT="$HOME/.ssh/pasu/agent.sock"
FAIL=0

pass() { echo "  [통과] $1"; }
fail() { echo "  [실패] $1"; FAIL=1; }

echo "== ssh -G Pasu 문맥 ($HOST)"
config=$(ssh -G "$HOST" </dev/null 2>/dev/null) || config=""
agent=$(echo "$config" | awk '$1=="identityagent" {print $2; exit}')
files=$(echo "$config" | awk '$1=="identityfile" {print $2}')

if [ "$agent" = "$PASU_AGENT" ]; then
  pass "IdentityAgent가 Pasu 소켓"
else
  fail "IdentityAgent=$agent (기대 $PASU_AGENT)"
fi

count=$(echo "$files" | awk 'NF { n++ } END { print n+0 }')
if [ "$count" -eq 1 ]; then
  pass "IdentityFile이 한 개로 제한됨"
else
  fail "IdentityFile이 ${count}개임: ${files:-없음}"
fi

if [ -n "$EXPECTED_KEY" ]; then
  expanded=${EXPECTED_KEY/#\~/$HOME}
  if [ "$files" = "$EXPECTED_KEY" ] || [ "$files" = "$expanded" ]; then
    pass "기대한 공개키 경로가 선택됨"
  else
    fail "IdentityFile=$files (기대 $EXPECTED_KEY)"
  fi
elif echo "$files" | grep -Eq '(^|/)\.ssh/pasu/(profiles/[A-Z0-9]{10}\.[A-Za-z0-9.-]+/keys/[0-9a-f-]{36}/key\.pub|keys/[0-9a-f-]{36}/key\.pub|key\.pub)$'; then
  pass "Pasu 공개키 경로 형식"
else
  fail "Pasu 공개키 경로가 아님: ${files:-없음}"
fi

for field in "identitiesonly yes" "forwardagent no" "addkeystoagent no" "usekeychain no"; do
  if echo "$config" | grep -qx "$field"; then
    pass "$field"
  else
    fail "$field 미적용"
  fi
done

echo
if [ "$FAIL" = 0 ]; then
  echo "Pasu SSH 설정 점검 통과 — 실제 연결이나 설정 변경은 수행하지 않았습니다"
else
  echo "Pasu SSH 설정 점검 실패"
fi
exit $FAIL
