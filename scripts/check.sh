#!/bin/zsh
# 저장소 로컬 검증. 모듈 캐시가 준비되면 기본 검사는 오프라인으로 실행할 수 있다.
# --release는 취약점 조회·정식 서명·기존 Keychain 데이터 접근 검사를 추가한다.
# 서명 인증서와 이미 설정된 Pasu 저장소가 필요하다. docs/BUILDING.md 참조.
set -euo pipefail
cd "${0:a:h}/.."
export PATH="/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/go/bin:/usr/local/bin"

RELEASE=0
case "${1:-}" in
  "") ;;
  --release) RELEASE=1 ;;
  *) echo "사용법: $0 [--release]" >&2; exit 2 ;;
esac

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	go_files=("${(@f)$(git ls-files --cached --others --exclude-standard -- '*.go')}")
else
	go_files=("${(@f)$(find . -type f -name '*.go' -not -path './dist/*' | sort)}")
fi
unformatted=$(gofmt -l "$go_files[@]")
if [ -n "$unformatted" ]; then
  echo "gofmt 필요:" >&2
  echo "$unformatted" >&2
  exit 1
fi

./build.sh
go vet ./...
go test -race ./...

if [ "$RELEASE" = 1 ]; then
  go run golang.org/x/vuln/cmd/govulncheck@latest ./...
  ./scripts/build-release.sh
  ./scripts/verify-release.sh
fi

echo "검증 통과$([ "$RELEASE" = 1 ] && echo ' (release)')"
