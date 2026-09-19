#!/bin/zsh
# 샘플 데이터로 관리 GUI를 미리 보거나 화면을 PNG로 저장한다.
# -D PASU_PREVIEW로만 컴파일되는 gui/Preview.swift의 진입점을 쓰므로 배포 빌드에는
# 들어가지 않으며, 실제 agent·Keychain·소켓·로그를 전혀 건드리지 않는다.
#
#   scripts/gui-preview.sh                 dist/gui-preview/*.png 스냅샷 저장
#   scripts/gui-preview.sh --out <dir>     지정한 디렉터리에 스냅샷 저장
#   scripts/gui-preview.sh --run           샘플 데이터로 GUI를 띄워 직접 조작
set -euo pipefail
cd "${0:a:h}/.."
export PATH="/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/go/bin:/usr/local/bin"

go run ./scripts/signing-config

OUT="dist/gui-preview"
MODE="snapshot"
case "${1:-}" in
	"") ;;
	--run) MODE="run" ;;
	--out)
		[[ -n "${2:-}" ]] || { echo "사용법: $0 [--run | --out <dir>]" >&2; exit 2 }
		OUT="$2" ;;
	*) echo "사용법: $0 [--run | --out <dir>]" >&2; exit 2 ;;
esac

export CLANG_MODULE_CACHE_PATH="${TMPDIR:-/tmp}/pasu-v2-clang-cache"
export SWIFT_MODULECACHE_PATH="${TMPDIR:-/tmp}/pasu-v2-swift-cache"
work=$(mktemp -d "${TMPDIR:-/tmp}/pasu-preview-build.XXXXXX")
trap 'rm -rf "$work"' EXIT
preview_version=$(<VERSION)
[[ -n "$preview_version" && "$preview_version" != *[^0-9A-Za-z.+-]* ]] || { echo "잘못된 VERSION" >&2; exit 1; }
print -r -- "let previewBuildVersion = \"$preview_version\"" > "$work/PreviewVersion.swift"
mkdir -p dist
xcrun swiftc -swift-version 5 -parse-as-library -O -D PASU_PREVIEW \
	-framework SwiftUI -framework AppKit -framework Security -lbsm \
	-o dist/PasuGUI-preview .build/signing/Identity.swift gui/*.swift "$work/PreviewVersion.swift"

rm -rf "$work"

if [[ "$MODE" == run ]]; then
	exec dist/PasuGUI-preview
fi
rm -rf "$OUT"
dist/PasuGUI-preview --snapshot "$OUT"
