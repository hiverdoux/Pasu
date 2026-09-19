package main

import (
	"context"
	"os/exec"
	"time"
)

// 알림 내용(프로세스 경로 등)은 신뢰할 수 없는 값이므로 AppleScript 문자열에
// 끼워 넣지 않고 osascript의 argv로 전달한다(스크립트 인젝션 차단).
const notifyScript = `on run argv
display notification (item 1 of argv) with title "pasu" subtitle (item 2 of argv)
end run`

func macNotify(subtitle, body string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "/usr/bin/osascript", "-e", notifyScript, "--", body, subtitle).Run()
}

// 테스트와 기동 실패 보고에서 교체할 수 있는 간접 호출점.
var macNotifyFn = macNotify
