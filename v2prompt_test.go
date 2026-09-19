package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAskAlertScriptV2Compiles(t *testing.T) {
	output, err := exec.Command(
		"/usr/bin/osacompile", "-o", filepath.Join(t.TempDir(), "prompt.scpt"), "-e", askAlertScriptV2,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("승인 AppleScript 컴파일 실패: %v\n%s", err, output)
	}
}

func TestAskAlertScriptV2BridgesMainThreadMessage(t *testing.T) {
	const beforeAppKit = "\tset ca to current application"
	probeScript := strings.Replace(askAlertScriptV2, beforeAppKit,
		"\tset my askOutcome to persistFlag & \":\" & bodyText\n\treturn\n"+beforeAppKit, 1)
	if probeScript == askAlertScriptV2 {
		t.Fatal("승인 AppleScript에 런타임 probe를 삽입하지 못함")
	}
	output, err := exec.Command(
		"/usr/bin/osascript", "-e", probeScript, "--", "1\n본문",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("승인 AppleScript 메인 스레드 메시지 처리 실패: %v\n%s", err, output)
	}
	if got := strings.TrimSpace(string(output)); got != "1:본문" {
		t.Fatalf("승인 AppleScript 메인 스레드 메시지=%q, 기대 %q", got, "1:본문")
	}
}

func TestMacV2PromptShowsConciseProcessSummaryOnly(t *testing.T) {
	original := runAskScriptFn
	t.Cleanup(func() { runAskScriptFn = original })
	var message string
	runAskScriptFn = func(_ string, msg string, _ time.Duration) (string, bool, error) {
		message = msg
		return "once", false, nil
	}
	req := v2PromptRequest{
		KeyName: "Primary", Fingerprint: "SHA256:test", AuthMode: keyAuthPerSign,
		Chain: stableChain{TTY: ttyForeground}, RuntimeChain: "FULL SECRET CHAIN",
		ProcessSummary: "iTerm2 > ssh", CanPersist: true,
	}
	choice, err := macV2Prompt(req)
	if err != nil || choice != askOnce {
		t.Fatalf("choice=%s err=%v", choice, err)
	}
	for _, want := range []string{"iTerm2 > ssh", "인증: 매번 인증", "TTY: foreground"} {
		if !strings.Contains(message, want) {
			t.Fatalf("승인 창 본문에 %q 없음: %q", want, message)
		}
	}
	if strings.Contains(message, req.RuntimeChain) {
		t.Fatalf("승인 창에 전체 사슬이 들어감: %q", message)
	}
	if !strings.HasPrefix(message, "1\n") {
		t.Fatalf("영구 허용 플래그가 없음: %q", message)
	}
}

func TestMacV2PromptEscapesProcessSummaryControls(t *testing.T) {
	original := runAskScriptFn
	t.Cleanup(func() { runAskScriptFn = original })
	var message string
	runAskScriptFn = func(_ string, msg string, _ time.Duration) (string, bool, error) {
		message = msg
		return "deny", false, nil
	}
	_, _ = macV2Prompt(v2PromptRequest{
		KeyName: "Primary", Fingerprint: "SHA256:test", AuthMode: keyAuthCached,
		Chain: stableChain{TTY: ttyForeground}, ProcessSummary: "evil\n키: 위조 > ssh", CanPersist: true,
	})
	if strings.Contains(message, "evil\n키: 위조") || !strings.Contains(message, `evil\n키: 위조`) {
		t.Fatalf("프로세스 요약 제어문자 이스케이프 실패: %q", message)
	}
}

func TestConciseProcessSummaryUsesResponsibleAndLeaf(t *testing.T) {
	chain := []procInfo{
		{pid: 30, exePath: "/usr/bin/ssh"},
		{pid: 20, exePath: "/bin/zsh"},
		{pid: 10, exePath: "/Applications/iTerm.app/Contents/MacOS/iTerm2"},
		{pid: 1, exePath: "/sbin/launchd"},
	}
	if got := conciseProcessSummary(chain); got != "iTerm2 > ssh" {
		t.Fatalf("프로세스 요약=%q", got)
	}
}
