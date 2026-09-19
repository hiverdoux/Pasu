package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func FuzzParseApprovalLine(f *testing.F) {
	for _, seed := range []string{
		`approve "/usr/bin/ssh" "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT"`,
		`approve "공백 있는 경로" "/Applications/앱.app" # 2026-09-02T00:00:00+09:00`,
		`approve "" "/root"`,
		`approve "짝없는`,
		"\x00\xff\n",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		k, ok := parseApprovalLine(line)
		if !ok {
			return
		}
		if k.peer == "" || k.root == "" {
			t.Fatalf("성공한 파서가 빈 경로를 반환: %+v", k)
		}
		round, roundOK := parseApprovalLine(fmt.Sprintf("approve %q %q # fuzz", k.peer, k.root))
		if !roundOK || round != k {
			t.Fatalf("승인 줄 왕복 실패: before=%+v after=%+v ok=%t", k, round, roundOK)
		}
	})
}

func askTestChain() []procInfo {
	return []procInfo{
		{pid: 30, exePath: "/usr/bin/ssh"},
		{pid: 20, exePath: "/bin/zsh"},
		{pid: 10, exePath: "/Applications/iTerm.app/Contents/MacOS/iTerm2"},
		{pid: 1, exePath: "/sbin/launchd"},
	}
}

func testAsker(t *testing.T) *asker {
	t.Helper()
	return newAsker(filepath.Join(t.TempDir(), "approvals.conf"), nil, nil, t.Logf)
}

// fixedPrompt는 항상 같은 선택을 돌려주는 가짜 창이다. 호출 횟수를 센다.
func fixedPrompt(choice askChoice, calls *atomic.Int32) func(string) (askChoice, error) {
	return func(_ string) (askChoice, error) {
		calls.Add(1)
		return choice, nil
	}
}

func TestAskKeyFromChain(t *testing.T) {
	k, root, ok := askKey(askTestChain())
	if !ok || k.peer != "/usr/bin/ssh" || k.root != "/Applications/iTerm.app/Contents/MacOS/iTerm2" {
		t.Fatalf("askKey 이상: %+v ok=%v", k, ok)
	}
	if root.pid != 10 {
		t.Fatalf("최상위 앱 프로세스 이상: %+v", root)
	}
	// launchd 바로 아래에서 직접 접속한 피어는 자기 자신이 최상위다.
	k, _, ok = askKey([]procInfo{{pid: 5, exePath: "/x/tool"}, {pid: 1, exePath: "/sbin/launchd"}})
	if !ok || k.peer != "/x/tool" || k.root != "/x/tool" {
		t.Fatalf("직접 자식 askKey 이상: %+v ok=%v", k, ok)
	}
}

func TestAskKeyRejectsIncompleteChain(t *testing.T) {
	// launchd(pid 1)까지 닿지 못한 사슬 — 신원 불완전은 창 없이 거부돼야 한다.
	chain := askTestChain()
	if _, _, ok := askKey(chain[:3]); ok {
		t.Error("불완전 사슬이 승인 대상이 됨")
	}
	// 최상위 앱의 실행 파일 경로 미상도 마찬가지.
	noRoot := askTestChain()
	noRoot[2].exePath = ""
	if _, _, ok := askKey(noRoot); ok {
		t.Error("최상위 경로 미상이 승인 대상이 됨")
	}
	if _, _, ok := askKey(nil); ok {
		t.Error("빈 사슬이 승인 대상이 됨")
	}
}

func TestParseAskDirective(t *testing.T) {
	if a := mustParse(t, "allow codesign team=AAAAAAAAAA id=pasu.test"); a.ask {
		t.Error("기본값이 on")
	}
	if a := mustParse(t, "ask on\nallow codesign team=AAAAAAAAAA id=pasu.test"); !a.ask {
		t.Error("ask on 미반영")
	}
	if a := mustParse(t, "ask off\nallow codesign team=AAAAAAAAAA id=pasu.test"); a.ask {
		t.Error("ask off 미반영")
	}
	for _, bad := range []string{
		"ask",            // 값 없음
		"ask maybe",      // 모르는 값
		"ask on extra",   // 잉여 토큰
		"ask on\nask on", // 중복 지시어
	} {
		if _, err := parseAllowlist(strings.NewReader(bad), "/home/tester"); err == nil {
			t.Errorf("오류 기대했으나 통과: %q", bad)
		}
	}
}

func TestAskDecideOnceIsNotRemembered(t *testing.T) {
	a := testAsker(t)
	var calls atomic.Int32
	a.prompt = fixedPrompt(askOnce, &calls)
	if res := a.decide(askTestChain()); !res.allow || res.via != "ask once" {
		t.Fatalf("이번만 허용 실패: %+v", res)
	}
	if res := a.decide(askTestChain()); !res.allow {
		t.Fatalf("두 번째 요청 거부: %+v", res)
	}
	if calls.Load() != 2 {
		t.Fatalf("이번만인데 창이 %d회(기대 2 — 매번 다시 물어야 함)", calls.Load())
	}
}

func TestAskDecideAlwaysPersistsAcrossRestart(t *testing.T) {
	a := testAsker(t)
	var calls atomic.Int32
	a.prompt = fixedPrompt(askAlways, &calls)
	res := a.decide(askTestChain())
	if !res.allow || res.via != "ask always" || res.persist == nil {
		t.Fatalf("항상 허용 실패: %+v", res)
	}
	if _, err := os.Stat(a.path); !os.IsNotExist(err) {
		t.Fatalf("서명 성공 전 approvals.conf가 생김: %v", err)
	}
	a.commitAlways(*res.persist)
	data, err := os.ReadFile(a.path)
	if err != nil || !strings.Contains(string(data), `approve "/usr/bin/ssh" "/Applications/iTerm.app/Contents/MacOS/iTerm2"`) {
		t.Fatalf("approvals.conf 기록 이상: err=%v\n%s", err, data)
	}
	// 재기동 시뮬레이션: 같은 파일 내용으로 새 asker를 만들면 창 없이 허용돼야 한다.
	b := newAsker(a.path, data, nil, t.Logf)
	b.prompt = fixedPrompt(askDenied, &calls) // 불리면 거부가 나와 테스트가 실패하게
	if res := b.decide(askTestChain()); !res.allow || res.via != "approval always" {
		t.Fatalf("재기동 후 항상 승인 미적용: %+v", res)
	}
	if calls.Load() != 1 {
		t.Fatalf("창 호출 %d회(기대 1)", calls.Load())
	}
}

func TestAskDecideDenyRemembered(t *testing.T) {
	a := testAsker(t)
	var calls atomic.Int32
	a.prompt = fixedPrompt(askDenied, &calls)
	if res := a.decide(askTestChain()); res.allow || res.reason != "승인_거부" {
		t.Fatalf("거부 판정 이상: %+v", res)
	}
	if res := a.decide(askTestChain()); res.allow || res.reason != "승인_거부_기억" {
		t.Fatalf("거부 기억 미적용: %+v", res)
	}
	if calls.Load() != 1 {
		t.Fatalf("거부 기억인데 창이 %d회(기대 1)", calls.Load())
	}
}

func TestAskDecideTimeoutNotRemembered(t *testing.T) {
	a := testAsker(t)
	var calls atomic.Int32
	a.prompt = fixedPrompt(askTimeout, &calls)
	if res := a.decide(askTestChain()); res.allow || res.reason != "승인_시간_초과" {
		t.Fatalf("시간 초과 판정 이상: %+v", res)
	}
	if res := a.decide(askTestChain()); res.reason != "승인_시간_초과" {
		t.Fatalf("시간 초과가 기억됨(다시 물어야 함): %+v", res)
	}
	if calls.Load() != 2 {
		t.Fatalf("창 호출 %d회(기대 2)", calls.Load())
	}
}

func TestAskDecideIncompleteChainDeniesWithoutPrompt(t *testing.T) {
	a := testAsker(t)
	var calls atomic.Int32
	a.prompt = fixedPrompt(askAlways, &calls)
	res := a.decide(askTestChain()[:3])
	if res.allow || res.reason != "승인_불가(사슬_불완전)" {
		t.Fatalf("불완전 사슬 판정 이상: %+v", res)
	}
	if calls.Load() != 0 {
		t.Fatal("불완전 사슬인데 창이 뜸")
	}
}

func TestAskSingleFlight(t *testing.T) {
	a := testAsker(t)
	started := make(chan struct{})
	release := make(chan askChoice)
	a.prompt = func(_ string) (askChoice, error) {
		close(started)
		return <-release, nil
	}
	done := make(chan askResult, 1)
	go func() { done <- a.decide(askTestChain()) }()
	<-started
	// 창이 떠 있는 동안 오는 다른 미지 요청은 즉시 거부돼야 한다.
	if res := a.decide(askTestChain()); res.allow || res.reason != "승인_창_사용_중" {
		t.Fatalf("직렬화 실패: %+v", res)
	}
	release <- askOnce
	if res := <-done; !res.allow {
		t.Fatalf("창 응답 후 허용 실패: %+v", res)
	}
	// 창이 닫힌 뒤에는 다시 물을 수 있어야 한다.
	var calls atomic.Int32
	a.prompt = fixedPrompt(askOnce, &calls)
	if res := a.decide(askTestChain()); !res.allow {
		t.Fatalf("창 종료 후 재질문 실패: %+v", res)
	}
}

func TestAskLoadSkipsCorruptLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "approvals.conf")
	content := "# 주석\n" +
		"approve \"/usr/bin/ssh\" \"/Applications/iTerm.app/Contents/MacOS/iTerm2\" # 2026-08-17\n" +
		"이건 깨진 줄\n" +
		"approve \"짝없는\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	a := newAsker(path, []byte(content), nil, t.Logf)
	var calls atomic.Int32
	a.prompt = fixedPrompt(askDenied, &calls)
	if res := a.decide(askTestChain()); !res.allow || res.via != "approval always" {
		t.Fatalf("정상 줄이 로드되지 않음: %+v", res)
	}
	if len(a.persisted) != 1 {
		t.Fatalf("깨진 줄이 로드됨: %d건", len(a.persisted))
	}
}

func TestAskPersistRoundtripWithSpaces(t *testing.T) {
	a := testAsker(t)
	k := approvalKey{peer: "/Applications/Some App.app/Contents/MacOS/tool", root: "/Applications/My \"Quoted\" App.app/bin"}
	if err := a.persist(k); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(a.path)
	if err != nil {
		t.Fatal(err)
	}
	b := newAsker(a.path, data, nil, t.Logf)
	if !b.persisted[k] {
		t.Fatalf("공백·따옴표 경로 왕복 실패: %+v", b.persisted)
	}
}

// interceptAskScripts는 runAskScriptFn을 가짜로 바꾸고 실행된 스크립트
// 순서를 기록한다. 반환된 함수로 원복한다.
func interceptAskScripts(t *testing.T, fake func(script, msg string) (string, bool, error)) *[]string {
	t.Helper()
	orig := runAskScriptFn
	t.Cleanup(func() { runAskScriptFn = orig })
	var ran []string
	runAskScriptFn = func(script, msg string, _ time.Duration) (string, bool, error) {
		ran = append(ran, script)
		return fake(script, msg)
	}
	return &ran
}

func TestParseAlertChoice(t *testing.T) {
	for out, want := range map[string]askChoice{
		"deny": askDenied, "이번만 허용": askOnce, "이 프로세스에 대해 항상 허용": askAlways,
		"timeout": askTimeout, "로그아웃까지": askTimeout, "이상한값": askTimeout, "": askTimeout,
	} {
		if got := parseAlertChoice(out); got != want {
			t.Errorf("%q → %v (기대 %v)", out, got, want)
		}
	}
}

func TestMacAskPromptAlertPath(t *testing.T) {
	ran := interceptAskScripts(t, func(script, msg string) (string, bool, error) {
		if script != askAlertScript {
			t.Errorf("승인 알림 창이 아닌 스크립트 실행: %.40q", script)
		}
		if !strings.Contains(msg, "본문") {
			t.Errorf("창 본문 전달 안 됨: %q", msg)
		}
		return "이 프로세스에 대해 항상 허용", false, nil
	})
	choice, err := macAskPrompt("본문")
	if choice != askAlways || err != nil {
		t.Fatalf("승인 알림 창 경로 이상: %v err=%v", choice, err)
	}
	if len(*ran) != 1 {
		t.Fatalf("스크립트 %d회 실행(기대 1)", len(*ran))
	}
}

func TestMacAskPromptAlertTimeoutNoFallback(t *testing.T) {
	// 무응답 시간 초과는 실행 실패와 구분한다.
	// 시간 초과 후에는 폴백 창을 추가로 표시하지 않는다.
	ran := interceptAskScripts(t, func(string, string) (string, bool, error) {
		return "timeout", false, nil
	})
	choice, err := macAskPrompt("본문")
	if choice != askTimeout || err != nil {
		t.Fatalf("시간 초과 판정 이상: %v err=%v", choice, err)
	}
	if len(*ran) != 1 {
		t.Fatalf("시간 초과 후 폴백이 실행됨: %d회", len(*ran))
	}
}

func TestMacAskPromptFallsBackToLegacy(t *testing.T) {
	ran := interceptAskScripts(t, func(script, _ string) (string, bool, error) {
		switch script {
		case askAlertScript:
			return "", false, errors.New("브리지 미동작")
		case askFallbackScript:
			return "이번만 허용", false, nil
		}
		t.Errorf("모르는 스크립트: %.40q", script)
		return "", false, errors.New("모르는 스크립트")
	})
	choice, err := macAskPrompt("본문")
	if choice != askOnce {
		t.Fatalf("폴백 판정 이상: %v", choice)
	}
	if err == nil || !strings.Contains(err.Error(), "폴백") {
		t.Fatalf("폴백 사실이 오류 설명에 없음: %v", err)
	}
	want := []string{askAlertScript, askFallbackScript}
	if len(*ran) != 2 || (*ran)[0] != want[0] || (*ran)[1] != want[1] {
		t.Fatalf("실행 순서 이상: %d회", len(*ran))
	}
}

func TestMacAskPromptFallbackCancelIsDeny(t *testing.T) {
	// 폴백 창의 "거부"는 취소 버튼이라 AppleScript 오류 -128(canceled)로
	// 돌아온다 — 명시적 거부로 판정돼 기억 대상이 되는지 확인한다.
	interceptAskScripts(t, func(script, _ string) (string, bool, error) {
		if script == askAlertScript {
			return "", false, errors.New("브리지 미동작")
		}
		return "", true, nil
	})
	choice, err := macAskPrompt("본문")
	if choice != askDenied {
		t.Fatalf("폴백 취소 판정 이상: %v", choice)
	}
	if err == nil || !strings.Contains(err.Error(), "폴백") {
		t.Fatalf("폴백 사실이 오류 설명에 없음: %v", err)
	}
}

func TestRunAskScriptTimeoutMapsToTimeout(t *testing.T) {
	// 실제 osascript를 1초 한도로 죽여 "timeout" 출력으로 접히는지 확인
	// (창 없는 스크립트라 화면에 아무것도 뜨지 않는다).
	out, canceled, err := runAskScript("on run argv\ndelay 10\nend run", "x", 1*time.Second)
	if out != "timeout" || canceled || err != nil {
		t.Fatalf("시간 초과 매핑 이상: out=%q canceled=%v err=%v", out, canceled, err)
	}
}

func TestRunAskScriptAcceptsLeadingHyphenArgument(t *testing.T) {
	out, canceled, err := runAskScript("on run argv\nreturn item 1 of argv\nend run", "-leading", time.Second)
	if err != nil || canceled || out != "-leading" {
		t.Fatalf("하이픈 인자 전달 실패: out=%q canceled=%v err=%v", out, canceled, err)
	}
}

func TestAppleScriptCancelRequiresExactErrorCode(t *testing.T) {
	if !isAppleScriptCanceled("execution error: User canceled. (-128)\n") {
		t.Fatal("정확한 -128 취소를 놓침")
	}
	if isAppleScriptCanceled("temporary path /tmp/job-128 failed (-1)") || isAppleScriptCanceled("unrelated -128 text") {
		t.Fatal("부분 문자열 -128을 사용자 취소로 오인")
	}
}

func TestAskPersistFailureStillAllows(t *testing.T) {
	// 존재하지 않는 폴더 → 파일 기록은 실패하지만 이번 프로세스 수명의
	// 메모리 승인으로는 남아야 한다.
	a := newAsker(filepath.Join(t.TempDir(), "no-such-dir", "approvals.conf"), nil, nil, t.Logf)
	var calls atomic.Int32
	a.prompt = fixedPrompt(askAlways, &calls)
	res := a.decide(askTestChain())
	if !res.allow || res.persist == nil {
		t.Fatalf("기록 실패가 허용을 막음: %+v", res)
	}
	a.commitAlways(*res.persist)
	if res := a.decide(askTestChain()); !res.allow || res.via != "approval always" {
		t.Fatalf("메모리 승인 미유지: %+v", res)
	}
	if calls.Load() != 1 {
		t.Fatalf("창 호출 %d회(기대 1)", calls.Load())
	}
}
