package main

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSafeTextEscapesASCIIControls(t *testing.T) {
	in := "정상 경로/a b\n줄\r캐리지\t탭\x01\x7f"
	want := `정상 경로/a b\n줄\r캐리지\t탭\x01\x7F`
	if got := safeText(in); got != want {
		t.Fatalf("safeText = %q, 기대 %q", got, want)
	}
}

func TestAuditLogKeepsInjectedMessageOnOneLine(t *testing.T) {
	a, path := testAuditLog(t, 0)
	a.logf("EVENT path=%s", "/tmp/정상\n2026-01-01 FAKE allow")
	got := readLog(t, path)
	if strings.Count(got, "\n") != 1 {
		t.Fatalf("감사 이벤트가 여러 물리 줄로 갈라짐: %q", got)
	}
	if !strings.Contains(got, `path=/tmp/정상\n2026-01-01 FAKE allow`) {
		t.Fatalf("제어문자 가시화 누락: %q", got)
	}
}

func TestAskTextEscapesInjectedLabels(t *testing.T) {
	chain := askTestChain()
	chain[0].exePath = "/tmp/evil\n최상위 앱: 위조"
	k, _, ok := askKey(chain)
	if !ok {
		t.Fatal("테스트 사슬이 승인 키로 해석되지 않음")
	}
	got := askText(k, chain)
	if strings.Contains(got, "evil\n최상위 앱: 위조") {
		t.Fatalf("승인 창 본문 줄 구조가 주입됨: %q", got)
	}
	if !strings.Contains(got, `evil\n최상위 앱: 위조`) {
		t.Fatalf("주입 문자가 가시화되지 않음: %q", got)
	}
}

func TestCooldownConfigDefaultsOverridesAndErrors(t *testing.T) {
	if got := compactDuration(0); got != "0s" {
		t.Fatalf("0 기간 표기=%q, 기대 0s", got)
	}
	a := mustParse(t, "allow codesign team=AAAAAAAAAA id=pasu.test")
	if a.askCooldown == nil || *a.askCooldown != 5*time.Minute {
		t.Fatalf("askcooldown 기본값 이상: %v", a.askCooldown)
	}
	if a.notifyCooldown == nil || *a.notifyCooldown != time.Minute {
		t.Fatalf("notify 기본값 이상: %v", a.notifyCooldown)
	}
	a = mustParse(t, "limit askcooldown 90s\nlimit notify 2m\nallow codesign team=AAAAAAAAAA id=pasu.test")
	if a.askCooldown == nil || *a.askCooldown != 90*time.Second ||
		a.notifyCooldown == nil || *a.notifyCooldown != 2*time.Minute {
		t.Fatalf("쿨다운 덮어쓰기 이상: ask=%v notify=%v", a.askCooldown, a.notifyCooldown)
	}
	a = mustParse(t, "limit askcooldown off\nlimit notify off\nallow codesign team=AAAAAAAAAA id=pasu.test")
	if a.askCooldown != nil || a.notifyCooldown != nil {
		t.Fatalf("off가 제한 해제로 해석되지 않음: ask=%v notify=%v", a.askCooldown, a.notifyCooldown)
	}
	for _, bad := range []string{
		"limit askcooldown 500ms",
		"limit notify never",
		"limit askcooldown 1m\nlimit askcooldown 2m",
		"limit notify off\nlimit notify 1m",
	} {
		if _, err := parseAllowlist(strings.NewReader(bad), "/home/tester"); err == nil {
			t.Errorf("오류 기대했으나 통과: %q", bad)
		}
	}
}

func TestAskCooldownStartsAfterPromptAndPreservesRememberedDecisions(t *testing.T) {
	var logs []string
	a := newAsker("/tmp/approvals.conf", nil, nil, func(f string, args ...any) {
		logs = append(logs, fmt.Sprintf(f, args...))
	})
	base := time.Unix(1_000_000, 0)
	a.now = func() time.Time { return base }
	a.cooldown = 5 * time.Minute
	var calls atomic.Int32
	a.prompt = fixedPrompt(askOnce, &calls)
	if res := a.decide(askTestChain()); !res.allow {
		t.Fatalf("첫 요청이 허용되지 않음: %+v", res)
	}
	if res := a.decide(askTestChain()); res.allow || res.reason != "승인_창_쿨다운" {
		t.Fatalf("쿨다운 거부 이상: %+v", res)
	}
	if res := a.decide(askTestChain()); res.allow || res.reason != "승인_창_쿨다운" {
		t.Fatalf("반복 쿨다운 거부 이상: %+v", res)
	}
	joined := strings.Join(logs, "\n")
	if strings.Count(joined, "ASK throttle") != 1 {
		t.Fatalf("쿨다운 한 번에 throttle 로그가 한 줄이 아님: %s", joined)
	}
	if calls.Load() != 1 {
		t.Fatalf("쿨다운 중 창 호출 수=%d", calls.Load())
	}

	k, _, _ := askKey(askTestChain())
	a.persisted[k] = true
	if res := a.decide(askTestChain()); !res.allow || res.via != "approval always" {
		t.Fatalf("기억된 승인이 쿨다운에 가려짐: %+v", res)
	}
	delete(a.persisted, k)
	a.denied[k] = true
	if res := a.decide(askTestChain()); res.allow || res.reason != "승인_거부_기억" {
		t.Fatalf("기억된 거부가 쿨다운에 가려짐: %+v", res)
	}
}

func TestDenyNotifyLimiterUsesRootAndReason(t *testing.T) {
	l := newDenyNotifyLimiter(time.Minute)
	now := time.Unix(1_000_000, 0)
	l.now = func() time.Time { return now }
	chain := askTestChain()
	peer1 := chain[0]
	if !l.allow(peer1, chain, "allowlist_불일치") {
		t.Fatal("첫 알림이 억제됨")
	}
	peer2 := peer1
	peer2.exePath = "/tmp/copied/ssh"
	if l.allow(peer2, chain, "allowlist_불일치") {
		t.Fatal("피어 경로 복사가 같은 최상위 앱 스로틀을 우회함")
	}
	if !l.allow(peer2, chain, "모르는_키_요청") {
		t.Fatal("다른 거부 사유까지 숨김")
	}
	now = now.Add(61 * time.Second)
	if !l.allow(peer2, chain, "allowlist_불일치") {
		t.Fatal("기간 경과 후 알림이 회복되지 않음")
	}
	off := newDenyNotifyLimiter(0)
	if !off.allow(peer1, chain, "x") || !off.allow(peer1, chain, "x") {
		t.Fatal("off(기간 0)가 매번 알림으로 동작하지 않음")
	}
}

func TestDenyRecorderSummarizesAndFlushesOnClose(t *testing.T) {
	var mu sync.Mutex
	var logs []string
	r := newDenyRecorder(time.Minute, func(f string, args ...any) {
		mu.Lock()
		logs = append(logs, fmt.Sprintf(f, args...))
		mu.Unlock()
	})
	key := denyKey{peer: "/usr/bin/ssh", reason: "allowlist_불일치"}
	r.record(key, "DENY sign peer=1")
	r.record(key, "DENY sign peer=2")
	r.record(key, "DENY sign peer=3")
	r.Close()
	mu.Lock()
	joined := strings.Join(logs, "\n")
	mu.Unlock()
	if strings.Count(joined, "DENY sign") != 1 {
		t.Fatalf("첫 전체 DENY 외의 반복이 축약되지 않음: %s", joined)
	}
	if !strings.Contains(joined, "DENY-SUMMARY") || !strings.Contains(joined, "suppressed=2") ||
		!strings.Contains(joined, "window=60s") {
		t.Fatalf("종료 flush 요약 이상: %s", joined)
	}
}

func TestDenyRecorderConcurrentBurst(t *testing.T) {
	var mu sync.Mutex
	var logs []string
	r := newDenyRecorder(time.Minute, func(f string, args ...any) {
		mu.Lock()
		logs = append(logs, fmt.Sprintf(f, args...))
		mu.Unlock()
	})
	key := denyKey{peer: "/tmp/tool", reason: "변경_연산_remove-all"}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r.record(key, "DENY remove-all peer=%d", i)
		}(i)
	}
	wg.Wait()
	r.Close()
	mu.Lock()
	joined := strings.Join(logs, "\n")
	mu.Unlock()
	if strings.Count(joined, "DENY remove-all") != 1 || !strings.Contains(joined, "suppressed=99") {
		t.Fatalf("동시 폭주 축약 이상: %s", joined)
	}
}

func TestDenyRecorderFlushesExpiredWindow(t *testing.T) {
	var logs []string
	r := newDenyRecorder(time.Hour, func(f string, args ...any) {
		logs = append(logs, fmt.Sprintf(f, args...))
	})
	defer r.Close()
	key := denyKey{peer: "/bin/x", reason: "test"}
	r.record(key, "DENY first")
	r.record(key, "DENY second")
	r.mu.Lock()
	expires := r.entries[key].first.Add(time.Hour)
	r.mu.Unlock()
	r.flushExpired(expires)
	joined := strings.Join(logs, "\n")
	if !strings.Contains(joined, "DENY-SUMMARY") || !strings.Contains(joined, "suppressed=1") {
		t.Fatalf("윈도 만료 요약 없음: %s", joined)
	}
}
