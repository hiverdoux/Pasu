package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// v1 승인창과 공통 승인 결과 형식. v2 승인 조정은 v2prompt.go에 있다.
// v1은 pasu.conf의 `ask on`일 때 허용 목록에 없는 요청을 사용자에게 묻는다.
// 승인 단위는 커널에서 조회한 요청 프로그램·최상위 앱의 실행 경로 쌍이다.
// 항상 허용은 서명 성공 후 approvals.conf에 저장하고, 명시적 거부는 종료까지
// 기억한다. 시간 초과·실행 실패는 영구 결정으로 남기지 않는다.
// 창은 하나씩 표시하며, 다른 미지 요청과 재표시 대기 시간의 요청은 거부한다.
// 승인은 서명 한도 검사와 키 잠금 해제보다 먼저 수행한다.

// approvalKey는 승인·거부를 기억하는 단위다.
type approvalKey struct {
	peer string // 소켓에 접속한 프로세스의 실행 파일 실제 경로
	root string // 조상 사슬에서 launchd 바로 아래(최상위 앱)의 실행 파일 실제 경로
}

// askChoice는 대화창의 결과다. 제로 값은 가장 보수적인 askTimeout
// (거부하되 기억하지 않음)이다.
type askChoice int

const (
	askTimeout askChoice = iota // 시간 초과·창 실행 실패 — 기억하지 않음
	askDenied                   // 명시적 거부 — 재기동까지 기억
	askOnce                     // 이 요청 1건만 허용
	askAlways                   // approvals.conf에 기록해 계속 허용
)

func (c askChoice) String() string {
	switch c {
	case askDenied:
		return "deny"
	case askOnce:
		return "once"
	case askAlways:
		return "always"
	}
	return "timeout"
}

// askResult는 asker.decide의 판정이다.
type askResult struct {
	allow   bool
	via     string       // 허용일 때 감사 로그 matched= 표기
	proc    procInfo     // 허용 근거 프로세스(최상위 앱) — 감사 로그 via= 표기용
	reason  string       // 거부일 때 deny reason
	persist *approvalKey // 서명 성공 뒤 디스크에 확정할 "항상 허용"
}

type asker struct {
	path   string                               // approvals.conf 경로
	bind   *confBinding                         // "항상" 기록 시 설정 지문 갱신(nil 허용)
	logf   func(string, ...any)                 // 감사 로그(audit.logf) — ASK 이벤트 기록
	prompt func(text string) (askChoice, error) // 실구현 macAskPrompt(테스트에서 교체)

	mu         sync.Mutex
	busy       bool // 창이 떠 있는 동안 참 — 전역 1창 직렬화
	denied     map[approvalKey]bool
	persisted  map[approvalKey]bool
	pending    map[approvalKey]bool // 메모리 승인은 됐지만 아직 디스크에 확정되지 않음
	persisting map[approvalKey]bool
	cooldown   time.Duration
	nextAsk    time.Time
	now        func() time.Time
	// 쿨다운 중 ASK throttle은 한 번만 기록한다. 실제 DENY 반복은 전역
	// denyRecorder가 peer+reason 단위로 축약한다.
	throttleLogged bool
}

// newAsker는 approvals.conf 원문(data)을 받아 만든다. 파일을 직접 읽지 않는
// 이유: 설정 결속(confBinding)과 승인 로드가 각자 파일을 읽으면 두 판독
// 사이에 끼어든 변조가 "정책엔 반영되고 지문 검증은 통과"하는 경쟁이 생긴다
// — run()이 한 번 읽어 양쪽에 같은 바이트를 준다.
func newAsker(path string, data []byte, bind *confBinding, logf func(string, ...any)) *asker {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	a := &asker{
		path:       path,
		bind:       bind,
		logf:       logf,
		prompt:     macAskPrompt,
		denied:     map[approvalKey]bool{},
		persisted:  map[approvalKey]bool{},
		pending:    map[approvalKey]bool{},
		persisting: map[approvalKey]bool{},
		now:        time.Now,
	}
	a.loadPersisted(data)
	return a
}

// askKey는 조상 사슬에서 승인 단위를 뽑는다. 사슬이 launchd(pid 1)까지
// 완전하고 피어·최상위 앱의 실행 파일 경로가 모두 확인될 때만 성립한다 —
// 신원이 불완전하면 창을 띄우지 않고 거부한다(불허 방향).
func askKey(chain []procInfo) (approvalKey, procInfo, bool) {
	if len(chain) < 2 || chain[len(chain)-1].pid != 1 {
		return approvalKey{}, procInfo{}, false
	}
	rootProc := chain[len(chain)-2]
	k := approvalKey{peer: chain[0].exePath, root: rootProc.exePath}
	if k.peer == "" || k.root == "" {
		return approvalKey{}, procInfo{}, false
	}
	return k, rootProc, true
}

// decide는 allowlist에 없는 서명 요청 하나를 판정한다. 기억된 결정이 있으면
// 창 없이 즉시 답하고, 없으면 대화창을 띄운다. 락은 창이 떠 있는 동안 잡지
// 않으므로 allowlist를 통과하는 정상 요청은 영향을 받지 않는다.
func (a *asker) decide(chain []procInfo) askResult {
	k, rootProc, ok := askKey(chain)
	if !ok {
		return askResult{reason: "승인_불가(사슬_불완전)"}
	}
	a.mu.Lock()
	now := a.now()
	switch {
	case a.persisted[k]:
		var pending *approvalKey
		if a.pending[k] {
			copy := k
			pending = &copy
		}
		a.mu.Unlock()
		return askResult{allow: true, via: "approval always", proc: rootProc, persist: pending}
	case a.denied[k]:
		a.mu.Unlock()
		return askResult{reason: "승인_거부_기억"}
	case a.busy:
		a.mu.Unlock()
		return askResult{reason: "승인_창_사용_중"}
	case a.cooldown > 0 && now.Before(a.nextAsk):
		logNow := !a.throttleLogged
		a.throttleLogged = true
		remaining := a.nextAsk.Sub(now).Round(time.Second)
		a.mu.Unlock()
		if logNow {
			a.logf("ASK throttle peer=%s root=%s remaining=%s",
				safeText(k.peer), safeText(k.root), compactDuration(remaining))
		}
		return askResult{reason: "승인_창_쿨다운"}
	}
	a.busy = true
	a.mu.Unlock()

	a.logf("ASK show peer=%s root=%s chain=%s", safeText(k.peer), safeText(k.root), chainString(chain))
	choice, perr := a.prompt(askText(k, chain))
	if perr != nil {
		a.logf("ASK prompt-fail err=%v", perr)
	}

	a.mu.Lock()
	a.busy = false
	if a.cooldown > 0 {
		a.nextAsk = a.now().Add(a.cooldown)
		a.throttleLogged = false
	}
	var res askResult
	switch choice {
	case askOnce:
		res = askResult{allow: true, via: "ask once", proc: rootProc}
	case askAlways:
		a.persisted[k] = true
		a.pending[k] = true
		copy := k
		res = askResult{allow: true, via: "ask always", proc: rootProc, persist: &copy}
	case askDenied:
		a.denied[k] = true
		res = askResult{reason: "승인_거부"}
	default: // askTimeout: 결정은 기억하지 않으며 재표시 대기 시간이 지난 뒤 다시 묻는다.
		res = askResult{reason: "승인_시간_초과"}
	}
	a.mu.Unlock()
	a.logf("ASK result=%s peer=%s root=%s", choice, safeText(k.peer), safeText(k.root))
	return res
}

// commitAlways는 실제 서명이 성공한 뒤에만 "항상 허용"을 디스크에 확정한다.
// 잠금 해제 실패 전에 approvals.conf부터 바뀌면 옛 conf.hmac과 어긋나 다음
// 기동이 자기 기록을 변조로 오인하므로, 메모리 판정과 영구 기록을 분리한다.
func (a *asker) commitAlways(k approvalKey) {
	if a == nil {
		return
	}
	a.mu.Lock()
	if !a.pending[k] || a.persisting[k] {
		a.mu.Unlock()
		return
	}
	a.persisting[k] = true
	a.mu.Unlock()

	err := a.persist(k)
	a.mu.Lock()
	delete(a.persisting, k)
	if err == nil {
		delete(a.pending, k)
	}
	a.mu.Unlock()
	if err != nil {
		// 파일 기록 실패는 이번 프로세스 수명의 메모리 승인으로 남기고,
		// 다음 성공 요청에서 다시 기록을 시도한다.
		a.logf("ASK persist-fail path=%s err=%v", safeText(a.path), err)
	}
}

// loadPersisted는 approvals.conf 원문에서 "항상 허용" 기록을 읽는다. 내용이
// 없으면(파일 부재 포함) 빈 상태로 시작한다. 깨진 줄은 건너뛰고 기록만
// 남긴다 — 승인 기록 손상이 기동 자체를 막는 것보다, 해당 승인이 무시되어
// 다시 물어보는 쪽(불허 방향)이 안전하다.
func (a *asker) loadPersisted(data []byte) {
	n, skipped := 0, 0
	// 내용이 비어도(첫 기동) 요약 한 줄은 남긴다 — 기동 시점에 승인 몇 건이
	// 로드됐는지 감사 로그만으로 알 수 있게.
	defer func() { a.logf("ASK load approvals=%d skipped=%d path=%s", n, skipped, safeText(a.path)) }()
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, ok := parseApprovalLine(line)
		if !ok {
			skipped++
			a.logf("ASK load-skip line=%d %q", i+1, line)
			continue
		}
		a.persisted[k] = true
		n++
	}
}

func parseApprovalLine(line string) (approvalKey, bool) {
	var k approvalKey
	if _, err := fmt.Sscanf(line, "approve %q %q", &k.peer, &k.root); err != nil || k.peer == "" || k.root == "" {
		return approvalKey{}, false
	}
	return k, true
}

// persist는 "항상 허용" 쌍을 approvals.conf에 한 줄 추가한다(0600, 없으면
// 생성). 경로는 %q로 인용해 공백·특수문자를 안전하게 담는다(읽기는 Sscanf %q).
// 실제로 써넣은 원문 그대로를 결속에 알려 설정 지문을 갱신한다 — 디스크
// 재판독 없이, pasu가 아는 내용만 지문에 들어간다.
func (a *asker) persist(k approvalKey) error {
	var buf bytes.Buffer
	return a.bind.appendApproval(func() ([]byte, error) {
		f, err := os.OpenFile(a.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, err
		}
		if st, err := f.Stat(); err == nil && st.Size() == 0 {
			fmt.Fprintln(&buf, `# pasu 승인 기록 — 승인 창에서 "항상"을 고른 쌍이 한 줄씩 쌓인다.`)
			fmt.Fprintln(&buf, `# pasu가 기록·관리한다. 철회: 줄 삭제 → pasu -trust-conf → 재기동.`)
		}
		fmt.Fprintf(&buf, "approve %q %q # %s\n", k.peer, k.root, time.Now().Format(time.RFC3339))
		if _, err := f.Write(buf.Bytes()); err != nil {
			_ = f.Close()
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	})
}

func askText(k approvalKey, chain []procInfo) string {
	return fmt.Sprintf("처음 보는 프로세스가 SSH 키(pasu) 서명을 요청했습니다.\n\n"+
		"요청 프로그램: %s (pid %d)\n최상위 앱: %s\n\n사슬: %s",
		safeText(k.peer), chain[0].pid, safeText(k.root), truncateUTF8Bytes(chainString(chain), 700))
}

// truncateUTF8Bytes는 s를 최대 max바이트로 줄이되 UTF-8 문자 중간을 자르지 않는다.
func truncateUTF8Bytes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	b := []byte(s[:max])
	for len(b) > 0 && b[len(b)-1]&0xC0 == 0x80 {
		b = b[:len(b)-1]
	}
	return string(b) + "…"
}

// 표시 내용은 실행 인수로 전달해 AppleScript 코드로 해석되지 않게 한다.
// NSAlert의 첫 버튼은 기본 버튼이며 반환 코드가 1000이다. 거부를 먼저 추가해
// Enter로 허용되지 않게 한다. Esc는 연결하지 않고 무응답 시 실행을 종료한다.
// osascript의 스크립트 실행 스레드와 분리해 화면 작업은 메인 스레드에서 수행한다.
const askAlertScript = `use framework "AppKit"

property askOutcome : "timeout"

on run argv
	my performSelectorOnMainThread:"showAsk:" withObject:(item 1 of argv) waitUntilDone:true
	return askOutcome
end run

on showAsk:msg
	set ca to current application
	ca's NSApplication's sharedApplication()
	ca's NSApp's setActivationPolicy:1
	set alert to ca's NSAlert's alloc()'s init()
	alert's setAlertStyle:2
	alert's setMessageText:"pasu — 처음 보는 SSH 서명 요청"
	alert's setInformativeText:msg
	alert's addButtonWithTitle:"거부"
	alert's addButtonWithTitle:"이번만 허용"
	alert's addButtonWithTitle:"이 프로세스에 대해 항상 허용"
	ca's NSApp's activateIgnoringOtherApps:true
	set code to alert's runModal()
	set n to code as integer
	if n is 1000 then set my askOutcome to "deny"
	if n is 1001 then set my askOutcome to "이번만 허용"
	if n is 1002 then set my askOutcome to "이 프로세스에 대해 항상 허용"
end showAsk:`

// 아래는 AppKit 경로 실패 시의 폴백이다. display dialog도 버튼이 최대 3개라
// 같은 세 선택지가 한 창에 그대로 들어간다. 기본 버튼(Enter)과 취소(Esc)는
// 모두 "거부"다(취소 버튼이라 클릭·Esc·Enter 모두 AppleScript 오류 -128로
// 돌아온다 — runAskScript가 canceled로 구분).
const askFallbackScript = `on run argv
set r to display dialog (item 1 of argv) with title "pasu — SSH 서명 요청" buttons {"이 프로세스에 대해 항상 허용", "이번만 허용", "거부"} default button "거부" cancel button "거부" with icon caution giving up after 60
if gave up of r then return "timeout"
return button returned of r
end run`

// runAskScriptFn은 테스트에서 osascript 실행을 가로채는 간접 호출점이다.
var runAskScriptFn = runAskScript

func macAskPrompt(text string) (askChoice, error) {
	out, _, err := runAskScriptFn(askAlertScript, text, 65*time.Second)
	if err == nil {
		return parseAlertChoice(out), nil
	}
	// AppKit 경로 실행 실패(브리지 미동작 등) — 표준 display dialog 한 창으로
	// 폴백한다. 반환하는 오류는 감사 로그(ASK prompt-fail)용 설명이고, 판정
	// 자체는 폴백 창의 결과를 따른다. 시간 초과는 실패가 아니라 위에서
	// "timeout" 출력으로 흡수되므로(runAskScript 참조) 무응답 뒤에 창이 또
	// 뜨지 않는다.
	choice, lerr := macAskPromptLegacy(text)
	if lerr != nil {
		return choice, fmt.Errorf("승인 알림 창 실패(%v) 후 폴백 창도 실패: %v", err, lerr)
	}
	return choice, fmt.Errorf("승인 알림 창 실패로 표준 창 폴백: %v", err)
}

// parseAlertChoice는 승인 창의 stdout 한 줄을 판정으로 바꾼다. 모르는
// 값은 전부 시간 초과(거부·비기억)로 접는다.
func parseAlertChoice(out string) askChoice {
	switch out {
	case "deny":
		return askDenied
	case "이번만 허용":
		return askOnce
	case "이 프로세스에 대해 항상 허용":
		return askAlways
	}
	return askTimeout
}

// macAskPromptLegacy는 표준 기능(display dialog)만 쓰는 3버튼 한 창 폴백이다.
func macAskPromptLegacy(text string) (askChoice, error) {
	out, canceled, err := runAskScriptFn(askFallbackScript, text, 75*time.Second)
	switch {
	case canceled:
		// 취소 버튼("거부") 클릭·Esc·Enter — 명시적 거부로 기억한다.
		return askDenied, nil
	case err != nil:
		return askTimeout, err
	}
	switch out {
	case "이번만 허용":
		return askOnce, nil
	case "이 프로세스에 대해 항상 허용":
		return askAlways, nil
	case "거부":
		// cancel button이라 보통 -128(canceled)로 오지만 방어적으로 처리한다.
		return askDenied, nil
	}
	return askTimeout, nil
}

// runAskScript는 osascript를 실행하고 명시적 취소(-128)와 실행 오류를 구분한다.
// 일시적인 실행 오류를 영구 거부로 기억하지 않도록 호출자가 따로 처리한다.
func runAskScript(script, msg string, timeout time.Duration) (out string, canceled bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/osascript", "-e", script, "--", msg)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			// 무응답 시간 초과 — osascript를 죽이면 창도 함께 닫힌다.
			// 실행 실패와 구분해 폴백·거부 기억을 유발하지 않게 한다.
			return "timeout", false, nil
		}
		if isAppleScriptCanceled(stderr.String()) {
			return "", true, nil
		}
		return "", false, fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), false, nil
}

func isAppleScriptCanceled(stderr string) bool {
	return strings.HasSuffix(strings.TrimSpace(stderr), "(-128)")
}
