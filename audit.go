package main

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// 감사 로그 크기 제한 — 한도(limit) 도달 시 <path>를 <path>.old로 밀어내고
// 새 파일을 시작한다(1세대 보관, 총 점유 ≤ 2×한도). 회전 실패는 서명 경로에
// 영향을 주지 않는다: 기록은 유효한 핸들로 계속 흘리고 성장만 허용한다.

// defaultLogSize는 v1 설정의 생략값과 v2 새 registry의 기본 로그 한도다.
// 기본 한도는 파일당 5MiB이며, 보존 기간은 실제 로그 발생량에 따라 달라진다.
const defaultLogSize logSize = 5 << 20 // 5MiB

// logSize는 conf에서 읽은 감사 로그 크기 한도다(바이트).
type logSize int64

func (s logSize) String() string {
	switch {
	case s >= 1<<20 && s%(1<<20) == 0:
		return strconv.FormatInt(int64(s>>20), 10) + "M"
	case s >= 1<<10 && s%(1<<10) == 0:
		return strconv.FormatInt(int64(s>>10), 10) + "K"
	}
	return strconv.FormatInt(int64(s), 10)
}

// 부호·공백·소수·잉여 토큰을 문법 수준에서 거른다(ParseInt는 "+5"도 받는다).
// 접미사는 대문자만 — 소문자 m은 rate 문법의 기간 표기(1m=1분)와 헷갈린다.
var logSizePattern = regexp.MustCompile(`^([0-9]+)([KM]?)$`)

// parseLogSize는 `limit logsize` 지시어의 값을 해석한다.
//
//	limit logsize <정수>[K|M]   바이트 단위 한도. K=1024배, M=1048576배 (1K 이상)
//	limit logsize off           제한 해제 — (nil, nil)을 돌려준다
func parseLogSize(val string) (*logSize, error) {
	if val == "off" {
		return nil, nil
	}
	m := logSizePattern.FindStringSubmatch(val)
	if m == nil {
		return nil, fmt.Errorf("크기는 5M, 512K 같은 <정수>[K|M] 표기 또는 off (%q)", val)
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil || n > 1<<40 {
		return nil, fmt.Errorf("크기가 너무 큼 (%q)", val)
	}
	switch m[2] {
	case "K":
		n <<= 10
	case "M":
		n <<= 20
	}
	if n < 1<<10 {
		return nil, fmt.Errorf("크기는 1K(1024바이트) 이상 (%q)", val)
	}
	s := logSize(n)
	return &s, nil
}

// auditLog는 감사 로그를 파일에 남기고, 터미널에서 실행됐다면 화면(stdout)에도
// 미러링한다. launchd 무인 기동에서는 stdout이 launchd.log로 리다이렉트되므로
// 미러링을 꺼서 이중 기록을 막는다(mirror=false).
type auditLog struct {
	mu     sync.Mutex
	f      *os.File
	path   string
	size   int64 // 현재 파일 크기 — 기동 시 Stat, 이후 쓴 바이트 누적
	limit  int64 // 회전 한도(바이트), 0이면 무제한
	mirror bool

	// 회전 실패 후에는 재시도와 marker를 멈춰 실패 자체가 로그 폭증이 되지
	// 않게 한다. 다음 프로세스 기동에서 자연 리셋된다.
	rotateFailed bool

	// 테스트에서 교체(signLimiter.now와 같은 관례).
	rename func(oldpath, newpath string) error
	reopen func(path string) (*os.File, error)
}

func openAuditFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
}

func newAuditLog(path string, limit int64, mirror bool) (*auditLog, error) {
	f, err := openAuditFile(path)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &auditLog{
		f:      f,
		path:   path,
		size:   st.Size(),
		limit:  limit,
		mirror: mirror,
		rename: os.Rename,
		reopen: openAuditFile,
	}, nil
}

func (a *auditLog) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.f.Close()
}

func (a *auditLog) logf(format string, args ...any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	msg := safeText(fmt.Sprintf(format, args...))
	line := fmt.Appendf(nil, "%s %s\n", time.Now().Format(time.RFC3339), msg)
	// 쓰기 전 검사라 파일이 한도를 넘지 않고, 기동 시 이미 초과된 파일도
	// 첫 기록(START) 직전에 회전돼 START 줄이 항상 새 파일에 남는다.
	if a.limit > 0 && !a.rotateFailed && a.size > 0 && a.size+int64(len(line)) > a.limit {
		a.rotate()
	}
	if a.limit > 0 && !a.rotateFailed {
		line = fitAuditLine(line, a.limit-a.size)
	}
	a.write(line)
}

func fitAuditLine(line []byte, max int64) []byte {
	if max <= 0 {
		return nil
	}
	if int64(len(line)) <= max {
		return line
	}
	const marker = "...[truncated]\n"
	if max <= int64(len(marker)) {
		keep := int(max) - 1
		for keep > 0 && !utf8.Valid(line[:keep]) {
			keep--
		}
		out := append([]byte(nil), line[:keep]...)
		return append(out, '\n')
	}
	keep := int(max) - len(marker)
	for keep > 0 && !utf8.Valid(line[:keep]) {
		keep--
	}
	out := append([]byte(nil), line[:keep]...)
	return append(out, marker...)
}

// write는 mu를 쥔 채로만 부른다. 파일 기록과 stdout 미러링을 분리 수행해
// stdout 쪽 상태(파이프 소비자 사망 등)가 파일 감사 기록을 막지 못하게 한다.
func (a *auditLog) write(p []byte) {
	n, _ := a.f.Write(p)
	a.size += int64(n)
	if a.mirror {
		os.Stdout.Write(p)
	}
}

// rotate는 mu를 쥔 채로만 부른다. 이 안에서 logf(재잠금 데드락)와 표준 log
// 패키지(libWriter 재귀)는 금지 — 기록은 전부 write 직접 호출로 한다.
// 순서가 핵심이다: 새 핸들을 확보하기 전에는 기존 핸들을 닫지 않는다.
func (a *auditLog) rotate() {
	stamp := func(format string, args ...any) []byte {
		return fmt.Appendf(nil, "%s %s\n", time.Now().Format(time.RFC3339), fmt.Sprintf(format, args...))
	}
	if err := a.rename(a.path, a.path+".old"); err != nil {
		a.rotateFailed = true
		a.write(stamp("LOG rotate-fail phase=rename err=%v", err))
		return
	}
	nf, err := a.reopen(a.path)
	if err != nil {
		// rename은 이미 성공 — 기존 핸들은 .old가 된 inode를 계속 가리키므로
		// 기록은 유실 없이 .old로 흘러간다.
		a.rotateFailed = true
		a.write(stamp("LOG rotate-fail phase=reopen err=%v", err))
		return
	}
	prev := a.size
	a.f.Close()
	a.f = nf
	a.size = 0
	a.write(stamp("LOG rotate rotated=%dB limit=%s", prev, logSize(a.limit)))
}

// stdoutIsTerminal은 stdout이 실제 터미널인지 판정한다. launchd 무인 기동이나
// 리다이렉트 실행에서는 false — 감사 로그 미러링을 끄는 기준이다.
func stdoutIsTerminal() bool {
	st, err := os.Stdout.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// libWriter는 x/crypto/ssh/agent가 표준 log 패키지로 찍는 내부 오류를
// 감사 로그로 흘려보내기 위한 어댑터다.
type libWriter struct{ a *auditLog }

func (w libWriter) Write(p []byte) (int, error) {
	w.a.logf("LIB %s", strings.TrimSpace(string(p)))
	return len(p), nil
}
