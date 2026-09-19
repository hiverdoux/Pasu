package main

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 서명 rate limit — 단시간 폭주 서명 발급을 막는 마지막 관문.
//
// allowlist를 통과한 조상(또는 그 후손에서 도는 임의 코드)이 짧은 시간에
// 서명을 무제한 받아 가는 것을 전역 슬라이딩 윈도로 제한한다. 실제로
// 서명이 나간 횟수만 세므로, 비인가 프로세스가 거부당할 요청을 퍼부어도
// 정상 에이전트의 예산은 줄지 않는다(자기 DoS 차단).

// defaultRateLimit는 v1 설정의 생략값과 v2 새 registry의 기본 서명 한도다.
// 기본 한도는 60초당 30회다. 필요한 처리량은 설정으로 조정할 수 있다.
var defaultRateLimit = rateLimit{max: 30, window: time.Minute}

// rateLimit는 conf에서 읽은 한도 설정이다.
type rateLimit struct {
	max    int
	window time.Duration
}

func (r rateLimit) String() string {
	return fmt.Sprintf("%d회/%d초", r.max, int(r.window.Seconds()))
}

// parseRateLimit는 `limit rate` 지시어의 값을 해석한다.
//
//	limit rate <횟수>/<기간>   기간은 60s, 1m 같은 Go duration 표기(1초 이상)
//	limit rate off             제한 해제 — (nil, nil)을 돌려준다
func parseRateLimit(val string) (*rateLimit, error) {
	if val == "" {
		return nil, fmt.Errorf("limit rate 지시어는 `limit rate <횟수>/<기간>` 또는 `limit rate off` 형식")
	}
	if val == "off" {
		return nil, nil
	}
	numStr, durStr, ok := strings.Cut(val, "/")
	if !ok {
		return nil, fmt.Errorf("한도는 `<횟수>/<기간>` 형식 (%q)", val)
	}
	n, err := strconv.Atoi(numStr)
	if err != nil || n < 1 {
		return nil, fmt.Errorf("횟수는 1 이상의 정수 (%q)", numStr)
	}
	d, err := time.ParseDuration(durStr)
	if err != nil || d < time.Second {
		return nil, fmt.Errorf("기간은 60s, 1m 같은 1초 이상의 기간 표기 (%q)", durStr)
	}
	return &rateLimit{max: n, window: d}, nil
}

// signLimiter는 rateLimit의 실행 상태다. 모든 연결이 하나를 공유한다(전역 합산).
type signLimiter struct {
	rateLimit
	mu       sync.Mutex
	issued   []time.Time      // 최근 window 안에 서명을 내준 시각들(길이 ≤ max)
	reserved int              // 검사 통과 뒤 아직 성공/실패가 정해지지 않은 요청
	notified time.Time        // 마지막 초과 알림 시각
	now      func() time.Time // 테스트에서 교체
}

type signReservation struct {
	limiter *signLimiter
	active  bool // limiter.mu로 보호
}

func newSignLimiter(cfg rateLimit) *signLimiter {
	return &signLimiter{rateLimit: cfg, now: time.Now}
}

// reserve는 잠금 해제 전에 발급 자리를 예약한다. 실제 서명이 성공하면 commit,
// 잠금 해제나 서명이 실패하면 cancel해야 한다. 예약도 한도에 포함해 동시 요청이
// 한꺼번에 한도를 뚫지 못하게 하되, 실패한 요청은 최종 예산을 소비하지 않는다.
func (l *signLimiter) reserve() (*signReservation, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	cut := now.Add(-l.window)
	live := l.issued[:0]
	for _, ts := range l.issued {
		if ts.After(cut) {
			live = append(live, ts)
		}
	}
	l.issued = live
	if len(l.issued)+l.reserved < l.max {
		l.reserved++
		return &signReservation{limiter: l, active: true}, false
	}
	if now.Sub(l.notified) >= l.window {
		l.notified = now
		return nil, true
	}
	return nil, false
}

func (r *signReservation) finish(commit bool) {
	if r == nil || r.limiter == nil {
		return
	}
	l := r.limiter
	l.mu.Lock()
	defer l.mu.Unlock()
	if !r.active {
		return
	}
	r.active = false
	l.reserved--
	if commit {
		l.issued = append(l.issued, l.now())
	}
}

func (r *signReservation) commit() { r.finish(true) }
func (r *signReservation) cancel() { r.finish(false) }

// take는 리미터 자체 테스트와 단순 호출용 편의 함수다. 예약 즉시 성공 발급으로
// 확정하며, 실제 서명 경로는 reserve/commit/cancel을 직접 사용한다.
func (l *signLimiter) take() (ok, notify bool) {
	r, notify := l.reserve()
	if r == nil {
		return false, notify
	}
	r.commit()
	return true, false
}
