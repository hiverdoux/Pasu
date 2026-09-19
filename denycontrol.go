package main

import (
	"fmt"
	"sync"
	"time"
)

const denySummaryWindow = time.Minute

type denyKey struct {
	peer   string
	reason string
}

type denyEntry struct {
	first      time.Time
	last       time.Time
	suppressed int
}

// denyRecorder는 같은 peer+reason의 폭주가 감사 로그 회전을 독점하지 못하게
// 첫 전체 DENY 뒤의 반복을 고정 윈도 요약으로 접는다. 모든 연결이 하나를 공유한다.
type denyRecorder struct {
	mu      sync.Mutex
	window  time.Duration
	entries map[denyKey]*denyEntry
	logf    func(string, ...any)
	now     func() time.Time
	stop    chan struct{}
	done    chan struct{}
	once    sync.Once
}

func newDenyRecorder(window time.Duration, logf func(string, ...any)) *denyRecorder {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	r := &denyRecorder{
		window:  window,
		entries: make(map[denyKey]*denyEntry),
		logf:    logf,
		now:     time.Now,
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	go r.run()
	return r
}

func (r *denyRecorder) run() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	defer close(r.done)
	for {
		select {
		case <-ticker.C:
			r.flushExpired(r.now())
		case <-r.stop:
			r.flushAll()
			return
		}
	}
}

func (r *denyRecorder) record(key denyKey, format string, args ...any) {
	if r == nil || r.window <= 0 {
		return
	}
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.entries[key]; e != nil && now.Sub(e.first) < r.window {
		e.suppressed++
		e.last = now
		return
	} else if e != nil {
		r.writeSummaryLocked(key, e)
	}
	r.entries[key] = &denyEntry{first: now, last: now}
	r.logf(format, args...)
}

func (r *denyRecorder) flushExpired(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, e := range r.entries {
		if now.Sub(e.first) >= r.window {
			r.writeSummaryLocked(key, e)
			delete(r.entries, key)
		}
	}
}

func (r *denyRecorder) flushAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, e := range r.entries {
		r.writeSummaryLocked(key, e)
		delete(r.entries, key)
	}
}

func (r *denyRecorder) writeSummaryLocked(key denyKey, e *denyEntry) {
	if e.suppressed == 0 {
		return
	}
	r.logf("DENY-SUMMARY peer=%s reason=%s suppressed=%d window=%s first=%s last=%s",
		key.peer, key.reason, e.suppressed, fmt.Sprintf("%ds", int(r.window/time.Second)),
		e.first.Format(time.RFC3339), e.last.Format(time.RFC3339))
}

func (r *denyRecorder) Close() {
	if r == nil {
		return
	}
	r.once.Do(func() {
		close(r.stop)
		<-r.done
	})
}

type denyNotifyKey struct {
	source string
	reason string
}

// denyNotifyLimiter는 동일 최상위 앱+사유의 알림만 묶는다. 감사 로그 축약과
// 독립적이며, 기간 0은 제한 해제(매번 알림)다.
type denyNotifyLimiter struct {
	mu       sync.Mutex
	cooldown time.Duration
	last     map[denyNotifyKey]time.Time
	now      func() time.Time
}

func newDenyNotifyLimiter(cooldown time.Duration) *denyNotifyLimiter {
	return &denyNotifyLimiter{cooldown: cooldown, last: make(map[denyNotifyKey]time.Time), now: time.Now}
}

func (l *denyNotifyLimiter) allow(peer procInfo, chain []procInfo, reason string) bool {
	if l == nil || l.cooldown <= 0 {
		return true
	}
	source := ""
	if len(chain) >= 2 && chain[len(chain)-1].pid == 1 {
		source = chain[len(chain)-2].exePath
	}
	if source == "" {
		source = peer.exePath
	}
	if source == "" {
		source = peer.comm
	}
	if source == "" {
		source = fmt.Sprintf("pid:%d", peer.pid)
	}
	key := denyNotifyKey{source: source, reason: reason}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if last := l.last[key]; !last.IsZero() && now.Sub(last) < l.cooldown {
		return false
	}
	l.last[key] = now
	for k, ts := range l.last {
		if now.Sub(ts) >= l.cooldown {
			delete(l.last, k)
		}
	}
	return true
}
