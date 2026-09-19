package main

import (
	"strings"
	"testing"
	"time"
)

func fixedClockLimiter(cfg rateLimit) (*signLimiter, *time.Time) {
	now := time.Unix(1_000_000, 0)
	l := newSignLimiter(cfg)
	l.now = func() time.Time { return now }
	return l, &now
}

func TestSignLimiterWindowSlides(t *testing.T) {
	l, now := fixedClockLimiter(rateLimit{max: 3, window: time.Minute})
	for i := 0; i < 3; i++ {
		if ok, _ := l.take(); !ok {
			t.Fatalf("%d번째 발급이 거부됨", i+1)
		}
	}
	if ok, _ := l.take(); ok {
		t.Fatal("한도 초과가 허용됨")
	}
	*now = now.Add(59 * time.Second)
	if ok, _ := l.take(); ok {
		t.Fatal("윈도가 지나기 전인데 허용됨")
	}
	*now = now.Add(2 * time.Second)
	if ok, _ := l.take(); !ok {
		t.Fatal("발급 기록이 윈도 밖으로 나갔는데도 거부됨")
	}
}

func TestSignLimiterPartialSlide(t *testing.T) {
	// 발급 시각이 흩어져 있으면 오래된 것부터 하나씩 만료되어야 한다.
	l, now := fixedClockLimiter(rateLimit{max: 2, window: time.Minute})
	l.take() // t=0
	*now = now.Add(30 * time.Second)
	l.take() // t=30
	if ok, _ := l.take(); ok {
		t.Fatal("가득 찬 상태인데 허용됨")
	}
	*now = now.Add(31 * time.Second) // t=61: t=0 것만 만료
	if ok, _ := l.take(); !ok {
		t.Fatal("자리 하나가 비었는데도 거부됨")
	}
	if ok, _ := l.take(); ok {
		t.Fatal("t=30·t=61 두 건으로 가득 찼는데 허용됨")
	}
}

func TestSignLimiterNotifyThrottle(t *testing.T) {
	l, now := fixedClockLimiter(rateLimit{max: 1, window: time.Minute})
	l.take() // 예산 소진 (t=0)
	if ok, notify := l.take(); ok || !notify {
		t.Fatalf("첫 초과는 거부+알림이어야 함: ok=%v notify=%v", ok, notify)
	}
	if ok, notify := l.take(); ok || notify {
		t.Fatalf("연속 초과는 알림 없이 거부여야 함: ok=%v notify=%v", ok, notify)
	}
	*now = now.Add(59 * time.Second)
	if _, notify := l.take(); notify {
		t.Fatal("같은 윈도 안에서 재알림")
	}
	*now = now.Add(2 * time.Second) // t=61: 예산 회복
	if ok, _ := l.take(); !ok {
		t.Fatal("윈도 경과 후 발급 실패")
	}
	// 다시 초과 — 마지막 알림에서 윈도만큼 지났으므로 재알림 차례다.
	if ok, notify := l.take(); ok || !notify {
		t.Fatalf("새 윈도의 초과는 다시 알림이어야 함: ok=%v notify=%v", ok, notify)
	}
}

func TestSignLimiterCanceledReservationReturnsBudget(t *testing.T) {
	l, _ := fixedClockLimiter(rateLimit{max: 1, window: time.Minute})
	r, _ := l.reserve()
	if r == nil {
		t.Fatal("첫 예약 거부")
	}
	if second, _ := l.reserve(); second != nil {
		t.Fatal("진행 중 예약을 무시하고 두 번째 자리 허용")
	}
	r.cancel()
	if next, _ := l.reserve(); next == nil {
		t.Fatal("취소한 예약이 예산을 계속 차지함")
	} else {
		next.commit()
	}
}

func TestParseRateLimitValues(t *testing.T) {
	lim, err := parseRateLimit("3/30s")
	if err != nil || lim == nil || lim.max != 3 || lim.window != 30*time.Second {
		t.Fatalf("파싱 결과 이상: %+v err=%v", lim, err)
	}
	if got := lim.String(); got != "3회/30초" {
		t.Fatalf("표기 이상: %q", got)
	}
	lim, err = parseRateLimit("5/1m")
	if err != nil || lim.window != time.Minute {
		t.Fatalf("1m 파싱 실패: %+v err=%v", lim, err)
	}
	lim, err = parseRateLimit("off")
	if err != nil || lim != nil {
		t.Fatalf("off는 (nil, nil)이어야 함: %+v err=%v", lim, err)
	}
}

func TestParseRateLimitRejectsBad(t *testing.T) {
	for _, bad := range []string{
		"10",       // 기간 없음
		"ten/60s",  // 숫자 아님
		"0/60s",    // 0회
		"-1/60s",   // 음수
		"10/0s",    // 0 기간
		"10/500ms", // 1초 미만
		"10/60",    // 단위 없는 기간
		"10/60s x", // 잉여 토큰
		"off x",    // off 뒤 잉여 토큰
		"",         // 빈 값
	} {
		if _, err := parseRateLimit(bad); err == nil {
			t.Errorf("오류 기대했으나 통과: %q", bad)
		}
	}
}

func TestParseConfRateLimitDefaultAndOverride(t *testing.T) {
	// 지시어가 없으면 기본값으로 켜진다.
	a := mustParse(t, "allow codesign team=AAAAAAAAAA id=pasu.test")
	if a.limit == nil || *a.limit != defaultRateLimit {
		t.Fatalf("기본 rate limit 이상: %+v", a.limit)
	}
	// 지시어가 있으면 그 값으로, off면 nil로.
	a = mustParse(t, "limit rate 3/30s\nallow codesign team=AAAAAAAAAA id=pasu.test")
	if a.limit == nil || a.limit.max != 3 || a.limit.window != 30*time.Second {
		t.Fatalf("지시어 반영 실패: %+v", a.limit)
	}
	a = mustParse(t, "limit rate off\nallow codesign team=AAAAAAAAAA id=pasu.test")
	if a.limit != nil {
		t.Fatalf("off인데 제한이 남음: %+v", a.limit)
	}
}

func TestParseConfRateLimitErrors(t *testing.T) {
	for _, bad := range []string{
		"limit rate 10/60s\nlimit rate 5/30s", // 중복 지시어
		"limit rate 10/60s\nlimit rate off",   // off와도 중복 불가
		"limit rate bogus",
		"limit rate",         // 값 없음
		"limit burst 10/60s", // 모르는 종류
		"limit",
	} {
		if _, err := parseAllowlist(strings.NewReader(bad), "/home/tester"); err == nil {
			t.Errorf("오류 기대했으나 통과: %q", bad)
		}
	}
}
