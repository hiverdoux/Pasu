package main

import (
	"fmt"
	"time"
)

var (
	defaultAskCooldown    = 5 * time.Minute
	defaultNotifyCooldown = time.Minute
)

// parseCooldown은 ask/notify 빈도 제한의 기간을 해석한다. off는 제한 해제
// (기능 비활성화가 아니라 매번 창/알림 허용)를 뜻해 nil을 돌려준다.
func parseCooldown(kind, val string) (*time.Duration, error) {
	if val == "off" {
		return nil, nil
	}
	d, err := time.ParseDuration(val)
	if err != nil || d < time.Second {
		return nil, fmt.Errorf("limit %s는 5m, 60s 같은 1초 이상의 기간 또는 off (%q)", kind, val)
	}
	return &d, nil
}

func durationDesc(d *time.Duration) string {
	if d == nil {
		return "off"
	}
	return compactDuration(*d)
}

func compactDuration(d time.Duration) string {
	if d == 0 {
		return "0s"
	}
	if d%time.Hour == 0 {
		return fmt.Sprintf("%dh", int(d/time.Hour))
	}
	if d%time.Minute == 0 {
		return fmt.Sprintf("%dm", int(d/time.Minute))
	}
	if d%time.Second == 0 {
		return fmt.Sprintf("%ds", int(d/time.Second))
	}
	return d.String()
}
