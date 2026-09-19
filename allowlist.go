package main

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"time"
)

// v1 allowlist 설정 형식: 한 줄에 규칙 하나, #으로 시작하면 주석.
// v2의 키별 규칙은 v2registry.go에서 관리한다.
//
//	allow codesign team=<팀ID> id=<식별자>
//	                               코드서명이 일치하는 조상 허용(실행 중 프로세스를
//	                               Developer ID + Team ID + identifier로 동적 검증)
//	limit rate <횟수>/<기간>        서명 발급 rate limit 변경 (기본 30회/60초,
//	                               `limit rate off`로 해제 — ratelimit.go 참조)
//	limit logsize <정수>[K|M]       감사 로그 크기 한도 변경 (기본 5M, 도달 시
//	                               .old 1세대 회전, `limit logsize off`로 해제
//	                               — audit.go 참조)
//	limit askcooldown <기간>|off    승인 창이 닫힌 뒤 새 창을 막는 전역 기간
//	                               (기본 5m, off는 제한 해제)
//	limit notify <기간>|off         동일 최상위 앱+거부 사유 알림 묶음 기간
//	                               (기본 60s, off는 제한 해제)
//	ask on|off                     allowlist 불일치 요청을 즉시 거부하는 대신
//	                               macOS 승인 창으로 물어봄 (기본 off — ask.go 참조)

type ruleKind string

const (
	ruleCodesign ruleKind = "codesign"
)

type rule struct {
	kind ruleKind
	team string // codesign 전용: Apple Team ID
	id   string // codesign 전용: 서명 identifier
	line int
}

func (r rule) String() string {
	return "codesign team=" + r.team + " id=" + r.id
}

type matchResult struct {
	rule rule
	proc procInfo
}

type allowlist struct {
	rules []rule
	// limit은 서명 발급 rate limit 설정. 지시어가 없으면 defaultRateLimit,
	// `limit rate off`면 nil(제한 없음).
	limit *rateLimit
	// logSize는 감사 로그 크기 한도. 지시어가 없으면 defaultLogSize,
	// `limit logsize off`면 nil(무제한).
	logSize *logSize
	// askCooldown은 미지 요청 창이 닫힌 뒤의 전역 쿨다운. nil이면 제한 없음.
	askCooldown *time.Duration
	// notifyCooldown은 동일 출처+사유 거부 알림의 묶음 기간. nil이면 제한 없음.
	notifyCooldown *time.Duration
	// ask는 allowlist 불일치 요청에 승인 창을 띄울지 여부(`ask on`). 기본
	// false — 즉시 거부가 보수적 기본값이다.
	ask bool
	// codesignCheck는 프로세스가 team+id 코드서명 requirement를 만족하는지
	// 판정한다. 실구현은 codesign_darwin.go의 codesignMatchesProc(테스트에서 교체).
	codesignCheck func(procInfo, string, string) bool
}

func parseAllowlist(r io.Reader, _ string) (*allowlist, error) {
	sc := bufio.NewScanner(r)
	lim := defaultRateLimit
	sz := defaultLogSize
	askCooldown := defaultAskCooldown
	notifyCooldown := defaultNotifyCooldown
	a := &allowlist{
		codesignCheck:  codesignMatchesProc,
		limit:          &lim,
		logSize:        &sz,
		askCooldown:    &askCooldown,
		notifyCooldown: &notifyCooldown,
	}
	rateSeen, logsizeSeen, askCooldownSeen, notifySeen, askSeen := false, false, false, false, false
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.ContainsRune(raw, '\t') {
			return nil, fmt.Errorf("%d행: 탭 문자는 지원하지 않음(공백을 사용하세요): %q", lineNo, line)
		}
		verb, rest, _ := strings.Cut(line, " ")
		if verb == "limit" {
			kind, val, _ := strings.Cut(strings.TrimSpace(rest), " ")
			val = strings.TrimSpace(val)
			var err error
			switch kind {
			case "rate":
				if rateSeen {
					err = fmt.Errorf("limit rate 지시어가 두 번")
				} else {
					rateSeen = true
					a.limit, err = parseRateLimit(val)
				}
			case "logsize":
				if logsizeSeen {
					err = fmt.Errorf("limit logsize 지시어가 두 번")
				} else {
					logsizeSeen = true
					a.logSize, err = parseLogSize(val)
				}
			case "askcooldown":
				if askCooldownSeen {
					err = fmt.Errorf("limit askcooldown 지시어가 두 번")
				} else {
					askCooldownSeen = true
					a.askCooldown, err = parseCooldown(kind, val)
				}
			case "notify":
				if notifySeen {
					err = fmt.Errorf("limit notify 지시어가 두 번")
				} else {
					notifySeen = true
					a.notifyCooldown, err = parseCooldown(kind, val)
				}
			default:
				err = fmt.Errorf("모르는 limit 종류 %q (rate, logsize, askcooldown, notify 중 하나)", kind)
			}
			if err != nil {
				return nil, fmt.Errorf("%d행: %v: %q", lineNo, err, line)
			}
			continue
		}
		if verb == "ask" {
			val := strings.TrimSpace(rest)
			var err error
			switch {
			case askSeen:
				err = fmt.Errorf("ask 지시어가 두 번")
			case val == "on":
				a.ask = true
			case val == "off":
				a.ask = false
			default:
				err = fmt.Errorf("ask 지시어는 `ask on` 또는 `ask off` 형식")
			}
			askSeen = true
			if err != nil {
				return nil, fmt.Errorf("%d행: %v: %q", lineNo, err, line)
			}
			continue
		}
		if verb != "allow" {
			return nil, fmt.Errorf("%d행: `allow`, `limit`, `ask` 중 하나로 시작해야 함: %q", lineNo, line)
		}
		kindStr, args, ok := strings.Cut(strings.TrimSpace(rest), " ")
		if !ok || strings.TrimSpace(args) == "" {
			return nil, fmt.Errorf("%d행: `allow codesign team=<팀ID> id=<식별자>` 형식이 아님: %q", lineNo, line)
		}
		kind := ruleKind(kindStr)
		switch kind {
		case ruleKind("exec"), ruleKind("exec-prefix"), ruleKind("script-prefix"):
			return nil, fmt.Errorf("%d행: 경로 기반 %s 규칙은 교체 가능한 파일 경로를 신뢰하므로 지원하지 않음; codesign 규칙을 사용하세요: %q", lineNo, kindStr, line)
		case ruleCodesign:
			team, id, err := parseCodesignArgs(strings.TrimSpace(args))
			if err != nil {
				return nil, fmt.Errorf("%d행: %v: %q", lineNo, err, line)
			}
			a.rules = append(a.rules, rule{kind: kind, team: team, id: id, line: lineNo})
			continue
		default:
			return nil, fmt.Errorf("%d행: 모르는 규칙 종류 %q (codesign만 지원)", lineNo, kindStr)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return a, nil
}

// parseCodesignArgs는 `team=<팀ID> id=<식별자>`(순서 무관)를 해석한다.
// 값의 문자셋 제한은 표기 검사가 아니라 보안 경계다: 이 값들은 Security
// framework의 requirement 문자열 안에 삽입되므로, 따옴표·역슬래시 등이
// 섞이면 requirement 인젝션이 된다. id를 생략할 수 없게 한 것도 의도다 —
// identifier는 자기 신고 값이라 team 없이 무의미하고, team만으로는 같은
// 개발사가 서명한 다른 앱까지 허용 범위가 넓어진다.
func parseCodesignArgs(s string) (team, id string, err error) {
	for _, f := range strings.Fields(s) {
		key, val, ok := strings.Cut(f, "=")
		if !ok {
			return "", "", fmt.Errorf("codesign 인자는 key=value 형식 (%q)", f)
		}
		switch key {
		case "team":
			if team != "" {
				return "", "", fmt.Errorf("team이 두 번")
			}
			if !teamIDPattern.MatchString(val) {
				return "", "", fmt.Errorf("team은 Apple Team ID(대문자·숫자 10자)여야 함 (%q)", val)
			}
			team = val
		case "id":
			if id != "" {
				return "", "", fmt.Errorf("id가 두 번")
			}
			if !signIDPattern.MatchString(val) {
				return "", "", fmt.Errorf("id에 허용되지 않는 문자 — 영숫자·점·밑줄·하이픈만 (%q)", val)
			}
			id = val
		default:
			return "", "", fmt.Errorf("모르는 codesign 인자 %q (team=, id= 만)", key)
		}
	}
	if team == "" || id == "" {
		return "", "", fmt.Errorf("codesign 규칙은 team=과 id=가 모두 필요")
	}
	return team, id, nil
}

// match는 피어의 조상 사슬(피어 자신 포함)에서 규칙과 일치하는
// 첫 프로세스를 찾는다. 없으면 nil.
func (a *allowlist) match(chain []procInfo) *matchResult {
	for _, p := range chain {
		for _, r := range a.rules {
			if r.kind == ruleCodesign && p.pid > 0 && a.codesignCheck != nil && a.codesignCheck(p, r.team, r.id) {
				return &matchResult{rule: r, proc: p}
			}
		}
	}
	return nil
}
