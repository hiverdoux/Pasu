package main

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func mustParse(t *testing.T, conf string) *allowlist {
	t.Helper()
	a, err := parseAllowlist(strings.NewReader(conf), "/home/tester")
	if err != nil {
		t.Fatalf("parse 실패: %v", err)
	}
	return a
}

func TestParseSkipsCommentsAndBlank(t *testing.T) {
	a := mustParse(t, "# 주석\n\n  \nallow codesign team=Q6L2SF6YDW id=com.anthropic.claude-code\n# 끝\n")
	if len(a.rules) != 1 {
		t.Fatalf("규칙 1개 기대, %d개", len(a.rules))
	}
}

func TestParseRejectsBadInput(t *testing.T) {
	for _, bad := range []string{
		"deny codesign team=Q6L2SF6YDW id=x",
		"allow codesign",
		"allow magic value",
	} {
		if _, err := parseAllowlist(strings.NewReader(bad), "/home/tester"); err == nil {
			t.Errorf("오류 기대했으나 통과: %q", bad)
		}
	}
}

func TestParseRejectsAllPathRules(t *testing.T) {
	for _, kind := range []string{"exec", "exec-prefix", "script-prefix"} {
		_, err := parseAllowlist(strings.NewReader("allow "+kind+" /pkg/codex/"), "/home/tester")
		if err == nil || !strings.Contains(err.Error(), "경로 기반") || !strings.Contains(err.Error(), "codesign") {
			t.Fatalf("%s가 코드서명 전용 정책으로 거부되지 않음: %v", kind, err)
		}
	}
}

func TestParseRejectsAmbiguousWhitespaceAndInlineComment(t *testing.T) {
	for _, bad := range []string{
		"allow\tcodesign team=Q6L2SF6YDW id=x",
		"allow codesign team=Q6L2SF6YDW id=x # inline",
	} {
		if _, err := parseAllowlist(strings.NewReader(bad), "/home/tester"); err == nil {
			t.Errorf("모호한 설정인데 통과: %q", bad)
		}
	}
}

func TestParseCodesignRule(t *testing.T) {
	a := mustParse(t, "allow codesign team=Q6L2SF6YDW id=com.anthropic.claude-code")
	r := a.rules[0]
	if r.kind != ruleCodesign || r.team != "Q6L2SF6YDW" || r.id != "com.anthropic.claude-code" {
		t.Fatalf("파싱 결과 이상: %+v", r)
	}
	if got := r.String(); got != "codesign team=Q6L2SF6YDW id=com.anthropic.claude-code" {
		t.Fatalf("로그 표기 이상: %q", got)
	}
	if a.codesignCheck == nil {
		t.Fatal("실제 검사기가 연결되지 않음")
	}
	// 인자 순서는 무관하다.
	a = mustParse(t, "allow codesign id=codex team=2DC432GLL2")
	if a.rules[0].team != "2DC432GLL2" || a.rules[0].id != "codex" {
		t.Fatalf("순서 뒤집힌 인자 파싱 실패: %+v", a.rules[0])
	}
}

func TestParseCodesignRejectsBad(t *testing.T) {
	for _, bad := range []string{
		"allow codesign team=Q6L2SF6YDW",                      // id 누락
		"allow codesign id=com.anthropic.claude-code",         // team 누락
		"allow codesign team=q6l2sf6ydw id=x",                 // 소문자 team
		"allow codesign team=Q6L2SF6YD id=x",                  // 9자
		"allow codesign team=Q6L2SF6YDWW id=x",                // 11자
		"allow codesign team=Q6L2SF6YDW team=Q6L2SF6YDW id=x", // team 중복
		"allow codesign team=Q6L2SF6YDW id=a id=b",            // id 중복
		"allow codesign team=Q6L2SF6YDW id=",                  // 빈 id
		"allow codesign team=Q6L2SF6YDW id=a\"b",              // requirement 인젝션 시도(따옴표)
		"allow codesign team=Q6L2SF6YDW uid=alien",            // 모르는 키
		"allow codesign /bin/a",                               // key=value 아님
	} {
		if _, err := parseAllowlist(strings.NewReader(bad), "/home/tester"); err == nil {
			t.Errorf("오류 기대했으나 통과: %q", bad)
		}
	}
}

func TestMatchCodesignUsesChecker(t *testing.T) {
	a := mustParse(t, "allow codesign team=Q6L2SF6YDW id=com.anthropic.claude-code")
	var asked []string
	a.codesignCheck = func(proc procInfo, team, id string) bool {
		asked = append(asked, fmt.Sprintf("%d %s %s", proc.pid, team, id))
		return proc.pid == 10
	}
	chain := []procInfo{
		{pid: 30, exePath: "/usr/bin/ssh"},
		{pid: 20, exePath: "/bin/zsh"},
		{pid: 10, exePath: "/agents/claude"},
	}
	m := a.match(chain)
	if m == nil || m.proc.pid != 10 || m.rule.kind != ruleCodesign {
		t.Fatalf("codesign 매칭 실패: %+v", m)
	}
	// 사슬 순서대로 물었는지, team·id가 그대로 전달됐는지 확인.
	want := []string{
		"30 Q6L2SF6YDW com.anthropic.claude-code",
		"20 Q6L2SF6YDW com.anthropic.claude-code",
		"10 Q6L2SF6YDW com.anthropic.claude-code",
	}
	if !reflect.DeepEqual(asked, want) {
		t.Fatalf("검사기 호출 이력 이상: %v", asked)
	}
}

func TestMatchCodesignCheckerFalse(t *testing.T) {
	a := mustParse(t, "allow codesign team=Q6L2SF6YDW id=x")
	a.codesignCheck = func(procInfo, string, string) bool { return false }
	if a.match([]procInfo{{pid: 5, exePath: "/a"}}) != nil {
		t.Error("검사기가 거짓인데 매칭됨")
	}
}

func TestMatchCodesignGuards(t *testing.T) {
	// pid가 없거나(0) 검사기가 없으면 절대 매칭되지 않아야 한다.
	a := mustParse(t, "allow codesign team=Q6L2SF6YDW id=x")
	a.codesignCheck = func(procInfo, string, string) bool { return true }
	if a.match([]procInfo{{pid: 0, exePath: "/a"}}) != nil {
		t.Error("pid 0이 매칭됨")
	}
	a.codesignCheck = nil
	if a.match([]procInfo{{pid: 5, exePath: "/a"}}) != nil {
		t.Error("검사기 없이 매칭됨")
	}
}
