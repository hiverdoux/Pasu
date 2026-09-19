package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// discardAuditLog는 임시 파일로 가는 무제한(회전 없음) 감사 로그를 만든다.
// gatekeeper 테스트처럼 로그 내용에 관심 없는 곳에서 쓴다.
func discardAuditLog(t *testing.T) *auditLog {
	t.Helper()
	a, err := newAuditLog(filepath.Join(t.TempDir(), "audit.log"), 0, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	return a
}

// 소형 한도는 파서의 하한(1K)과 무관하게 생성자가 받아 준다 — 회전을 몇 줄
// 만에 유발하기 위한 테스트 전용 값이다.
func testAuditLog(t *testing.T, limit int64) (*auditLog, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pasu.log")
	a, err := newAuditLog(path, limit, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	return a, path
}

func readLog(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestAuditLogRotates(t *testing.T) {
	a, path := testAuditLog(t, 300)
	for i := 0; i < 20; i++ {
		a.logf("EVENT n=%02d", i)
	}
	old := readLog(t, path+".old")
	if !strings.Contains(old, "EVENT") {
		t.Fatalf(".old에 이월된 기록이 없음:\n%s", old)
	}
	cur := readLog(t, path)
	firstLine := strings.SplitN(cur, "\n", 2)[0]
	if !strings.Contains(firstLine, "LOG rotate ") {
		t.Fatalf("새 파일 첫 줄이 회전 기록이 아님: %q", firstLine)
	}
	if !strings.Contains(cur, "EVENT n=19") {
		t.Fatalf("회전 후 기록이 이어지지 않음:\n%s", cur)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() > 300 {
		t.Fatalf("회전 후에도 한도 초과: %dB", st.Size())
	}
}

func TestAuditLogCountsExistingSize(t *testing.T) {
	// 기동 시 이미 한도를 넘어 있던 파일은 첫 기록 직전에 회전돼야 한다
	// (START 줄이 항상 새 파일에 남는 성질의 근거).
	dir := t.TempDir()
	path := filepath.Join(dir, "pasu.log")
	prior := strings.Repeat("이전 세션의 기록\n", 30)
	if err := os.WriteFile(path, []byte(prior), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := newAuditLog(path, 200, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	a.logf("START version=test")
	if got := readLog(t, path+".old"); got != prior {
		t.Fatalf(".old가 기존 내용 그대로가 아님 (len=%d, 기대 len=%d)", len(got), len(prior))
	}
	cur := readLog(t, path)
	if !strings.Contains(cur, "LOG rotate ") || !strings.Contains(cur, "START version=test") {
		t.Fatalf("새 파일에 회전 기록+START가 없음:\n%s", cur)
	}
}

func TestAuditLogTruncatesSingleOversizedEvent(t *testing.T) {
	a, path := testAuditLog(t, 200)
	a.logf("EVENT value=%s", strings.Repeat("가", 300))
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() > 200 {
		t.Fatalf("단일 이벤트가 한도 초과: %d", st.Size())
	}
	got := readLog(t, path)
	if !strings.Contains(got, "...[truncated]") || !strings.Contains(got, "EVENT value=") {
		t.Fatalf("잘림 표식 또는 이벤트 앞부분 없음: %q", got)
	}
}

func TestAuditLogStaysWithinLimitAfterRotationMarker(t *testing.T) {
	a, path := testAuditLog(t, 220)
	a.logf("FIRST %s", strings.Repeat("x", 140))
	a.logf("SECOND %s", strings.Repeat("y", 400))
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() > 220 {
		t.Fatalf("회전 표식 뒤 이벤트가 한도 초과: %d", st.Size())
	}
	got := readLog(t, path)
	if !strings.Contains(got, "LOG rotate ") || !strings.Contains(got, "SECOND") {
		t.Fatalf("회전 뒤 기록 이상: %q", got)
	}
}

func TestAuditLogSecondRotationReplacesOld(t *testing.T) {
	a, path := testAuditLog(t, 120)
	for i := 0; i < 30; i++ {
		a.logf("EVENT n=%02d", i)
	}
	// 첫 .old 세대는 EVENT로 시작하지만, 두 번째 회전부터는 marker로 시작하는
	// 세대가 자리를 대체한다 — 1세대만 보관됨을 첫 줄로 판별한다.
	firstLine := strings.SplitN(readLog(t, path+".old"), "\n", 2)[0]
	if !strings.Contains(firstLine, "LOG rotate ") {
		t.Fatalf(".old가 최신 세대로 교체되지 않음 — 첫 줄: %q", firstLine)
	}
}

func TestAuditLogNoLimit(t *testing.T) {
	a, path := testAuditLog(t, 0)
	for i := 0; i < 50; i++ {
		a.logf("EVENT n=%02d", i)
	}
	if _, err := os.Stat(path + ".old"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("무제한인데 .old가 생김: %v", err)
	}
	cur := readLog(t, path)
	if !strings.Contains(cur, "EVENT n=00") || !strings.Contains(cur, "EVENT n=49") {
		t.Fatal("무제한 모드에서 기록 유실")
	}
}

func TestAuditLogRenameFailFallback(t *testing.T) {
	a, path := testAuditLog(t, 150)
	a.rename = func(_, _ string) error { return errors.New("강제 실패") }
	for i := 0; i < 20; i++ {
		a.logf("EVENT n=%02d", i)
	}
	if _, err := os.Stat(path + ".old"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rename 실패인데 .old가 생김")
	}
	cur := readLog(t, path)
	if n := strings.Count(cur, "LOG rotate-fail phase=rename"); n != 1 {
		t.Fatalf("실패 기록이 정확히 1회여야 함 (스팸 억제): %d회", n)
	}
	if !strings.Contains(cur, "EVENT n=00") || !strings.Contains(cur, "EVENT n=19") {
		t.Fatal("실패 후에도 같은 파일로 기록이 이어져야 함")
	}
}

func TestAuditLogReopenFailFallback(t *testing.T) {
	a, path := testAuditLog(t, 150)
	a.reopen = func(string) (*os.File, error) { return nil, errors.New("강제 실패") }
	for i := 0; i < 20; i++ {
		a.logf("EVENT n=%02d", i)
	}
	// rename은 성공했으므로 기존 핸들은 .old inode로 계속 기록한다 — 유실 없음.
	old := readLog(t, path+".old")
	if n := strings.Count(old, "LOG rotate-fail phase=reopen"); n != 1 {
		t.Fatalf("실패 기록이 정확히 1회여야 함: %d회", n)
	}
	if !strings.Contains(old, "EVENT n=00") || !strings.Contains(old, "EVENT n=19") {
		t.Fatal("reopen 실패 후 기록 유실")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("reopen이 실패했는데 원래 경로에 파일이 있음")
	}
}

func TestAuditLogConcurrentWrites(t *testing.T) {
	// 회전을 다수 유발하며 동시 기록 — -race 안전망.
	a, _ := testAuditLog(t, 500)
	var wg sync.WaitGroup
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				a.logf("EVENT g=%d n=%d", g, i)
			}
		}(g)
	}
	wg.Wait()
}

func TestParseLogSizeValues(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int64
		str  string
	}{
		{"5M", 5 << 20, "5M"},
		{"512K", 512 << 10, "512K"},
		{"2048", 2048, "2K"},
		{"1K", 1 << 10, "1K"}, // 하한 경계
		{"1025", 1025, "1025"},
	} {
		s, err := parseLogSize(tc.in)
		if err != nil || s == nil || int64(*s) != tc.want {
			t.Errorf("%q 파싱 이상: %v err=%v", tc.in, s, err)
			continue
		}
		if got := s.String(); got != tc.str {
			t.Errorf("%q 표기 이상: %q (기대 %q)", tc.in, got, tc.str)
		}
	}
	s, err := parseLogSize("off")
	if err != nil || s != nil {
		t.Fatalf("off는 (nil, nil)이어야 함: %v err=%v", s, err)
	}
}

func TestParseLogSizeRejectsBad(t *testing.T) {
	for _, bad := range []string{
		"",              // 빈 값
		"0",             // 0
		"1023",          // 하한(1K) 미달
		"5",             // 하한 미달 — 5M 의도 오타 보호
		"-1",            // 음수
		"+5M",           // 부호
		"5m",            // 소문자 접미사 (rate의 1m과 혼동)
		"5G",            // 지원 안 하는 단위
		"1.5M",          // 소수
		"5 M",           // 공백
		"5M x",          // 잉여 토큰
		"off x",         // off 뒤 잉여 토큰
		"1099511627777", // 1<<40 초과
	} {
		if _, err := parseLogSize(bad); err == nil {
			t.Errorf("오류 기대했으나 통과: %q", bad)
		}
	}
}

func TestParseConfLogSizeDefaultAndOverride(t *testing.T) {
	a := mustParse(t, "allow codesign team=AAAAAAAAAA id=pasu.test")
	if a.logSize == nil || *a.logSize != defaultLogSize {
		t.Fatalf("기본 log size 이상: %v", a.logSize)
	}
	a = mustParse(t, "limit logsize 1M\nallow codesign team=AAAAAAAAAA id=pasu.test")
	if a.logSize == nil || *a.logSize != 1<<20 {
		t.Fatalf("지시어 반영 실패: %v", a.logSize)
	}
	a = mustParse(t, "limit logsize off\nallow codesign team=AAAAAAAAAA id=pasu.test")
	if a.logSize != nil {
		t.Fatalf("off인데 한도가 남음: %v", a.logSize)
	}
	// rate와 logsize는 공존 가능(순서 무관).
	a = mustParse(t, "limit rate 3/30s\nlimit logsize 2M\nallow codesign team=AAAAAAAAAA id=pasu.test")
	if a.limit == nil || a.limit.max != 3 || a.logSize == nil || *a.logSize != 2<<20 {
		t.Fatalf("공존 반영 실패: limit=%v logSize=%v", a.limit, a.logSize)
	}
	a = mustParse(t, "limit logsize 2M\nlimit rate 3/30s\nallow codesign team=AAAAAAAAAA id=pasu.test")
	if a.limit == nil || a.limit.max != 3 || a.logSize == nil || *a.logSize != 2<<20 {
		t.Fatalf("역순 공존 반영 실패: limit=%v logSize=%v", a.limit, a.logSize)
	}
}

func TestParseConfLogSizeErrors(t *testing.T) {
	for _, bad := range []string{
		"limit logsize 1M\nlimit logsize 2M",  // 중복 지시어
		"limit logsize 1M\nlimit logsize off", // off와도 중복 불가
		"limit logsize",                       // 값 없음
		"limit logsize bogus",
	} {
		if _, err := parseAllowlist(strings.NewReader(bad), "/home/tester"); err == nil {
			t.Errorf("오류 기대했으나 통과: %q", bad)
		}
	}
}
