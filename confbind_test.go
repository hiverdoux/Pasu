package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func testBindKey(t *testing.T) []byte {
	t.Helper()
	k, err := newBindKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(k) != bindKeyLen {
		t.Fatalf("K 길이 = %d, 기대 %d", len(k), bindKeyLen)
	}
	return k
}

// 신뢰할 설정의 지문을 기록한 뒤 같은 내용·같은 K로 만든 새 결속은 검증을 통과해야 한다
// (재기동 왕복 재현).
func TestConfBindingRoundTrip(t *testing.T) {
	mac := filepath.Join(t.TempDir(), "conf.hmac")
	conf, appr := []byte("ask on\nallow codesign team=AAAAAAAAAA id=pasu.test\n"), []byte("")
	k := testBindKey(t)
	if err := newConfBinding(mac, conf, appr, t.Logf).adoptNewKey(k, "test"); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(mac)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("conf.hmac 권한 = %o, 기대 600", st.Mode().Perm())
	}
	b := newConfBinding(mac, conf, appr, t.Logf)
	if err := b.verify(k); err != nil {
		t.Fatalf("동일 내용 검증 실패: %v", err)
	}
	if b.modeDesc() != "on" {
		t.Fatalf("검증 후 mode = %q, 기대 on", b.modeDesc())
	}
}

// 파일 변조·지문 부재·지문 손상·다른 K는 전부 errConfTampered로 거부돼야 한다.
func TestConfBindingDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	mac := filepath.Join(dir, "conf.hmac")
	conf, appr := []byte("allow codesign team=AAAAAAAAAA id=pasu.test\n"), []byte("approve \"/a\" \"/b\"\n")
	k := testBindKey(t)
	if err := newConfBinding(mac, conf, appr, t.Logf).adoptNewKey(k, "test"); err != nil {
		t.Fatal(err)
	}
	cases := map[string]*confBinding{
		"conf 변조":      newConfBinding(mac, []byte("allow codesign team=AAAAAAAAAA id=pasu.evil\n"), appr, t.Logf),
		"approvals 변조": newConfBinding(mac, conf, []byte("approve \"/e\" \"/e\"\n"), t.Logf),
		"경계 이동":        newConfBinding(mac, []byte("allow codesign team=AAAAAAAAAA id=pasu.test\napprove \"/a\" \"/b\"\n"), nil, t.Logf),
	}
	for name, b := range cases {
		if err := b.verify(k); !errors.Is(err, errConfTampered) {
			t.Errorf("%s: errConfTampered 기대, 실제 %v", name, err)
		}
	}
	good := func() *confBinding { return newConfBinding(mac, conf, appr, t.Logf) }
	if err := good().verify(testBindKey(t)); !errors.Is(err, errConfTampered) {
		t.Errorf("다른 K인데 통과: %v", err)
	}
	if err := os.WriteFile(mac, []byte("not-hex\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := good().verify(k); !errors.Is(err, errConfTampered) {
		t.Errorf("지문 손상인데 통과: %v", err)
	}
	if err := os.Remove(mac); err != nil {
		t.Fatal(err)
	}
	if err := good().verify(k); !errors.Is(err, errConfTampered) {
		t.Errorf("지문 부재인데 통과: %v", err)
	}
}

// 변조 감지는 1회 안내 알림을 보낸다.
func TestConfBindingNotifiesOnTamper(t *testing.T) {
	mac := filepath.Join(t.TempDir(), "conf.hmac")
	b := newConfBinding(mac, []byte("x"), nil, t.Logf)
	var notified atomic.Int32
	done := make(chan struct{})
	b.notify = func(subtitle, body string) {
		if !strings.Contains(body, "-trust-conf") {
			t.Errorf("안내에 복구 명령 없음: %q", body)
		}
		notified.Add(1)
		close(done)
	}
	if err := b.verify(testBindKey(t)); !errors.Is(err, errConfTampered) {
		t.Fatalf("지문 부재인데 통과: %v", err)
	}
	<-done
	if notified.Load() != 1 {
		t.Fatalf("알림 %d회(기대 1)", notified.Load())
	}
}

// K 채택 후의 승인 추가는 지문을 즉시 갱신해, 재기동 후에도 검증이 통과해야 한다.
func TestConfBindingApprovalAppendUpdatesMAC(t *testing.T) {
	mac := filepath.Join(t.TempDir(), "conf.hmac")
	conf := []byte("ask on\n")
	k := testBindKey(t)
	b := newConfBinding(mac, conf, nil, t.Logf)
	if err := b.adoptNewKey(k, "test"); err != nil {
		t.Fatal(err)
	}
	chunk := []byte("approve \"/usr/bin/ssh\" \"/Applications/iTerm.app\" # t\n")
	if err := b.appendApproval(func() ([]byte, error) { return chunk, nil }); err != nil {
		t.Fatal(err)
	}
	restarted := newConfBinding(mac, conf, chunk, t.Logf)
	if err := restarted.verify(k); err != nil {
		t.Fatalf("승인 추가 후 재기동 검증 실패: %v", err)
	}
	// 추가 전 상태로 되돌린 재기동은 실패해야 한다(지문이 이미 앞섰다).
	rolled := newConfBinding(mac, conf, nil, t.Logf)
	if err := rolled.verify(k); !errors.Is(err, errConfTampered) {
		t.Fatalf("승인 롤백인데 통과: %v", err)
	}
}

// 결속 K가 오기 전에는 승인 파일 writer 자체를 호출하지 않아야 한다. 그래야
// 잠금 해제 취소 뒤 재기동해도 pasu 자신의 기록을 변조로 오인하지 않는다.
func TestConfBindingRejectsApprovalBeforeVerifyWithoutWriting(t *testing.T) {
	mac := filepath.Join(t.TempDir(), "conf.hmac")
	conf := []byte("ask on\n")
	k := testBindKey(t)
	if err := newConfBinding(mac, conf, nil, t.Logf).adoptNewKey(k, "test"); err != nil {
		t.Fatal(err)
	}
	b := newConfBinding(mac, conf, nil, t.Logf)
	b.mode = "on"
	chunk := []byte("approve \"/p\" \"/r\" # t\n")
	called := false
	err := b.appendApproval(func() ([]byte, error) {
		called = true
		return chunk, nil
	})
	if err == nil || called {
		t.Fatalf("잠긴 결속에서 writer가 실행됨: called=%v err=%v", called, err)
	}
	restarted := newConfBinding(mac, conf, nil, t.Logf)
	if err := restarted.verify(k); err != nil {
		t.Fatalf("거부된 승인 뒤 기존 상태 재기동 검증 실패: %v", err)
	}
}

// 터미널(off) 모드의 승인 추가는 지문 파일을 만들지 않아야 한다.
func TestConfBindingOffModeInert(t *testing.T) {
	mac := filepath.Join(t.TempDir(), "conf.hmac")
	b := newConfBinding(mac, []byte("x"), nil, t.Logf)
	called := false
	if err := b.appendApproval(func() ([]byte, error) {
		called = true
		return []byte("approve \"/a\" \"/b\"\n"), nil
	}); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("off 모드 writer가 실행되지 않음")
	}
	if _, err := os.Stat(mac); !os.IsNotExist(err) {
		t.Fatalf("off 모드인데 conf.hmac 생성됨: %v", err)
	}
	var nilBinding *confBinding
	if err := nilBinding.appendApproval(func() ([]byte, error) { return []byte("x"), nil }); err != nil {
		t.Fatal(err)
	}
	if nilBinding.modeDesc() != "off" {
		t.Fatal("nil 결속의 modeDesc가 off가 아님")
	}
}
