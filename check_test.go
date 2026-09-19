package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCheckConf(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "pasu.conf")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCheckConfigurationTerminalMode(t *testing.T) {
	dir := t.TempDir()
	key := genTestKey(t, "check-pass")
	conf := writeCheckConf(t, dir, "ask on\nallow codesign team=AAAAAAAAAA id=pasu.test\n")
	got, err := checkConfiguration("/home/tester", key, filepath.Join(dir, "sewrap"), conf, filepath.Join(dir, "conf.hmac"), keychainUnavailable)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"CHECK ok", "key=encrypted", "sewrap=off", "bind=off", "ask=true", "ask-cooldown=5m", "notify-cooldown=1m"} {
		if !strings.Contains(got, want) {
			t.Errorf("CHECK 결과에 %q 없음: %s", want, got)
		}
	}
}

func TestCheckConfigurationTerminalModeDoesNotRequirePublicKey(t *testing.T) {
	dir := t.TempDir()
	key := genTestKey(t, "check-pass")
	if err := os.Remove(key + ".pub"); err != nil {
		t.Fatal(err)
	}
	conf := writeCheckConf(t, dir, "allow codesign team=AAAAAAAAAA id=pasu.test\n")
	got, err := checkConfiguration("/home/tester", key, filepath.Join(dir, "sewrap"), conf, filepath.Join(dir, "conf.hmac"), keychainUnavailable)
	if err != nil || !strings.Contains(got, "key-pub=not-required") {
		t.Fatalf("터미널 모드가 불필요한 key.pub을 요구함: got=%q err=%v", got, err)
	}
}

func TestCheckConfigurationV2RequiresWellFormedMAC(t *testing.T) {
	dir := t.TempDir()
	key := genTestKey(t, "check-pass")
	conf := writeCheckConf(t, dir, "allow codesign team=AAAAAAAAAA id=pasu.test\n")
	wrap := filepath.Join(dir, "sewrap")
	if err := writeSEWrap(wrap, &seWrap{V: sewrapV2, Blob: []byte("b"), Eph: []byte("e"), Ct: []byte("c")}); err != nil {
		t.Fatal(err)
	}
	mac := filepath.Join(dir, "conf.hmac")
	if _, err := checkConfiguration("/home/tester", key, wrap, conf, mac, keychainUnavailable); err == nil || !strings.Contains(err.Error(), "지문 검사 실패") {
		t.Fatalf("conf.hmac 부재 오류 이상: %v", err)
	}
	if err := os.WriteFile(mac, []byte("not-hex\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := checkConfiguration("/home/tester", key, wrap, conf, mac, keychainUnavailable); err == nil || !strings.Contains(err.Error(), "형식 오류") {
		t.Fatalf("conf.hmac 손상 오류 이상: %v", err)
	}
	if err := os.WriteFile(mac, []byte(strings.Repeat("00", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := checkConfiguration("/home/tester", key, wrap, conf, mac, keychainUnavailable)
	if err != nil || !strings.Contains(got, "sewrap=v2 bind=deferred") {
		t.Fatalf("v2 정적 검사 실패: got=%q err=%v", got, err)
	}
}

func TestCheckConfigurationProtectedKeychain(t *testing.T) {
	dir := t.TempDir()
	key := genTestKey(t, "check-pass")
	conf := writeCheckConf(t, dir, "allow codesign team=AAAAAAAAAA id=pasu.test\n")
	mac := filepath.Join(dir, "conf.hmac")
	if err := os.WriteFile(mac, []byte(strings.Repeat("00", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := checkConfiguration("/home/tester", key, filepath.Join(dir, "sewrap"), conf, mac, keychainProtected)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"keychain=protected", "sewrap=off", "bind=deferred"} {
		if !strings.Contains(got, want) {
			t.Errorf("CHECK 결과에 %q 없음: %s", want, got)
		}
	}
	if _, err := checkConfiguration("/home/tester", key, filepath.Join(dir, "sewrap"), conf, mac, keychainMissing); err == nil {
		t.Fatal("Developer ID 앱의 Keychain 항목 부재가 통과함")
	}
}

func TestCheckConfigurationRejectsBadInputs(t *testing.T) {
	t.Run("conf", func(t *testing.T) {
		dir := t.TempDir()
		conf := writeCheckConf(t, dir, "not-a-directive\n")
		if _, err := checkConfiguration("/home/tester", "/no/key", filepath.Join(dir, "sewrap"), conf, filepath.Join(dir, "conf.hmac"), keychainUnavailable); err == nil || !strings.Contains(err.Error(), "설정 로드 실패") {
			t.Fatalf("잘못된 conf 오류 이상: %v", err)
		}
	})

	t.Run("unencrypted-key", func(t *testing.T) {
		dir := t.TempDir()
		key := genTestKey(t, "")
		conf := writeCheckConf(t, dir, "allow codesign team=AAAAAAAAAA id=pasu.test\n")
		if _, err := checkConfiguration("/home/tester", key, filepath.Join(dir, "sewrap"), conf, filepath.Join(dir, "conf.hmac"), keychainUnavailable); err == nil || !strings.Contains(err.Error(), "passphrase 없는 키") {
			t.Fatalf("평문 키 오류 이상: %v", err)
		}
	})

	t.Run("corrupt-sewrap", func(t *testing.T) {
		dir := t.TempDir()
		key := genTestKey(t, "check-pass")
		conf := writeCheckConf(t, dir, "allow codesign team=AAAAAAAAAA id=pasu.test\n")
		wrap := filepath.Join(dir, "sewrap")
		if err := os.WriteFile(wrap, []byte("broken"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := checkConfiguration("/home/tester", key, wrap, conf, filepath.Join(dir, "conf.hmac"), keychainUnavailable); err == nil || !strings.Contains(err.Error(), "Touch ID 설정 읽기 실패") {
			t.Fatalf("손상 sewrap 오류 이상: %v", err)
		}
	})
}
