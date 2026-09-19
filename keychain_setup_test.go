package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func saveKeychainHooks(t *testing.T) {
	t.Helper()
	probe, read := probeKeychainFn, keychainReadFn
	add, update, del := keychainAddFn, keychainUpdateFn, keychainDeleteFn
	confirm := managementConfirmFn
	readPass := readPassphraseFn
	openWrap := openSEWrapForMigrationFn
	t.Cleanup(func() {
		probeKeychainFn, keychainReadFn = probe, read
		keychainAddFn, keychainUpdateFn, keychainDeleteFn = add, update, del
		managementConfirmFn = confirm
		readPassphraseFn = readPass
		openSEWrapForMigrationFn = openWrap
	})
}

func TestKeychainOperationErrorAddsLockHintOnlyWhenRelevant(t *testing.T) {
	locked := keychainOperationError(append([]byte("Keychain 읽기 실패: OSStatus -25308"), 0))
	if !strings.Contains(locked.Error(), "화면을 풀고") {
		t.Fatalf("화면 잠금 오류에 복구 안내가 없음: %v", locked)
	}
	missing := keychainOperationError(append([]byte("Keychain 읽기 실패: OSStatus -25300"), 0))
	if strings.Contains(missing.Error(), "화면을 풀고") {
		t.Fatalf("항목 없음 오류에 잘못된 화면 잠금 안내가 붙음: %v", missing)
	}
}

func TestSetupKeychainFailureDeletesPartialItem(t *testing.T) {
	saveKeychainHooks(t)
	dir := t.TempDir()
	keyPath := genTestKey(t, "setup-pass")
	confPath := writeCheckConf(t, dir, "allow codesign team=AAAAAAAAAA id=pasu.test\n")
	probeKeychainFn = func() (keychainState, error) { return keychainMissing, nil }
	managementConfirmFn = func(string) (bool, error) { return true, nil }
	readPassphraseFn = func(string) ([]byte, error) { return []byte("setup-pass"), nil }
	var added []byte
	keychainAddFn = func(payload []byte) error {
		added = append([]byte(nil), payload...)
		return nil
	}
	keychainReadFn = func(string) ([]byte, error) { return append([]byte(nil), added...), nil }
	deleted := 0
	keychainDeleteFn = func() error { deleted++; return nil }
	badMACPath := filepath.Join(dir, "missing", "conf.hmac")
	err := runSetupKeychain(keyPath, confPath, filepath.Join(dir, "approvals.conf"), badMACPath)
	if err == nil {
		t.Fatal("지문 기록 실패인데 setup 성공")
	}
	if deleted != 1 {
		t.Fatalf("반쪽 Keychain 항목 삭제=%d회, 기대 1", deleted)
	}
}

func TestMigrateKeychainReadbackFailureRollsBack(t *testing.T) {
	saveKeychainHooks(t)
	dir := t.TempDir()
	keyPath := genTestKey(t, "migrate-pass")
	confPath := writeCheckConf(t, dir, "allow codesign team=AAAAAAAAAA id=pasu.test\n")
	wrapPath := filepath.Join(dir, "sewrap")
	if err := writeSEWrap(wrapPath, &seWrap{V: sewrapV2, Blob: []byte("b"), Eph: []byte("e"), Ct: []byte("c")}); err != nil {
		t.Fatal(err)
	}
	k := bytes.Repeat([]byte{6}, bindKeyLen)
	macPath := filepath.Join(dir, "conf.hmac")
	if err := newConfBinding(macPath, []byte("allow codesign team=AAAAAAAAAA id=pasu.test\n"), nil, t.Logf).adoptNewKey(k, "test"); err != nil {
		t.Fatal(err)
	}
	probeKeychainFn = func() (keychainState, error) { return keychainMissing, nil }
	managementConfirmFn = func(string) (bool, error) { return true, nil }
	openSEWrapForMigrationFn = func(*seWrap, string) ([]byte, error) {
		return append(append([]byte{}, []byte("migrate-pass")...), k...), nil
	}
	keychainAddFn = func([]byte) error { return nil }
	keychainReadFn = func(string) ([]byte, error) { return nil, errors.New("강제 readback 실패") }
	deleted := 0
	keychainDeleteFn = func() error { deleted++; return nil }
	if err := runMigrateKeychain(keyPath, wrapPath, confPath, filepath.Join(dir, "approvals.conf"), macPath); err == nil {
		t.Fatal("readback 실패인데 이전 성공")
	}
	if deleted != 1 {
		t.Fatalf("실패한 새 Keychain 항목 삭제=%d회, 기대 1", deleted)
	}
	if _, err := os.Stat(wrapPath); err != nil {
		t.Fatalf("실패 뒤 원본 sewrap이 사라짐: %v", err)
	}
}

func TestRemoveLegacySEWrapFailurePreservesFile(t *testing.T) {
	saveKeychainHooks(t)
	dir := t.TempDir()
	keyPath := genTestKey(t, "remove-pass")
	confPath := writeCheckConf(t, dir, "allow codesign team=AAAAAAAAAA id=pasu.test\n")
	wrapPath := filepath.Join(dir, "sewrap")
	if err := os.WriteFile(wrapPath, []byte("legacy"), 0o600); err != nil {
		t.Fatal(err)
	}
	probeKeychainFn = func() (keychainState, error) { return keychainProtected, nil }
	managementConfirmFn = func(string) (bool, error) { return true, nil }
	keychainReadFn = func(string) ([]byte, error) { return nil, errors.New("강제 인증 실패") }
	err := runRemoveLegacySEWrap(keyPath, wrapPath, confPath, filepath.Join(dir, "approvals.conf"), filepath.Join(dir, "conf.hmac"))
	if err == nil {
		t.Fatal("검증 실패인데 legacy sewrap 삭제 성공")
	}
	if _, err := os.Stat(wrapPath); err != nil {
		t.Fatalf("실패 뒤 legacy sewrap이 사라짐: %v", err)
	}
}

func TestProductionFlagErrorRejectsPathAndStdinOverrides(t *testing.T) {
	for _, name := range []string{"dir", "socket", "key", "config", "log", "passphrase-stdin"} {
		if err := productionFlagError(map[string]bool{name: true}); err == nil || !strings.Contains(err.Error(), "-"+name) {
			t.Errorf("%s 옵션이 production에서 거부되지 않음: %v", name, err)
		}
	}
	if err := productionFlagError(map[string]bool{"check": true, "trust-conf": true}); err != nil {
		t.Fatalf("고정 경로 관리 옵션까지 거부됨: %v", err)
	}
}

func TestProductionHomeIgnoresInjectedEnvironment(t *testing.T) {
	want, err := resolveHomeDir(true)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", "/tmp/pasu-attacker-home")
	got, err := resolveHomeDir(true)
	if err != nil || got != want {
		t.Fatalf("production home=%q, 기대 %q, err=%v", got, want, err)
	}
	dev, err := resolveHomeDir(false)
	if err != nil || dev != "/tmp/pasu-attacker-home" {
		t.Fatalf("ad-hoc 개발 HOME 호환이 깨짐: home=%q err=%v", dev, err)
	}
}

func TestNewKeySourceUsesProtectedKeychainAndVerifiesBinding(t *testing.T) {
	saveKeychainHooks(t)
	dir := t.TempDir()
	keyPath := genTestKey(t, "kc-pass")
	conf := []byte("allow codesign team=AAAAAAAAAA id=pasu.test\n")
	appr := []byte("# none\n")
	macPath := filepath.Join(dir, "conf.hmac")
	k := bytes.Repeat([]byte{9}, bindKeyLen)
	b := newConfBinding(macPath, conf, appr, t.Logf)
	if err := b.adoptNewKey(k, "test"); err != nil {
		t.Fatal(err)
	}
	payload := append(append([]byte{}, []byte("kc-pass")...), k...)
	keychainReadFn = func(reason string) ([]byte, error) {
		if reason == "" {
			t.Fatal("Touch ID 사유가 비어 있음")
		}
		return append([]byte(nil), payload...), nil
	}
	audit := discardAuditLog(t)
	src, desc, err := newKeySource(keyPath, filepath.Join(dir, "sewrap"), false, keychainProtected, audit,
		newConfBinding(macPath, conf, appr, t.Logf))
	if err != nil {
		t.Fatal(err)
	}
	if desc != "keychain(touchid)" {
		t.Fatalf("source=%q", desc)
	}
	signer, err := src.Signer()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := loadPublicKey(keyPath + ".pub")
	if err != nil || !bytes.Equal(signer.PublicKey().Marshal(), pub.Marshal()) {
		t.Fatalf("Keychain signer 공개키 불일치: %v", err)
	}
}

func TestNewKeySourceFailsClosedForBadProductionKeychainState(t *testing.T) {
	audit := discardAuditLog(t)
	for _, state := range []keychainState{keychainMissing, keychainUnprotected} {
		_, _, err := newKeySource("/no/key", "/no/sewrap", false, state, audit,
			newConfBinding("/no/mac", nil, nil, nil))
		if err == nil || !strings.Contains(err.Error(), "Keychain") {
			t.Errorf("state=%s가 불허 방향으로 실패하지 않음: %v", state, err)
		}
	}
}

func TestNewKeySourceLatchesWrongKeychainPassphrase(t *testing.T) {
	saveKeychainHooks(t)
	keyPath := genTestKey(t, "right-pass")
	dir := t.TempDir()
	k := bytes.Repeat([]byte{8}, bindKeyLen)
	payload := append(append([]byte{}, []byte("wrong-pass")...), k...)
	var reads atomic.Int32
	keychainReadFn = func(string) ([]byte, error) {
		reads.Add(1)
		return append([]byte(nil), payload...), nil
	}
	audit := discardAuditLog(t)
	src, _, err := newKeySource(keyPath, filepath.Join(dir, "sewrap"), false, keychainProtected, audit,
		newConfBinding(filepath.Join(dir, "conf.hmac"), nil, nil, t.Logf))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := src.Signer(); !errors.Is(err, errKeyMaterialInvalid) {
			t.Fatalf("결정적 복호화 오류 표식 누락: %v", err)
		}
	}
	if got := reads.Load(); got != 1 {
		t.Fatalf("잘못된 passphrase가 Keychain 프롬프트를 %d회 유발", got)
	}
}

func TestConfigSnapshotDoesNotBlessLaterFileMutation(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "pasu.conf")
	apprPath := filepath.Join(dir, "approvals.conf")
	macPath := filepath.Join(dir, "conf.hmac")
	if err := os.WriteFile(confPath, []byte("allow codesign team=AAAAAAAAAA id=pasu.safe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := readConfigSnapshot(confPath, apprPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(confPath, []byte("allow codesign team=AAAAAAAAAA id=pasu.evil\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	k := bytes.Repeat([]byte{3}, bindKeyLen)
	if err := snapshot.record(k, macPath, "test"); err != nil {
		t.Fatal(err)
	}
	changed, err := readConfigSnapshot(confPath, apprPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := changed.verify(k, macPath); !errors.Is(err, errConfTampered) {
		t.Fatalf("확인 뒤 바뀐 설정이 신뢰 기준으로 기록됨: %v", err)
	}
}

func TestTrustConfKeychainRotatesPayloadAndRecordsMatchingMAC(t *testing.T) {
	saveKeychainHooks(t)
	dir := t.TempDir()
	keyPath := genTestKey(t, "trust-pass")
	confPath := filepath.Join(dir, "pasu.conf")
	apprPath := filepath.Join(dir, "approvals.conf")
	macPath := filepath.Join(dir, "conf.hmac")
	if err := os.WriteFile(confPath, []byte("allow codesign team=AAAAAAAAAA id=pasu.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldK := bytes.Repeat([]byte{4}, bindKeyLen)
	oldPayload := append(append([]byte{}, []byte("trust-pass")...), oldK...)
	probeKeychainFn = func() (keychainState, error) { return keychainProtected, nil }
	keychainReadFn = func(string) ([]byte, error) { return append([]byte(nil), oldPayload...), nil }
	var updated []byte
	keychainUpdateFn = func(v []byte) error {
		updated = append([]byte(nil), v...)
		return nil
	}
	managementConfirmFn = func(string) (bool, error) { return true, nil }
	if err := runTrustConfKeychain(keyPath, confPath, apprPath, macPath); err != nil {
		t.Fatal(err)
	}
	pass, newK, err := splitSealedPayload(updated, sewrapV2)
	if err != nil || string(pass) != "trust-pass" || bytes.Equal(newK, oldK) {
		t.Fatalf("Keychain 회전 결과 이상: pass=%q old=%x new=%x err=%v", pass, oldK, newK, err)
	}
	snapshot, err := readConfigSnapshot(confPath, apprPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshot.verify(newK, macPath); err != nil {
		t.Fatalf("새 K와 설정 지문 불일치: %v", err)
	}
}

func TestRemoveKeychainRequiresConfirmationAndUserPresence(t *testing.T) {
	saveKeychainHooks(t)
	macPath := filepath.Join(t.TempDir(), "conf.hmac")
	if err := os.WriteFile(macPath, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	probeKeychainFn = func() (keychainState, error) { return keychainProtected, nil }
	managementConfirmFn = func(string) (bool, error) { return true, nil }
	read := 0
	deleted := 0
	keychainReadFn = func(string) ([]byte, error) {
		read++
		return []byte("authenticated"), nil
	}
	keychainDeleteFn = func() error {
		deleted++
		return nil
	}
	if err := runRemoveKeychain(macPath); err != nil {
		t.Fatal(err)
	}
	if read != 1 || deleted != 1 {
		t.Fatalf("read=%d delete=%d", read, deleted)
	}
	if _, err := os.Stat(macPath); !os.IsNotExist(err) {
		t.Fatalf("conf.hmac이 삭제되지 않음: %v", err)
	}
}

func TestRemoveLegacyV1KeychainLeavesV2StateOutOfScope(t *testing.T) {
	saveKeychainHooks(t)
	probeKeychainFn = func() (keychainState, error) { return keychainProtected, nil }
	managementConfirmFn = func(text string) (bool, error) {
		if !strings.Contains(text, "v2 registry와 UUID 키별 Keychain 항목은 삭제하지 않습니다") {
			t.Fatalf("삭제 범위 안내 누락: %q", text)
		}
		return true, nil
	}
	read := 0
	deleted := 0
	keychainReadFn = func(reason string) ([]byte, error) {
		read++
		if !strings.Contains(reason, "v1 legacy") {
			t.Fatalf("인증 사유가 불명확함: %q", reason)
		}
		return []byte("authenticated legacy payload"), nil
	}
	keychainDeleteFn = func() error {
		deleted++
		return nil
	}
	if err := runRemoveLegacyV1Keychain(); err != nil {
		t.Fatal(err)
	}
	if read != 1 || deleted != 1 {
		t.Fatalf("read=%d delete=%d", read, deleted)
	}
}
