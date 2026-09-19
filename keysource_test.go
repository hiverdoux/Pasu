package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
)

// 지연 키: 첫 서명에서 한 번만 잠금 해제하고 이후 캐시를 쓰는지.
func TestLazyKeyUnlocksOnceAndCaches(t *testing.T) {
	signer := testSigner(t)
	var calls atomic.Int32
	lk := &lazyKey{
		pub: signer.PublicKey(),
		unlock: func() (ssh.Signer, error) {
			calls.Add(1)
			return signer, nil
		},
	}
	cl := dialAgent(t, startServerWithKey(t, selfCodesignRules(t, ""), lk))
	keys, err := cl.List()
	if err != nil || len(keys) != 1 {
		t.Fatalf("List: keys=%d err=%v", len(keys), err)
	}
	if calls.Load() != 0 {
		t.Fatalf("List가 잠금을 건드림: unlock=%d", calls.Load())
	}
	data := []byte("lazy sign")
	sig, err := cl.Sign(keys[0], data)
	if err != nil {
		t.Fatalf("허용 기대했으나 거부: %v", err)
	}
	if err := keys[0].Verify(data, sig); err != nil {
		t.Fatalf("서명 검증 실패: %v", err)
	}
	if _, err := cl.Sign(keys[0], data); err != nil {
		t.Fatalf("두 번째 서명 거부: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("잠금 해제 횟수 = %d, 기대 1(캐시)", got)
	}
}

// 잠금 해제 실패: List는 여전히 응답하고 Sign만 거부되며, 다음 서명에서 재시도한다.
func TestLazyKeyUnlockFailureDeniesSignOnly(t *testing.T) {
	signer := testSigner(t)
	var calls atomic.Int32
	lk := &lazyKey{
		pub: signer.PublicKey(),
		unlock: func() (ssh.Signer, error) {
			calls.Add(1)
			return nil, errors.New("사용자 취소")
		},
	}
	cl := dialAgent(t, startServerWithKey(t, selfCodesignRules(t, ""), lk))
	keys, err := cl.List()
	if err != nil || len(keys) != 1 {
		t.Fatalf("List: keys=%d err=%v", len(keys), err)
	}
	if _, err := cl.Sign(keys[0], []byte("x")); err == nil {
		t.Fatal("잠금 해제 실패인데 서명됨")
	}
	if _, err := cl.Sign(keys[0], []byte("x")); err == nil {
		t.Fatal("잠금 해제 실패인데 서명됨(재시도)")
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("실패 시 재시도 횟수 = %d, 기대 2", got)
	}
}

// 설정 결속 불일치는 고정(latch)돼야 한다: 일반 해제 실패와 달리 재시도가
// 잠금 해제(= Touch ID 프롬프트)를 다시 유발하면 안 된다.
func TestLazyKeyLatchesConfTampered(t *testing.T) {
	signer := testSigner(t)
	var calls atomic.Int32
	lk := &lazyKey{
		pub: signer.PublicKey(),
		unlock: func() (ssh.Signer, error) {
			calls.Add(1)
			return nil, fmt.Errorf("검증: %w", errConfTampered)
		},
	}
	cl := dialAgent(t, startServerWithKey(t, selfCodesignRules(t, ""), lk))
	keys, err := cl.List()
	if err != nil || len(keys) != 1 {
		t.Fatalf("List: keys=%d err=%v", len(keys), err)
	}
	for i := 1; i <= 3; i++ {
		if _, err := cl.Sign(keys[0], []byte("x")); err == nil {
			t.Fatalf("%d번째: 변조 의심인데 서명됨", i)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("잠금 해제 시도 %d회(기대 1 — latch가 프롬프트 반복을 막아야 함)", got)
	}
}

// 해제된 개인키가 광고 중인 공개키와 다르면 서명을 거부한다(구성 오류 방어).
func TestLazyKeyRejectsMismatchedUnlock(t *testing.T) {
	advertised := testSigner(t)
	other := testSigner(t)
	var calls atomic.Int32
	lk := &lazyKey{
		pub:    advertised.PublicKey(),
		unlock: func() (ssh.Signer, error) { calls.Add(1); return other, nil },
	}
	cl := dialAgent(t, startServerWithKey(t, selfCodesignRules(t, ""), lk))
	keys, err := cl.List()
	if err != nil || len(keys) != 1 {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := cl.Sign(keys[0], []byte("x")); err == nil {
			t.Fatal("키 불일치인데 서명됨")
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("결정적 키 불일치가 latch되지 않음: unlock=%d", got)
	}
}

func TestLazyKeyLatchesKeyMaterialError(t *testing.T) {
	signer := testSigner(t)
	var calls atomic.Int32
	lk := &lazyKey{
		pub: signer.PublicKey(),
		unlock: func() (ssh.Signer, error) {
			calls.Add(1)
			return nil, fmt.Errorf("%w: 잘못된 passphrase", errKeyMaterialInvalid)
		},
	}
	for i := 0; i < 3; i++ {
		if _, err := lk.Signer(); !errors.Is(err, errKeyMaterialInvalid) {
			t.Fatalf("고정 오류가 보존되지 않음: %v", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("고정 오류 unlock=%d, 기대 1", got)
	}
}

func TestLazyKeyConcurrentCallsUnlockOnce(t *testing.T) {
	signer := testSigner(t)
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	lk := &lazyKey{
		pub: signer.PublicKey(),
		unlock: func() (ssh.Signer, error) {
			if calls.Add(1) == 1 {
				close(started)
			}
			<-release
			return signer, nil
		},
	}
	const n = 12
	var wg sync.WaitGroup
	errCh := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := lk.Signer()
			errCh <- err
		}()
	}
	<-started
	close(release)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("동시 요청이 잠금 해제를 %d회 실행", got)
	}
}

func TestNewKeySourceRejectsCorruptSEWrap(t *testing.T) {
	dir := t.TempDir()
	wrap := filepath.Join(dir, "sewrap")
	if err := os.WriteFile(wrap, []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	audit := discardAuditLog(t)
	_, _, err := newKeySource(filepath.Join(dir, "key"), wrap, false, keychainUnavailable, audit,
		newConfBinding(filepath.Join(dir, "conf.hmac"), nil, nil, t.Logf))
	if err == nil || !strings.Contains(err.Error(), "Touch ID 설정 읽기 실패") {
		t.Fatalf("손상 sewrap 오류 이상: %v", err)
	}
}

func TestNewKeySourceRequiresPublicKeyInSEWrapMode(t *testing.T) {
	dir := t.TempDir()
	keyPath := genTestKey(t, "pass")
	// genTestKey의 개인키만 테스트 디렉터리로 복사하고 key.pub은 의도적으로 뺀다.
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	keyPath = filepath.Join(dir, "key")
	if err := os.WriteFile(keyPath, keyData, 0o600); err != nil {
		t.Fatal(err)
	}
	wrapPath := filepath.Join(dir, "sewrap")
	if err := writeSEWrap(wrapPath, &seWrap{V: sewrapV1, Blob: []byte("b"), Eph: []byte("e"), Ct: []byte("c")}); err != nil {
		t.Fatal(err)
	}
	audit := discardAuditLog(t)
	_, _, err = newKeySource(keyPath, wrapPath, false, keychainUnavailable, audit,
		newConfBinding(filepath.Join(dir, "conf.hmac"), nil, nil, t.Logf))
	if err == nil || !strings.Contains(err.Error(), "공개키 파일이 필요") {
		t.Fatalf("key.pub 부재 오류 이상: %v", err)
	}
}
