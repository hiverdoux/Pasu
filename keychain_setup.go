package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// configSnapshot은 사용자가 확인한 설정 바이트와 실제로 HMAC할 바이트를
// 하나로 고정한다. 확인 창 뒤에 공격자가 파일을 바꾸면 다음 기동의 판독값과
// 지문이 달라져 서명이 거부된다(확인한 내용과 다른 파일을 신뢰 기준으로 기록하지 않음).
type configSnapshot struct {
	conf      []byte
	approvals []byte
	confPath  string
	apprPath  string
}

func readConfigSnapshot(confPath, approvalsPath string) (configSnapshot, error) {
	conf, err := os.ReadFile(confPath)
	if err != nil {
		return configSnapshot{}, fmt.Errorf("pasu.conf 읽기 실패: %w", err)
	}
	approvals, err := os.ReadFile(approvalsPath)
	if err != nil && !os.IsNotExist(err) {
		return configSnapshot{}, fmt.Errorf("approvals.conf 읽기 실패: %w", err)
	}
	return configSnapshot{
		conf:      conf,
		approvals: approvals,
		confPath:  confPath,
		apprPath:  approvalsPath,
	}, nil
}

func (s configSnapshot) record(k []byte, macPath, cause string) error {
	b := newConfBinding(macPath, s.conf, s.approvals, nil)
	return b.adoptNewKey(k, cause)
}

func (s configSnapshot) verify(k []byte, macPath string) error {
	b := newConfBinding(macPath, s.conf, s.approvals, nil)
	b.setMode("on")
	return b.verify(k)
}

func (s configSnapshot) confirmationText() string {
	confHash := sha256.Sum256(s.conf)
	apprHash := sha256.Sum256(s.approvals)
	return fmt.Sprintf(
		"현재 설정을 새 신뢰 기준으로 기록합니다.\n\n설정: %s\nSHA-256: %x\n\n승인: %s\nSHA-256: %x\n\n본인이 방금 검토한 파일이 맞을 때만 계속하세요.",
		s.confPath, confHash, s.apprPath, apprHash,
	)
}

const managementConfirmScript = `on run argv
set r to display dialog (item 1 of argv) with title "pasu — 보안 설정 변경" buttons {"계속", "취소"} default button "취소" cancel button "취소" with icon caution giving up after 90
if gave up of r then return "timeout"
return button returned of r
end run`

func macManagementConfirm(text string) (bool, error) {
	out, canceled, err := runAskScriptFn(managementConfirmScript, text, 95*time.Second)
	if canceled {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return out == "계속", nil
}

var managementConfirmFn = macManagementConfirm

func requireManagementConfirmation(text string) error {
	ok, err := managementConfirmFn(text)
	if err != nil {
		return fmt.Errorf("보안 설정 확인 창 실패: %w", err)
	}
	if !ok {
		return errors.New("사용자가 보안 설정 변경을 취소함")
	}
	return nil
}

func ensureKeyMatches(keyPath string, pass []byte, createPublic bool) (ssh.Signer, error) {
	pemBytes, err := readEncryptedKey(keyPath)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKeyWithPassphrase(pemBytes, pass)
	if err != nil {
		return nil, fmt.Errorf("복호화 실패 (passphrase 확인): %w", err)
	}
	if err := requireEd25519PublicKey(signer.PublicKey(), keyPath); err != nil {
		return nil, err
	}
	pubPath := keyPath + ".pub"
	pub, err := loadPublicKey(pubPath)
	switch {
	case err == nil:
		if !bytes.Equal(pub.Marshal(), signer.PublicKey().Marshal()) {
			return nil, fmt.Errorf("%s이 개인키와 일치하지 않음", pubPath)
		}
	case createPublic && os.IsNotExist(err):
		if err := os.WriteFile(pubPath, ssh.MarshalAuthorizedKey(signer.PublicKey()), 0o600); err != nil {
			return nil, err
		}
		fmt.Printf("공개키 파일 생성: %s\n", pubPath)
	case err != nil:
		return nil, fmt.Errorf("공개키 검사 실패: %w", err)
	}
	return signer, nil
}

func parseKeychainPayload(keyPath string, payload []byte) (pass, k []byte, err error) {
	pass, k, err = splitSealedPayload(payload, sewrapV2)
	if err != nil {
		return nil, nil, fmt.Errorf("Keychain 내용 형식 오류: %w", err)
	}
	if _, err := ensureKeyMatches(keyPath, pass, false); err != nil {
		return nil, nil, err
	}
	return pass, k, nil
}

func requireKeychainState(want keychainState) error {
	got, err := probeKeychainFn()
	if err != nil {
		return err
	}
	if got == keychainUnprotected {
		return errors.New("pasu Keychain 항목에 userPresence가 없음 — 보호되지 않은 항목은 사용하지 않음")
	}
	if got != want {
		return fmt.Errorf("pasu Keychain 상태가 %s임(필요: %s)", got, want)
	}
	return nil
}

// runSetupKeychain은 새 설치에서 passphrase와 새 K를 앱 전용 Keychain에
// 넣는다. 추가 뒤 실제 읽기(Touch ID)로 값을 확인하고 나서만 설정 지문을
// 기록한다. 검증 실패 시 새 항목을 삭제해 반쯤 설정된 상태를 남기지 않는다.
func runSetupKeychain(keyPath, confPath, approvalsPath, macPath string) error {
	if err := requireKeychainState(keychainMissing); err != nil {
		return err
	}
	snapshot, err := readConfigSnapshot(confPath, approvalsPath)
	if err != nil {
		return err
	}
	if err := requireManagementConfirmation(snapshot.confirmationText() + "\n\n확인한 설정과 SSH 키 passphrase를 앱 전용 Keychain에 결속합니다."); err != nil {
		return err
	}
	pass, err := readPassphraseFn(fmt.Sprintf("%s passphrase: ", keyPath))
	if err != nil {
		return err
	}
	defer wipe(pass)
	if _, err := ensureKeyMatches(keyPath, pass, true); err != nil {
		return err
	}
	k, err := newBindKey()
	if err != nil {
		return err
	}
	payload := append(append([]byte{}, pass...), k...)
	defer wipe(payload)
	if err := keychainAddFn(payload); err != nil {
		return err
	}
	rollback := true
	defer func() {
		if rollback {
			_ = keychainDeleteFn()
		}
	}()
	fmt.Println("Touch ID(또는 로그인 암호)로 앱 전용 Keychain 읽기를 검증합니다 …")
	got, err := keychainReadFn("pasu 설정 검증: SSH 키 잠금 해제")
	if err != nil {
		return fmt.Errorf("Keychain 읽기 검증 실패: %w", err)
	}
	same := bytes.Equal(got, payload)
	wipe(got)
	if !same {
		return errors.New("Keychain 읽기 검증 값 불일치")
	}
	if err := snapshot.record(k, macPath, "setup-keychain"); err != nil {
		return err
	}
	rollback = false
	fmt.Println("완료: Developer ID 앱 전용 Data Protection Keychain")
	fmt.Printf("설정 결속 기록: %s\n", macPath)
	return nil
}

// runMigrateKeychain은 기존 sewrap의 passphrase‖K를 그대로 앱 전용
// Keychain으로 복사한다. 기존 설정 HMAC을 먼저 검증하고 새 저장소의 실제
// Touch ID 읽기까지 왕복한 뒤 성공한다. sewrap 삭제는 새 서비스 확인 뒤의
// 별도 명령으로 남겨 복구 가능성을 보존한다.
func runMigrateKeychain(keyPath, wrapPath, confPath, approvalsPath, macPath string) error {
	if err := requireKeychainState(keychainMissing); err != nil {
		return err
	}
	if err := requireManagementConfirmation("기존 sewrap을 Developer ID 앱 전용 Keychain으로 이전합니다.\n\n이 작업은 아직 sewrap을 삭제하지 않습니다. 새 설치본 검증 뒤 별도 단계에서 제거합니다."); err != nil {
		return err
	}
	snapshot, err := readConfigSnapshot(confPath, approvalsPath)
	if err != nil {
		return err
	}
	w, err := readSEWrap(wrapPath)
	if err != nil {
		return fmt.Errorf("기존 sewrap 읽기 실패: %w", err)
	}
	payload, err := openSEWrapForMigrationFn(w, "pasu 이전: 기존 sewrap 잠금 해제")
	if err != nil {
		return err
	}
	defer wipe(payload)
	pass, k, err := splitSealedPayload(payload, w.V)
	if err != nil {
		return err
	}
	if _, err := ensureKeyMatches(keyPath, pass, false); err != nil {
		return err
	}
	needsRecord := false
	if k == nil {
		k, err = newBindKey()
		if err != nil {
			return err
		}
		payload = append(append([]byte{}, pass...), k...)
		defer wipe(payload)
		needsRecord = true
	} else if err := snapshot.verify(k, macPath); err != nil {
		return fmt.Errorf("기존 설정 결속 검증 실패: %w", err)
	}
	if err := keychainAddFn(payload); err != nil {
		return err
	}
	rollback := true
	defer func() {
		if rollback {
			_ = keychainDeleteFn()
		}
	}()
	fmt.Println("새 Keychain 항목을 Touch ID로 다시 읽어 이전 결과를 검증합니다 …")
	got, err := keychainReadFn("pasu 이전 검증: 새 Keychain 잠금 해제")
	if err != nil {
		return err
	}
	same := bytes.Equal(got, payload)
	wipe(got)
	if !same {
		return errors.New("Keychain 이전 검증 값 불일치")
	}
	if needsRecord {
		if err := snapshot.record(k, macPath, "migrate-v1"); err != nil {
			return err
		}
	}
	rollback = false
	fmt.Println("Keychain 이전 완료 — 새 설치본의 키 인증과 SSH 연결을 확인한 뒤 기존 sewrap을 제거하세요.")
	return nil
}

var openSEWrapForMigrationFn = func(w *seWrap, reason string) ([]byte, error) {
	return w.open(reason)
}

func runTrustConfKeychain(keyPath, confPath, approvalsPath, macPath string) error {
	if err := requireKeychainState(keychainProtected); err != nil {
		return err
	}
	snapshot, err := readConfigSnapshot(confPath, approvalsPath)
	if err != nil {
		return err
	}
	if err := requireManagementConfirmation(snapshot.confirmationText()); err != nil {
		return err
	}
	oldPayload, err := keychainReadFn("pasu 설정 결속: 현재 Keychain 잠금 해제")
	if err != nil {
		return err
	}
	defer wipe(oldPayload)
	pass, _, err := parseKeychainPayload(keyPath, oldPayload)
	if err != nil {
		return err
	}
	newK, err := newBindKey()
	if err != nil {
		return err
	}
	newPayload := append(append([]byte{}, pass...), newK...)
	defer wipe(newPayload)
	if err := keychainUpdateFn(newPayload); err != nil {
		return err
	}
	if err := snapshot.record(newK, macPath, "trust-conf-keychain"); err != nil {
		if rollbackErr := keychainUpdateFn(oldPayload); rollbackErr != nil {
			return fmt.Errorf("설정 지문 기록 실패(%v), Keychain 롤백도 실패(%v) — 서명은 불허 방향으로 중단됨", err, rollbackErr)
		}
		return err
	}
	fmt.Printf("신뢰 기준 기록 완료: %s (Keychain K 회전)\n", macPath)
	return nil
}

func runRemoveKeychain(macPath string) error {
	state, err := probeKeychainFn()
	if err != nil {
		return err
	}
	if state == keychainMissing {
		fmt.Println("pasu Keychain 항목이 없습니다.")
		return nil
	}
	if state != keychainProtected {
		return fmt.Errorf("삭제할 수 없는 Keychain 상태: %s", state)
	}
	if err := requireManagementConfirmation("pasu의 앱 전용 Keychain 항목을 삭제합니다.\n\n삭제 뒤에는 SSH 키 자동 잠금 해제가 중단됩니다."); err != nil {
		return err
	}
	payload, err := keychainReadFn("pasu Keychain 잠금 해제 설정 삭제 확인")
	if err != nil {
		return fmt.Errorf("삭제 전 사용자 인증 실패: %w", err)
	}
	wipe(payload)
	if err := keychainDeleteFn(); err != nil {
		return err
	}
	if err := os.Remove(macPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("Keychain은 삭제됐지만 설정 지문 삭제 실패: %w", err)
	}
	fmt.Println("Keychain 잠금 해제 설정과 설정 지문을 삭제했습니다.")
	return nil
}

func runRemoveLegacyV1Keychain() error {
	state, err := probeKeychainFn()
	if err != nil {
		return err
	}
	if state == keychainMissing {
		fmt.Println("Pasu v1 legacy Keychain 항목이 이미 없습니다.")
		return nil
	}
	if state != keychainProtected {
		return fmt.Errorf("삭제할 수 없는 v1 legacy Keychain 상태: %s", state)
	}
	if err := requireManagementConfirmation("이전이 끝난 Pasu v1 legacy Keychain 항목을 영구 삭제합니다.\n\nv2 registry와 UUID 키별 Keychain 항목은 삭제하지 않습니다."); err != nil {
		return err
	}
	payload, err := keychainReadFn("Pasu v1 legacy Keychain 삭제 확인")
	if err != nil {
		return fmt.Errorf("삭제 전 사용자 인증 실패: %w", err)
	}
	wipe(payload)
	if err := keychainDeleteFn(); err != nil {
		return err
	}
	fmt.Println("Pasu v1 legacy Keychain 항목을 삭제했습니다.")
	return nil
}

func runRemoveLegacySEWrap(keyPath, wrapPath, confPath, approvalsPath, macPath string) error {
	if err := requireKeychainState(keychainProtected); err != nil {
		return err
	}
	if _, err := os.Stat(wrapPath); err != nil {
		if os.IsNotExist(err) {
			fmt.Println("기존 sewrap이 이미 없습니다:", wrapPath)
			return nil
		}
		return err
	}
	if err := requireManagementConfirmation("기존 sewrap 파일을 영구 삭제합니다.\n\n새 Developer ID 앱이 정상 서명까지 완료된 것을 확인한 뒤에만 계속하세요.\n\n대상: " + wrapPath); err != nil {
		return err
	}
	snapshot, err := readConfigSnapshot(confPath, approvalsPath)
	if err != nil {
		return err
	}
	payload, err := keychainReadFn("기존 sewrap 제거 전 새 Keychain 검증")
	if err != nil {
		return err
	}
	defer wipe(payload)
	_, k, err := parseKeychainPayload(keyPath, payload)
	if err != nil {
		return err
	}
	if err := snapshot.verify(k, macPath); err != nil {
		return fmt.Errorf("새 Keychain과 설정 결속 검증 실패: %w", err)
	}
	if err := os.Remove(wrapPath); err != nil {
		return err
	}
	fmt.Println("기존 sewrap 삭제 완료 — 가짜 프로그램의 옛 봉인 재사용 경로가 닫혔습니다.")
	return nil
}

func productionFlagError(visited map[string]bool) error {
	var forbidden []string
	for _, name := range []string{"dir", "socket", "key", "config", "log", "passphrase-stdin"} {
		if visited[name] {
			forbidden = append(forbidden, "-"+name)
		}
	}
	if len(forbidden) > 0 {
		return fmt.Errorf("Developer ID 설치본은 보안 경로를 고정하므로 다음 옵션을 허용하지 않음: %s", strings.Join(forbidden, ", "))
	}
	return nil
}
