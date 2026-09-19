package main

/*
#include <stdint.h>
int32_t pasuKCGroupBridgeEnabled(void);
int32_t pasuKCGroupCounts(int32_t *oldCount, int32_t *newCount, char *errBuf, int32_t errLen);
int32_t pasuKCMoveGroup(int32_t reverse, char *errBuf, int32_t errLen);
int32_t pasuKCVerifyOldGroup(char *errBuf, int32_t errLen);
*/
import "C"

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/crypto/ssh"
)

func keychainGroupCounts() (int, int, error) {
	var oldCount, newCount C.int32_t
	buf := keychainErrorBuffer()
	if C.pasuKCGroupCounts(&oldCount, &newCount, (*C.char)(unsafe.Pointer(&buf[0])), C.int32_t(len(buf))) != 0 {
		return 0, 0, errors.New(cErrString(buf))
	}
	return int(oldCount), int(newCount), nil
}

func keychainBuildMode() string {
	if C.pasuKCGroupBridgeEnabled() != 0 {
		return "migration"
	}
	return "final"
}

func verifyOldGroupAccess() error {
	buf := keychainErrorBuffer()
	if C.pasuKCVerifyOldGroup((*C.char)(unsafe.Pointer(&buf[0])), C.int32_t(len(buf))) != 0 {
		return errors.New(cErrString(buf))
	}
	fmt.Println("KEYCHAIN-OLD-ACCESS verified (비밀 출력·변경 없음)")
	return nil
}

func runKeychainGroupMove(baseDir string, reverse bool) error {
	if C.pasuKCGroupBridgeEnabled() == 0 {
		return errors.New("그룹 이전은 migration 서명본으로만 실행할 수 있음")
	}
	home, err := resolveHomeDir(true)
	if err != nil {
		return err
	}
	lock, err := acquireStoppedAgentLock(filepath.Join(pasuRuntimeDirectory(home), "agent.sock"), "키체인 그룹 이전")
	if err != nil {
		return err
	}
	defer releaseInstanceLock(lock)
	buf := keychainErrorBuffer()
	direction := C.int32_t(0)
	if reverse {
		direction = 1
	}
	if C.pasuKCMoveGroup(direction, (*C.char)(unsafe.Pointer(&buf[0])), C.int32_t(len(buf))) != 0 {
		return errors.New(cErrString(buf))
	}
	fmt.Printf("KEYCHAIN-GROUP move verified reverse=%t\n", reverse)
	return nil
}

// A final build must never create an empty registry over an existing key store
// merely because its new access group has not been migrated yet.
func guardMissingRegistry(baseDir string) error {
	entries, err := os.ReadDir(filepath.Join(baseDir, "keys"))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(entries) > 0 {
		return errors.New("기존 키 파일이 있지만 새 그룹 registry가 없음: 먼저 키체인 그룹 이전을 완료하세요")
	}
	return nil
}

func guardKeychainBridge() error {
	if C.pasuKCGroupBridgeEnabled() == 0 {
		return nil
	}
	return errors.New("migration 서명본은 그룹 조회·이전·복원 전용입니다. SSH 서비스는 final 서명본으로 실행하세요")
}

// Authenticated read/decrypt verification only; no SSH signature, cache,
// registry changes or public-key repairs. Run while the service is stopped.
func verifyMigratedSecrets(baseDir string) error {
	home, err := resolveHomeDir(true)
	if err != nil {
		return err
	}
	lock, err := acquireStoppedAgentLock(filepath.Join(pasuRuntimeDirectory(home), "agent.sock"), "키체인 이전 검증")
	if err != nil {
		return err
	}
	defer releaseInstanceLock(lock)
	store := keychainV2Store{}
	if _, err := checkV2Configuration(baseDir, store); err != nil {
		return err
	}
	registry, err := loadV2Registry(store)
	if err != nil {
		return err
	}
	for _, record := range registry.keys() {
		modes := []bool{true}
		if record.AuthMode == keyAuthNone {
			modes = append(modes, false)
		}
		for _, presence := range modes {
			if err := verifyOneMigratedSecret(baseDir, store, record, presence); err != nil {
				return err
			}
		}
	}
	fmt.Printf("KEYCHAIN-VERIFY ok keys=%d (인증·복호화·지문 확인, 서명 없음)\n", len(registry.keys()))
	return nil
}

func verifyOneMigratedSecret(baseDir string, store v2Store, record managedKeyRecord, presence bool) error {
	payload, err := store.ReadSecret(record.ID, "Pasu 키체인 이전 검증: "+record.Name, presence)
	if err != nil {
		return err
	}
	defer wipe(payload)
	if err := validateSecretIdentity(record, payload); err != nil {
		return err
	}
	_, _, passphrase, err := decodeV2Secret(payload)
	if err != nil {
		return err
	}
	defer wipe(passphrase)
	data, err := readEncryptedKey(filepath.Join(baseDir, "keys", record.ID, "key"))
	if err != nil {
		return err
	}
	signer, err := ssh.ParsePrivateKeyWithPassphrase(data, passphrase)
	if err != nil {
		return err
	}
	pub, err := loadPublicKey(filepath.Join(baseDir, "keys", record.ID, "key.pub"))
	if err != nil {
		return err
	}
	if ssh.FingerprintSHA256(signer.PublicKey()) != record.Fingerprint || !bytes.Equal(pub.Marshal(), signer.PublicKey().Marshal()) {
		return errors.New("이전 검증: 개인키·공개키·registry 지문 불일치")
	}
	return nil
}
