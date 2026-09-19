package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

// checkConfiguration은 기동에 필요한 정적 파일만 읽어 검사한다. 개인키
// passphrase 일치와 conf.hmac 진위는 Touch ID/사람 입력 없이는 확인할 수
// 없으므로 정상 첫 해제 경로에 남긴다. 파일·소켓·로그를 만들지 않는다.
func checkConfiguration(home, keyPath, wrapPath, confPath, macPath string, kcState keychainState) (string, error) {
	confData, err := os.ReadFile(confPath)
	if err != nil {
		return "", fmt.Errorf("설정 로드 실패: %w", err)
	}
	rules, err := parseAllowlist(strings.NewReader(string(confData)), home)
	if err != nil {
		return "", fmt.Errorf("설정 로드 실패: %w", err)
	}
	if _, err := readEncryptedKey(keyPath); err != nil {
		return "", err
	}

	wrapDesc := "off"
	bindDesc := "off"
	keychainDesc := kcState.String()
	needPublic := false
	if kcState != keychainUnavailable {
		switch kcState {
		case keychainProtected:
			needPublic = true
			if err := checkConfMACFormat(macPath); err != nil {
				return "", err
			}
			bindDesc = "deferred"
			if _, err := os.Stat(wrapPath); err == nil {
				wrapDesc = "legacy-present"
			} else if !os.IsNotExist(err) {
				return "", fmt.Errorf("기존 sewrap 상태 검사 실패: %w", err)
			}
		case keychainMissing:
			return "", fmt.Errorf("앱 전용 Keychain 항목 없음 — -setup-touchid 또는 -migrate-keychain 필요")
		case keychainUnprotected:
			return "", fmt.Errorf("앱 전용 Keychain 항목에 userPresence가 없음")
		}
	} else {
		w, err := readSEWrap(wrapPath)
		switch {
		case err == nil:
			needPublic = true
			wrapDesc = fmt.Sprintf("v%d", w.V)
			if w.V >= sewrapV2 {
				if err := checkConfMACFormat(macPath); err != nil {
					return "", err
				}
				bindDesc = "deferred"
			} else {
				bindDesc = "upgrade"
			}
		case os.IsNotExist(err):
			// ad-hoc 터미널 모드 — sewrap과 설정 결속 없음.
		default:
			return "", fmt.Errorf("Touch ID 설정 읽기 실패 — -setup-touchid 재실행 또는 -remove-touchid: %w", err)
		}
	}
	pubDesc := "not-required"
	if needPublic {
		pub, err := loadPublicKey(keyPath + ".pub")
		if err != nil {
			return "", fmt.Errorf("공개키 검사 실패: %w", err)
		}
		pubDesc = ssh.FingerprintSHA256(pub)
	}

	return fmt.Sprintf("CHECK ok rules=%d key=encrypted key-pub=%s keychain=%s sewrap=%s bind=%s ask=%t ask-cooldown=%s notify-cooldown=%s",
		len(rules.rules), pubDesc, keychainDesc, wrapDesc, bindDesc, rules.ask,
		durationDesc(rules.askCooldown), durationDesc(rules.notifyCooldown)), nil
}

func checkConfMACFormat(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("설정 결속 지문 검사 실패: %w", err)
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(b) != sha256.Size {
		return fmt.Errorf("설정 결속 지문 검사 실패: %s 형식 오류", path)
	}
	return nil
}
