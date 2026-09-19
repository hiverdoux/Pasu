package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func legacyV1Present(baseDir string) bool {
	for _, name := range []string{"key", "key.pub", "pasu.conf"} {
		info, err := os.Lstat(filepath.Join(baseDir, name))
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
	}
	return true
}

func applyLegacySafeSettings(registry *v2Registry, legacy *allowlist) error {
	if legacy == nil {
		return nil
	}
	return registry.mutate(func(data *v2RegistryData) error {
		if legacy.limit != nil {
			data.Settings.RateCount = legacy.limit.max
			data.Settings.RateWindow = legacy.limit.window
		}
		if legacy.logSize != nil {
			data.Settings.LogSize = int64(*legacy.logSize)
		}
		if legacy.askCooldown != nil {
			data.Settings.AskCooldown = *legacy.askCooldown
		}
		if legacy.notifyCooldown != nil {
			data.Settings.NotifyCooldown = *legacy.notifyCooldown
		}
		return nil
	})
}

func migrateV1ToV2(baseDir string, manager *v2KeyManager, registry *v2Registry) error {
	if !registry.snapshot().MigrationPending {
		return nil
	}
	if !legacyV1Present(baseDir) {
		return errors.New("v1 이전 파일이 완전하지 않음")
	}
	payload, err := keychainReadFn("Pasu v2 이전: 기존 단일 키 잠금 해제")
	if err != nil {
		return err
	}
	defer wipe(payload)
	passphrase, bindKey, err := parseKeychainPayload(filepath.Join(baseDir, "key"), payload)
	if err != nil {
		return err
	}
	snapshot, err := readConfigSnapshot(filepath.Join(baseDir, "pasu.conf"), filepath.Join(baseDir, "approvals.conf"))
	if err != nil {
		return err
	}
	if err := snapshot.verify(bindKey, filepath.Join(baseDir, "conf.hmac")); err != nil {
		return fmt.Errorf("v1 설정 결속 검증 실패: %w", err)
	}
	legacy, err := parseAllowlist(bytes.NewReader(snapshot.conf), filepath.Dir(baseDir))
	if err != nil {
		return fmt.Errorf("v1 안전 설정 해석 실패: %w", err)
	}
	if err := applyLegacySafeSettings(registry, legacy); err != nil {
		return err
	}
	if _, err := manager.importLegacy("기존 Pasu 키", filepath.Join(baseDir, "key"), filepath.Join(baseDir, "key.pub"), passphrase); err != nil {
		return fmt.Errorf("v1 키 복사 실패: %w", err)
	}
	if err := registry.setMigrationPending(false); err != nil {
		return fmt.Errorf("v1 키는 복사됐지만 이전 완료 기록 실패: %w", err)
	}
	return nil
}
