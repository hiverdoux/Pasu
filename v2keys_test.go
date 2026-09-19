package main

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestV2Manager(t *testing.T) (*v2KeyManager, *memoryV2Store) {
	t.Helper()
	store := newMemoryV2Store()
	reg, err := createV2Registry(store, false)
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(t.TempDir(), "pasu")
	manager, err := newV2KeyManager(base, filepath.Join(t.TempDir(), "Trash"), reg, store)
	if err != nil {
		t.Fatal(err)
	}
	return manager, store
}

func TestV2CreateCachedKeyAndLock(t *testing.T) {
	manager, store := newTestV2Manager(t)
	pass := []byte("correct horse battery staple")
	record, err := manager.create("Primary", keyAuthCached, pass)
	if err != nil {
		t.Fatal(err)
	}
	if !record.Enabled || record.AuthMode != keyAuthCached {
		t.Fatalf("record=%+v", record)
	}
	if !strings.HasSuffix(strings.TrimSpace(record.PublicKey), " pasu-Primary") {
		t.Fatalf("새 키 공개키 주석=%q", record.PublicKey)
	}
	key, ok := manager.runtime(record.ID)
	if !ok {
		t.Fatal("runtime 없음")
	}
	if key.unlocked() {
		t.Fatal("새 키가 이미 열려 있음")
	}
	before := store.reads
	signer, err := key.signerForRequest("test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Sign(rand.Reader, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if _, err := key.signerForRequest("test second"); err != nil {
		t.Fatal(err)
	}
	if store.reads != before+1 {
		t.Fatalf("cached 읽기 횟수=%d, 기대=%d", store.reads, before+1)
	}
	manager.lock(record.ID)
	if key.unlocked() {
		t.Fatal("잠금 뒤 signer가 남음")
	}
}

func TestV2PerSignNeverCaches(t *testing.T) {
	manager, store := newTestV2Manager(t)
	record, err := manager.create("Per Sign", keyAuthPerSign, []byte("another strong passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	key, _ := manager.runtime(record.ID)
	before := store.reads
	for i := 0; i < 2; i++ {
		signer, err := key.signerForRequest("per sign")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := signer.Sign(rand.Reader, []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if store.reads != before+2 || key.unlocked() {
		t.Fatalf("reads=%d before=%d unlocked=%t", store.reads, before, key.unlocked())
	}
}

func TestV2NoneNeverCachesAndUsesUnattendedSecret(t *testing.T) {
	manager, store := newTestV2Manager(t)
	record, err := manager.create("No Authentication", keyAuthNone, []byte("no authentication passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.secrets[memorySecretKey(record.ID, false)]; !ok {
		t.Fatal("인증 없음 secret이 unattended 저장소에 없음")
	}
	if _, ok := store.secrets[memorySecretKey(record.ID, true)]; !ok {
		t.Fatal("인증 없음 키의 관리 보호 secret이 없음")
	}
	key, _ := manager.runtime(record.ID)
	before := store.reads
	for i := 0; i < 2; i++ {
		if _, err := key.signerForRequest("none"); err != nil {
			t.Fatal(err)
		}
	}
	if store.reads != before+2 || key.unlocked() {
		t.Fatalf("reads=%d before=%d unlocked=%t", store.reads, before, key.unlocked())
	}
}

func TestV2AuthenticationModeTransitionMovesSecretAndClearsCache(t *testing.T) {
	manager, store := newTestV2Manager(t)
	record, err := manager.create("Transition", keyAuthCached, []byte("transition passphrase long"))
	if err != nil {
		t.Fatal(err)
	}
	key, _ := manager.runtime(record.ID)
	if _, err := key.signerForRequest("unlock before transition"); err != nil {
		t.Fatal(err)
	}
	if !key.unlocked() {
		t.Fatal("전환 전 cached 키가 열리지 않음")
	}
	if err := manager.setAuthMode(record.ID, keyAuthNone); err != nil {
		t.Fatal(err)
	}
	if key.unlocked() {
		t.Fatal("인증 없음 전환 뒤 cached signer가 남음")
	}
	if _, ok := store.secrets[memorySecretKey(record.ID, false)]; !ok {
		t.Fatal("인증 없음 secret이 없음")
	}
	if _, ok := store.secrets[memorySecretKey(record.ID, true)]; !ok {
		t.Fatal("전환 뒤 관리 보호 secret이 없음")
	}
	if err := manager.setAuthMode(record.ID, keyAuthPerSign); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.secrets[memorySecretKey(record.ID, true)]; !ok {
		t.Fatal("매번 인증 전환 뒤 protected secret이 없음")
	}
	if _, ok := store.secrets[memorySecretKey(record.ID, false)]; ok {
		t.Fatal("매번 인증 전환 뒤 unattended secret이 남음")
	}
}

func TestV2NoneManagementAuthenticationUsesProtectedSecret(t *testing.T) {
	manager, store := newTestV2Manager(t)
	record, err := manager.create("Protected Management", keyAuthNone, []byte("protected management passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	protectedBefore := store.protectedReads
	unattendedBefore := store.unattendedReads
	if err := manager.authenticate(record.ID, "management"); err != nil {
		t.Fatal(err)
	}
	if store.protectedReads != protectedBefore+1 || store.unattendedReads != unattendedBefore {
		t.Fatalf("관리 인증 reads protected=%d unattended=%d", store.protectedReads, store.unattendedReads)
	}
}

func TestV2AuthenticationModeStoreFailureKeepsOldSecret(t *testing.T) {
	manager, store := newTestV2Manager(t)
	record, err := manager.create("Atomic Mode", keyAuthCached, []byte("atomic mode passphrase long"))
	if err != nil {
		t.Fatal(err)
	}
	store.failSave = true
	if err := manager.setAuthMode(record.ID, keyAuthNone); err == nil {
		t.Fatal("registry 저장 실패인데 인증 방식 변경이 성공함")
	}
	updated, _ := manager.reg.key(record.ID)
	if updated.AuthMode != keyAuthCached {
		t.Fatalf("실패 뒤 인증 방식=%s", updated.AuthMode)
	}
	if _, ok := store.secrets[memorySecretKey(record.ID, true)]; !ok {
		t.Fatal("실패 뒤 기존 protected secret이 없음")
	}
	if _, ok := store.secrets[memorySecretKey(record.ID, false)]; ok {
		t.Fatal("실패 뒤 새 unattended secret이 남음")
	}
}

func TestV2ManagerStartupRemovesObsoleteAuthenticationSecret(t *testing.T) {
	manager, store := newTestV2Manager(t)
	record, err := manager.create("Cleanup", keyAuthCached, []byte("cleanup passphrase long"))
	if err != nil {
		t.Fatal(err)
	}
	payload := append([]byte(nil), store.secrets[memorySecretKey(record.ID, true)]...)
	store.secrets[memorySecretKey(record.ID, false)] = payload
	if _, err := newV2KeyManager(manager.baseDir, manager.trash, manager.reg, store); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.secrets[memorySecretKey(record.ID, false)]; ok {
		t.Fatal("재기동 뒤 불필요한 인증 없음 secret이 남음")
	}
}

func TestV2ManagerStartupKeepsNoneSigningAndManagementSecrets(t *testing.T) {
	manager, store := newTestV2Manager(t)
	record, err := manager.create("None Restart", keyAuthNone, []byte("none restart passphrase long"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newV2KeyManager(manager.baseDir, manager.trash, manager.reg, store); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.secrets[memorySecretKey(record.ID, true)]; !ok {
		t.Fatal("재기동 뒤 관리 보호 secret이 없음")
	}
	if _, ok := store.secrets[memorySecretKey(record.ID, false)]; !ok {
		t.Fatal("재기동 뒤 인증 없음 서명 secret이 없음")
	}
}

func TestV2DuplicateNameRejected(t *testing.T) {
	manager, _ := newTestV2Manager(t)
	if _, err := manager.create("Same", keyAuthCached, []byte("passphrase one long")); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.create("same", keyAuthCached, []byte("passphrase two long")); err == nil {
		t.Fatal("대소문자만 다른 중복 이름을 허용함")
	}
}

func TestV2RenameUpdatesRegistryAndPublicKeyComment(t *testing.T) {
	manager, _ := newTestV2Manager(t)
	record, err := manager.create("Before", keyAuthCached, []byte("rename passphrase long"))
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.rename(record.ID, "After"); err != nil {
		t.Fatal(err)
	}
	updated, ok := manager.reg.key(record.ID)
	if !ok || updated.Name != "After" || updated.Fingerprint != record.Fingerprint ||
		!strings.HasSuffix(strings.TrimSpace(updated.PublicKey), " pasu-After") {
		t.Fatalf("registry rename=%+v ok=%t", updated, ok)
	}
	data, err := os.ReadFile(filepath.Join(manager.keysDir, record.ID, "key.pub"))
	if err != nil || !strings.HasSuffix(strings.TrimSpace(string(data)), " pasu-After") {
		t.Fatalf("key.pub rename err=%v data=%q", err, data)
	}
}

func TestV2RenameStoreFailureRollsBackPublicKeyComment(t *testing.T) {
	manager, store := newTestV2Manager(t)
	record, err := manager.create("Before", keyAuthCached, []byte("rename rollback passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	store.failSave = true
	if err := manager.rename(record.ID, "After"); err == nil {
		t.Fatal("registry 저장 실패인데 이름 변경이 성공함")
	}
	updated, _ := manager.reg.key(record.ID)
	data, err := os.ReadFile(filepath.Join(manager.keysDir, record.ID, "key.pub"))
	if err != nil || updated.Name != "Before" || !strings.HasSuffix(strings.TrimSpace(string(data)), " pasu-Before") {
		t.Fatalf("rename rollback record=%+v err=%v data=%q", updated, err, data)
	}
}

func TestV2ManagerStartupRepairsPublicKeyCommentFromRegistry(t *testing.T) {
	manager, store := newTestV2Manager(t)
	record, err := manager.create("Registry Name", keyAuthCached, []byte("comment repair passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(manager.keysDir, record.ID, "key.pub")
	wrong := managedPublicKeyLine(manager.keys[record.ID].PublicKey(), "Interrupted Rename")
	if err := os.WriteFile(pubPath, []byte(wrong), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newV2KeyManager(manager.baseDir, manager.trash, manager.reg, store); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(pubPath)
	if err != nil || string(data) != record.PublicKey {
		t.Fatalf("key.pub 주석 복구 err=%v data=%q", err, data)
	}
}

func TestV2ManagerAcceptsUnprefixedV21PublicKeyComment(t *testing.T) {
	manager, store := newTestV2Manager(t)
	record, err := manager.create("Existing", keyAuthCached, []byte("existing v2.1 passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	legacyLine := canonicalPublicKeyLine(manager.keys[record.ID].PublicKey(), record.Name)
	if err := manager.reg.mutate(func(data *v2RegistryData) error {
		for i := range data.Keys {
			if data.Keys[i].ID == record.ID {
				data.Keys[i].PublicKey = legacyLine
				return nil
			}
		}
		return errors.New("테스트 키 없음")
	}); err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(manager.keysDir, record.ID, "key.pub")
	if err := os.WriteFile(pubPath, []byte(legacyLine), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newV2KeyManager(manager.baseDir, manager.trash, manager.reg, store); err != nil {
		t.Fatalf("v2.1 공개키 주석을 읽지 못함: %v", err)
	}
	data, err := os.ReadFile(pubPath)
	if err != nil || string(data) != legacyLine {
		t.Fatalf("v2.1 공개키 주석이 바뀜: err=%v data=%q", err, data)
	}
}

func TestV2DeleteMovesEncryptedFilesToTrash(t *testing.T) {
	manager, store := newTestV2Manager(t)
	record, err := manager.create("Disposable", keyAuthCached, []byte("disposable passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	target, err := manager.delete(record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(target, "key")); err != nil {
		t.Fatalf("휴지통 개인키 없음: %v", err)
	}
	if _, ok := store.secrets[memorySecretKey(record.ID, true)]; ok {
		t.Fatal("삭제 뒤 protected secret이 남음")
	}
	if _, ok := store.secrets[memorySecretKey(record.ID, false)]; ok {
		t.Fatal("삭제 뒤 unattended secret이 남음")
	}
	if _, ok := manager.runtime(record.ID); ok {
		t.Fatal("삭제 뒤 runtime이 남음")
	}
}

func TestV2SecretFingerprintMismatchFailsClosed(t *testing.T) {
	manager, store := newTestV2Manager(t)
	record, err := manager.create("Mismatch", keyAuthCached, []byte("mismatch passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := encodeV2Secret(record.ID, "SHA256:not-the-key", []byte("mismatch passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.secrets[memorySecretKey(record.ID, true)] = payload
	store.mu.Unlock()
	key, _ := manager.runtime(record.ID)
	if _, err := key.signerForRequest("mismatch"); err == nil {
		t.Fatal("Keychain 지문 불일치인데 signer를 반환함")
	}
}

func TestV2KeyLoaderRejectsSymlink(t *testing.T) {
	manager, _ := newTestV2Manager(t)
	record, err := manager.create("Symlink", keyAuthCached, []byte("symlink passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(manager.keysDir, record.ID, "key.pub")
	target := filepath.Join(t.TempDir(), "outside.pub")
	data, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(pubPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, pubPath); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.loadRuntime(record); err == nil {
		t.Fatal("symlink key.pub을 허용함")
	}
}
