package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestMigrateV1CopiesAndLeavesLegacyFiles(t *testing.T) {
	base := filepath.Join(t.TempDir(), "pasu")
	if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatal(err)
	}
	pass := []byte("legacy strong passphrase")
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(private, "legacy", pass)
	if err != nil {
		t.Fatal(err)
	}
	keyData := pem.EncodeToMemory(block)
	if err := os.WriteFile(filepath.Join(base, "key"), keyData, 0o600); err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(private)
	if err := os.WriteFile(filepath.Join(base, "key.pub"), ssh.MarshalAuthorizedKey(signer.PublicKey()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "pasu.conf"), []byte("ask on\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bindKey := make([]byte, bindKeyLen)
	snapshot, err := readConfigSnapshot(filepath.Join(base, "pasu.conf"), filepath.Join(base, "approvals.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshot.record(bindKey, filepath.Join(base, "conf.hmac"), "test-v1"); err != nil {
		t.Fatal(err)
	}
	store := newMemoryV2Store()
	registry, err := createV2Registry(store, true)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := newV2KeyManager(base, filepath.Join(t.TempDir(), "Trash"), registry, store)
	if err != nil {
		t.Fatal(err)
	}
	oldRead := keychainReadFn
	defer func() { keychainReadFn = oldRead }()
	payload := append(append([]byte(nil), pass...), bindKey...)
	keychainReadFn = func(string) ([]byte, error) { return append([]byte(nil), payload...), nil }
	if err := migrateV1ToV2(base, manager, registry); err != nil {
		t.Fatal(err)
	}
	if registry.snapshot().MigrationPending || len(registry.keys()) != 1 {
		t.Fatalf("registry=%+v", registry.snapshot())
	}
	if _, err := os.Stat(filepath.Join(base, "key")); err != nil {
		t.Fatalf("v1 개인키가 제거됨: %v", err)
	}
	if _, err := os.Stat(filepath.Join(base, "keys", registry.keys()[0].ID, "key")); err != nil {
		t.Fatalf("v2 복사본 없음: %v", err)
	}
}
