package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestV2MissingRegistryNeverReplacesExistingKeys(t *testing.T) {
	dir := t.TempDir()
	if err := guardMissingRegistry(dir); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(dir, "keys")
	if err := os.Mkdir(keys, 0700); err != nil {
		t.Fatal(err)
	}
	if err := guardMissingRegistry(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(keys, "sample-key"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := guardMissingRegistry(dir); err == nil {
		t.Fatal("existing keys allowed empty registry creation")
	}
}

func TestV2GroupModesRejectCombinationsBeforeKeychain(t *testing.T) {
	for _, args := range [][]string{
		{"-migrate-keychain-group", "-rollback-keychain-group"},
		{"-service", "-migrate-keychain-group"},
		{"-check", "-keychain-group-status"},
		{"-service", "-launchd-uid", "501"},
	} {
		if err := runV2(args); err == nil || !strings.Contains(err.Error(), "한 번에 하나") {
			t.Fatalf("%v: %v", args, err)
		}
	}
}

func TestV2MigrationVerificationAuthenticatesWithoutCachingOrEditing(t *testing.T) {
	m, store := newTestV2Manager(t)
	record, err := m.create("sample", keyAuthNone, []byte("sample migration passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	key, _ := m.runtime(record.ID)
	before, err := os.ReadFile(key.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	baseDir := m.baseDir
	for _, presence := range []bool{true, false} {
		if err := verifyOneMigratedSecret(baseDir, store, record, presence); err != nil {
			t.Fatal(err)
		}
	}
	if key.unlocked() {
		t.Fatal("verification populated signer cache")
	}
	after, err := os.ReadFile(key.keyPath)
	if err != nil || string(before) != string(after) {
		t.Fatal("verification changed key file")
	}
	bad := record
	bad.Fingerprint = "SHA256:sample-invalid"
	if err := verifyOneMigratedSecret(baseDir, store, bad, true); err == nil {
		t.Fatal("mismatched registry accepted")
	}
}
