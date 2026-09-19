package main

import (
	"errors"
	"strings"
	"testing"
)

func TestRegistryProbeDistinguishesInaccessibleFromMissing(t *testing.T) {
	err := keychainV2RegistryProbeError(errSecInteractionNotAllowed)
	if err == nil || errors.Is(err, errV2RegistryMissing) {
		t.Fatalf("inaccessible registry treated as missing or readable: %v", err)
	}
	for _, want := range []string{"-25308", "화면 잠금을 해제"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing actionable diagnosis %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "userPresence") {
		t.Fatalf("diagnosis assumes an unverified protection setting: %v", err)
	}
	if err := keychainV2RegistryProbeError(errSecSuccess); err != nil {
		t.Fatalf("readable registry rejected: %v", err)
	}
	if err := keychainV2RegistryProbeError(errSecItemNotFound); !errors.Is(err, errV2RegistryMissing) {
		t.Fatalf("missing registry not distinguished: %v", err)
	}
	for _, status := range []int32{errSecMissingEntitlement, -25291} {
		if err := keychainV2RegistryProbeError(status); err == nil || errors.Is(err, errV2RegistryMissing) {
			t.Fatalf("Keychain failure %d could initialize a replacement registry: %v", status, err)
		}
	}
}
