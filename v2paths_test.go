package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProductionDataLayoutAndSharedRuntime(t *testing.T) {
	home := t.TempDir()
	if err := preparePasuDirectories(home); err != nil {
		t.Fatal(err)
	}
	if pasuRuntimeDirectory(home) != filepath.Join(home, ".ssh/pasu") {
		t.Fatal("SSH socket root changed")
	}
	if pasuDataDirectory(home) != filepath.Join(home, ".ssh/pasu/profiles", pasuTeamID+"."+pasuGUIIdentifier) {
		t.Fatal("data identity changed")
	}
	for _, path := range []string{pasuRuntimeDirectory(home), filepath.Join(pasuRuntimeDirectory(home), "profiles"), pasuDataDirectory(home)} {
		if err := requireOwnedDir(path); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDataDirectoryRejectsSymlink(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh/pasu"), 0700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(home, ".ssh/pasu/profiles")); err != nil {
		t.Fatal(err)
	}
	if err := preparePasuDirectories(home); err == nil {
		t.Fatal("accepted linked profile root")
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatalf("wrote outside data root: %v %v", entries, err)
	}
}

func TestDataDirectoryRejectsUnsafePermissionsWithoutChangingThem(t *testing.T) {
	for _, relative := range []string{".ssh/pasu", ".ssh/pasu/profiles", ".ssh/pasu/profiles/" + pasuTeamID + "." + pasuGUIIdentifier} {
		t.Run(relative, func(t *testing.T) {
			home := t.TempDir()
			if err := preparePasuDirectories(home); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(home, relative)
			if err := os.Chmod(path, 0755); err != nil {
				t.Fatal(err)
			}
			if err := preparePasuDirectories(home); err == nil {
				t.Fatal("accepted an accessible data directory")
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0755 {
				t.Fatalf("silently changed existing permissions: %v %v", info, err)
			}
		})
	}
}
