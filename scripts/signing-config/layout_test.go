package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func layoutShell(t *testing.T, root, body string) ([]byte, error) {
	t.Helper()
	code := `set -euo pipefail
source "$1/scripts/signing-common.sh"
source "$1/scripts/data-layout.sh"
CURRENT_UID=$(id -u)
root="$2"
` + body
	return exec.Command("/bin/zsh", "-c", code, "layout-test", repository(t), root).CombinedOutput()
}

func TestLayoutMoveResumeRollbackAndOtherProfiles(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(root, "keys/sample/key"), "encrypted sample", 0600)
	writeFixture(t, filepath.Join(root, "pasu.log"), "old log", 0600)
	other := filepath.Join(root, "profiles/ZZZZZ12345.org.example.other/keys/sample/key")
	writeFixture(t, other, "other developer", 0600)
	// Simulate interruption after only one of two entries has moved.
	target := filepath.Join(root, "profiles/ABCDE12345.org.example.pasu")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(root, "keys"), filepath.Join(target, "keys")); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(root, ".legacy-layout"), "ABCDE12345.org.example.pasu\nkeys\npasu.log\n", 0600)
	out, err := layoutShell(t, root, `move_legacy_data "$root" ABCDE12345 org.example.pasu`)
	if err != nil {
		t.Fatalf("resume: %v %s", err, out)
	}
	writeFixture(t, filepath.Join(target, "new-file"), "created after upgrade", 0600)
	out, err = layoutShell(t, root, `restore_legacy_data "$root"`)
	if err != nil {
		t.Fatalf("rollback: %v %s", err, out)
	}
	for name, want := range map[string]string{"keys/sample/key": "encrypted sample", "pasu.log": "old log", "new-file": "created after upgrade", "profiles/ZZZZZ12345.org.example.other/keys/sample/key": "other developer"} {
		got, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || string(got) != want {
			t.Fatalf("%s: %q %v", name, got, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, ".legacy-layout")); !os.IsNotExist(err) {
		t.Fatal("journal not removed", err)
	}
}

func TestLayoutRefusesMergeAndSymlinksWithoutMovingData(t *testing.T) {
	for _, kind := range []string{"existing-profile", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			writeFixture(t, filepath.Join(root, "keys/sample/key"), "preserve", 0600)
			if kind == "existing-profile" {
				writeFixture(t, filepath.Join(root, "profiles/ABCDE12345.org.example.pasu/sample"), "other", 0600)
			} else {
				if err := os.Symlink(t.TempDir(), filepath.Join(root, "linked")); err != nil {
					t.Fatal(err)
				}
			}
			out, err := layoutShell(t, root, `move_legacy_data "$root" ABCDE12345 org.example.pasu`)
			if err == nil {
				t.Fatalf("unsafe move: %s", out)
			}
			got, _ := os.ReadFile(filepath.Join(root, "keys/sample/key"))
			if string(got) != "preserve" {
				t.Fatal("data changed")
			}
		})
	}
}

func TestLayoutRejectsJournalTraversal(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(root, ".legacy-layout"), "ABCDE12345.org.example.pasu\n../outside\n", 0600)
	_, err := layoutShell(t, root, `restore_legacy_data "$root"`)
	if err == nil {
		t.Fatal("accepted journal traversal")
	}
}

func TestFinderMetadataDoesNotCountAsLegacyData(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(root, ".DS_Store"), "Finder settings", 0600)
	out, err := layoutShell(t, root, `legacy_data_entries "$root"
(( ${#LAYOUT_ENTRIES} == 0 ))
move_legacy_data "$root" ABCDE12345 org.example.pasu
[[ ! -e "$root/.legacy-layout" && ! -e "$root/profiles" ]]`)
	if err != nil {
		t.Fatalf("metadata mistaken for legacy data: %v %s", err, out)
	}
}

func TestFinderMetadataDuringLayoutRecovery(t *testing.T) {
	for _, oldJournal := range []bool{false, true} {
		for _, action := range []string{"restore_legacy_data", "finalize_data_layout"} {
			name := action + "/new-journal"
			if oldJournal {
				name = action + "/old-journal"
			}
			t.Run(name, func(t *testing.T) {
				root := t.TempDir()
				if err := os.Chmod(root, 0700); err != nil {
					t.Fatal(err)
				}
				writeFixture(t, filepath.Join(root, "keys/sample/key"), "preserve key", 0600)
				writeFixture(t, filepath.Join(root, ".DS_Store"), "root settings", 0600)
				out, err := layoutShell(t, root, `move_legacy_data "$root" ABCDE12345 org.example.pasu`)
				if err != nil {
					t.Fatalf("move: %v %s", err, out)
				}
				target := filepath.Join(root, "profiles/ABCDE12345.org.example.pasu")
				if oldJournal {
					writeFixture(t, filepath.Join(root, ".legacy-layout"), "ABCDE12345.org.example.pasu\n.DS_Store\nkeys\n", 0600)
					// Resume an older journal even if its recorded Finder metadata is absent.
					if err := os.Remove(filepath.Join(root, ".DS_Store")); err != nil {
						t.Fatal(err)
					}
					out, err = layoutShell(t, root, `move_legacy_data "$root" ABCDE12345 org.example.pasu`)
					if err != nil {
						t.Fatalf("resume old journal: %v %s", err, out)
					}
				}
				writeFixture(t, filepath.Join(root, ".DS_Store"), "new root settings", 0600)
				writeFixture(t, filepath.Join(target, ".DS_Store"), "new profile settings", 0600)
				out, err = layoutShell(t, root, action+` "$root"`)
				if err != nil {
					t.Fatalf("recovery: %v %s", err, out)
				}
				keyRoot := target
				if action == "restore_legacy_data" {
					keyRoot = root
					if _, err := os.Stat(target); !os.IsNotExist(err) {
						t.Fatalf("restored profile still blocks later migration: %v", err)
					}
				}
				for path, want := range map[string]string{
					filepath.Join(keyRoot, "keys/sample/key"): "preserve key",
					filepath.Join(root, ".DS_Store"):          "new root settings",
				} {
					got, err := os.ReadFile(path)
					if err != nil || string(got) != want {
						t.Fatalf("preservation: %s %q %v", path, got, err)
					}
				}
				if _, err := os.Stat(filepath.Join(root, ".legacy-layout")); !os.IsNotExist(err) {
					t.Fatalf("journal remains: %v", err)
				}
			})
		}
	}
}

func TestFinderMetadataDoesNotHideUnsafeFilesOrRealCollisions(t *testing.T) {
	for _, kind := range []string{"metadata-link", "metadata-directory", "key-collision"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			writeFixture(t, filepath.Join(root, "keys/sample/key"), "preserve key", 0600)
			out, err := layoutShell(t, root, `move_legacy_data "$root" ABCDE12345 org.example.pasu`)
			if err != nil {
				t.Fatalf("move: %v %s", err, out)
			}
			target := filepath.Join(root, "profiles/ABCDE12345.org.example.pasu")
			switch kind {
			case "metadata-link":
				if err := os.Symlink(filepath.Join(target, "keys/sample/key"), filepath.Join(target, ".DS_Store")); err != nil {
					t.Fatal(err)
				}
			case "metadata-directory":
				writeFixture(t, filepath.Join(target, ".DS_Store/preserve"), "unexpected data", 0600)
			case "key-collision":
				writeFixture(t, filepath.Join(root, "keys/sample/key"), "conflicting key", 0600)
			}
			out, err = layoutShell(t, root, `restore_legacy_data "$root"`)
			if err == nil {
				t.Fatalf("accepted unsafe recovery: %s", out)
			}
			got, err := os.ReadFile(filepath.Join(target, "keys/sample/key"))
			if err != nil || string(got) != "preserve key" {
				t.Fatalf("key changed: %q %v", got, err)
			}
		})
	}
}

func TestCleanupOnlyRemovesUncommittedStage(t *testing.T) {
	f := newInstallerFixture(t)
	stage := filepath.Join(f.root, "installed/Pasu.app.new")
	writeFixture(t, filepath.Join(stage, "partial"), "partial app", 0600)
	writeFixture(t, filepath.Join(f.root, "home/.ssh/pasu/profiles/ABCDE12345.org.example.pasu/keys/sample/key"), "preserve", 0600)
	out, rc := f.run(true, nil, "cleanup")
	if rc != 0 {
		t.Fatalf("cleanup %d %s", rc, out)
	}
	if _, err := os.Stat(stage); !os.IsNotExist(err) {
		t.Fatal("stage remains", err)
	}
	writeFixture(t, filepath.Join(stage, "partial"), "partial app", 0600)
	writeFixture(t, filepath.Join(f.root, "installed/Pasu.app.rollback/backup"), "last app", 0600)
	out, rc = f.run(true, nil, "cleanup")
	if rc == 0 || !strings.Contains(string(out), "rollback/finalize") {
		t.Fatalf("discarded backup context: %d %s", rc, out)
	}
	if _, err := os.Stat(stage); err != nil {
		t.Fatal("deleted recoverable stage", err)
	}
}
