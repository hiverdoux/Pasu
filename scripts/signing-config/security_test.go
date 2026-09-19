package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuntimeFlagCannotBeSuppliedByPathsOrNames(t *testing.T) {
	for _, tc := range []struct {
		text string
		ok   bool
	}{
		{"Executable=/tmp/runtime/Pasu\nCodeDirectory flags=0x0(none)", false},
		{"Authority=Developer ID Application: runtime\nCodeDirectory flags=0x0(none)", false},
		{"CodeDirectory v=20500 size=123 flags=0x10000(runtime) hashes=3", true},
		{"CodeDirectory v=20500 size=123 flags=0x10002(adhoc,runtime) hashes=3", true},
		{"CodeDirectory flags=0x20000(runtime)", false},
	} {
		out, err := shellCheck(t, `has_hardened_runtime "$1"`, tc.text)
		if (err == nil) != tc.ok {
			t.Errorf("%q: %v %s", tc.text, err, out)
		}
	}
}

func TestCertificateSelectionDeduplicatesFingerprints(t *testing.T) {
	sha := strings.Repeat("A", 40)
	inventory := "  1) " + sha + " \"Developer ID Application: Example (ABCDE12345)\"\n  2) " + strings.ToLower(sha) + " \"Developer ID Application: Example (ABCDE12345)\""
	for _, request := range []string{"", sha, "Developer ID Application: Example (ABCDE12345)"} {
		out, err := shellCheck(t, `select_pasu_identity ABCDE12345 "$1" "$2"`, request, inventory)
		if err != nil || strings.TrimSpace(string(out)) != sha {
			t.Fatalf("duplicate: %v %s", err, out)
		}
	}
	out, err := shellCheck(t, `select_pasu_identity ABCDE12345 missing "$1"`, inventory)
	if err == nil || !strings.Contains(string(out), "없습니다") {
		t.Fatalf("missing identity diagnostic: %v %s", err, out)
	}
}

func TestDeveloperRequirementContainsAllTrustConstraints(t *testing.T) {
	out, err := shellCheck(t, `developer_requirement ABCDE12345 org.example.pasu`)
	want := `anchor apple generic and identifier "org.example.pasu" and certificate 1[field.1.2.840.113635.100.6.2.6] and certificate leaf[field.1.2.840.113635.100.6.1.13] and certificate leaf[subject.OU] = "ABCDE12345"`
	if err != nil || strings.TrimSpace(string(out)) != want {
		t.Fatalf("requirement changed: %v %s", err, out)
	}
}

func TestServiceTemplateUsesSemanticCompatibility(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repository(t), "packaging/PasuAgent.plist"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "service.plist")
	for _, tc := range []struct {
		name, from, to string
		ok             bool
	}{
		{"formatting", "<key>", "\n  <key>", true},
		{"process-type", "Interactive", "Background", true},
		{"program", "Contents/Library/LoginItems/PasuAgent.app/Contents/MacOS/pasu", "/tmp/example", false},
		{"label", "PASU_AGENT_ID", "org.example.other.agent", false},
		{"extra-args", "<string>-service</string>", "<string>-service</string><string>-dir</string>", false},
	} {
		text := strings.ReplaceAll(string(b), tc.from, tc.to)
		text = strings.ReplaceAll(text, "PASU_AGENT_ID", "org.example.pasu.agent")
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		out, err := shellCheck(t, `assert_service_plist "$1" org.example.pasu.agent`, path)
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v %s", tc.name, err, out)
		}
	}
}

func TestBuildConfigPriorityAndRelativePaths(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, filepath.Join(root, "packaging/signing.json"), `{"team_id":"ABCDE12345","bundle_id":"org.example.default"}`, 0600)
	check := func(explicit, profile, want string) config {
		t.Helper()
		c, err := loadBuildConfig(root, explicit, "", profile, "")
		if err != nil || c.BundleID != want {
			t.Fatalf("load %s: %+v %v", explicit, c, err)
		}
		return c
	}
	check("", "", "org.example.default")
	writeFixture(t, filepath.Join(root, "signing.local.json"), `{"team_id":"ABCDE12345","bundle_id":"org.example.local"}`, 0600)
	check("", "", "org.example.local")
	explicit := filepath.Join(root, "settings/custom.json")
	writeFixture(t, explicit, `{"team_id":"ABCDE12345","bundle_id":"org.example.explicit","profile":"sample.provisionprofile"}`, 0600)
	c := check(explicit, "", "org.example.explicit")
	if c.Profile != filepath.Join(root, "settings/sample.provisionprofile") {
		t.Fatal(c.Profile)
	}
	c = check(explicit, "override.provisionprofile", "org.example.explicit")
	absolute, _ := filepath.Abs("override.provisionprofile")
	if c.Profile != absolute {
		t.Fatal(c.Profile)
	}
	if _, err := loadBuildConfig(root, explicit+".missing", "", "", ""); err == nil {
		t.Fatal("missing explicit config fell back")
	}
}

func TestMissingAppHasActionableDiagnostic(t *testing.T) {
	out, err := shellCheck(t, `load_app_identity "$1" "$2"`, filepath.Join(t.TempDir(), "missing.app"), filepath.Join(repository(t), "packaging/signing.json"))
	if err == nil || !strings.Contains(string(out), "앱을 찾을 수 없습니다") {
		t.Fatalf("missing app: %v %s", err, out)
	}
}

func TestAgentLaunchFailureIsNotReportedAsModeMismatch(t *testing.T) {
	f := newInstallerFixture(t)
	app := f.app("dist/Pasu.app", "ABCDE12345", "org.example.pasu", 1, true)
	writeFixture(t, filepath.Join(app, "Contents/Library/LoginItems/PasuAgent.app/Contents/MacOS/pasu"), "#!/bin/zsh\nexit 137\n", 0700)
	out, rc := f.run(false, nil, "verify-app")
	if rc == 0 || !strings.Contains(string(out), "agent를 실행할 수 없습니다") || strings.Contains(string(out), "모드 불일치") {
		t.Fatalf("diagnostic: %d %s", rc, out)
	}
}

func TestLegacyGUIIdentityMigrationAndRollback(t *testing.T) {
	f := newInstallerFixture(t)
	old := f.app("installed/Pasu.app", "AYTVXW6P5Q", "com.dennis.pasu", 0, false)
	plist := filepath.Join(old, "Contents/Info.plist")
	if out, err := exec.Command("plutil", "-replace", "CFBundleIdentifier", "-string", "com.dennis.pasu.gui", plist).CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
	writeFixture(t, filepath.Join(old, "test-signature"), "Identifier=com.dennis.pasu.gui\nTeamIdentifier=AYTVXW6P5Q\nflags=0x10000(runtime)\n", 0600)
	writeFixture(t, filepath.Join(old, "Contents/Library/LoginItems/PasuAgent.app/test-signature"), "Identifier=com.dennis.pasu\nTeamIdentifier=AYTVXW6P5Q\nflags=0x10000(runtime)\n", 0600)
	writeFixture(t, filepath.Join(old, "Contents/MacOS/Pasu"), "#!/bin/zsh\nexit 95\n", 0700)
	f.app("dist/Pasu.app", "AYTVXW6P5Q", "com.dennis.pasu", 1, true)
	bridge := f.app("dist/migration/Pasu.app", "AYTVXW6P5Q", "com.dennis.pasu", 1, true)
	for _, args := range [][]string{
		{"-replace", "PasuKeychainMigration", "-bool", "true", filepath.Join(bridge, "Contents/Info.plist")},
		{"-insert", "keychain-access-groups.1", "-string", "AYTVXW6P5Q.com.dennis.pasu", filepath.Join(bridge, "Contents/Library/LoginItems/PasuAgent.app/test-entitlements.plist")},
	} {
		if out, err := exec.Command("plutil", args...).CombinedOutput(); err != nil {
			t.Fatal(err, string(out))
		}
	}
	bin := filepath.Join(bridge, "Contents/Library/LoginItems/PasuAgent.app/Contents/MacOS/pasu")
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Replace(string(data), "echo final", "echo migration", 1)
	text = strings.Replace(text, " -check|-check-legacy-data)", " -keychain-group-status|-migrate-keychain-group|-rollback-keychain-group|-check|-check-legacy-data)", 1)
	writeFixture(t, bin, text, 0700)
	writeFixture(t, filepath.Join(f.root, "old.plist"), `<plist version="1.0"><dict><key>ProgramArguments</key><array><string>`+filepath.Join(old, "Contents/Library/LoginItems/PasuAgent.app/Contents/MacOS/pasu")+`</string></array></dict></plist>`, 0600)
	writeFixture(t, filepath.Join(f.root, "home/.ssh/pasu/pasu.log"), "sample START version=2.2.0\n", 0600)
	for _, args := range [][]string{{"install", "--migrate"}, {"rollback"}} {
		out, rc := f.run(true, nil, args...)
		if rc != 0 {
			t.Fatalf("%v: %d %s", args, rc, out)
		}
	}
	if _, err := os.Stat(filepath.Join(f.root, "old.plist")); err != nil {
		t.Fatal("old service not restored", err)
	}
}

func TestRootPermissionProbeFailuresStopBeforeMutation(t *testing.T) {
	for _, command := range []string{"stat", "find"} {
		t.Run(command, func(t *testing.T) {
			f := newInstallerFixture(t)
			f.app("installed/Pasu.app", "ABCDE12345", "org.example.pasu", 1, true)
			f.app("dist/Pasu.app", "ABCDE12345", "org.example.pasu", 1, true)
			writeFixture(t, filepath.Join(f.root, "bin", command), "#!/bin/zsh\nexit 1\n", 0700)
			out, rc := f.run(false, nil, "install")
			changes, _ := os.ReadFile(filepath.Join(f.root, "changes"))
			if rc == 0 || len(changes) != 0 || !strings.Contains(string(out), "오류:") {
				t.Fatalf("permission probe: %d %s changes=%s", rc, out, changes)
			}
		})
	}
}
