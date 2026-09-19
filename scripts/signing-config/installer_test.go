package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func writeFixture(t *testing.T, path, data string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
}

func replaceOnce(t *testing.T, text, from, to string) string {
	t.Helper()
	if strings.Count(text, from) != 1 {
		t.Fatalf("test isolation replacement count is not one: %q", from)
	}
	return strings.Replace(text, from, to, 1)
}

type installerFixture struct {
	t    *testing.T
	root string
}

func newInstallerFixture(t *testing.T) installerFixture {
	t.Helper()
	f := installerFixture{t, t.TempDir()}
	for _, name := range []string{"scripts/launchd.sh", "scripts/signing-common.sh", "scripts/data-layout.sh", "packaging/signing.json", "packaging/Info.plist", "packaging/Agent-Info.plist", "packaging/Pasu.entitlements", "packaging/PasuAgent.plist"} {
		b, err := os.ReadFile(filepath.Join(repository(t), name))
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		if name == "scripts/launchd.sh" {
			s = replaceOnce(t, s, `INSTALL_APP="/Applications/Pasu.app"`, `INSTALL_APP="$TEST_ROOT/installed/Pasu.app"`)
			s = replaceOnce(t, s, `OLD_PLIST="/Library/LaunchAgents/com.dennis.pasu.plist"`, `OLD_PLIST="$TEST_ROOT/old.plist"`)
			s = replaceOnce(t, s, "SELF=", "export PATH=\"$TEST_ROOT/bin:$PATH\"\nSELF=")
			s = replaceOnce(t, s, "wait_live() {", "wait_live() { return 0; }\nunused_wait_live() {")
			if strings.Contains(s, "/Applications/Pasu.app") || strings.Contains(s, "/Library/LaunchAgents/com.dennis.pasu.plist") {
				t.Fatal("unrelocated system path in test")
			}
		}
		writeFixture(t, filepath.Join(f.root, name), s, 0700)
	}
	commands := map[string]string{
		"codesign": `app="${argv[-1]}"
if [[ "$1" == --verify ]]; then
 [[ -f "$app/test-signature" ]] || exit 1
 if [[ "${3:-}" == -R ]]; then [[ "$4" == '=anchor apple generic and identifier '* ]] || exit 1; fi
 exit 0
fi
if [[ "$*" == *--entitlements* ]]; then
 [[ ! -f "$app/test-entitlements.plist" ]] || cat "$app/test-entitlements.plist"
else
 cat "$app/test-signature"
fi`,
		"security":    `cat "${argv[-1]}"`,
		"dscacheutil": `echo "dir: $TEST_ROOT/home"`,
		"ps":          `exit 0`,
		"stat":        `if [[ "$*" == *%Su:%Sg* ]]; then echo root:wheel; else /usr/bin/stat "$@"; fi`,
		"find":        `if [[ "$1" == "$TEST_ROOT/installed/"* ]]; then exit 0; else /usr/bin/find "$@"; fi`,
		"sudo": `echo "sudo $*" >> "$TEST_ROOT/changes"
[[ "${TEST_INSTALL_FULL:-0}" == 1 ]] || exit 73
for arg in "$@"; do
 if [[ "$arg" == /* && "$arg" != "$TEST_ROOT/"* ]]; then echo "forbidden system mutation: $arg" >&2; exit 99; fi
done
case "$1" in
 -v) exit 0 ;;
 chown) exit 0 ;;
 ditto) shift; /usr/bin/ditto "$@" ;;
 chmod|cp|mv|rm) command="$1"; shift; /bin/"$command" "$@" ;;
 *) exit 99 ;;
esac`,
		"launchctl": `echo "launchctl $*" >> "$TEST_ROOT/changes"
[[ "${TEST_INSTALL_FULL:-0}" == 1 ]] || exit 74
[[ "$1" != print ]] || echo 'state = running'`,
	}
	for name, body := range commands {
		writeFixture(t, filepath.Join(f.root, "bin", name), "#!/bin/zsh\nset -euo pipefail\n"+body+"\n", 0700)
	}
	return f
}

func (f installerFixture) app(rel, team, bundle string, layout int, marker bool) string {
	f.t.Helper()
	c := config{TeamID: team, BundleID: bundle}
	if err := generate(f.root, c); err != nil {
		f.t.Fatal(err)
	}
	app := filepath.Join(f.root, rel)
	for _, pair := range [][2]string{
		{"Info.plist", "Contents/Info.plist"},
		{"Agent-Info.plist", "Contents/Library/LoginItems/PasuAgent.app/Contents/Info.plist"},
		{"Pasu.entitlements", "Contents/Library/LoginItems/PasuAgent.app/test-entitlements.plist"},
		{"PasuAgent.plist", "Contents/Library/LaunchAgents/" + bundle + ".agent.plist"},
	} {
		b, err := os.ReadFile(filepath.Join(f.root, ".build/signing", pair[0]))
		if err != nil {
			f.t.Fatal(err)
		}
		s := string(b)
		if pair[0] == "Info.plist" {
			s = replaceOnce(f.t, s, "</dict>", "<key>PasuKeychainMigration</key><false/></dict>")
		}
		writeFixture(f.t, filepath.Join(app, pair[1]), s, 0600)
	}
	info := filepath.Join(app, "Contents/Info.plist")
	if layout == 0 {
		if out, err := exec.Command("plutil", "-remove", "PasuDataLayout", info).CombinedOutput(); err != nil {
			f.t.Fatal(err, string(out))
		}
	}
	if !marker {
		if out, err := exec.Command("plutil", "-remove", "PasuSigningTeam", info).CombinedOutput(); err != nil {
			f.t.Fatal(err, string(out))
		}
	}
	for _, part := range []struct{ rel, id, bin string }{{"", bundle, "Pasu"}, {"Contents/Library/LoginItems/PasuAgent.app", bundle + ".agent", "pasu"}} {
		base := filepath.Join(app, part.rel)
		writeFixture(f.t, filepath.Join(base, "test-signature"), fmt.Sprintf("Identifier=%s\nTeamIdentifier=%s\nCodeDirectory flags=0x10000(runtime)\n", part.id, team), 0600)
		script := fmt.Sprintf(`#!/bin/zsh
case "$1" in
 -build-mode) echo final ;;
 -data-layout) echo 1 ;;
 -build-identity|--build-identity) echo '%s %s %s.agent' ;;
 -check|-check-legacy-data) echo 'CHECK v2 ok keys=0 rules=0 migration-pending=false' ;;
 -version) echo 'pasu 2.2.0' ;;
 --service) echo '%s:'"$2" >> "$TEST_ROOT/services"; echo "${TEST_SERVICE_STATE:-enabled}" ;;
 *) exit 1 ;;
esac
`, team, bundle, bundle, bundle)
		writeFixture(f.t, filepath.Join(base, "Contents/MacOS", part.bin), script, 0700)
	}
	profile := fmt.Sprintf(`<plist version="1.0"><dict><key>Entitlements</key><dict><key>com.apple.application-identifier</key><string>%s.%s.agent</string><key>com.apple.developer.team-identifier</key><string>%s</string><key>keychain-access-groups</key><array><string>%s.*</string></array></dict><key>Platform</key><array><string>OSX</string></array><key>ProvisionsAllDevices</key><true/><key>ExpirationDate</key><date>2099-01-01T00:00:00Z</date></dict></plist>`, team, bundle, team, team)
	writeFixture(f.t, filepath.Join(app, "Contents/Library/LoginItems/PasuAgent.app/Contents/embedded.provisionprofile"), profile, 0600)
	writeFixture(f.t, filepath.Join(f.root, "VERSION"), "2.2.0\n", 0600)
	return app
}

func (f installerFixture) run(full bool, env []string, args ...string) ([]byte, int) {
	f.t.Helper()
	cmd := exec.Command("/bin/zsh", append([]string{filepath.Join(f.root, "scripts/launchd.sh")}, args...)...)
	// Avoid inheriting a real candidate or local signing configuration.
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "PASU_") && !strings.HasPrefix(v, "TEST_") {
			cmd.Env = append(cmd.Env, v)
		}
	}
	cmd.Env = append(cmd.Env, "TEST_ROOT="+f.root, fmt.Sprintf("TEST_INSTALL_FULL=%d", map[bool]int{false: 0, true: 1}[full]))
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, cmd.ProcessState.ExitCode()
	}
	return out, 0
}

func TestInstallPreflightBeforeAnySystemChange(t *testing.T) {
	for _, tc := range []struct {
		name, team, bundle, option string
		marker, ready              bool
	}{
		{"fresh", "", "", "", true, true},
		{"same-identity-update", "ABCDE12345", "org.example.pasu", "", true, true},
		{"different-team", "ZZZZZ12345", "org.example.pasu", "", true, false},
		{"different-app", "ABCDE12345", "org.example.other", "", true, false},
		{"explicit-switch", "ZZZZZ12345", "org.example.other", "--switch-developer", true, true},
		{"unmarked-custom", "ABCDE12345", "org.example.pasu", "", false, false},
		{"custom-legacy-like-name", "ABCDE12345", "com.dennis.pasu.gui", "--switch-developer", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newInstallerFixture(t)
			f.app("dist/Pasu.app", "ABCDE12345", "org.example.pasu", 1, true)
			if tc.team != "" {
				f.app("installed/Pasu.app", tc.team, tc.bundle, 1, tc.marker)
			}
			out, rc := f.run(false, nil, "install", tc.option)
			changes, _ := os.ReadFile(filepath.Join(f.root, "changes"))
			if tc.ready {
				if rc != 73 || string(changes) != "sudo -v\n" {
					t.Fatalf("preflight: rc=%d %s changes=%s", rc, out, changes)
				}
			} else if rc == 0 || len(changes) > 0 {
				t.Fatalf("unsafe change: rc=%d %s %s", rc, out, changes)
			}
		})
	}
}

// Real file copies/moves are confined to the fixture. Signing, Keychain and
// service responses are doubles; these tests do not validate Developer ID trust.
func TestDeveloperSwitchRoundTripAndReinstall(t *testing.T) {
	f := newInstallerFixture(t)
	a, b := "ABCDE12345.org.example.first", "ZZZZZ12345.org.example.second"
	f.app("installed/Pasu.app", "ABCDE12345", "org.example.first", 1, true)
	f.app("dist/Pasu.app", "ZZZZZ12345", "org.example.second", 1, true)
	for _, id := range []string{a, b} {
		writeFixture(t, filepath.Join(f.root, "home/.ssh/pasu/profiles", id, "keys/sample/key"), "encrypted-"+id, 0600)
		writeFixture(t, filepath.Join(f.root, "home/.ssh/pasu/profiles", id, "pasu.log"), "sample START version=2.2.0\n", 0600)
	}
	for _, args := range [][]string{{"install", "--switch-developer"}, {"rollback"}, {"install", "--switch-developer"}, {"finalize"}, {"uninstall"}, {"install"}} {
		out, rc := f.run(true, nil, args...)
		if rc != 0 {
			t.Fatalf("%v rc=%d: %s", args, rc, out)
		}
		for _, id := range []string{a, b} {
			got, err := os.ReadFile(filepath.Join(f.root, "home/.ssh/pasu/profiles", id, "keys/sample/key"))
			if err != nil || string(got) != "encrypted-"+id {
				t.Fatalf("lost data %s: %s %v", id, got, err)
			}
		}
	}
	back := f.app("return/Pasu.app", "ABCDE12345", "org.example.first", 1, true)
	out, rc := f.run(true, []string{"PASU_CANDIDATE_APP=" + back}, "install", "--switch-developer")
	if rc != 0 {
		t.Fatalf("return after finalize: %d %s", rc, out)
	}
	for _, id := range []string{a, b} {
		got, err := os.ReadFile(filepath.Join(f.root, "home/.ssh/pasu/profiles", id, "keys/sample/key"))
		if err != nil || string(got) != "encrypted-"+id {
			t.Fatalf("lost inactive profile %s", id)
		}
	}
	services, _ := os.ReadFile(filepath.Join(f.root, "services"))
	for _, want := range []string{"org.example.first:unregister", "org.example.second:register", "org.example.second:unregister", "org.example.first:register"} {
		if !strings.Contains(string(services), want) {
			t.Errorf("missing service transition %s: %s", want, services)
		}
	}
}

func TestUnmarkedOfficialUpgradeAndLayoutRollback(t *testing.T) {
	f := newInstallerFixture(t)
	f.app("installed/Pasu.app", "AYTVXW6P5Q", "com.dennis.pasu", 0, false)
	f.app("dist/Pasu.app", "AYTVXW6P5Q", "com.dennis.pasu", 1, true)
	root := filepath.Join(f.root, "home/.ssh/pasu")
	writeFixture(t, filepath.Join(root, "keys/sample/key"), "preserve", 0600)
	writeFixture(t, filepath.Join(root, "pasu.log"), "sample START version=2.2.0\n", 0600)
	out, rc := f.run(true, nil, "install")
	if rc != 0 {
		t.Fatalf("upgrade %d %s", rc, out)
	}
	moved := filepath.Join(root, "profiles/AYTVXW6P5Q.com.dennis.pasu/keys/sample/key")
	if _, err := os.Stat(moved); err != nil {
		t.Fatal(err)
	}
	out, rc = f.run(true, nil, "rollback")
	if rc != 0 {
		t.Fatalf("rollback %d %s", rc, out)
	}
	got, err := os.ReadFile(filepath.Join(root, "keys/sample/key"))
	if err != nil || string(got) != "preserve" {
		t.Fatalf("restoration: %s %v", got, err)
	}
}

func TestApprovalStatusPrecedesMissingLog(t *testing.T) {
	f := newInstallerFixture(t)
	f.app("installed/Pasu.app", "ABCDE12345", "org.example.pasu", 1, true)
	out, rc := f.run(true, []string{"TEST_SERVICE_STATE=requiresApproval"}, "status")
	if rc != 3 || !strings.Contains(string(out), "requiresApproval") || strings.Contains(string(out), "감사 로그 없음") {
		t.Fatalf("approval: %d %s", rc, out)
	}
}
