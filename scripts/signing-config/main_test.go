package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func repository(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func TestSigningConfigRejectsUnsafeOrIncompatibleIdentity(t *testing.T) {
	official, err := readConfig(filepath.Join(repository(t), "packaging/signing.json"))
	if err != nil {
		t.Fatal(err)
	}
	custom := config{TeamID: "ABCDE12345", BundleID: "org.example.pasu"}
	if err := custom.validate("final", official); err != nil {
		t.Fatal(err)
	}
	if err := official.validate("migration", official); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*config){
		func(c *config) { c.TeamID = "" },
		func(c *config) { c.TeamID = "abcde12345" },
		func(c *config) { c.TeamID = `ABCDE12345" or true` },
		func(c *config) { c.BundleID = `org.example.pasu" or true` },
		func(c *config) { c.BundleID = "org.example.$(id)" },
		func(c *config) { c.BundleID = "org..example" },
		func(c *config) { c.BundleID = "org.example\n" },
		func(c *config) { c.SignIdentity = "Developer ID Application: Example (ZZZZZ12345)" },
		func(c *config) { c.SignIdentity = "Apple Development: Example (ABCDE12345)" },
		func(c *config) { c.Profile = "profile\x00file" },
	} {
		c := custom
		change(&c)
		if err := c.validate("final", official); err == nil {
			t.Errorf("accepted unsafe config: %+v", c)
		}
	}
	for _, mode := range []string{"migration", "unknown"} {
		if err := custom.validate(mode, official); err == nil {
			t.Errorf("accepted unsupported custom mode %s", mode)
		}
	}
}

func TestSigningConfigParseErrors(t *testing.T) {
	p := filepath.Join(t.TempDir(), "signing.json")
	for _, data := range []string{`{"team":"ABCDE12345"}`, `{} {}`, `{"team_id":12}`, `null trailing`} {
		if err := os.WriteFile(p, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readConfig(p); err == nil {
			t.Errorf("accepted %s", data)
		}
	}
	if _, err := readConfig(p + ".missing"); err == nil {
		t.Fatal("accepted missing explicit config")
	}
}

func TestGeneratedIdentityAgreesAcrossComponents(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "packaging"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Info.plist", "Agent-Info.plist", "PasuAgent.plist", "Pasu.entitlements"} {
		b, err := os.ReadFile(filepath.Join(repository(t), "packaging", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "packaging", name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	c := config{TeamID: "ABCDE12345", BundleID: "org.example.pasu", SignIdentity: "Developer ID Application: Example & Sample (ABCDE12345)", Profile: "/example/profile & sample.provisionprofile"}
	if err := generate(root, c); err != nil {
		t.Fatal(err)
	}
	checks := map[string][]string{
		"signing_identity_generated.go":    {c.TeamID, c.BundleID, c.BundleID + ".agent"},
		".build/signing/Identity.swift":    {c.TeamID, c.BundleID, c.BundleID + ".agent"},
		".build/signing/Info.plist":        {c.TeamID, c.BundleID},
		".build/signing/Agent-Info.plist":  {c.BundleID + ".agent"},
		".build/signing/PasuAgent.plist":   {c.BundleID + ".agent"},
		".build/signing/Pasu.entitlements": {c.TeamID + "." + c.BundleID + ".agent"},
		".build/signing/settings.plist":    {"Example &amp; Sample", "profile &amp; sample"},
	}
	for name, values := range checks {
		b, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		wantMode := os.FileMode(0644)
		if name == ".build/signing/settings.plist" {
			wantMode = 0600
		}
		if info.Mode().Perm() != wantMode {
			t.Errorf("%s: permissions %o, want %o", name, info.Mode().Perm(), wantMode)
		}
		for _, value := range values {
			if !strings.Contains(string(b), value) {
				t.Errorf("%s missing %s", name, value)
			}
		}
		if strings.Contains(string(b), "PASU_") || strings.Contains(string(b), "com.dennis.pasu") {
			t.Errorf("%s retains a placeholder or official identity", name)
		}
		if name != ".build/signing/settings.plist" && (strings.Contains(string(b), "profile &") || strings.Contains(string(b), "Developer ID Application:")) {
			t.Errorf("%s contains local signing inputs", name)
		}
		if strings.HasSuffix(name, ".plist") || strings.HasSuffix(name, ".entitlements") {
			if out, err := exec.Command("plutil", "-lint", filepath.Join(root, name)).CombinedOutput(); err != nil {
				t.Fatalf("invalid plist: %s %v", out, err)
			}
		}
	}
}

func shellCheck(t *testing.T, script string, args ...string) ([]byte, error) {
	t.Helper()
	argv := []string{"-c", "set -euo pipefail\nsource \"$1\"\nshift\n" + script, "signing-test", filepath.Join(repository(t), "scripts/signing-common.sh")}
	return exec.Command("/bin/zsh", append(argv, args...)...).CombinedOutput()
}

func TestProfilePermissionAndExpiration(t *testing.T) {
	for _, tc := range []struct {
		name, team, app, groups, expiry string
		ok                              bool
	}{
		{"wildcard", "ABCDE12345", "ABCDE12345.org.example.pasu.agent", "<string>ABCDE12345.*</string>", "2099", true},
		{"exact-second", "ABCDE12345", "ABCDE12345.org.example.pasu.agent", "<string>ABCDE12345.other</string><string>ABCDE12345.org.example.pasu.agent</string>", "2099", true},
		{"wrong-team", "ZZZZZ12345", "ABCDE12345.org.example.pasu.agent", "<string>ABCDE12345.*</string>", "2099", false},
		{"wrong-app", "ABCDE12345", "ABCDE12345.org.example.other", "<string>ABCDE12345.*</string>", "2099", false},
		{"wrong-group", "ABCDE12345", "ABCDE12345.org.example.pasu.agent", "<string>ZZZZZ12345.*</string>", "2099", false},
		{"expired", "ABCDE12345", "ABCDE12345.org.example.pasu.agent", "<string>ABCDE12345.*</string>", "2000", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "profile.plist")
			data := fmt.Sprintf(`<?xml version="1.0"?><plist version="1.0"><dict>
<key>Entitlements</key><dict><key>com.apple.application-identifier</key><string>%s</string>
<key>com.apple.developer.team-identifier</key><string>%s</string><key>keychain-access-groups</key><array>%s</array></dict>
<key>Platform</key><array><string>OSX</string></array><key>ProvisionsAllDevices</key><true/>
<key>ExpirationDate</key><date>%s-01-01T00:00:00Z</date></dict></plist>`, tc.app, tc.team, tc.groups, tc.expiry)
			if err := os.WriteFile(p, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			out, err := shellCheck(t, `assert_pasu_profile "$1" ABCDE12345 org.example.pasu.agent`, p)
			if (err == nil) != tc.ok {
				t.Fatalf("ok=%t err=%v output=%s", tc.ok, err, out)
			}
			if tc.name == "expired" {
				out, err := shellCheck(t, `assert_pasu_profile "$1" ABCDE12345 org.example.pasu.agent existing`, p)
				if err != nil {
					t.Fatalf("expired old profile must allow replacement: %v %s", err, out)
				}
			}
		})
	}
}

// A command double checks installer decisions without claiming OS signature validation.
func TestInstallerRequiresExactExistingDeveloperIdentity(t *testing.T) {
	const check = `
codesign() {
 if [[ "$1" == --display ]]; then
  print -r -- "Identifier=$actual_bundle"
  print -r -- "TeamIdentifier=$actual_team"
  print -r -- 'flags=0x10000(runtime)'
 fi
}

actual_team="$1"; actual_bundle="$2"
assert_developer_signature sample.app ABCDE12345 org.example.pasu
`
	for _, tc := range []struct {
		team, bundle string
		ok           bool
	}{
		{"ABCDE12345", "org.example.pasu", true},
		{"ZZZZZ12345", "org.example.pasu", false},
		{"ABCDE12345", "org.example.other", false},
		{"ABCDE12345suffix", "org.example.pasu", false},
	} {
		out, err := shellCheck(t, check, tc.team, tc.bundle)
		if (err == nil) != tc.ok {
			t.Errorf("%+v: %v %s", tc, err, out)
		}
	}
	out, err := shellCheck(t, `developer_requirement 'ABCDE12345' 'org.example.pasu" or true'`)
	if err == nil {
		t.Fatalf("accepted injected requirement: %s", out)
	}
}

func TestProfileAcceptsAnyListedCertificate(t *testing.T) {
	var certificates []string
	var fingerprints []string
	for i := 1; i <= 3; i++ {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(i)), NotBefore: time.Unix(0, 0), NotAfter: time.Now().Add(time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		certificates = append(certificates, "<data>"+base64.StdEncoding.EncodeToString(der)+"</data>")
		fingerprints = append(fingerprints, fmt.Sprintf("%X", sha1.Sum(der)))
	}
	work := t.TempDir()
	profile := filepath.Join(work, "profile.plist")
	data := `<plist version="1.0"><dict><key>DeveloperCertificates</key><array>` + strings.Join(certificates[:2], "") + `</array></dict></plist>`
	if err := os.WriteFile(profile, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	for i, fingerprint := range fingerprints {
		out, err := shellCheck(t, `assert_profile_certificate "$1" "$2" "$3"`, profile, fingerprint, work)
		if (err == nil) != (i < 2) {
			t.Errorf("certificate %d: %v %s", i, err, out)
		}
	}
}

func TestCertificateSelectionDuringRenewal(t *testing.T) {
	first := strings.Repeat("A", 40)
	second := strings.Repeat("B", 40)
	name := "Developer ID Application: Example Developer (ABCDE12345)"
	inventory := fmt.Sprintf("  1) %s %q\n  2) %s %q\n  3) %s %q\n  4) %s %q\n", first, name, second, name,
		strings.Repeat("C", 40), "Apple Development: Example Developer (ABCDE12345)",
		strings.Repeat("D", 40), "Developer ID Application: Another Developer (ZZZZZ12345)")
	for _, requested := range []string{"", name, strings.Repeat("E", 40), first, strings.ToLower(second)} {
		out, err := shellCheck(t, `select_pasu_identity ABCDE12345 "$1" "$2"`, requested, inventory)
		want := strings.ToUpper(requested)
		if want == first || want == second {
			if err != nil || strings.TrimSpace(string(out)) != want {
				t.Errorf("explicit fingerprint %s: %v %s", requested, err, out)
			}
		} else if err == nil {
			t.Errorf("accepted missing or ambiguous identity %s: %s", requested, out)
		}
	}
	one := fmt.Sprintf("  1) %s %q\n", first, name)
	for _, requested := range []string{"", name} {
		out, err := shellCheck(t, `select_pasu_identity ABCDE12345 "$1" "$2"`, requested, one)
		if err != nil || strings.TrimSpace(string(out)) != first {
			t.Errorf("single identity: %v %s", err, out)
		}
	}
}
