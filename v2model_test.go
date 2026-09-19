package main

import (
	"testing"
	"time"
)

func testStableChain(t *testing.T, tty ttyClass) stableChain {
	t.Helper()
	return stableChain{TTY: tty, Members: []stableProcess{
		{Path: "/usr/bin/ssh", UID: 501, Identity: codeIdentity{Kind: codeIdentityApple, Identifier: "com.apple.ssh"}},
		{Path: "/bin/zsh", UID: 501, Identity: codeIdentity{Kind: codeIdentityApple, Identifier: "com.apple.zsh"}},
		{Path: "/Applications/iTerm.app/Contents/MacOS/iTerm2", UID: 501, Identity: codeIdentity{Kind: codeIdentityDeveloper, TeamID: "H7V7XYVQ7D", Identifier: "com.googlecode.iterm2"}},
		{Path: "/sbin/launchd", UID: 0, Identity: codeIdentity{Kind: codeIdentityApple, Identifier: "com.apple.launchd"}},
	}}
}

func TestStableChainRequiresExactMembersAndTTY(t *testing.T) {
	base := testStableChain(t, ttyForeground)
	copyChain := testStableChain(t, ttyForeground)
	if !stableChainEqual(base, copyChain) {
		t.Fatal("같은 사슬이 일치하지 않음")
	}
	copyChain.Members[1].Path = "/bin/bash"
	if stableChainEqual(base, copyChain) {
		t.Fatal("경로가 다른 사슬이 일치함")
	}
	copyChain = testStableChain(t, ttyBackground)
	if stableChainEqual(base, copyChain) {
		t.Fatal("TTY 상태가 다른 사슬이 일치함")
	}
	copyChain = testStableChain(t, ttyForeground)
	copyChain.Members[2], copyChain.Members[1] = copyChain.Members[1], copyChain.Members[2]
	if stableChainEqual(base, copyChain) {
		t.Fatal("순서가 다른 사슬이 일치함")
	}
}

func TestChainRuleIDIncludesDecision(t *testing.T) {
	chain := testStableChain(t, ttyForeground)
	allow, err := newChainRule(ruleAllow, chain, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	deny, err := newChainRule(ruleDeny, chain, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if allow.ID == deny.ID {
		t.Fatal("허용과 거부 규칙 ID가 같음")
	}
	allow2, _ := newChainRule(ruleAllow, chain, time.Unix(2, 0))
	if allow.ID != allow2.ID {
		t.Fatal("동적 생성 시각이 규칙 ID에 들어감")
	}
}

func TestValidateRegistryRejectsDuplicateNames(t *testing.T) {
	firstID, err := newKeyID()
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := newKeyID()
	if err != nil {
		t.Fatal(err)
	}
	r := defaultV2Registry()
	r.Keys = []managedKeyRecord{
		{ID: firstID, Name: "Work", Fingerprint: "SHA256:a", PublicKey: "ssh-ed25519 A", AuthMode: keyAuthCached},
		{ID: secondID, Name: "work", Fingerprint: "SHA256:b", PublicKey: "ssh-ed25519 B", AuthMode: keyAuthPerSign},
	}
	if err := validateRegistry(r); err == nil {
		t.Fatal("대소문자만 다른 중복 이름을 허용함")
	}
}

func TestChainTTY(t *testing.T) {
	if got := chainTTY([]procInfo{{tdev: -1}}); got != ttyNone {
		t.Fatalf("TTY 없음=%s", got)
	}
	if got := chainTTY([]procInfo{{tdev: 1, pgid: 7, tpgid: 7}}); got != ttyForeground {
		t.Fatalf("foreground=%s", got)
	}
	if got := chainTTY([]procInfo{{tdev: 1, pgid: 7, tpgid: 8}}); got != ttyBackground {
		t.Fatalf("background=%s", got)
	}
}

func TestUsesV2RuntimeByMajorVersion(t *testing.T) {
	for _, value := range []string{"2.0.0", "2.1.0", "3.1.0", "10.0.0"} {
		if !usesV2Runtime(value) {
			t.Fatalf("%s가 v2 runtime을 선택하지 않음", value)
		}
	}
	for _, value := range []string{"1.2.1", "dev", ""} {
		if usesV2Runtime(value) {
			t.Fatalf("%s가 v2 runtime을 잘못 선택함", value)
		}
	}
}
