package main

import (
	"errors"
	"os"
	"os/exec"
	"testing"
)

func TestSigningRequirementRejectsNonLiteralFields(t *testing.T) {
	for _, id := range []string{"", "com.example.sample\x00suffix", "com.example.sample\n", `com.example.\sample`, `com.example."sample`, "com.example.sample or true", "com.example.예시"} {
		if req, err := codesignRequirement("EXAMPLE000", id); !errors.Is(err, errCodeIdentityUntrusted) || req != "" {
			t.Errorf("Developer ID field %q generated a requirement", id)
		}
		if req, err := applePlatformRequirement(id); !errors.Is(err, errCodeIdentityUntrusted) || req != "" {
			t.Errorf("Apple field %q generated a requirement", id)
		}
	}
	for _, team := range []string{"", "example000", "EXAMPLE00", "EXAMPLE0000", "EXAMPLE00\x00", `EXAMPLE0"0`, "EXAMPLE000\n"} {
		if req, err := codesignRequirement(team, "com.example.sample"); !errors.Is(err, errCodeIdentityUntrusted) || req != "" {
			t.Errorf("team field %q generated a requirement", team)
		}
	}
	for _, id := range []string{"com.example.sample", "com.example.Sample_1-helper", "com.apple.ssh"} {
		if _, err := codesignRequirement("EXAMPLE000", id); err != nil {
			t.Errorf("valid Developer ID fields rejected: %v", err)
		}
		if _, err := applePlatformRequirement(id); err != nil {
			t.Errorf("valid Apple identifier rejected: %v", err)
		}
	}
}

// 실제 Security framework를 부르는 테스트. 독립 검증 도구는 experiments/codesign.

// go test 바이너리는 ad-hoc(linker) 서명이라 Developer ID requirement를
// 절대 통과할 수 없다 — 어디서 실행해도 안정적인 음성 사례.
func TestCodesignMatchesRejectsAdhocSelf(t *testing.T) {
	if codesignMatches(os.Getpid(), "Q6L2SF6YDW", "com.anthropic.claude-code") {
		t.Fatal("ad-hoc 테스트 바이너리가 Developer ID 규칙을 통과함")
	}
}

func TestCodesignMatchesRejectsDeadPid(t *testing.T) {
	cmd := exec.Command("/usr/bin/true")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	cmd.Wait()
	if codesignMatches(pid, "Q6L2SF6YDW", "com.anthropic.claude-code") {
		t.Fatal("죽은 pid가 통과함")
	}
}

func TestApplePlatformSigningIdentity(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "5")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	proc, err := lookupProcVerified(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := signingInfoForProc(proc)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Kind != codeIdentityApple || identity.Identifier == "" || identity.TeamID != "" {
		t.Fatalf("identity=%+v", identity)
	}
}

// 현재 프로세스를 대상으로 실제 Security framework의 조건식 해석을 검사한다.
// 입력 필드가 별도의 조건식으로 해석되어서는 안 된다.
func TestCodesignRejectsRequirementInjection(t *testing.T) {
	conn, _ := connectedUnixPair(t)
	peer, err := peerIdentity(conn)
	if err != nil {
		t.Fatal(err)
	}
	for _, proc := range []procInfo{
		{pid: os.Getpid()},
		{pid: peer.pid, hasToken: true, token: peer.token},
	} {
		name := "pid"
		if proc.hasToken {
			name = "audit-token"
		}
		t.Run(name, func(t *testing.T) {
			for _, fields := range [][2]string{
				{"EXAMPLE000", `com.example.sample" or true or identifier "com.example.sample`},
				{`EXAMPLE000" or true or identifier "com.example.sample`, "com.example.sample"},
			} {
				if codesignMatchesProc(proc, fields[0], fields[1]) {
					t.Errorf("Developer ID requirement accepted injected fields: %q", fields)
				}
			}
			if codesignMatchesApple(proc, `com.example.sample" or true or identifier "com.example.sample`) {
				t.Error("Apple requirement accepted an injected identifier")
			}
			if _, err := signingInfoForProc(proc); err == nil {
				t.Error("ad-hoc process was classified as trusted by the v2 metadata path")
			}
		})
	}
}

// 지정한 Developer ID 앱이 조상 사슬에 있으면 허용 판정까지 검증한다.
// 이 선택적 대조군이 없으면 해당 테스트만 건너뛴다.
func TestCodesignMatchesClaudeAncestor(t *testing.T) {
	for _, p := range ancestry(os.Getpid()) {
		if codesignMatches(p.pid, "Q6L2SF6YDW", "com.anthropic.claude-code") {
			t.Logf("양성 확인: pid %d (%s)", p.pid, p.exePath)
			return
		}
	}
	t.Skip("선택적 Developer ID 대조군이 조상 사슬에 없어 허용 판정 검사를 건너뜀")
}
