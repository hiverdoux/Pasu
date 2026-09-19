package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRedirectProcessOutputCapturesRuntimePanic(t *testing.T) {
	const (
		childEnv = "PASU_TEST_REDIRECT_PANIC"
		pathEnv  = "PASU_TEST_REDIRECT_PATH"
		marker   = "pasu-runtime-panic-marker"
	)
	if os.Getenv(childEnv) == "1" {
		f, err := os.OpenFile(os.Getenv(pathEnv), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			panic(err)
		}
		if err := redirectProcessOutput(f); err != nil {
			panic(err)
		}
		if err := f.Close(); err != nil {
			panic(err)
		}
		fmt.Fprintln(os.Stdout, "pasu-stdout-marker")
		fmt.Fprintln(os.Stderr, "pasu-stderr-marker")
		go func() { panic(marker) }()
		select {}
	}

	path := filepath.Join(t.TempDir(), "launchd.log")
	cmd := exec.Command(os.Args[0], "-test.run=^TestRedirectProcessOutputCapturesRuntimePanic$")
	cmd.Env = append(os.Environ(), childEnv+"=1", pathEnv+"="+path)
	var childStderr bytes.Buffer
	cmd.Stderr = &childStderr
	if err := cmd.Run(); err == nil {
		t.Fatal("패닉 자식 프로세스가 성공 종료함")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"pasu-stdout-marker", "pasu-stderr-marker", marker} {
		if !bytes.Contains(data, []byte(want)) {
			t.Fatalf("launchd.log에 %q가 없음\nlog=%s\n원래 stderr=%s", want, data, childStderr.Bytes())
		}
	}
}

func TestOpenAgentListenerIsPrivateAndSingleInstance(t *testing.T) {
	sock := shortTempSocket(t)
	l, lock, err := openAgentListener(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { l.Close(); releaseInstanceLock(lock) }()
	st, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Mode().Perm(); got != 0o600 {
		t.Fatalf("소켓 권한=%o, 기대 600", got)
	}
	if _, secondLock, err := openAgentListener(sock); err == nil {
		releaseInstanceLock(secondLock)
		t.Fatal("동시 두 번째 listener가 열림")
	}
}

func TestOpenAgentListenerReclaimsStaleSocket(t *testing.T) {
	sock := shortTempSocket(t)
	stale, err := listenPrivateUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	// net.UnixListener가 자동 unlink한 경우에도 낡은 경로를 다시 만들어 같은
	// 회수 분기를 통과시킨다.
	if _, err := os.Stat(sock); os.IsNotExist(err) {
		f, err := os.Create(filepath.Clean(sock))
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	l, lock, err := openAgentListener(sock)
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	releaseInstanceLock(lock)
}

func TestStoppedAgentCommandCoversEveryStateChangingMode(t *testing.T) {
	tests := []struct {
		want                                        string
		setup, remove, trust, migrate, removeLegacy bool
	}{
		{want: "-setup-touchid", setup: true},
		{want: "-remove-touchid", remove: true},
		{want: "-trust-conf", trust: true},
		{want: "-migrate-keychain", migrate: true},
		{want: "-remove-legacy-sewrap", removeLegacy: true},
		{want: ""},
	}
	for _, tt := range tests {
		if got := stoppedAgentCommand(tt.setup, tt.remove, tt.trust, tt.migrate, tt.removeLegacy); got != tt.want {
			t.Errorf("상태 변경 명령=%q, 기대 %q", got, tt.want)
		}
	}
}

func TestAcquireStoppedAgentLock(t *testing.T) {
	sock := shortTempSocket(t)
	l, err := listenPrivateUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"-setup-touchid", "-remove-touchid", "-trust-conf", "-migrate-keychain", "-remove-legacy-sewrap"} {
		if lock, err := acquireStoppedAgentLock(sock, command); err == nil || !strings.Contains(err.Error(), command) {
			releaseInstanceLock(lock)
			t.Fatalf("실행 중 에이전트가 %s를 막지 않음: %v", command, err)
		}
	}
	l.Close()
	lock, err := acquireStoppedAgentLock(sock, "-trust-conf")
	if err != nil {
		t.Fatalf("중지 뒤에도 상태 변경 명령이 막힘: %v", err)
	}
	defer releaseInstanceLock(lock)
	if listener, second, err := openAgentListener(sock); err == nil {
		listener.Close()
		releaseInstanceLock(second)
		t.Fatal("상태 변경 명령 중 새 pasu 기동 잠금이 열림")
	}
}

func TestRequestTrackerWaitsOnlyForActiveWork(t *testing.T) {
	r := newRequestTracker()
	if !r.begin() {
		t.Fatal("가동 중 첫 요청 거부")
	}
	r.stop()
	if r.begin() {
		t.Fatal("종료 시작 뒤 새 요청 허용")
	}
	done := make(chan struct{})
	go func() {
		r.wait()
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("진행 중 요청이 있는데 drain 완료")
	case <-time.After(50 * time.Millisecond):
	}
	r.done()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("진행 중 요청 종료 뒤 drain이 끝나지 않음")
	}
}

func TestLaunchdStopAndRestartWaitCoverInteractiveDrain(t *testing.T) {
	data, err := os.ReadFile("scripts/launchd.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, want := range []string{
		"SERVICE_STOP_WAIT_TENTHS=900",
		"SERVICE_STOP_NOTICE_TENTHS=100",
		"wait_for_service_exit()",
		"stop_target()",
		`stop_target "$TARGET"`,
		`stop_target "$OLD_TARGET"`,
		"i <= SERVICE_STOP_WAIT_TENTHS",
		"진행 중 서명·Touch ID·승인 창",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("stop/restart 대기 계약 누락: %q", want)
		}
	}
}

func TestLegacySetupRequiresExplicitTestDirectoryWhenProductionInstalled(t *testing.T) {
	if err := legacySetupConflict(true, false, false, true); err == nil {
		t.Fatal("ad-hoc 기본 경로 setup이 production 설치를 덮을 수 있음")
	}
	for _, tc := range []struct {
		setup, production, explicitDir, installed bool
	}{
		{false, false, false, true},
		{true, true, false, true},
		{true, false, true, true},
		{true, false, false, false},
	} {
		if err := legacySetupConflict(tc.setup, tc.production, tc.explicitDir, tc.installed); err != nil {
			t.Fatalf("정상 조합이 거부됨: %+v err=%v", tc, err)
		}
	}
}
