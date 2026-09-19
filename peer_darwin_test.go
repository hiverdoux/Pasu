package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// 소켓 경로가 유닉스 소켓 한계(약 104바이트)를 넘지 않도록 짧은 임시 폴더를 쓴다.
func shortTempSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "pasu-t-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	if len(sock) > 100 {
		t.Fatalf("소켓 경로가 너무 김(%d바이트): %s", len(sock), sock)
	}
	return sock
}

func TestPeerIdentitySelf(t *testing.T) {
	sock := shortTempSocket(t)
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := net.Dial("unix", sock)
		if err != nil {
			return
		}
		<-done
		c.Close()
	}()
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	id, err := peerIdentity(c.(*net.UnixConn))
	if err != nil {
		t.Fatal(err)
	}
	if id.pid != os.Getpid() {
		t.Errorf("peer pid=%d, 기대 %d", id.pid, os.Getpid())
	}
	if id.uid != uint32(os.Getuid()) {
		t.Errorf("peer uid=%d, 기대 %d", id.uid, os.Getuid())
	}
	if id.token == (auditToken{}) {
		t.Fatal("LOCAL_PEERTOKEN이 빈 audit token을 반환함")
	}
	path, err := pidPathAudit(id.token)
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if path != normalizePath(exe) {
		t.Errorf("audit token 경로=%q, 기대 %q", path, normalizePath(exe))
	}
	if !codesignAuditResolvable(id.token) {
		t.Fatal("Security framework가 직접 피어 audit token을 동적 코드로 해석하지 못함")
	}
}

func TestAncestrySelf(t *testing.T) {
	chain := ancestry(os.Getpid())
	if len(chain) < 2 {
		t.Fatalf("사슬이 너무 짧음: %+v", chain)
	}
	self := chain[0]
	if self.pid != os.Getpid() {
		t.Errorf("chain[0].pid=%d, 기대 %d", self.pid, os.Getpid())
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if self.exePath != normalizePath(exe) {
		t.Errorf("chain[0].exePath=%q, 기대 %q", self.exePath, normalizePath(exe))
	}
	if self.ppid != os.Getppid() {
		t.Errorf("chain[0].ppid=%d, 기대 %d", self.ppid, os.Getppid())
	}
	if chain[1].pid != os.Getppid() {
		t.Errorf("chain[1].pid=%d, 기대 %d", chain[1].pid, os.Getppid())
	}
}

func TestAncestryStopsAtCycle(t *testing.T) {
	chain := ancestryWithLookup(5, func(pid int) procInfo {
		if pid == 5 {
			return procInfo{pid: 5, ppid: 4}
		}
		return procInfo{pid: 4, ppid: 5}
	})
	if len(chain) != 2 || chain[0].pid != 5 || chain[1].pid != 4 {
		t.Fatalf("순환 탐지 실패: %+v", chain)
	}
}

func TestAncestryCapsDepth(t *testing.T) {
	chain := ancestryWithLookup(2, func(pid int) procInfo {
		return procInfo{pid: pid, ppid: pid + 1}
	})
	if len(chain) != maxAncestors {
		t.Fatalf("조상 상한=%d, 기대 %d", len(chain), maxAncestors)
	}
}

func TestVerifiedAncestryRequiresLaunchdAndNoCycle(t *testing.T) {
	lookup := func(pid int) (procInfo, error) {
		switch pid {
		case 3:
			return procInfo{pid: 3, ppid: 2, exePath: "/three"}, nil
		case 2:
			return procInfo{pid: 2, ppid: 1, exePath: "/two"}, nil
		case 1:
			return procInfo{pid: 1, ppid: 0, exePath: "/sbin/launchd"}, nil
		default:
			return procInfo{}, os.ErrNotExist
		}
	}
	chain, err := verifiedAncestryWithLookup(3, lookup)
	if err != nil || len(chain) != 3 || chain[2].pid != 1 {
		t.Fatalf("완전 사슬 실패: chain=%+v err=%v", chain, err)
	}
	if _, err := verifiedAncestryWithLookup(3, func(pid int) (procInfo, error) {
		return procInfo{pid: pid, ppid: 3, exePath: "/cycle"}, nil
	}); err == nil {
		t.Fatal("순환 사슬이 검증됨")
	}
	if _, err := verifiedAncestryWithLookup(3, func(pid int) (procInfo, error) {
		return procInfo{pid: pid, ppid: 0, exePath: "/partial"}, nil
	}); err == nil {
		t.Fatal("launchd 전 부분 사슬이 검증됨")
	}
}

func TestVerifiedPeerChainSelfStable(t *testing.T) {
	conn, _ := connectedUnixPair(t)
	id, err := peerIdentity(conn)
	if err != nil {
		t.Fatal(err)
	}
	chain, verify, err := verifiedPeerChain(conn, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) < 2 || chain[0].pid != os.Getpid() || !chain[0].hasToken || chain[len(chain)-1].pid != 1 {
		t.Fatalf("검증된 사슬 이상: %+v", chain)
	}
	if err := verify(); err != nil {
		t.Fatalf("변경 없는 사슬 재검증 실패: %v", err)
	}
}

func TestSameProcChainDetectsGenerationAndPathChanges(t *testing.T) {
	base := []procInfo{{pid: 2, ppid: 1, startSec: 10, startUsec: 20, exePath: "/a"}, {pid: 1, exePath: "/sbin/launchd"}}
	copyChain := append([]procInfo(nil), base...)
	if !sameProcChain(base, copyChain) {
		t.Fatal("같은 사슬이 다르다고 판정됨")
	}
	copyChain[0].startUsec++
	if sameProcChain(base, copyChain) {
		t.Fatal("프로세스 시작 시각 변경을 놓침")
	}
	copyChain = append([]procInfo(nil), base...)
	copyChain[0].exePath = "/b"
	if sameProcChain(base, copyChain) {
		t.Fatal("실행 경로 변경을 놓침")
	}
}
