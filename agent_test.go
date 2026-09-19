package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type blockingSigner struct {
	ssh.Signer
	started chan struct{}
	release chan struct{}
}

func (s *blockingSigner) Sign(r io.Reader, data []byte) (*ssh.Signature, error) {
	close(s.started)
	<-s.release
	return s.Signer.Sign(r, data)
}

func genTestKey(t *testing.T, passphrase string) (keyPath string) {
	t.Helper()
	keyPath = filepath.Join(t.TempDir(), "key")
	out, err := exec.Command("/usr/bin/ssh-keygen",
		"-t", "ed25519", "-f", keyPath, "-N", passphrase, "-C", "pasu-test").CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
	return keyPath
}

func testSigner(t *testing.T) ssh.Signer {
	t.Helper()
	pemBytes, err := os.ReadFile(genTestKey(t, "test-pass"))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKeyWithPassphrase(pemBytes, []byte("test-pass"))
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// startServer는 실제 유닉스 소켓 위에 gatekeeper를 띄운다.
// 접속자는 테스트 프로세스 자신이므로, 조상 사슬에는 테스트 바이너리가 들어간다.
func startServer(t *testing.T, rules *allowlist) string {
	return startServerWithKey(t, rules, nil)
}

// startServerWithKey는 키 출처를 지정할 수 있는 변형이다(nil이면 즉시 로드 키).
func startServerWithKey(t *testing.T, rules *allowlist, src keySource) string {
	return startServerFull(t, rules, src, nil)
}

// startServerFull은 키 출처와 승인기(ask)까지 지정하는 변형이다.
func startServerFull(t *testing.T, rules *allowlist, src keySource, ask *asker) string {
	t.Helper()
	sock := shortTempSocket(t)
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	if src == nil {
		src = eagerKey{signer: testSigner(t)}
	}
	audit := discardAuditLog(t)
	// main.go run()과 같은 방식: conf의 limit 설정으로 공유 리미터를 만든다.
	var limiter *signLimiter
	if rules.limit != nil {
		limiter = newSignLimiter(*rules.limit)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			uc := c.(*net.UnixConn)
			g := &gatekeeper{
				key:     src,
				rules:   rules,
				limit:   limiter,
				ask:     ask,
				audit:   audit,
				notify:  func(string, string) {},
				selfUID: uint32(os.Getuid()),
				conn:    uc,
			}
			go func() {
				defer uc.Close()
				agent.ServeAgent(g, uc)
			}()
		}
	}()
	return sock
}

func dialAgent(t *testing.T, sock string) agent.ExtendedAgent {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return agent.NewClient(c)
}

func selfCodesignRules(t *testing.T, directives string) *allowlist {
	t.Helper()
	conf := strings.TrimSpace(directives)
	if conf != "" {
		conf += "\n"
	}
	conf += "allow codesign team=AAAAAAAAAA id=pasu.test"
	rules := mustParse(t, conf)
	rules.codesignCheck = func(proc procInfo, _, _ string) bool { return proc.pid == os.Getpid() }
	return rules
}

func TestSignAllowedForAllowlistedAncestor(t *testing.T) {
	cl := dialAgent(t, startServer(t, selfCodesignRules(t, "")))
	keys, err := cl.List()
	if err != nil || len(keys) != 1 {
		t.Fatalf("List: keys=%d err=%v", len(keys), err)
	}
	data := []byte("integration sign")
	sig, err := cl.Sign(keys[0], data)
	if err != nil {
		t.Fatalf("허용 기대했으나 거부: %v", err)
	}
	if err := keys[0].Verify(data, sig); err != nil {
		t.Fatalf("서명 검증 실패: %v", err)
	}
}

func TestSignDeniedForUnmatchedChain(t *testing.T) {
	rules := mustParse(t, "allow codesign team=AAAAAAAAAA id=nonexistent.agent")
	cl := dialAgent(t, startServer(t, rules))
	keys, err := cl.List()
	if err != nil || len(keys) != 1 {
		t.Fatalf("List는 항상 허용이어야 함: keys=%d err=%v", len(keys), err)
	}
	if _, err := cl.Sign(keys[0], []byte("x")); err == nil {
		t.Fatal("거부 기대했으나 서명됨")
	}
}

func TestSignDeniedForEmptyAllowlist(t *testing.T) {
	cl := dialAgent(t, startServer(t, mustParse(t, "# 빈 설정\n")))
	keys, err := cl.List()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.Sign(keys[0], []byte("x")); err == nil {
		t.Fatal("빈 allowlist인데 서명됨")
	}
}

func TestSignDeniedForUnknownKey(t *testing.T) {
	cl := dialAgent(t, startServer(t, selfCodesignRules(t, "")))
	other := testSigner(t).PublicKey()
	if _, err := cl.Sign(other, []byte("x")); err == nil {
		t.Fatal("광고하지 않은 키의 서명 요청이 허용됨")
	}
}

func TestSignDeniedForNonzeroFlags(t *testing.T) {
	cl := dialAgent(t, startServer(t, selfCodesignRules(t, "")))
	keys, err := cl.List()
	if err != nil || len(keys) != 1 {
		t.Fatalf("List: keys=%d err=%v", len(keys), err)
	}
	if _, err := cl.SignWithFlags(keys[0], []byte("x"), agent.SignatureFlagRsaSha256); err == nil {
		t.Fatal("ed25519 키의 비영 서명 플래그가 허용됨")
	}
}

func TestSignRateLimitDeniesBurst(t *testing.T) {
	rules := selfCodesignRules(t, "limit rate 2/60s")
	cl := dialAgent(t, startServer(t, rules))
	keys, err := cl.List()
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 2; i++ {
		if _, err := cl.Sign(keys[0], []byte("x")); err != nil {
			t.Fatalf("한도 안 %d번째 서명이 거부됨: %v", i, err)
		}
	}
	if _, err := cl.Sign(keys[0], []byte("x")); err == nil {
		t.Fatal("한도 초과 서명이 허용됨")
	}
	// List는 rate limit과 무관하게 계속 응답해야 한다.
	if _, err := cl.List(); err != nil {
		t.Fatalf("한도 초과 상태에서 List 실패: %v", err)
	}
}

func TestSignRateLimitOff(t *testing.T) {
	rules := selfCodesignRules(t, "limit rate off")
	cl := dialAgent(t, startServer(t, rules))
	keys, err := cl.List()
	if err != nil {
		t.Fatal(err)
	}
	// 기본값(30회)보다 많이 서명해도 전부 허용돼야 한다.
	for i := 1; i <= 35; i++ {
		if _, err := cl.Sign(keys[0], []byte("x")); err != nil {
			t.Fatalf("off인데 %d번째 서명이 거부됨: %v", i, err)
		}
	}
}

func TestFailedUnlockDoesNotConsumeRateLimit(t *testing.T) {
	signer := testSigner(t)
	var calls atomic.Int32
	lk := &lazyKey{
		pub: signer.PublicKey(),
		unlock: func() (ssh.Signer, error) {
			if calls.Add(1) == 1 {
				return nil, errors.New("사용자 취소")
			}
			return signer, nil
		},
	}
	rules := selfCodesignRules(t, "limit rate 1/60s")
	cl := dialAgent(t, startServerWithKey(t, rules, lk))
	keys, err := cl.List()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.Sign(keys[0], []byte("first")); err == nil {
		t.Fatal("첫 잠금 해제 실패가 서명됨")
	}
	if _, err := cl.Sign(keys[0], []byte("second")); err != nil {
		t.Fatalf("실패 요청이 예산을 소모함: %v", err)
	}
	if _, err := cl.Sign(keys[0], []byte("third")); err == nil {
		t.Fatal("실제 성공 1건 뒤 한도 초과가 허용됨")
	}
}

func TestAlwaysApprovalPersistsOnlyAfterSuccessfulUnlock(t *testing.T) {
	dir := t.TempDir()
	macPath := filepath.Join(dir, "conf.hmac")
	apprPath := filepath.Join(dir, "approvals.conf")
	conf := []byte("ask on\n")
	k := testBindKey(t)
	if err := newConfBinding(macPath, conf, nil, t.Logf).adoptNewKey(k, "test"); err != nil {
		t.Fatal(err)
	}
	activeBind := newConfBinding(macPath, conf, nil, t.Logf)
	activeBind.setMode("on")
	signer := testSigner(t)
	var unlocks atomic.Int32
	lk := &lazyKey{
		pub: signer.PublicKey(),
		unlock: func() (ssh.Signer, error) {
			if unlocks.Add(1) == 1 {
				return nil, errors.New("사용자 취소")
			}
			if err := activeBind.verify(k); err != nil {
				return nil, err
			}
			return signer, nil
		},
	}
	ask := newAsker(apprPath, nil, activeBind, t.Logf)
	var prompts atomic.Int32
	ask.prompt = fixedPrompt(askAlways, &prompts)
	rules := mustParse(t, "ask on\nlimit rate off")
	cl := dialAgent(t, startServerFull(t, rules, lk, ask))
	keys, err := cl.List()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.Sign(keys[0], []byte("first")); err == nil {
		t.Fatal("취소된 잠금 해제가 서명됨")
	}
	if _, err := os.Stat(apprPath); !os.IsNotExist(err) {
		t.Fatalf("실패한 요청이 승인 파일을 남김: %v", err)
	}
	if err := newConfBinding(macPath, conf, nil, t.Logf).verify(k); err != nil {
		t.Fatalf("실패한 요청 뒤 재기동 결속이 깨짐: %v", err)
	}
	if _, err := cl.Sign(keys[0], []byte("second")); err != nil {
		t.Fatalf("두 번째 잠금 해제·서명 실패: %v", err)
	}
	appr, err := os.ReadFile(apprPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := newConfBinding(macPath, conf, appr, t.Logf).verify(k); err != nil {
		t.Fatalf("성공 뒤 승인·지문 재기동 검증 실패: %v", err)
	}
	if prompts.Load() != 1 {
		t.Fatalf("항상 허용 창 호출=%d, 기대 1", prompts.Load())
	}
}

func connectedUnixPair(t *testing.T) (*net.UnixConn, net.Conn) {
	t.Helper()
	sock := shortTempSocket(t)
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.Dial("unix", sock)
	if err != nil {
		l.Close()
		t.Fatal(err)
	}
	server, err := l.Accept()
	_ = l.Close()
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close(); client.Close() })
	return server.(*net.UnixConn), client
}

func TestUIDMismatchStopsBeforeAncestry(t *testing.T) {
	conn, _ := connectedUnixPair(t)
	audit := discardAuditLog(t)
	called := false
	signer := testSigner(t)
	g := &gatekeeper{
		key: eagerKey{signer: signer}, rules: selfCodesignRules(t, ""), audit: audit,
		notify: func(string, string) {}, selfUID: uint32(os.Getuid() + 1), conn: conn,
		ancestry: func(int) []procInfo { called = true; return nil },
	}
	if _, err := g.Sign(signer.PublicKey(), []byte("x")); err == nil {
		t.Fatal("다른 UID가 서명됨")
	}
	if called {
		t.Fatal("UID 불일치인데 조상 조회가 실행됨")
	}
}

func TestPeerStabilityRecheckedAfterUnlockBeforeSigning(t *testing.T) {
	conn, _ := connectedUnixPair(t)
	audit := discardAuditLog(t)
	signer := testSigner(t)
	checks := 0
	g := &gatekeeper{
		key: eagerKey{signer: signer}, rules: selfCodesignRules(t, ""), audit: audit,
		notify: func(string, string) {}, selfUID: uint32(os.Getuid()), conn: conn,
		ancestry: func(pid int) []procInfo { return []procInfo{{pid: pid, exePath: "/test/client"}} },
		stability: func() error {
			checks++
			if checks == 2 {
				return errors.New("피어 변경 재현")
			}
			return nil
		},
	}
	if _, err := g.Sign(signer.PublicKey(), []byte("x")); err == nil {
		t.Fatal("잠금 해제 뒤 피어가 바뀌었는데 서명됨")
	}
	if checks != 2 {
		t.Fatalf("안정성 검사 횟수=%d, 기대 2", checks)
	}
}

func TestExtensionRejectedAndLogged(t *testing.T) {
	conn, _ := connectedUnixPair(t)
	path := filepath.Join(t.TempDir(), "audit.log")
	audit, err := newAuditLog(path, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	g := &gatekeeper{audit: audit, conn: conn}
	if _, err := g.Extension("example@vendor", nil); !errors.Is(err, agent.ErrExtensionUnsupported) {
		t.Fatalf("확장 거부 오류 이상: %v", err)
	}
	if got := readLog(t, path); !strings.Contains(got, "EXTENSION unsupported") || !strings.Contains(got, "example@vendor") || strings.Contains(got, "DENY extension") {
		t.Fatalf("확장 거부 로그 없음: %s", got)
	}
}

func TestShutdownDrainPreservesAllowAudit(t *testing.T) {
	conn, _ := connectedUnixPair(t)
	path := filepath.Join(t.TempDir(), "audit.log")
	audit, err := newAuditLog(path, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	base := testSigner(t)
	blocked := &blockingSigner{Signer: base, started: make(chan struct{}), release: make(chan struct{})}
	requests := newRequestTracker()
	g := &gatekeeper{
		key: eagerKey{signer: blocked}, rules: selfCodesignRules(t, ""), audit: audit,
		notify: func(string, string) {}, selfUID: uint32(os.Getuid()), conn: conn, requests: requests,
	}
	signDone := make(chan error, 1)
	go func() {
		_, err := g.Sign(base.PublicKey(), []byte("drain"))
		signDone <- err
	}()
	<-blocked.started
	requests.stop()
	waitDone := make(chan struct{})
	go func() { requests.wait(); close(waitDone) }()
	select {
	case <-waitDone:
		t.Fatal("진행 중 서명 전에 drain 완료")
	case <-time.After(50 * time.Millisecond):
	}
	close(blocked.release)
	if err := <-signDone; err != nil {
		t.Fatal(err)
	}
	<-waitDone
	if got := readLog(t, path); !strings.Contains(got, "ALLOW sign") {
		t.Fatalf("drain 뒤 ALLOW 감사 줄 유실: %s", got)
	}
}

// 승인 창 통합: allowlist에 없는 요청(이 테스트 바이너리)이 가짜 창의
// "이번만"으로 서명받는지. 실제 조상 사슬이 launchd까지 걸어져야 성립한다.
func TestSignAskApprovedOnce(t *testing.T) {
	ask := newAsker(filepath.Join(t.TempDir(), "approvals.conf"), nil, nil, t.Logf)
	var calls atomic.Int32
	ask.prompt = func(text string) (askChoice, error) {
		calls.Add(1)
		if !strings.Contains(text, "요청 프로그램:") {
			t.Errorf("창 본문에 요청 정보 없음: %q", text)
		}
		return askOnce, nil
	}
	rules := mustParse(t, "ask on")
	cl := dialAgent(t, startServerFull(t, rules, nil, ask))
	keys, err := cl.List()
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("ask sign")
	sig, err := cl.Sign(keys[0], data)
	if err != nil {
		t.Fatalf("승인했는데 거부: %v", err)
	}
	if err := keys[0].Verify(data, sig); err != nil {
		t.Fatalf("서명 검증 실패: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("창 호출 %d회(기대 1)", calls.Load())
	}
}

// 승인 창 통합: 명시적 거부는 서명이 거부되고, 재시도에도 창이 다시 뜨지 않는다.
func TestSignAskDeniedRemembered(t *testing.T) {
	ask := newAsker(filepath.Join(t.TempDir(), "approvals.conf"), nil, nil, t.Logf)
	var calls atomic.Int32
	ask.prompt = func(_ string) (askChoice, error) {
		calls.Add(1)
		return askDenied, nil
	}
	rules := mustParse(t, "ask on")
	cl := dialAgent(t, startServerFull(t, rules, nil, ask))
	keys, err := cl.List()
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 2; i++ {
		if _, err := cl.Sign(keys[0], []byte("x")); err == nil {
			t.Fatalf("%d번째: 거부했는데 서명됨", i)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("거부 기억인데 창이 %d회(기대 1)", calls.Load())
	}
}

func TestMutationsAlwaysDenied(t *testing.T) {
	cl := dialAgent(t, startServer(t, selfCodesignRules(t, "")))
	if err := cl.RemoveAll(); err == nil {
		t.Error("RemoveAll이 허용됨")
	}
	if err := cl.Lock([]byte("pw")); err == nil {
		t.Error("Lock이 허용됨")
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := cl.Add(agent.AddedKey{PrivateKey: priv, Comment: "evil"}); err == nil {
		t.Error("Add가 허용됨")
	}
}

func TestLoadSignerRejectsUnencryptedKey(t *testing.T) {
	keyPath := genTestKey(t, "")
	_, err := loadSigner(keyPath, false)
	if err == nil || !strings.Contains(err.Error(), "passphrase 없는 키") {
		t.Fatalf("암호화 안 된 키 거부 실패: %v", err)
	}
}

func TestLoadSignerMissingFile(t *testing.T) {
	if _, err := loadSigner(filepath.Join(t.TempDir(), "ghost"), false); err == nil {
		t.Fatal("없는 키 파일인데 통과")
	}
}

func TestRejectsEncryptedRSAKeyAndPublicKey(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "rsa-key")
	out, err := exec.Command("/usr/bin/ssh-keygen",
		"-q", "-t", "rsa", "-b", "2048", "-f", keyPath, "-N", "test-pass", "-C", "pasu-rsa-test").CombinedOutput()
	if err != nil {
		t.Fatalf("RSA 테스트 키 생성: %v\n%s", err, out)
	}
	if _, err := loadPublicKey(keyPath + ".pub"); err == nil || !strings.Contains(err.Error(), "ed25519만 사용") {
		t.Fatalf("RSA 공개키가 거부되지 않음: %v", err)
	}
	if _, err := ensureKeyMatches(keyPath, []byte("test-pass"), false); err == nil || !strings.Contains(err.Error(), "ed25519만 사용") {
		t.Fatalf("RSA 개인키가 거부되지 않음: %v", err)
	}
}
