package main

import (
	"net"
	"os"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh/agent"
)

type v2AgentHarness struct {
	client   agent.ExtendedAgent
	manager  *v2KeyManager
	registry *v2Registry
	core     *v2AgentCore
	listener net.Listener
}

func startV2AgentHarness(t *testing.T, choice askChoice) *v2AgentHarness {
	t.Helper()
	manager, _ := newTestV2Manager(t)
	record, err := manager.create("Harness", keyAuthCached, []byte("harness passphrase with enough length"))
	if err != nil {
		t.Fatal(err)
	}
	audit := discardAuditLog(t)
	var prompts atomic.Int32
	prompt := newV2PromptCoordinator(0, func(v2PromptRequest) (askChoice, error) {
		prompts.Add(1)
		return choice, nil
	}, audit.logf)
	core := newV2AgentCore(manager, manager.reg, prompt, audit, nil, newRequestTracker(), uint32(os.Getuid()))
	sock := shortTempSocket(t)
	listener, err := net.Listen("unix", sock)
	if err != nil {
		core.close()
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			unixConn := conn.(*net.UnixConn)
			go func() {
				defer unixConn.Close()
				agent.ServeAgent(&v2Gatekeeper{core: core, conn: unixConn}, unixConn)
			}()
		}
	}()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		listener.Close()
		core.close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		conn.Close()
		listener.Close()
		core.close()
	})
	_ = record
	return &v2AgentHarness{
		client: agent.NewClient(conn).(agent.ExtendedAgent), manager: manager,
		registry: manager.reg, core: core, listener: listener,
	}
}

func withTrustedTestSigningIdentities(t *testing.T) {
	t.Helper()
	old := signingInfoForProcFn
	signingInfoForProcFn = func(proc procInfo) (codeIdentity, error) {
		return codeIdentity{Kind: codeIdentityApple, Identifier: "test:" + proc.exePath}, nil
	}
	t.Cleanup(func() { signingInfoForProcFn = old })
}

func TestV2AgentAlwaysAllowPersistsAfterSuccessfulSign(t *testing.T) {
	withTrustedTestSigningIdentities(t)
	h := startV2AgentHarness(t, askAlways)
	keys, err := h.client.List()
	if err != nil || len(keys) != 1 {
		t.Fatalf("List keys=%d err=%v", len(keys), err)
	}
	if _, err := h.client.Sign(keys[0], []byte("first")); err != nil {
		t.Fatal(err)
	}
	records := h.registry.keys()
	if len(records[0].Rules) != 1 || records[0].Rules[0].Decision != ruleAllow {
		t.Fatalf("rules=%+v", records[0].Rules)
	}
	if _, err := h.client.Sign(keys[0], []byte("second")); err != nil {
		t.Fatal(err)
	}
}

func TestV2AgentPersistentDenyFiltersList(t *testing.T) {
	withTrustedTestSigningIdentities(t)
	h := startV2AgentHarness(t, askDenied)
	keys, err := h.client.List()
	if err != nil || len(keys) != 1 {
		t.Fatalf("List keys=%d err=%v", len(keys), err)
	}
	if _, err := h.client.Sign(keys[0], []byte("deny")); err == nil {
		t.Fatal("영구 거부인데 서명됨")
	}
	keys, err = h.client.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("영구 거부 뒤 List keys=%d", len(keys))
	}
}

func TestV2AgentAlwaysAllowNotSavedWhenUnlockFails(t *testing.T) {
	withTrustedTestSigningIdentities(t)
	h := startV2AgentHarness(t, askAlways)
	record := h.registry.keys()[0]
	store := h.manager.store.(*memoryV2Store)
	store.mu.Lock()
	store.secrets[memorySecretKey(record.ID, true)] = []byte("broken")
	store.mu.Unlock()
	keys, err := h.client.List()
	if err != nil || len(keys) != 1 {
		t.Fatalf("List keys=%d err=%v", len(keys), err)
	}
	if _, err := h.client.Sign(keys[0], []byte("unlock-fails")); err == nil {
		t.Fatal("손상 secret인데 서명됨")
	}
	if rules := h.registry.keys()[0].Rules; len(rules) != 0 {
		t.Fatalf("실패한 서명 뒤 allow 규칙이 저장됨: %+v", rules)
	}
}
