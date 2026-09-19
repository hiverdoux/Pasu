package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestV2ChainModeMatchesOnlyResponsibleIdentity(t *testing.T) {
	base := testStableChain(t, ttyForeground)
	cases := []struct {
		name   string
		change func(*stableChain)
		match  bool
	}{
		{"same", func(c *stableChain) {}, true},
		{"tty", func(c *stableChain) { c.TTY = ttyBackground }, true},
		{"leaf", func(c *stableChain) { c.Members[0].Path = "/usr/bin/scp" }, true},
		{"wrapper", func(c *stableChain) { c.Members = append(c.Members[:1:1], c.Members...) }, true},
		{"descendant identity", func(c *stableChain) {
			c.Members[1].Identity = codeIdentity{Kind: codeIdentityUntrusted, Identifier: "untrusted"}
		}, true},
		{"responsible path", func(c *stableChain) { c.Members[2].Path = "/Applications/Other.app/Contents/MacOS/sample" }, false},
		{"responsible uid", func(c *stableChain) { c.Members[2].UID++ }, false},
		{"responsible team", func(c *stableChain) { c.Members[2].Identity.TeamID = "OTHERTEAM" }, false},
		{"responsible identifier", func(c *stableChain) { c.Members[2].Identity.Identifier = "example.other" }, false},
		{"responsible untrusted", func(c *stableChain) {
			c.Members[2].Identity = codeIdentity{Kind: codeIdentityUntrusted, Identifier: "untrusted"}
		}, false},
		{"missing launchd", func(c *stableChain) { c.Members = c.Members[:3] }, false},
		{"empty", func(c *stableChain) { c.Members = nil }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changed := testStableChain(t, ttyForeground)
			tc.change(&changed)
			if got := chainMatchesMode(base, changed, chainCheckResponsible); got != tc.match {
				t.Fatalf("match=%v want=%v", got, tc.match)
			}
			if got := chainMatchesMode(base, changed, ""); got != (tc.name == "same") {
				t.Fatalf("default full match=%v", got)
			}
		})
	}
	if chainMatchesMode(base, base, "invalid") {
		t.Fatal("unknown mode matched")
	}
}

func TestV2ChainModeDefaultPersistenceAndRulesPreserved(t *testing.T) {
	store := newMemoryV2Store()
	r, err := createV2Registry(store, false)
	if err != nil {
		t.Fatal(err)
	}
	key := registryTestKey(t, "sample", "SHA256:sample")
	other := registryTestKey(t, "other", "SHA256:other")
	for _, k := range []managedKeyRecord{key, other} {
		if err := r.appendKey(k); err != nil {
			t.Fatal(err)
		}
	}
	chain := testStableChain(t, ttyForeground)
	rule, err := r.addRule(key.ID, ruleAllow, chain)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.markUsed(key.ID, rule.ID); err != nil {
		t.Fatal(err)
	}
	before, _ := r.key(key.ID)
	original, _ := store.LoadRegistry()
	if bytes.Contains(original, []byte("chain_check_mode")) {
		t.Fatal("default must use legacy format")
	}
	r, err = loadV2Registry(store)
	if err != nil {
		t.Fatal(err)
	}
	changed := testStableChain(t, ttyBackground)
	changed.Members[1].Path = "/bin/bash"
	if state, _, _ := r.classify(key.ID, changed); state != chainUnknown {
		t.Fatal("old registry is not full-chain by default")
	}
	if err := r.setChainCheckMode(key.ID, chainCheckResponsible); err != nil {
		t.Fatal(err)
	}
	r, err = loadV2Registry(store)
	if err != nil {
		t.Fatal(err)
	}
	if state, id, _ := r.classify(key.ID, changed); state != chainAllowed || id != rule.ID {
		t.Fatalf("responsible state=%s id=%s", state, id)
	}
	gotOther, _ := r.key(other.ID)
	if gotOther.ChainCheckMode.effective() != chainCheckFull {
		t.Fatal("other key mode changed")
	}
	after, _ := r.key(key.ID)
	if !reflect.DeepEqual(before.Rules, after.Rules) {
		t.Fatal("mode changed rule metadata")
	}
	store.failSave = true
	if err := r.setChainCheckMode(key.ID, chainCheckFull); err == nil {
		t.Fatal("save failure ignored")
	}
	after, _ = r.key(key.ID)
	if after.ChainCheckMode != chainCheckResponsible {
		t.Fatal("save failure changed mode")
	}
	store.failSave = false
	if err := r.setChainCheckMode(key.ID, chainCheckFull); err != nil {
		t.Fatal(err)
	}
	restored, _ := store.LoadRegistry()
	if !bytes.Equal(original, restored) {
		t.Fatal("full-chain round trip changed stored data")
	}
	if state, _, _ := r.classify(key.ID, changed); state != chainUnknown {
		t.Fatal("full-chain did not restore exact matching")
	}
	if err := r.setChainCheckMode(key.ID, "invalid"); err == nil {
		t.Fatal("invalid mode accepted")
	}
	data := r.snapshot()
	data.Keys[0].ChainCheckMode = "invalid"
	store.registry, _ = json.Marshal(data)
	if _, err := loadV2Registry(store); err == nil {
		t.Fatal("invalid saved mode accepted")
	}
}

func TestV2ChainModeDenyWinsAcrossDifferentChains(t *testing.T) {
	a := testStableChain(t, ttyForeground)
	b := testStableChain(t, ttyBackground)
	b.Members[1].Path = "/bin/bash"
	allow, _ := newChainRule(ruleAllow, a, time.Now())
	deny, _ := newChainRule(ruleDeny, b, time.Now())
	for _, rules := range [][]chainRule{{allow, deny}, {deny, allow}} {
		state, id := classifyRulesWithMode(rules, a, chainCheckResponsible)
		if state != chainDenied || id != deny.ID {
			t.Fatal("responsible deny must win regardless of order")
		}
		state, id = classifyRulesWithMode(rules, a, chainCheckFull)
		if state != chainAllowed || id != allow.ID {
			t.Fatal("full-chain unexpectedly broadened deny")
		}
	}
}

func TestV2ControlChainModeAuthenticatesAndPreservesCache(t *testing.T) {
	server, manager, registry := newTestControlServer(t)
	record, err := manager.create("sample", keyAuthCached, []byte("sample passphrase long enough"))
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.unlock(record.ID); err != nil {
		t.Fatal(err)
	}
	store := manager.store.(*memoryV2Store)
	before := store.protectedReads
	response := server.handle(v2ControlRequest{Action: "set_chain_check_mode", KeyID: record.ID, ChainCheckMode: string(chainCheckResponsible)})
	if response.Error != "" || response.Keys[0].ChainCheckMode != chainCheckResponsible || !response.Keys[0].Unlocked {
		t.Fatalf("response=%+v", response)
	}
	if store.protectedReads != before+1 {
		t.Fatal("mode change did not authenticate")
	}
	secret := memorySecretKey(record.ID, true)
	saved := store.secrets[secret]
	delete(store.secrets, secret)
	if err := manager.setChainCheckMode(record.ID, chainCheckFull); err == nil {
		t.Fatal("authentication failure ignored")
	}
	got, _ := registry.key(record.ID)
	if got.ChainCheckMode != chainCheckResponsible {
		t.Fatal("failed authentication changed mode")
	}
	store.secrets[secret] = saved
	if err := manager.setChainCheckMode(record.ID, chainCheckFull); err != nil {
		t.Fatal(err)
	}
	if server.keyViews()[0].ChainCheckMode != chainCheckFull {
		t.Fatal("default not normalized in response")
	}
	for _, mode := range []string{"", "invalid"} {
		if res := server.handle(v2ControlRequest{Action: "set_chain_check_mode", KeyID: record.ID, ChainCheckMode: mode}); res.Error == "" {
			t.Fatal("invalid control mode accepted")
		}
	}
}

func TestV2AgentChainModeUsedForListAndSign(t *testing.T) {
	withTrustedTestSigningIdentities(t)
	h := startV2AgentHarness(t, askAlways)
	keys, err := h.client.List()
	if err != nil || len(keys) != 1 {
		t.Fatalf("keys=%v err=%v", keys, err)
	}
	record := h.registry.keys()[0]
	if err := h.manager.setChainCheckMode(record.ID, chainCheckResponsible); err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.Sign(keys[0], []byte("initial")); err != nil {
		t.Fatal(err)
	}
	rule := h.registry.keys()[0].Rules[0]
	if len(rule.Chain.Members) < 2 || rule.Chain.Members[len(rule.Chain.Members)-1].Path != "/sbin/launchd" {
		t.Fatal("responsible mode did not persist full chain")
	}
	altered := rule.Chain
	altered.Members = append([]stableProcess(nil), rule.Chain.Members...)
	altered.Members[0].Path = "/usr/bin/sample-other"
	altered.TTY = ttyBackground
	if err := h.registry.deleteRule(record.ID, rule.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.registry.addRule(record.ID, ruleAllow, altered); err != nil {
		t.Fatal(err)
	}
	var prompts atomic.Int32
	h.core.prompt.handler = func(v2PromptRequest) (askChoice, error) { prompts.Add(1); return askOnce, nil }
	if _, err := h.client.Sign(keys[0], []byte("responsible reuse")); err != nil {
		t.Fatal(err)
	}
	if prompts.Load() != 0 {
		t.Fatal("responsible allow did not match")
	}
	if err := h.manager.setChainCheckMode(record.ID, chainCheckFull); err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.Sign(keys[0], []byte("full unknown")); err != nil {
		t.Fatal(err)
	}
	if prompts.Load() != 1 {
		t.Fatal("full-chain failed to prompt")
	}
	if _, err := h.registry.addRule(record.ID, ruleDeny, altered); err != nil {
		t.Fatal(err)
	}
	listed, err := h.client.List()
	if err != nil || len(listed) != 1 {
		t.Fatal("full-chain wrongly filtered")
	}
	if err := h.manager.setChainCheckMode(record.ID, chainCheckResponsible); err != nil {
		t.Fatal(err)
	}
	listed, err = h.client.List()
	if err != nil || len(listed) != 0 {
		t.Fatal("responsible deny did not filter List")
	}
	if _, err := h.client.Sign(keys[0], []byte("deny direct")); err == nil {
		t.Fatal("responsible deny permitted Sign")
	}
	if prompts.Load() != 1 {
		t.Fatal("deny prompted")
	}
}

func TestV2ChainModeWaitsForActiveRequests(t *testing.T) {
	manager, _ := newTestV2Manager(t)
	record, err := manager.create("sample", keyAuthCached, []byte("sample passphrase long enough"))
	if err != nil {
		t.Fatal(err)
	}
	runtime, _ := manager.runtime(record.ID)
	if !runtime.beginSign() {
		t.Fatal("cannot begin request")
	}
	done := make(chan error, 1)
	go func() { done <- manager.setChainCheckMode(record.ID, chainCheckResponsible) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		runtime.mu.Lock()
		paused := runtime.deleting
		runtime.mu.Unlock()
		if paused {
			break
		}
		if time.Now().After(deadline) {
			runtime.endSign()
			t.Fatal("mode change did not pause requests")
		}
		time.Sleep(time.Millisecond)
	}
	old, _ := manager.reg.key(record.ID)
	if old.ChainCheckMode.effective() != chainCheckFull {
		runtime.endSign()
		t.Fatal("mode changed during request")
	}
	if runtime.beginSign() {
		runtime.endSign()
		runtime.endSign()
		t.Fatal("new request entered during change")
	}
	runtime.endSign()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("mode change failed to resume")
	}
	if !runtime.beginSign() {
		t.Fatal("requests not resumed")
	}
	runtime.endSign()
	updated, _ := manager.reg.key(record.ID)
	if updated.ChainCheckMode != chainCheckResponsible {
		t.Fatal("mode not saved")
	}
}
