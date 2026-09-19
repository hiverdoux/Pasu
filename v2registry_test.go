package main

import (
	"errors"
	"sync"
	"testing"
	"time"
)

type memoryV2Store struct {
	mu              sync.Mutex
	registry        []byte
	secrets         map[string][]byte
	failSave        bool
	reads           int
	protectedReads  int
	unattendedReads int
}

func newMemoryV2Store() *memoryV2Store { return &memoryV2Store{secrets: make(map[string][]byte)} }

func memorySecretKey(id string, requirePresence bool) string {
	if requirePresence {
		return "protected:" + id
	}
	return "unattended:" + id
}

func (s *memoryV2Store) LoadRegistry() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.registry == nil {
		return nil, errV2RegistryMissing
	}
	return append([]byte(nil), s.registry...), nil
}

func (s *memoryV2Store) SaveRegistry(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failSave {
		return errors.New("save failed")
	}
	s.registry = append([]byte(nil), data...)
	return nil
}

func (s *memoryV2Store) AddSecret(id string, payload []byte, requirePresence bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := memorySecretKey(id, requirePresence)
	if _, ok := s.secrets[key]; ok {
		return errors.New("duplicate secret")
	}
	s.secrets[key] = append([]byte(nil), payload...)
	return nil
}

func (s *memoryV2Store) ReadSecret(id, _ string, requirePresence bool) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	if requirePresence {
		s.protectedReads++
	} else {
		s.unattendedReads++
	}
	data, ok := s.secrets[memorySecretKey(id, requirePresence)]
	if !ok {
		return nil, errors.New("missing secret")
	}
	return append([]byte(nil), data...), nil
}

func (s *memoryV2Store) DeleteSecret(id string, requirePresence bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.secrets, memorySecretKey(id, requirePresence))
	return nil
}

func registryTestKey(t *testing.T, name, fp string) managedKeyRecord {
	t.Helper()
	id, err := newKeyID()
	if err != nil {
		t.Fatal(err)
	}
	return managedKeyRecord{
		ID: id, Name: name, Fingerprint: fp, PublicKey: "ssh-ed25519 AAAA", AuthMode: keyAuthCached,
		Enabled: true, CreatedAt: time.Unix(1, 0).UTC(),
	}
}

func TestV2RegistryRuleLifecycle(t *testing.T) {
	store := newMemoryV2Store()
	r, err := createV2Registry(store, false)
	if err != nil {
		t.Fatal(err)
	}
	key := registryTestKey(t, "one", "SHA256:one")
	if err := r.appendKey(key); err != nil {
		t.Fatal(err)
	}
	chain := testStableChain(t, ttyForeground)
	if state, _, err := r.classify(key.ID, chain); err != nil || state != chainUnknown {
		t.Fatalf("초기 상태=%s err=%v", state, err)
	}
	allow, err := r.addRule(key.ID, ruleAllow, chain)
	if err != nil {
		t.Fatal(err)
	}
	if state, id, _ := r.classify(key.ID, chain); state != chainAllowed || id != allow.ID {
		t.Fatalf("허용 상태=%s id=%s", state, id)
	}
	deny, err := r.addRule(key.ID, ruleDeny, chain)
	if err != nil {
		t.Fatal(err)
	}
	if state, id, _ := r.classify(key.ID, chain); state != chainDenied || id != deny.ID {
		t.Fatalf("거부 우선순위=%s id=%s", state, id)
	}
	if err := r.deleteRule(key.ID, deny.ID); err != nil {
		t.Fatal(err)
	}
	if state, _, _ := r.classify(key.ID, chain); state != chainAllowed {
		t.Fatalf("거부 삭제 뒤=%s", state)
	}
}

func TestV2RegistryMutationIsAtomicOnStoreFailure(t *testing.T) {
	store := newMemoryV2Store()
	r, err := createV2Registry(store, false)
	if err != nil {
		t.Fatal(err)
	}
	key := registryTestKey(t, "one", "SHA256:one")
	if err := r.appendKey(key); err != nil {
		t.Fatal(err)
	}
	store.failSave = true
	if err := r.setEnabled(key.ID, false); err == nil {
		t.Fatal("저장 실패가 전파되지 않음")
	}
	got, _ := r.key(key.ID)
	if !got.Enabled {
		t.Fatal("저장 실패인데 메모리 상태가 바뀜")
	}
}

func TestV2RegistryDenyPrecedesAllow(t *testing.T) {
	chain := testStableChain(t, ttyForeground)
	allow, _ := newChainRule(ruleAllow, chain, time.Now())
	deny, _ := newChainRule(ruleDeny, chain, time.Now())
	state, id := classifyRules([]chainRule{allow, deny}, chain)
	if state != chainDenied || id != deny.ID {
		t.Fatalf("state=%s id=%s", state, id)
	}
}
