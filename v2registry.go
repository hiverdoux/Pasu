package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"
)

var errV2RegistryMissing = errors.New("v2 registry 없음")

type v2Store interface {
	LoadRegistry() ([]byte, error)
	SaveRegistry([]byte) error
	AddSecret(id string, payload []byte, requirePresence bool) error
	ReadSecret(id, reason string, requirePresence bool) ([]byte, error)
	DeleteSecret(id string, requirePresence bool) error
}

type v2Registry struct {
	mu    sync.RWMutex
	store v2Store
	data  v2RegistryData
	now   func() time.Time
}

func loadV2Registry(store v2Store) (*v2Registry, error) {
	data, err := store.LoadRegistry()
	if err != nil {
		return nil, err
	}
	var decoded v2RegistryData
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&decoded); err != nil {
		return nil, fmt.Errorf("v2 registry 해석 실패: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("v2 registry 뒤에 예상하지 않은 데이터가 있음")
	}
	if err := validateRegistry(decoded); err != nil {
		return nil, fmt.Errorf("v2 registry 검증 실패: %w", err)
	}
	return &v2Registry{store: store, data: decoded, now: time.Now}, nil
}

func createV2Registry(store v2Store, pendingMigration bool) (*v2Registry, error) {
	r := &v2Registry{store: store, data: defaultV2Registry(), now: time.Now}
	r.data.MigrationPending = pendingMigration
	if err := r.persistLocked(r.data); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *v2Registry) snapshot() v2RegistryData {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return cloneRegistry(r.data)
}

func cloneRegistry(in v2RegistryData) v2RegistryData {
	out := in
	out.Keys = make([]managedKeyRecord, len(in.Keys))
	for i := range in.Keys {
		out.Keys[i] = in.Keys[i]
		out.Keys[i].Rules = append([]chainRule(nil), in.Keys[i].Rules...)
	}
	return out
}

func (r *v2Registry) persistLocked(next v2RegistryData) error {
	if err := validateRegistry(next); err != nil {
		return err
	}
	data, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if len(data) > maxControlMessage {
		return fmt.Errorf("v2 registry가 안전 크기 한도 %d바이트를 넘음", maxControlMessage)
	}
	if err := r.store.SaveRegistry(data); err != nil {
		return err
	}
	r.data = next
	return nil
}

func (r *v2Registry) mutate(fn func(*v2RegistryData) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	next := cloneRegistry(r.data)
	if err := fn(&next); err != nil {
		return err
	}
	return r.persistLocked(next)
}

func findKeyIndex(data *v2RegistryData, id string) int {
	for i := range data.Keys {
		if data.Keys[i].ID == id {
			return i
		}
	}
	return -1
}

func (r *v2Registry) key(id string) (managedKeyRecord, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	idx := findKeyIndex(&r.data, id)
	if idx < 0 {
		return managedKeyRecord{}, false
	}
	key := r.data.Keys[idx]
	key.Rules = append([]chainRule(nil), key.Rules...)
	return key, true
}

func (r *v2Registry) keys() []managedKeyRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	keys := make([]managedKeyRecord, len(r.data.Keys))
	for i := range r.data.Keys {
		keys[i] = r.data.Keys[i]
		keys[i].Rules = append([]chainRule(nil), r.data.Keys[i].Rules...)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].CreatedAt.Before(keys[j].CreatedAt)
	})
	return keys
}

type chainPolicyState string

const (
	chainUnknown chainPolicyState = "unknown"
	chainAllowed chainPolicyState = "allowed"
	chainDenied  chainPolicyState = "denied"
)

func classifyRules(rules []chainRule, chain stableChain) (chainPolicyState, string) {
	return classifyRulesWithMode(rules, chain, chainCheckFull)
}

func classifyRulesWithMode(rules []chainRule, chain stableChain, mode chainCheckMode) (chainPolicyState, string) {
	allowID := ""
	for _, rule := range rules {
		if !chainMatchesMode(rule.Chain, chain, mode) {
			continue
		}
		if rule.Decision == ruleDeny {
			return chainDenied, rule.ID
		}
		if rule.Decision == ruleAllow {
			allowID = rule.ID
		}
	}
	if allowID != "" {
		return chainAllowed, allowID
	}
	return chainUnknown, ""
}

func (r *v2Registry) classify(id string, chain stableChain) (chainPolicyState, string, error) {
	key, ok := r.key(id)
	if !ok {
		return chainDenied, "", errors.New("모르는 키")
	}
	if !key.Enabled {
		return chainDenied, "", errors.New("비활성 키")
	}
	state, ruleID := classifyRulesWithMode(key.Rules, chain, key.ChainCheckMode)
	return state, ruleID, nil
}

func (r *v2Registry) addRule(id string, decision ruleDecision, chain stableChain) (chainRule, error) {
	rule, err := newChainRule(decision, chain, r.now())
	if err != nil {
		return chainRule{}, err
	}
	err = r.mutate(func(data *v2RegistryData) error {
		idx := findKeyIndex(data, id)
		if idx < 0 {
			return errors.New("모르는 키")
		}
		for _, existing := range data.Keys[idx].Rules {
			if existing.ID == rule.ID {
				rule = existing
				return nil
			}
		}
		data.Keys[idx].Rules = append(data.Keys[idx].Rules, rule)
		return nil
	})
	return rule, err
}

func (r *v2Registry) deleteRule(keyID, ruleID string) error {
	return r.mutate(func(data *v2RegistryData) error {
		idx := findKeyIndex(data, keyID)
		if idx < 0 {
			return errors.New("모르는 키")
		}
		rules := data.Keys[idx].Rules
		for i := range rules {
			if rules[i].ID == ruleID {
				data.Keys[idx].Rules = append(rules[:i], rules[i+1:]...)
				return nil
			}
		}
		return errors.New("모르는 규칙")
	})
}

func (r *v2Registry) setEnabled(id string, enabled bool) error {
	return r.mutate(func(data *v2RegistryData) error {
		idx := findKeyIndex(data, id)
		if idx < 0 {
			return errors.New("모르는 키")
		}
		data.Keys[idx].Enabled = enabled
		return nil
	})
}

func (r *v2Registry) renameKey(id, name, publicKey string) error {
	return r.mutate(func(data *v2RegistryData) error {
		idx := findKeyIndex(data, id)
		if idx < 0 {
			return errors.New("모르는 키")
		}
		data.Keys[idx].Name = name
		data.Keys[idx].PublicKey = publicKey
		return nil
	})
}

func (r *v2Registry) setAuthMode(id string, mode keyAuthMode) error {
	return r.mutate(func(data *v2RegistryData) error {
		idx := findKeyIndex(data, id)
		if idx < 0 {
			return errors.New("모르는 키")
		}
		data.Keys[idx].AuthMode = mode
		return nil
	})
}

func (r *v2Registry) appendKey(key managedKeyRecord) error {
	return r.mutate(func(data *v2RegistryData) error {
		data.Keys = append(data.Keys, key)
		return nil
	})
}

func (r *v2Registry) removeKey(id string) error {
	return r.mutate(func(data *v2RegistryData) error {
		idx := findKeyIndex(data, id)
		if idx < 0 {
			return errors.New("모르는 키")
		}
		data.Keys = append(data.Keys[:idx], data.Keys[idx+1:]...)
		return nil
	})
}

func (r *v2Registry) setMigrationPending(pending bool) error {
	return r.mutate(func(data *v2RegistryData) error {
		data.MigrationPending = pending
		return nil
	})
}

func (r *v2Registry) markUsed(keyID, ruleID string) error {
	return r.mutate(func(data *v2RegistryData) error {
		idx := findKeyIndex(data, keyID)
		if idx < 0 {
			return errors.New("모르는 키")
		}
		now := r.now().UTC()
		data.Keys[idx].LastUsed = &now
		for i := range data.Keys[idx].Rules {
			if data.Keys[idx].Rules[i].ID == ruleID {
				data.Keys[idx].Rules[i].LastUsed = &now
			}
		}
		return nil
	})
}

func (r *v2Registry) setChainCheckMode(id string, mode chainCheckMode) error {
	if mode != chainCheckFull && mode != chainCheckResponsible {
		return errors.New("잘못된 사슬 검사 방식")
	}
	return r.mutate(func(data *v2RegistryData) error {
		idx := findKeyIndex(data, id)
		if idx < 0 {
			return errors.New("모르는 키")
		}
		// 기본값은 생략해서 전체 사슬 검사로 되돌리면 기존 저장 형식도 유지한다.
		if mode == chainCheckFull {
			mode = ""
		}
		data.Keys[idx].ChainCheckMode = mode
		return nil
	})
}
