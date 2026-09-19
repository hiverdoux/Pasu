package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const v2RegistryVersion = 2
const maxControlMessage = 1 << 20

type keyAuthMode string

const (
	keyAuthCached  keyAuthMode = "cached"
	keyAuthPerSign keyAuthMode = "per-sign"
	keyAuthNone    keyAuthMode = "none"
)

func (m keyAuthMode) valid() bool {
	return m == keyAuthCached || m == keyAuthPerSign || m == keyAuthNone
}

func (m keyAuthMode) requiresPresence() bool { return m != keyAuthNone }

func (m keyAuthMode) label() string {
	switch m {
	case keyAuthCached:
		return "첫 인증 후 agent 종료까지"
	case keyAuthPerSign:
		return "매번 인증"
	case keyAuthNone:
		return "인증 없음"
	default:
		return string(m)
	}
}

// 빈 값은 기존 registry와 새 키의 기본값인 전체 사슬 검사다.
type chainCheckMode string

const (
	chainCheckFull        chainCheckMode = "full-chain"
	chainCheckResponsible chainCheckMode = "responsible-only"
)

func (m chainCheckMode) effective() chainCheckMode {
	if m == "" {
		return chainCheckFull
	}
	return m
}

func (m chainCheckMode) valid() bool {
	return m.effective() == chainCheckFull || m == chainCheckResponsible
}

// 규칙 원본은 항상 전체 사슬이다. 이 함수는 적용할 때만 비교 범위를 정한다.
func chainMatchesMode(a, b stableChain, mode chainCheckMode) bool {
	switch mode.effective() {
	case chainCheckFull:
		return stableChainEqual(a, b)
	case chainCheckResponsible:
		if len(a.Members) < 2 || len(b.Members) < 2 ||
			a.Members[len(a.Members)-1].Path != "/sbin/launchd" ||
			b.Members[len(b.Members)-1].Path != "/sbin/launchd" {
			return false
		}
		return a.Members[len(a.Members)-2] == b.Members[len(b.Members)-2]
	default:
		return false
	}
}

type ttyClass string

const (
	ttyNone       ttyClass = "none"
	ttyForeground ttyClass = "foreground"
	ttyBackground ttyClass = "background"
)

type stableProcess struct {
	Path     string       `json:"path"`
	UID      uint32       `json:"uid"`
	Identity codeIdentity `json:"identity"`
}

type stableChain struct {
	TTY     ttyClass        `json:"tty"`
	Members []stableProcess `json:"members"`
}

type ruleDecision string

const (
	ruleAllow ruleDecision = "allow"
	ruleDeny  ruleDecision = "deny"
)

type chainRule struct {
	ID        string       `json:"id"`
	Decision  ruleDecision `json:"decision"`
	Chain     stableChain  `json:"chain"`
	CreatedAt time.Time    `json:"created_at"`
	LastUsed  *time.Time   `json:"last_used,omitempty"`
}

type managedKeyRecord struct {
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	Fingerprint    string         `json:"fingerprint"`
	PublicKey      string         `json:"public_key"`
	AuthMode       keyAuthMode    `json:"auth_mode"`
	ChainCheckMode chainCheckMode `json:"chain_check_mode,omitempty"`
	Enabled        bool           `json:"enabled"`
	CreatedAt      time.Time      `json:"created_at"`
	LastUsed       *time.Time     `json:"last_used,omitempty"`
	Rules          []chainRule    `json:"rules,omitempty"`
}

type v2GlobalSettings struct {
	RateCount      int           `json:"rate_count"`
	RateWindow     time.Duration `json:"rate_window"`
	LogSize        int64         `json:"log_size"`
	AskCooldown    time.Duration `json:"ask_cooldown"`
	NotifyCooldown time.Duration `json:"notify_cooldown"`
}

type v2RegistryData struct {
	Version          int                `json:"version"`
	MigrationPending bool               `json:"migration_pending,omitempty"`
	Settings         v2GlobalSettings   `json:"settings"`
	Keys             []managedKeyRecord `json:"keys"`
}

func defaultV2Registry() v2RegistryData {
	return v2RegistryData{
		Version: v2RegistryVersion,
		Settings: v2GlobalSettings{
			RateCount:      defaultRateLimit.max,
			RateWindow:     defaultRateLimit.window,
			LogSize:        int64(defaultLogSize),
			AskCooldown:    defaultAskCooldown,
			NotifyCooldown: defaultNotifyCooldown,
		},
	}
}

func newKeyID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func validKeyID(id string) bool {
	if id != strings.ToLower(id) || len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return false
	}
	_, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
	return err == nil
}

func chainTTY(chain []procInfo) ttyClass {
	if len(chain) == 0 || chain[0].tdev == -1 || chain[0].tdev == 0 || chain[0].tpgid <= 0 {
		return ttyNone
	}
	if chain[0].pgid == chain[0].tpgid {
		return ttyForeground
	}
	return ttyBackground
}

func stabilizeChain(chain []procInfo) (stableChain, bool, error) {
	if len(chain) < 2 || chain[len(chain)-1].pid != 1 {
		return stableChain{}, false, errors.New("launchd까지 완전한 사슬이 아님")
	}
	stable := stableChain{TTY: chainTTY(chain), Members: make([]stableProcess, 0, len(chain))}
	trusted := true
	for _, proc := range chain {
		if proc.exePath == "" {
			return stableChain{}, false, fmt.Errorf("pid %d의 실행 경로 없음", proc.pid)
		}
		identity, err := signingInfoForProcFn(proc)
		if err != nil {
			trusted = false
			identity = codeIdentity{Kind: codeIdentityUntrusted, Identifier: "untrusted"}
		}
		stable.Members = append(stable.Members, stableProcess{
			Path:     normalizePath(proc.exePath),
			UID:      proc.uid,
			Identity: identity,
		})
	}
	return stable, trusted, nil
}

func stableChainTrusted(chain stableChain) bool {
	if len(chain.Members) == 0 {
		return false
	}
	for _, member := range chain.Members {
		if member.Identity.Kind != codeIdentityApple && member.Identity.Kind != codeIdentityDeveloper {
			return false
		}
	}
	return true
}

func stableChainEqual(a, b stableChain) bool {
	if a.TTY != b.TTY || len(a.Members) != len(b.Members) {
		return false
	}
	for i := range a.Members {
		if a.Members[i] != b.Members[i] {
			return false
		}
	}
	return true
}

func chainRuleID(decision ruleDecision, chain stableChain) (string, error) {
	payload := struct {
		Domain   string       `json:"domain"`
		Decision ruleDecision `json:"decision"`
		Chain    stableChain  `json:"chain"`
	}{Domain: "pasu-chain-rule-v2", Decision: decision, Chain: chain}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func newChainRule(decision ruleDecision, chain stableChain, now time.Time) (chainRule, error) {
	if decision != ruleAllow && decision != ruleDeny {
		return chainRule{}, errors.New("잘못된 사슬 규칙 결정")
	}
	id, err := chainRuleID(decision, chain)
	if err != nil {
		return chainRule{}, err
	}
	return chainRule{ID: id, Decision: decision, Chain: chain, CreatedAt: now.UTC()}, nil
}

func validateRegistry(data v2RegistryData) error {
	if data.Version != v2RegistryVersion {
		return fmt.Errorf("registry version=%d, 필요=%d", data.Version, v2RegistryVersion)
	}
	names := make(map[string]bool)
	ids := make(map[string]bool)
	fingerprints := make(map[string]bool)
	for i := range data.Keys {
		key := &data.Keys[i]
		if !validKeyID(key.ID) {
			return fmt.Errorf("잘못된 키 UUID: %q", key.ID)
		}
		if ids[key.ID] {
			return fmt.Errorf("중복 키 UUID: %s", key.ID)
		}
		ids[key.ID] = true
		name := strings.TrimSpace(key.Name)
		if name == "" || len([]byte(name)) > 128 {
			return fmt.Errorf("키 %s의 이름이 비었거나 너무 김", key.ID)
		}
		for _, r := range name {
			if r < 0x20 || r == 0x7f {
				return fmt.Errorf("키 %s의 이름에 제어문자가 있음", key.ID)
			}
		}
		folded := strings.ToLower(name)
		if names[folded] {
			return fmt.Errorf("중복 키 이름: %s", name)
		}
		names[folded] = true
		if key.Fingerprint == "" || fingerprints[key.Fingerprint] {
			return fmt.Errorf("키 %s의 지문이 비었거나 중복됨", key.ID)
		}
		fingerprints[key.Fingerprint] = true
		if !key.AuthMode.valid() {
			return fmt.Errorf("키 %s의 인증 방식이 잘못됨", key.ID)
		}
		if !key.ChainCheckMode.valid() {
			return fmt.Errorf("키 %s의 사슬 검사 방식이 잘못됨", key.ID)
		}
		seenRules := make(map[string]bool)
		for _, rule := range key.Rules {
			if rule.Decision != ruleAllow && rule.Decision != ruleDeny {
				return fmt.Errorf("키 %s의 규칙 결정이 잘못됨", key.ID)
			}
			if rule.Decision == ruleAllow && !stableChainTrusted(rule.Chain) {
				return fmt.Errorf("키 %s의 허용 규칙에 신뢰할 수 없는 코드가 있음", key.ID)
			}
			if rule.Chain.TTY != ttyNone && rule.Chain.TTY != ttyForeground && rule.Chain.TTY != ttyBackground {
				return fmt.Errorf("키 %s의 규칙 TTY 값이 잘못됨", key.ID)
			}
			if len(rule.Chain.Members) < 2 || len(rule.Chain.Members) > maxAncestors ||
				rule.Chain.Members[len(rule.Chain.Members)-1].Path != "/sbin/launchd" {
				return fmt.Errorf("키 %s의 규칙 사슬이 launchd까지 완전하지 않음", key.ID)
			}
			for _, member := range rule.Chain.Members {
				if !strings.HasPrefix(member.Path, "/") || len(member.Path) > 4096 || normalizePath(member.Path) != member.Path ||
					member.Identity.Identifier == "" {
					return fmt.Errorf("키 %s의 규칙 구성원 형식이 잘못됨", key.ID)
				}
				switch member.Identity.Kind {
				case codeIdentityApple:
					if member.Identity.TeamID != "" {
						return fmt.Errorf("키 %s의 Apple 규칙에 Team ID가 있음", key.ID)
					}
				case codeIdentityDeveloper:
					if member.Identity.TeamID == "" {
						return fmt.Errorf("키 %s의 Developer ID 규칙에 Team ID가 없음", key.ID)
					}
				case codeIdentityUntrusted:
					if rule.Decision == ruleAllow {
						return fmt.Errorf("키 %s의 허용 규칙에 untrusted 구성원이 있음", key.ID)
					}
				default:
					return fmt.Errorf("키 %s의 규칙 코드 신원 종류가 잘못됨", key.ID)
				}
			}
			want, err := chainRuleID(rule.Decision, rule.Chain)
			if err != nil || rule.ID != want || seenRules[rule.ID] {
				return fmt.Errorf("키 %s의 규칙 ID가 잘못되거나 중복됨", key.ID)
			}
			seenRules[rule.ID] = true
		}
	}
	return nil
}
