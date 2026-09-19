package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

type v2PromptRequest struct {
	ID             string      `json:"id"`
	KeyID          string      `json:"key_id"`
	KeyName        string      `json:"key_name"`
	Fingerprint    string      `json:"fingerprint"`
	AuthMode       keyAuthMode `json:"auth_mode"`
	Chain          stableChain `json:"chain"`
	RuntimeChain   string      `json:"runtime_chain"`
	ProcessSummary string      `json:"process_summary"`
	CanPersist     bool        `json:"can_persist"`
	CreatedAt      time.Time   `json:"created_at"`
}

type v2PromptHandler func(v2PromptRequest) (askChoice, error)

type v2PromptCoordinator struct {
	mu       sync.Mutex
	busy     string
	cooldown time.Duration
	blocked  map[string]time.Time
	now      func() time.Time
	handler  v2PromptHandler
	logf     func(string, ...any)
}

func newV2PromptCoordinator(cooldown time.Duration, handler v2PromptHandler, logf func(string, ...any)) *v2PromptCoordinator {
	if handler == nil {
		handler = macV2Prompt
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &v2PromptCoordinator{
		cooldown: cooldown, blocked: make(map[string]time.Time), now: time.Now,
		handler: handler, logf: logf,
	}
}

func v2PromptFingerprint(keyID string, chain stableChain) string {
	data, _ := json.Marshal(struct {
		KeyID string      `json:"key_id"`
		Chain stableChain `json:"chain"`
	}{keyID, chain})
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func (p *v2PromptCoordinator) decide(req v2PromptRequest) (askChoice, error) {
	fingerprint := v2PromptFingerprint(req.KeyID, req.Chain)
	p.mu.Lock()
	now := p.now()
	for key, until := range p.blocked {
		if !now.Before(until) {
			delete(p.blocked, key)
		}
	}
	if until := p.blocked[fingerprint]; now.Before(until) {
		p.mu.Unlock()
		return askTimeout, errors.New("승인 요청 cooldown")
	}
	if p.busy != "" {
		same := p.busy == fingerprint
		p.mu.Unlock()
		if same {
			return askTimeout, errors.New("동일 승인 요청이 이미 표시 중")
		}
		return askTimeout, errors.New("다른 승인 요청이 이미 표시 중")
	}
	p.busy = fingerprint
	p.mu.Unlock()

	p.logf("ASK-V2 show key_id=%s key_fp=%s chain_id=%s chain=%s",
		req.KeyID, req.Fingerprint, fingerprint, safeText(req.RuntimeChain))
	choice, err := p.handler(req)
	if choice == askAlways && !req.CanPersist {
		choice = askTimeout
		if err == nil {
			err = errors.New("사슬에 신뢰할 수 없는 코드가 있어 항상 허용할 수 없음")
		}
	}
	p.mu.Lock()
	p.busy = ""
	if choice == askTimeout && p.cooldown > 0 {
		p.blocked[fingerprint] = p.now().Add(p.cooldown)
	}
	p.mu.Unlock()
	p.logf("ASK-V2 result=%s key_id=%s chain_id=%s", choice, req.KeyID, fingerprint)
	return choice, err
}

func macV2Prompt(req v2PromptRequest) (askChoice, error) {
	persistNote := "모든 구성원의 코드 신원이 검증되어 이 정확한 사슬을 저장할 수 있습니다."
	if !req.CanPersist {
		persistNote = "미서명 또는 ad-hoc 구성원이 있어 항상 허용은 사용할 수 없습니다."
	}
	text := fmt.Sprintf("키: %s\n지문: %s\n인증: %s\n요청: %s\nTTY: %s\n\n%s",
		safeText(req.KeyName), req.Fingerprint, req.AuthMode.label(),
		safeText(req.ProcessSummary), req.Chain.TTY, persistNote)
	return macAskPromptV2(text, req.CanPersist)
}

const askAlertScriptV2 = `use framework "AppKit"

property askOutcome : "timeout"

on run argv
	my performSelectorOnMainThread:"showAsk:" withObject:(item 1 of argv) waitUntilDone:true
	return askOutcome
end run

on showAsk:msg
	set msgText to msg as text
	set persistFlag to text 1 of msgText
	set bodyText to text 3 thru -1 of msgText
	set ca to current application
	ca's NSApplication's sharedApplication()
	ca's NSApp's setActivationPolicy:1
	set alert to ca's NSAlert's alloc()'s init()
	alert's setAlertStyle:2
	alert's setMessageText:"Pasu — 처음 보는 SSH 서명 사슬"
	alert's setInformativeText:bodyText
	alert's addButtonWithTitle:"이 사슬 항상 거부"
	alert's addButtonWithTitle:"이번만 허용"
	set alwaysButton to alert's addButtonWithTitle:"이 사슬 항상 허용"
	if persistFlag is "0" then alwaysButton's setEnabled:false
	ca's NSApp's activateIgnoringOtherApps:true
	set code to alert's runModal()
	set n to code as integer
	if n is 1000 then set my askOutcome to "deny"
	if n is 1001 then set my askOutcome to "once"
	if n is 1002 then set my askOutcome to "always"
end showAsk:`

func macAskPromptV2(text string, canPersist bool) (askChoice, error) {
	persistFlag := "0"
	if canPersist {
		persistFlag = "1"
	}
	out, canceled, err := runAskScriptFn(askAlertScriptV2, persistFlag+"\n"+text, 65*time.Second)
	if err != nil {
		return askTimeout, err
	}
	if canceled {
		return askTimeout, nil
	}
	switch out {
	case "deny":
		return askDenied, nil
	case "once":
		return askOnce, nil
	case "always":
		if !canPersist {
			return askTimeout, errors.New("항상 허용 불가")
		}
		return askAlways, nil
	default:
		return askTimeout, nil
	}
}
