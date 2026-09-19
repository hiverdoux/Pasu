package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func conciseProcessName(proc procInfo) string {
	if proc.exePath != "" {
		name := filepath.Base(proc.exePath)
		if name != "." && name != string(filepath.Separator) {
			return safeText(name)
		}
	}
	return displayName(proc)
}

func conciseProcessSummary(chain []procInfo) string {
	if len(chain) == 0 {
		return "알수없음 > 알수없음"
	}
	responsible := chain[0]
	if len(chain) >= 2 && chain[len(chain)-1].pid == 1 {
		responsible = chain[len(chain)-2]
	}
	return conciseProcessName(responsible) + " > " + conciseProcessName(chain[0])
}

type v2AgentCore struct {
	manager  *v2KeyManager
	registry *v2Registry
	prompt   *v2PromptCoordinator
	audit    *auditLog
	notify   func(string, string)
	requests *requestTracker
	selfUID  uint32

	mu          sync.Mutex
	globalLimit *signLimiter
	keyLimits   map[string]*signLimiter
	limitConfig rateLimit
	denyLog     *denyRecorder
	denyNotify  *denyNotifyLimiter
}

func newV2AgentCore(manager *v2KeyManager, registry *v2Registry, prompt *v2PromptCoordinator,
	audit *auditLog, notify func(string, string), requests *requestTracker, selfUID uint32) *v2AgentCore {
	settings := registry.snapshot().Settings
	limit := rateLimit{max: settings.RateCount, window: settings.RateWindow}
	if limit.max <= 0 || limit.window <= 0 {
		limit = defaultRateLimit
	}
	if notify == nil {
		notify = func(string, string) {}
	}
	return &v2AgentCore{
		manager: manager, registry: registry, prompt: prompt, audit: audit, notify: notify,
		requests: requests, selfUID: selfUID, globalLimit: newSignLimiter(limit),
		keyLimits: make(map[string]*signLimiter), limitConfig: limit,
		denyLog:    newDenyRecorder(denySummaryWindow, audit.logf),
		denyNotify: newDenyNotifyLimiter(settings.NotifyCooldown),
	}
}

func (c *v2AgentCore) close() {
	if c.denyLog != nil {
		c.denyLog.Close()
	}
}

func (c *v2AgentCore) limiterForKey(id string) *signLimiter {
	c.mu.Lock()
	defer c.mu.Unlock()
	limiter := c.keyLimits[id]
	if limiter == nil {
		limiter = newSignLimiter(c.limitConfig)
		c.keyLimits[id] = limiter
	}
	return limiter
}

type v2Gatekeeper struct {
	core *v2AgentCore
	conn *net.UnixConn
}

func (g *v2Gatekeeper) begin() bool {
	return g.core.requests == nil || g.core.requests.begin()
}

func (g *v2Gatekeeper) end() {
	if g.core.requests != nil {
		g.core.requests.done()
	}
}

func (g *v2Gatekeeper) verifiedRequestChain() (peerID, []procInfo, stableChain, bool, func() error, error) {
	id, err := peerIdentity(g.conn)
	if err != nil {
		return peerID{}, nil, stableChain{}, false, nil, err
	}
	if id.uid != g.core.selfUID {
		return id, nil, stableChain{}, false, nil, fmt.Errorf("다른 UID(%d)", id.uid)
	}
	chain, verify, err := verifiedPeerChain(g.conn, id)
	if err != nil {
		return id, nil, stableChain{}, false, nil, err
	}
	stable, trusted, err := stabilizeChain(chain)
	if err != nil {
		return id, chain, stableChain{}, false, verify, err
	}
	return id, chain, stable, trusted, verify, nil
}

func (g *v2Gatekeeper) List() ([]*agent.Key, error) {
	if !g.begin() {
		return nil, errSignDenied
	}
	defer g.end()
	id, chain, stable, _, verify, err := g.verifiedRequestChain()
	if err != nil {
		g.core.audit.logf("DENY list reason=피어_사슬_검증_실패 err=%v", err)
		return []*agent.Key{}, nil
	}
	if err := verify(); err != nil {
		g.core.audit.logf("DENY list peer=%d reason=피어_사슬_변경 err=%v", id.pid, err)
		return []*agent.Key{}, nil
	}
	var out []*agent.Key
	for _, runtime := range g.core.manager.runtimes() {
		record, ok := g.core.registry.key(runtime.recordSnapshot().ID)
		if !ok || !record.Enabled {
			continue
		}
		state, ruleID, err := g.core.registry.classify(record.ID, stable)
		if err != nil || state == chainDenied {
			g.core.audit.logf("LIST-FILTER key_id=%s key_fp=%s peer=%d decision=deny rule_id=%s",
				record.ID, record.Fingerprint, id.pid, ruleID)
			continue
		}
		pub := runtime.PublicKey()
		out = append(out, &agent.Key{Format: pub.Type(), Blob: pub.Marshal(), Comment: record.Name})
	}
	g.core.audit.logf("LIST peer=%d uid=%d keys=%d chain=%s", id.pid, id.uid, len(out), chainString(chain))
	return out, nil
}

func (g *v2Gatekeeper) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return g.SignWithFlags(key, data, 0)
}

func (g *v2Gatekeeper) findKey(public ssh.PublicKey) (*managedKeyRuntime, managedKeyRecord, bool) {
	for _, runtime := range g.core.manager.runtimes() {
		if bytes.Equal(runtime.PublicKey().Marshal(), public.Marshal()) {
			record, ok := g.core.registry.key(runtime.recordSnapshot().ID)
			return runtime, record, ok
		}
	}
	return nil, managedKeyRecord{}, false
}

func (g *v2Gatekeeper) SignWithFlags(public ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	if !g.begin() {
		return nil, errSignDenied
	}
	defer g.end()
	id, chain, stable, trusted, verifyStable, err := g.verifiedRequestChain()
	if err != nil {
		g.deny("", "", procInfo{pid: id.pid}, chain, "피어_사슬_검증_실패", err)
		return nil, errSignDenied
	}
	peer := chain[0]
	runtime, record, ok := g.findKey(public)
	if !ok {
		g.deny("", ssh.FingerprintSHA256(public), peer, chain, "모르는_키_요청", nil)
		return nil, errSignDenied
	}
	if !record.Enabled {
		g.deny(record.ID, record.Fingerprint, peer, chain, "비활성_키", nil)
		return nil, errSignDenied
	}
	if flags != 0 {
		g.deny(record.ID, record.Fingerprint, peer, chain, fmt.Sprintf("지원하지_않는_플래그(%d)", flags), nil)
		return nil, errSignDenied
	}
	if !runtime.beginSign() {
		g.deny(record.ID, record.Fingerprint, peer, chain, "키_삭제_중", nil)
		return nil, errSignDenied
	}
	defer runtime.endSign()

	state, ruleID, err := g.core.registry.classify(record.ID, stable)
	if err != nil || state == chainDenied {
		g.deny(record.ID, record.Fingerprint, peer, chain, "영구_거부", err)
		return nil, errSignDenied
	}
	choice := askAlways
	persistAllow := false
	if state == chainUnknown {
		reqID, _ := newKeyID()
		processSummary := conciseProcessSummary(chain)
		choice, err = g.core.prompt.decide(v2PromptRequest{
			ID: reqID, KeyID: record.ID, KeyName: record.Name, Fingerprint: record.Fingerprint,
			AuthMode: record.AuthMode, Chain: stable, RuntimeChain: chainString(chain),
			ProcessSummary: processSummary, CanPersist: trusted, CreatedAt: g.core.prompt.now().UTC(),
		})
		if err != nil {
			g.core.audit.logf("ASK-V2 detail key_id=%s err=%v", record.ID, err)
		}
		switch choice {
		case askDenied:
			if _, perr := g.core.registry.addRule(record.ID, ruleDeny, stable); perr != nil {
				g.core.audit.logf("POLICY persist-deny-fail key_id=%s err=%v", record.ID, perr)
			}
			g.deny(record.ID, record.Fingerprint, peer, chain, "사용자_영구_거부", nil)
			return nil, errSignDenied
		case askOnce:
		case askAlways:
			persistAllow = true
		default:
			g.deny(record.ID, record.Fingerprint, peer, chain, "승인_없음", err)
			return nil, errSignDenied
		}
	}
	if err := verifyStable(); err != nil {
		g.deny(record.ID, record.Fingerprint, peer, chain, "피어_사슬_변경", err)
		return nil, errSignDenied
	}

	globalReservation, notifyGlobal := g.core.globalLimit.reserve()
	if globalReservation == nil {
		g.deny(record.ID, record.Fingerprint, peer, chain, "전역_서명_한도_초과", nil)
		if notifyGlobal {
			g.core.notify("SSH 서명 거부", "Pasu 전역 서명 한도를 초과했습니다.")
		}
		return nil, errSignDenied
	}
	defer globalReservation.cancel()
	keyReservation, notifyKey := g.core.limiterForKey(record.ID).reserve()
	if keyReservation == nil {
		g.deny(record.ID, record.Fingerprint, peer, chain, "키별_서명_한도_초과", nil)
		if notifyKey {
			g.core.notify("SSH 서명 거부", record.Name+" 키의 서명 한도를 초과했습니다.")
		}
		return nil, errSignDenied
	}
	defer keyReservation.cancel()

	signer, err := runtime.signerForRequest(fmt.Sprintf(
		"Pasu SSH 서명: %s — %s", record.Name, conciseProcessSummary(chain),
	))
	if err != nil {
		g.deny(record.ID, record.Fingerprint, peer, chain, "키_잠금_해제_실패", err)
		return nil, errSignDenied
	}
	if err := verifyStable(); err != nil {
		g.deny(record.ID, record.Fingerprint, peer, chain, "피어_사슬_변경", err)
		return nil, errSignDenied
	}
	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		g.deny(record.ID, record.Fingerprint, peer, chain, "서명_실패", err)
		return nil, errSignDenied
	}
	if err := verifyStable(); err != nil {
		g.deny(record.ID, record.Fingerprint, peer, chain, "피어_사슬_변경", err)
		return nil, errSignDenied
	}
	globalReservation.commit()
	globalReservation = nil
	keyReservation.commit()
	keyReservation = nil
	if persistAllow {
		rule, perr := g.core.registry.addRule(record.ID, ruleAllow, stable)
		if perr != nil {
			g.core.audit.logf("POLICY persist-allow-fail key_id=%s err=%v", record.ID, perr)
		} else {
			ruleID = rule.ID
		}
	}
	if err := g.core.registry.markUsed(record.ID, ruleID); err != nil {
		g.core.audit.logf("POLICY last-used-fail key_id=%s err=%v", record.ID, err)
	}
	g.core.audit.logf("ALLOW sign key_id=%s key_fp=%s rule_id=%s peer=%d exe=%s choice=%s chain=%s",
		record.ID, record.Fingerprint, ruleID, id.pid, displayName(peer), choice, chainString(chain))
	return sig, nil
}

func (g *v2Gatekeeper) deny(keyID, fingerprint string, peer procInfo, chain []procInfo, reason string, detail error) {
	entryKey := denyKey{peer: denyPeerKey(peer), reason: keyID + ":" + reason}
	g.core.denyLog.record(entryKey,
		"DENY sign key_id=%s key_fp=%s peer=%d uid=%d exe=%s reason=%s detail=%v chain=%s",
		keyID, fingerprint, peer.pid, peer.uid, displayName(peer), reason, detail, chainString(chain))
	if g.core.denyNotify.allow(peer, chain, reason) {
		g.core.notify("SSH 서명 거부", fmt.Sprintf("%s — %s", displayName(peer), reason))
	}
}

func (g *v2Gatekeeper) denyMutation(op string) error {
	if !g.begin() {
		return errMutationDenied
	}
	defer g.end()
	g.core.audit.logf("DENY %s reason=SSH_agent_변경_연산_불허", op)
	return errMutationDenied
}

func (g *v2Gatekeeper) Add(agent.AddedKey) error       { return g.denyMutation("add") }
func (g *v2Gatekeeper) Remove(ssh.PublicKey) error     { return g.denyMutation("remove") }
func (g *v2Gatekeeper) RemoveAll() error               { return g.denyMutation("remove-all") }
func (g *v2Gatekeeper) Lock([]byte) error              { return g.denyMutation("lock") }
func (g *v2Gatekeeper) Unlock([]byte) error            { return g.denyMutation("unlock") }
func (g *v2Gatekeeper) Signers() ([]ssh.Signer, error) { return nil, errMutationDenied }
func (g *v2Gatekeeper) Extension(extensionType string, _ []byte) ([]byte, error) {
	if !g.begin() {
		return nil, agent.ErrExtensionUnsupported
	}
	defer g.end()
	g.core.audit.logf("EXTENSION unsupported type=%s", safeText(extensionType))
	return nil, agent.ErrExtensionUnsupported
}

var _ agent.ExtendedAgent = (*v2Gatekeeper)(nil)

func v2SignDenied(err error) bool { return errors.Is(err, errSignDenied) }
