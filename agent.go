package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"net"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	errMutationDenied = errors.New("pasu: 키 변경 연산은 지원하지 않음")
	errSignDenied     = errors.New("pasu: 서명 정책에 의해 거부됨")
)

// gatekeeper는 v1 호환·회귀 검사용 ssh-agent 구현이다. v2는 v2Gatekeeper를 사용한다.
// 서명 요청이 올 때마다(연결 시 1회가 아니라) 피어의 조상 사슬을 다시 검사한다.
type gatekeeper struct {
	key       keySource
	rules     *allowlist
	limit     *signLimiter // nil이면 제한 없음. 모든 연결이 하나를 공유(전역 합산)
	ask       *asker       // nil이면 승인 창 없이 즉시 거부(`ask on`일 때만 존재, 전역 공유)
	denyLog   *denyRecorder
	denyNtf   *denyNotifyLimiter
	audit     *auditLog
	notify    func(subtitle, body string)
	selfUID   uint32
	conn      *net.UnixConn
	requests  *requestTracker
	ancestry  func(int) []procInfo // 테스트에서 UID 선검사 순서를 확인하는 주입점
	stability func() error         // 테스트에서 인가 뒤 재검사 시점을 확인하는 주입점
}

func (g *gatekeeper) beginRequest() bool {
	return g.requests == nil || g.requests.begin()
}

func (g *gatekeeper) endRequest() {
	if g.requests != nil {
		g.requests.done()
	}
}

func (g *gatekeeper) List() ([]*agent.Key, error) {
	if !g.beginRequest() {
		return nil, errSignDenied
	}
	defer g.endRequest()
	// 공개키 목록은 비밀이 아니므로 누구에게나 응답한다. 이렇게 해야
	// 비인가 ssh도 서명 요청 단계까지 진행해 와서 거부 흔적(알림·로그)이 남는다.
	if id, err := peerIdentity(g.conn); err == nil {
		p := lookupProc(id.pid)
		g.audit.logf("LIST peer=%d uid=%d exe=%s", id.pid, id.uid, displayName(p))
	}
	// Touch ID 모드에서도 잠금 해제 없이 공개키를 광고한다(키 잠금은 서명에만 관여).
	pub := g.key.PublicKey()
	return []*agent.Key{{Format: pub.Type(), Blob: pub.Marshal(), Comment: "pasu"}}, nil
}

func (g *gatekeeper) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return g.SignWithFlags(key, data, 0)
}

func (g *gatekeeper) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	if !g.beginRequest() {
		return nil, errSignDenied
	}
	defer g.endRequest()
	id, err := peerIdentity(g.conn)
	if err != nil {
		g.recordDeny(denyKey{peer: "unknown", reason: "피어_식별_실패"},
			"DENY sign reason=피어_식별_실패 err=%v", err)
		return nil, errSignDenied
	}
	// 다른 UID는 조상 조회나 코드서명 검사 전에 즉시 거부한다. 다른 사용자의
	// 프로세스 정보를 불필요하게 읽지 않고 문서화된 검사 순서도 지킨다.
	if id.uid != g.selfUID {
		g.deny(id, procInfo{pid: id.pid}, nil, fmt.Sprintf("다른_UID(%d)", id.uid), true)
		return nil, errSignDenied
	}
	ancestryFn := g.ancestry
	var chain []procInfo
	verifyStable := g.stability
	if verifyStable == nil {
		verifyStable = func() error { return nil }
	}
	if ancestryFn != nil {
		// 단위 테스트 전용 주입점. production은 아래 verifiedPeerChain 경로만 쓴다.
		chain = ancestryFn(id.pid)
	} else {
		chain, verifyStable, err = verifiedPeerChain(g.conn, id)
		if err != nil {
			peer := lookupProc(id.pid)
			g.audit.logf("PEER-VERIFY-FAIL peer=%d err=%v", id.pid, err)
			g.deny(id, peer, nil, "피어_사슬_검증_실패", true)
			return nil, errSignDenied
		}
	}
	peer := procInfo{pid: id.pid}
	if len(chain) > 0 {
		peer = chain[0]
	}

	if !bytes.Equal(key.Marshal(), g.key.PublicKey().Marshal()) {
		g.deny(id, peer, chain, "모르는_키_요청", true)
		return nil, errSignDenied
	}
	if flags != 0 {
		// ed25519에는 서명 플래그(RSA 해시 선택용)가 올 일이 없다.
		g.deny(id, peer, chain, fmt.Sprintf("지원하지_않는_플래그(%d)", flags), true)
		return nil, errSignDenied
	}
	// 허용 근거는 둘 중 하나다: allowlist 매칭, 또는(`ask on`) 승인 창의
	// 결정(기억된 승인 포함). 승인 창도 rate limit·잠금 해제보다 앞이라
	// 승인 없이는 Touch ID 프롬프트를 유발할 수 없다는 성질이 유지된다.
	var matchedDesc string
	var viaProc procInfo
	var persist *approvalKey
	if m := g.rules.match(chain); m != nil {
		matchedDesc = m.rule.String()
		viaProc = m.proc
	} else if g.ask != nil {
		res := g.ask.decide(chain)
		if !res.allow {
			g.deny(id, peer, chain, res.reason, true)
			return nil, errSignDenied
		}
		matchedDesc = res.via
		viaProc = res.proc
		persist = res.persist
	} else {
		g.deny(id, peer, chain, "allowlist_불일치", true)
		return nil, errSignDenied
	}
	verifyPeerStable := func(phase string) error {
		if err := verifyStable(); err != nil {
			g.audit.logf("PEER-STABILITY-FAIL peer=%d phase=%s err=%v", id.pid, phase, err)
			g.deny(id, peer, chain, "피어_사슬_변경", true)
			return errSignDenied
		}
		return nil
	}
	// 코드서명 또는 사용자 승인이 끝난 뒤 같은 audit token과 완전한 조상 사슬이
	// 유지되는지 다시 확인한다. 바뀐 요청은 rate 예산·Touch ID를 쓰기 전에 막는다.
	if err := verifyPeerStable("post-auth"); err != nil {
		return nil, err
	}
	// 서명 한도는 인가 후, 잠금 해제 전에 검사한다. 초과 시 인증을 요청하지 않는다.
	// 반복 거부는 denyRecorder가 요약하고 한도 초과 알림은 기간당 한 번으로 제한한다.
	var reservation *signReservation
	if g.limit != nil {
		var notifyNow bool
		reservation, notifyNow = g.limit.reserve()
		if reservation == nil {
			g.deny(id, peer, chain, "서명_한도_초과("+g.limit.String()+")", notifyNow)
			return nil, errSignDenied
		}
		defer reservation.cancel()
	}
	// 잠금 해제는 인가 뒤에 수행해 비인가 요청이 인증창을 반복해서 띄우지 못하게 한다.
	signer, err := g.key.Signer()
	if err != nil {
		// 설정 변조 의심과 인증 취소를 로그에서 구분한다.
		// 복구 안내는 confbind.verify가 최초 감지 시 한 번 보낸다.
		reason := "키_잠금_해제_실패"
		if errors.Is(err, errConfTampered) {
			reason = "설정_결속_불일치"
		}
		g.audit.logf("UNLOCK-FAIL peer=%d err=%v", id.pid, err)
		g.deny(id, peer, chain, reason, true)
		return nil, errSignDenied
	}
	// 첫 서명의 Touch ID는 오래 걸릴 수 있으므로 잠금 해제 뒤에도 원래 피어와
	// 조상 사슬이 그대로인지 확인한다. 바뀌었다면 해제된 signer를 캐시했더라도
	// 이 요청에는 사용하지 않는다.
	if err := verifyPeerStable("post-unlock"); err != nil {
		return nil, err
	}
	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		g.audit.logf("SIGN-FAIL peer=%d err=%v", id.pid, err)
		g.deny(id, peer, chain, "서명_실패", true)
		return nil, errSignDenied
	}
	// 서명 계산 중 경합도 결과를 피어에게 돌려주기 전에 마지막으로 거른다.
	if err := verifyPeerStable("post-sign"); err != nil {
		return nil, err
	}
	if reservation != nil {
		reservation.commit()
		reservation = nil
	}
	if persist != nil {
		g.ask.commitAlways(*persist)
	}
	g.audit.logf("ALLOW sign peer=%d exe=%s matched=%q via=%s(%d) chain=%s",
		id.pid, displayName(peer), matchedDesc, displayName(viaProc), viaProc.pid, chainString(chain))
	return sig, nil
}

// deny는 거부를 감사 로그에 남기고, notify가 참이면 macOS 알림도 요청한다.
// 일반 거부는 denyNtf, 서명 한도 초과는 rate limiter까지 두 단계로 묶인다.
func (g *gatekeeper) deny(id peerID, peer procInfo, chain []procInfo, reason string, notify bool) {
	g.recordDeny(denyKey{peer: denyPeerKey(peer), reason: reason},
		"DENY sign peer=%d uid=%d exe=%s reason=%s chain=%s",
		id.pid, id.uid, displayName(peer), reason, chainString(chain))
	if notify && g.denyNtf.allow(peer, chain, reason) {
		g.notify("SSH 서명 거부", fmt.Sprintf("%s (pid %d) — %s", displayName(peer), id.pid, reason))
	}
}

func (g *gatekeeper) recordDeny(key denyKey, format string, args ...any) {
	if g.denyLog != nil {
		g.denyLog.record(key, format, args...)
		return
	}
	g.audit.logf(format, args...)
}

func denyPeerKey(p procInfo) string {
	if p.exePath != "" {
		return p.exePath
	}
	if p.comm != "" {
		return p.comm
	}
	return fmt.Sprintf("pid:%d", p.pid)
}

func (g *gatekeeper) denyMutation(op string) error {
	if !g.beginRequest() {
		return errMutationDenied
	}
	defer g.endRequest()
	pid := -1
	peer := procInfo{pid: pid}
	if id, err := peerIdentity(g.conn); err == nil {
		pid = id.pid
		peer = lookupProc(pid)
	}
	g.recordDeny(denyKey{peer: denyPeerKey(peer), reason: "변경_연산_" + op},
		"DENY %s peer=%d exe=%s (변경 연산은 항상 거부)", op, pid, displayName(peer))
	return errMutationDenied
}

func (g *gatekeeper) Add(key agent.AddedKey) error   { return g.denyMutation("add") }
func (g *gatekeeper) Remove(key ssh.PublicKey) error { return g.denyMutation("remove") }
func (g *gatekeeper) RemoveAll() error               { return g.denyMutation("remove-all") }
func (g *gatekeeper) Lock(passphrase []byte) error   { return g.denyMutation("lock") }
func (g *gatekeeper) Unlock(passphrase []byte) error { return g.denyMutation("unlock") }
func (g *gatekeeper) Signers() ([]ssh.Signer, error) { return nil, errMutationDenied }
func (g *gatekeeper) Extension(extensionType string, contents []byte) ([]byte, error) {
	if !g.beginRequest() {
		return nil, agent.ErrExtensionUnsupported
	}
	defer g.endRequest()
	pid := -1
	peer := procInfo{pid: pid}
	if id, err := peerIdentity(g.conn); err == nil {
		pid = id.pid
		peer = lookupProc(pid)
	}
	// OpenSSH는 정상 연결에서도 session-bind 확장을 먼저 제안한다. pasu는
	// 확장을 지원하지 않아 계속 거부하지만, 정상 협상을 보안 DENY로 집계하지
	// 않도록 중립 이벤트로 남긴다.
	g.audit.logf("EXTENSION unsupported peer=%d exe=%s type=%s", pid, displayName(peer), safeText(extensionType))
	return nil, agent.ErrExtensionUnsupported
}

func displayName(p procInfo) string {
	if p.exePath != "" {
		return safeText(p.exePath)
	}
	if p.comm != "" {
		return safeText(p.comm) + "?"
	}
	return "알수없음"
}
