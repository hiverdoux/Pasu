package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

// v1 설정 결속: pasu.conf·approvals.conf의 변조를 검출한다.
// 같은 사용자 권한의 다른 프로세스도 설정을 바꿀 수 있으므로 파일 권한만으로는
// 충분하지 않다. 앱 전용 Keychain에 둔 비밀 키 K로 두 파일의 HMAC(인증값)을
// 계산하고, 잠금 해제 후 실제 적용 중인 설정과 conf.hmac이 일치하는지 검사한다.
// 불일치하면 서명을 거부하고 변조 의심 기록을 남긴다.
//
// 항상 허용 기록은 서명 성공 후 추가한다. 기동 시 원문과 추가 기록용 사본을
// 분리해, Pasu가 직접 저장한 승인만 새 인증값에 포함한다. 설정을 다시 신뢰하는
// 관리 작업에서는 K를 교체해 이전 설정과 인증값의 동시 복원을 거부한다.
// 같은 K에서 이전 승인 목록을 복원하면 허용 규칙이 줄어들 뿐이다.
// 이 검사는 파일 변경 자체를 막지 않으며, 실행 파일 보호는 코드 서명과 소유권에 맡긴다.
type confBinding struct {
	mu      sync.Mutex
	macPath string
	// startConf·startAppr는 기동 시 읽은 원문 스냅샷 — 지금 적용 중인 정책
	// 그 자체이므로 검증(verify)의 기준이다. liveAppr는 스냅샷에 이번 기동에서
	// pasu가 덧붙인 승인을 더한 사본 — 지문 기록(writeMAC)의 기준이다.
	// pasu는 pasu.conf를 쓰지 않으므로 conf는 스냅샷 하나로 충분하다.
	startConf []byte
	startAppr []byte
	liveAppr  []byte
	k         []byte // Keychain/legacy payload의 MAC 키 — 첫 잠금 해제 뒤에만 존재
	mode      string // START 표기: off(결속 없음)·upgrade(legacy v1)·on
	logf      func(string, ...any)
	notify    func(subtitle, body string) // 변조 감지 1회 안내(없으면 무시)
}

// bindKeyLen은 MAC 키 K의 길이다. Keychain/legacy payload의 마지막 바이트들이다.
const bindKeyLen = 32

// errConfTampered는 설정 검증 실패다. lazyKey는 종료까지 이 오류를 유지해
// 같은 변조 상태에서 인증창을 반복 표시하지 않는다.
var errConfTampered = errors.New("설정 결속 불일치(변조 의심)")

func newConfBinding(macPath string, conf, approvals []byte, logf func(string, ...any)) *confBinding {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &confBinding{
		macPath:   macPath,
		startConf: append([]byte(nil), conf...),
		startAppr: append([]byte(nil), approvals...),
		liveAppr:  append([]byte(nil), approvals...),
		mode:      "off",
		logf:      logf,
	}
}

// bindMAC은 두 파일 원문의 지문을 계산한다. 길이 프레이밍으로 파일 경계
// 이동에 따른 모호성을 막고, 도메인 문자열로 다른 HMAC 용도와 분리한다.
func bindMAC(k, conf, appr []byte) []byte {
	m := hmac.New(sha256.New, k)
	m.Write([]byte("pasu-confbind-v1\x00"))
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(conf)))
	m.Write(n[:])
	m.Write(conf)
	binary.BigEndian.PutUint64(n[:], uint64(len(appr)))
	m.Write(n[:])
	m.Write(appr)
	return m.Sum(nil)
}

func newBindKey() ([]byte, error) {
	k := make([]byte, bindKeyLen)
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("MAC 키 생성 실패: %w", err)
	}
	return k, nil
}

// verify는 잠금 해제 직후 호출된다: 기동 시 스냅샷의 지문을 conf.hmac과
// 대조한다. conf.hmac은 디스크에서 새로 읽는다 — 값 자체는 K 없이 위조
// 불가능하므로 신선 판독이 안전하다. -trust-conf는 실행 중 데몬이 없을 때만
// 허용해 K 세대가 갈라지지 않게 하고, 성공 시 이 프로세스가 K를 채택한다.
func (b *confBinding) verify(k []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	fail := func(detail string) error {
		b.logf("BIND verify FAIL mac=%s detail=%s", b.macPath, detail)
		if b.notify != nil {
			b.notify("설정 변조 의심", "pasu.conf·approvals.conf가 신뢰 기준과 다릅니다. 본인 수정이면 pasu -trust-conf 후 재기동하세요.")
		}
		return fmt.Errorf("%w: %s — 본인이 설정을 바꿨다면 pasu -trust-conf 후 재기동", errConfTampered, detail)
	}
	data, err := os.ReadFile(b.macPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fail("지문 파일 없음")
		}
		return fail(fmt.Sprintf("지문 파일 읽기 실패: %v", err))
	}
	want, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(want) != sha256.Size {
		return fail("지문 파일 형식 오류")
	}
	if !hmac.Equal(bindMAC(k, b.startConf, b.startAppr), want) {
		return fail("지문 불일치")
	}
	b.k = append([]byte(nil), k...)
	b.mode = "on"
	b.logf("BIND verify ok mac=%s", b.macPath)
	return nil
}

// adoptNewKey는 새 K로 현재 상태의 지문을 기록하고 K를 채택한다.
// Keychain 설정·재신뢰와 legacy v1 이전이 쓴다.
func (b *confBinding) adoptNewKey(k []byte, cause string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.writeMACLocked(k, cause); err != nil {
		return err
	}
	b.k = append([]byte(nil), k...)
	b.mode = "on"
	return nil
}

// appendApproval은 결속 K가 준비된 뒤에만 승인 파일 쓰기와 지문 갱신을 한
// 임계 구역에서 수행한다. write는 실제 파일에 추가한 원문을 돌려준다.
func (b *confBinding) appendApproval(write func() ([]byte, error)) error {
	if b == nil {
		_, err := write()
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.mode != "off" && b.k == nil {
		return errors.New("설정 결속 키가 아직 잠겨 있어 승인을 영구 기록할 수 없음")
	}
	chunk, err := write()
	if err != nil {
		return err
	}
	b.liveAppr = append(b.liveAppr, chunk...)
	if b.k != nil {
		if err := b.writeMACLocked(b.k, "approval"); err != nil {
			b.logf("BIND record-fail cause=approval err=%v", err)
			return err
		}
	}
	return nil
}

// writeMACLocked는 live 상태의 지문을 conf.hmac에 원자적으로 기록한다(0600).
// 호출자가 mu를 잡고 있어야 한다.
func (b *confBinding) writeMACLocked(k []byte, cause string) error {
	line := hex.EncodeToString(bindMAC(k, b.startConf, b.liveAppr)) + "\n"
	tmp := b.macPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(line), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, b.macPath); err != nil {
		return err
	}
	b.logf("BIND record cause=%s mac=%s", cause, b.macPath)
	return nil
}

// setMode는 기동 시 newKeySource가 설정 검증의 활성 상태를 표시할 때 쓴다.
func (b *confBinding) setMode(m string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.mode = m
}

// modeDesc는 START 줄 표기용이다(nil 안전).
func (b *confBinding) modeDesc() string {
	if b == nil {
		return "off"
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.mode
}
