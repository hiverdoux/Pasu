package main

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"golang.org/x/crypto/ssh"
)

// keySource는 v1 호환 경로의 서명 키 로드를 추상화한다.
// - eagerKey: 기동 시 passphrase로 복호화를 마친 키(기존 모드).
// - lazyKey: 공개키만 들고 시작해, 첫 서명 순간에 잠금을 해제하는 키(Touch ID 모드).
// 어느 쪽이든 PublicKey는 항상 응답한다 — List가 잠금 상태와 무관해야
// 비인가 접속이 서명 단계까지 와서 흔적을 남기는 기존 설계가 유지된다.
type keySource interface {
	PublicKey() ssh.PublicKey
	// Signer는 서명 가능한 키를 돌려준다. lazyKey에서는 첫 호출이 잠금 해제
	// (Touch ID 프롬프트)를 유발할 수 있고, 실패하면 오류를 돌려준다.
	Signer() (ssh.Signer, error)
}

type eagerKey struct{ signer ssh.Signer }

func (k eagerKey) PublicKey() ssh.PublicKey    { return k.signer.PublicKey() }
func (k eagerKey) Signer() (ssh.Signer, error) { return k.signer, nil }

// lazyKey는 잠금 해제를 첫 서명까지 미룬다. 해제 성공 후에는 프로세스가
// 끝날 때까지 메모리에 유지해 이후 서명에서 인증 결과를 재사용한다.
// mutex가 동시 서명 요청의 프롬프트 중복을 막는다.
type lazyKey struct {
	mu     sync.Mutex
	pub    ssh.PublicKey
	unlock func() (ssh.Signer, error)
	signer ssh.Signer
	// fatal은 설정 결속 불일치와 고정된 키 자료 오류를 고정(latch)한다.
	// 사용자 취소 같은 일시 실패는 다음 서명에서 재시도하지만, 같은 프로세스
	// 수명에서 바뀌지 않는 오류는 프롬프트 반복만 만들므로 재기동까지 굳힌다.
	fatal error
}

var errKeyMaterialInvalid = errors.New("고정 키 자료 오류")

func (k *lazyKey) PublicKey() ssh.PublicKey { return k.pub }

func (k *lazyKey) Signer() (ssh.Signer, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.signer != nil {
		return k.signer, nil
	}
	if k.fatal != nil {
		return nil, k.fatal
	}
	s, err := k.unlock()
	if err != nil {
		if errors.Is(err, errConfTampered) || errors.Is(err, errKeyMaterialInvalid) {
			k.fatal = err
		}
		return nil, err
	}
	if s == nil {
		k.fatal = fmt.Errorf("%w: 잠금 해제가 빈 signer를 반환", errKeyMaterialInvalid)
		return nil, k.fatal
	}
	// 무결성 검사: 해제된 개인키가 지금껏 광고해 온 공개키(key.pub)와
	// 일치해야 한다. 불일치는 파일 뒤바뀜·설정 오류의 신호다.
	if !bytes.Equal(s.PublicKey().Marshal(), k.pub.Marshal()) {
		k.fatal = fmt.Errorf("%w: 해제된 개인키가 key.pub과 불일치 — 키 파일 구성을 확인", errKeyMaterialInvalid)
		return nil, k.fatal
	}
	k.signer = s
	return s, nil
}
