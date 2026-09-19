package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

// runSetupLegacyTouchID는 터미널에서 passphrase를 1회 받아 검증한 뒤, 새 결속
// MAC 키 K를 뽑아 passphrase‖K를 Secure Enclave 키(userPresence)로 봉인해
// <dir>/sewrap(v2)에 저장하고, 현재 설정의 지문을 conf.hmac에 기록한다.
// 마지막에 실제 Touch ID 왕복으로 해제까지 검증해야 설정이 완료된다
// (실패하면 되돌림). passphrase 자체는 어디에도 저장되지 않는다 — 저장되는
// 것은 SE 없이는 풀 수 없는 봉인뿐이다.
// Developer ID 앱 도입 뒤에는 기존 sewrap에서 Keychain으로 옮기는 마이그레이션과
// ad-hoc 개발 빌드의 호환 경로로만 사용한다.
func runSetupLegacyTouchID(keyPath, wrapPath, confPath, approvalsPath, macPath string) error {
	pass, err := readPassphraseFn(fmt.Sprintf("%s passphrase: ", keyPath))
	if err != nil {
		return err
	}
	defer wipe(pass)
	if _, err := ensureKeyMatches(keyPath, pass, true); err != nil {
		return err
	}

	k, err := newBindKey()
	if err != nil {
		return err
	}
	payload := append(append([]byte{}, pass...), k...)
	defer wipe(payload)
	w, err := seSeal(payload, sewrapV2)
	if err != nil {
		return err
	}

	// 해제 왕복 검증은 메모리의 봉인으로 한다 — 파일은 전부 검증 뒤에 쓰므로
	// 여기서 실패하면 아무것도 남지 않는다.
	fmt.Println("Touch ID(또는 로그인 암호)로 해제를 검증합니다 …")
	got, err := w.open("설정 검증: SSH 키(pasu) 잠금 해제")
	if err != nil {
		return fmt.Errorf("해제 검증 실패 — 아무것도 기록하지 않음: %w", err)
	}
	same := bytes.Equal(got, payload)
	wipe(got)
	if !same {
		return errors.New("해제 검증 값 불일치 — 아무것도 기록하지 않음")
	}

	// 순서는 지문 먼저, 봉인 나중(runTrustLegacyConf와 같은 원칙) — 중간에 죽어도
	// "새 봉인+옛 지문"(서명 불능)이 아니라 "옛 봉인+새 지문"(다음 설정 작업이
	// 덮어씀)으로 남는다.
	if err := recordTrustedConf(k, confPath, approvalsPath, macPath); err != nil {
		return err
	}
	if err := writeSEWrap(wrapPath, w); err != nil {
		return err
	}

	fmt.Printf("완료: %s\n", wrapPath)
	fmt.Printf("설정 결속 기록: %s — pasu.conf·approvals.conf가 변조되면 서명이 거부됩니다.\n", macPath)
	fmt.Println("이후 설정을 직접 고치면 pasu를 멈춘 뒤 `pasu -trust-conf`로 재신뢰하고 재기동하세요.")
	fmt.Println("이제 pasu는 기동 시 passphrase를 묻지 않고, 첫 서명 요청 때 Touch ID로 잠금을 해제합니다.")
	fmt.Println("로그인 자동 시작까지 원하면: ./scripts/launchd.sh install")
	return nil
}

func runRemoveLegacyTouchID(wrapPath, macPath string) error {
	if err := os.Remove(wrapPath); err != nil {
		if os.IsNotExist(err) {
			fmt.Println("Touch ID 설정이 없습니다:", wrapPath)
			return nil
		}
		return err
	}
	// 설정 지문은 sewrap 속 K와 한 쌍이라 함께 정리한다(터미널 모드는 결속 off).
	if err := os.Remove(macPath); err == nil {
		fmt.Printf("설정 지문 삭제: %s\n", macPath)
	} else if !os.IsNotExist(err) {
		fmt.Printf("경고: 설정 지문 삭제 실패(%v) — 무해하지만 %s를 직접 지워도 됩니다\n", err, macPath)
	}
	fmt.Printf("삭제 완료: %s\n", wrapPath)
	fmt.Println("SE 키는 비영구라 다른 잔여 상태가 없습니다. 다음 기동부터 터미널 passphrase 모드로 동작합니다.")
	return nil
}

// runTrustLegacyConf는 수정한 pasu.conf·approvals.conf를 사용자 인증 후
// 새 신뢰 기준으로 기록한다. Touch ID 인증으로 봉인을 해제하므로 passphrase
// 재입력은 필요하지 않다. 새 K로 재봉인해 이전 설정 지문을 무효화하고,
// 이전 설정과 지문을 함께 복원하는 공격을 거부한다. v1 sewrap은 v2로 승격한다.
func runTrustLegacyConf(wrapPath, confPath, approvalsPath, macPath string) error {
	w, err := readSEWrap(wrapPath)
	if err != nil {
		if os.IsNotExist(err) {
			return errors.New("설정 결속은 Touch ID 모드 전용 — 먼저 -setup-touchid를 실행하세요 (터미널 모드는 재기동에 사람의 passphrase 입력이 필요해 결속 없이도 무인 편승 공격이 성립하지 않습니다)")
		}
		return err
	}
	payload, err := w.open("설정 결속: 현재 pasu.conf·approvals.conf를 신뢰 기준으로 기록")
	if err != nil {
		return err
	}
	defer wipe(payload)
	pass, _, err := splitSealedPayload(payload, w.V)
	if err != nil {
		return err
	}

	k, err := newBindKey()
	if err != nil {
		return err
	}
	newPayload := append(append([]byte{}, pass...), k...)
	defer wipe(newPayload)
	nw, err := seSeal(newPayload, sewrapV2)
	if err != nil {
		return err
	}
	// 순서는 지문 먼저, 봉인 나중 — 중간에 죽어도 "새 봉인+옛 지문"(서명
	// 불능)이 아니라 "옛 봉인+새 지문"(다음 설정 작업·승격이 덮어씀)으로 남는다.
	if err := recordTrustedConf(k, confPath, approvalsPath, macPath); err != nil {
		return err
	}
	if err := writeSEWrap(wrapPath, nw); err != nil {
		return err
	}
	fmt.Printf("신뢰 기준 기록 완료: %s (K 회전 — 이전 지문은 전부 무효)\n", macPath)
	fmt.Println("가동 중인 pasu가 있으면 재기동해야 새 설정과 지문으로 서명합니다:")
	fmt.Println("  ./scripts/launchd.sh stop && ./scripts/launchd.sh start")
	return nil
}

// recordTrustedConf는 디스크의 두 설정 파일 원문을 읽어 K의 지문을 기록한다.
// pasu.conf는 필수(없으면 실수 방지를 위해 실패), approvals.conf는 없으면
// 빈 내용으로 취급한다(첫 승인 때 pasu가 만들며 지문도 그때 갱신된다).
func recordTrustedConf(k []byte, confPath, approvalsPath, macPath string) error {
	confData, err := os.ReadFile(confPath)
	if err != nil {
		return fmt.Errorf("pasu.conf 읽기 실패 — 결속은 설정 파일이 준비된 뒤에: %w", err)
	}
	apprData, err := os.ReadFile(approvalsPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("approvals.conf 읽기 실패: %w", err)
		}
		apprData = nil
	}
	b := newConfBinding(macPath, confData, apprData, nil)
	return b.adoptNewKey(k, "trust-conf")
}

func loadPublicKey(path string) (ssh.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("%s 해석 실패: %w", path, err)
	}
	if err := requireEd25519PublicKey(pub, path); err != nil {
		return nil, err
	}
	return pub, nil
}

func requireEd25519PublicKey(pub ssh.PublicKey, source string) error {
	if pub == nil {
		return fmt.Errorf("%s: 공개키가 비어 있음", source)
	}
	if pub.Type() != ssh.KeyAlgoED25519 {
		return fmt.Errorf("%s: 지원하지 않는 SSH 키 형식 %q — pasu는 ed25519만 사용", source, pub.Type())
	}
	return nil
}
