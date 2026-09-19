package main

/*
#cgo LDFLAGS: ${SRCDIR}/libpasuse.a -L/usr/lib/swift
#include <stdlib.h>
#include <stdint.h>

// 구현은 sewrap_darwin.swift(→ build.sh가 libpasuse.a로 빌드).
int pasuSESeal(const uint8_t *secret, int32_t secretLen,
	uint8_t **outBlob, int32_t *outBlobLen,
	uint8_t **outEph, int32_t *outEphLen,
	uint8_t **outCt, int32_t *outCtLen,
	char *errBuf, int32_t errLen);
int pasuSEOpen(const uint8_t *blob, int32_t blobLen,
	const uint8_t *eph, int32_t ephLen,
	const uint8_t *ct, int32_t ctLen,
	const char *reason,
	uint8_t **outSecret, int32_t *outSecretLen,
	char *errBuf, int32_t errLen);
*/
import "C"

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"unsafe"
)

// seWrap은 Secure Enclave로 봉인된 passphrase 꾸러미다(<dir>/sewrap, JSON).
// Blob은 SE 키의 dataRepresentation이다. 키를 생성한 기기의 SE와
// 사용자 인증(Touch ID/암호)이 있어야 봉인을 해제할 수 있다.
// 암호 구성과 복원 방식은 sewrap_darwin.swift 참조.
//
// V는 봉인 내용물의 프레이밍을 뜻한다:
//   - v1: 내용물 전체가 passphrase.
//   - v2: 내용물 = passphrase‖K(마지막 bindKeyLen바이트가 설정 결속 MAC 키 —
//     confbind.go). v1은 첫 잠금 해제 때 v2로 자동 승격된다(main.go).
//
// 주의: 이 봉인은 기밀성만 보장한다 — SE '공개키'로 암호화하므로 같은 UID가
// 임의 내용물로 새 봉인을 만들어 파일을 바꿔치기할 수 있다(무결성 없음).
// 위조본에 올바른 passphrase가 없으면 복호화가 실패한다. 파일 교체에 따른
// 서비스 거부는 이 봉인으로 방지하지 못한다. 무결성이 필요한 값(설정 지문)은
// 봉인이 아니라 내용물 속 K의 HMAC으로 지킨다 — confbind.go 참조.
type seWrap struct {
	V    int    `json:"v"`
	Blob []byte `json:"se_blob"`
	Eph  []byte `json:"eph_pub"`
	Ct   []byte `json:"ct"`
}

const (
	sewrapV1 = 1
	sewrapV2 = 2
)

// splitSealedPayload는 해제된 봉인 내용물을 버전에 따라 passphrase와 결속
// MAC 키 K로 가른다. v1은 K 없이(passphrase만) 돌아온다. 반환 조각은 payload와
// 저장 공간을 공유하므로 호출자는 payload만 wipe하면 된다.
func splitSealedPayload(payload []byte, v int) (pass, k []byte, err error) {
	if v < sewrapV2 {
		return payload, nil, nil
	}
	if len(payload) <= bindKeyLen {
		return nil, nil, fmt.Errorf("sewrap v%d 내용물이 너무 짧음(%d바이트) — -setup-touchid 재실행 필요", v, len(payload))
	}
	return payload[:len(payload)-bindKeyLen], payload[len(payload)-bindKeyLen:], nil
}

func cbuf(b []byte) *C.uint8_t {
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

func cErrString(buf []byte) string {
	for i, c := range buf {
		if c == 0 {
			return string(buf[:i])
		}
	}
	return string(buf)
}

// lockHint는 Keychain·SE의 -25308(interaction not allowed)에 화면 잠금
// 안내를 덧붙인다. 둘 다 WhenUnlockedThisDeviceOnly 보호를 사용하므로 화면이
// 잠겨 있으면 읽기·생성·사용이 안 된다.
func lockHint(msg string) string {
	if strings.Contains(msg, "-25308") {
		return " — 화면이 잠겨 있으면 실패합니다. 화면을 풀고 다시 시도하세요"
	}
	return ""
}

// seSeal은 secret을 새 SE 키(userPresence)로 봉인한다. 무인(인증 UI 없음).
// v는 내용물 프레이밍 버전(sewrapV1·sewrapV2) — 내용물 구성은 호출자 책임이다.
func seSeal(secret []byte, v int) (*seWrap, error) {
	if len(secret) == 0 {
		return nil, errors.New("빈 secret은 봉인할 수 없음")
	}
	if v != sewrapV1 && v != sewrapV2 {
		return nil, fmt.Errorf("모르는 sewrap 버전 %d", v)
	}
	var blob, eph, ct *C.uint8_t
	var blobLen, ephLen, ctLen C.int32_t
	errBuf := make([]byte, 512)
	rc := C.pasuSESeal(cbuf(secret), C.int32_t(len(secret)),
		&blob, &blobLen, &eph, &ephLen, &ct, &ctLen,
		(*C.char)(unsafe.Pointer(&errBuf[0])), C.int32_t(len(errBuf)))
	if rc != 0 {
		return nil, fmt.Errorf("SE 봉인 실패: %s%s", cErrString(errBuf), lockHint(cErrString(errBuf)))
	}
	defer C.free(unsafe.Pointer(blob))
	defer C.free(unsafe.Pointer(eph))
	defer C.free(unsafe.Pointer(ct))
	return &seWrap{
		V:    v,
		Blob: C.GoBytes(unsafe.Pointer(blob), C.int(blobLen)),
		Eph:  C.GoBytes(unsafe.Pointer(eph), C.int(ephLen)),
		Ct:   C.GoBytes(unsafe.Pointer(ct), C.int(ctLen)),
	}, nil
}

// open은 봉인을 해제한다. SE 연산 시점에 OS가 Touch ID(또는 로그인 암호)를
// 요구하며 reason이 그 프롬프트에 표시된다. 반환된 secret은 쓰고 나서
// 호출자가 wipe할 책임이 있다.
func (w *seWrap) open(reason string) ([]byte, error) {
	cReason := C.CString(reason)
	defer C.free(unsafe.Pointer(cReason))
	var out *C.uint8_t
	var outLen C.int32_t
	errBuf := make([]byte, 512)
	rc := C.pasuSEOpen(cbuf(w.Blob), C.int32_t(len(w.Blob)),
		cbuf(w.Eph), C.int32_t(len(w.Eph)),
		cbuf(w.Ct), C.int32_t(len(w.Ct)),
		cReason, &out, &outLen,
		(*C.char)(unsafe.Pointer(&errBuf[0])), C.int32_t(len(errBuf)))
	if rc != 0 {
		return nil, fmt.Errorf("SE 해제 실패(취소 포함): %s%s", cErrString(errBuf), lockHint(cErrString(errBuf)))
	}
	secret := C.GoBytes(unsafe.Pointer(out), C.int(outLen))
	// C 쪽 사본은 소거 후 해제한다.
	cs := unsafe.Slice((*byte)(unsafe.Pointer(out)), int(outLen))
	for i := range cs {
		cs[i] = 0
	}
	C.free(unsafe.Pointer(out))
	return secret, nil
}

func writeSEWrap(path string, w *seWrap) error {
	data, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readSEWrap(path string) (*seWrap, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var w seWrap
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("%s 해석 실패: %w", path, err)
	}
	if w.V != sewrapV1 && w.V != sewrapV2 {
		return nil, fmt.Errorf("%s: 모르는 버전 %d (지원: %d·%d)", path, w.V, sewrapV1, sewrapV2)
	}
	if len(w.Blob) == 0 || len(w.Eph) == 0 || len(w.Ct) == 0 {
		return nil, fmt.Errorf("%s: 필드 누락", path)
	}
	return &w, nil
}
