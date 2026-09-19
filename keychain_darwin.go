package main

/*
#include <stdint.h>
#include <stdlib.h>

int32_t pasuKCProbe(void);
int32_t pasuKCRead(const char *reason,
	uint8_t **outSecret, int32_t *outSecretLen,
	char *errBuf, int32_t errLen);
int32_t pasuKCAdd(const uint8_t *secret, int32_t secretLen,
	char *errBuf, int32_t errLen);
int32_t pasuKCUpdate(const uint8_t *secret, int32_t secretLen,
	char *errBuf, int32_t errLen);
int32_t pasuKCDelete(char *errBuf, int32_t errLen);
int32_t pasuKCV2Probe(const char *account);
int32_t pasuKCV2Read(const char *account, const char *reason,
	uint8_t **outSecret, int32_t *outSecretLen,
	char *errBuf, int32_t errLen);
int32_t pasuKCV2Add(const char *account,
	const uint8_t *secret, int32_t secretLen, int32_t requirePresence,
	char *errBuf, int32_t errLen);
int32_t pasuKCV2Update(const char *account,
	const uint8_t *secret, int32_t secretLen,
	char *errBuf, int32_t errLen);
int32_t pasuKCV2Delete(const char *account, char *errBuf, int32_t errLen);
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

// keychainState는 이 실행 코드가 production access group을 쓸 수 있는지와
// 그 그룹에 보호 항목이 있는지를 구분한다. ad-hoc 개발 빌드는 unavailable,
// Developer ID 앱은 missing 또는 protected여야 한다. unprotected는 같은
// 그룹에 항목이 있지만 userPresence가 빠진 잘못된 상태라 사용하지 않는다.
type keychainState int

const (
	keychainUnavailable keychainState = iota
	keychainMissing
	keychainProtected
	keychainUnprotected
)

const (
	errSecSuccess               = 0
	errSecItemNotFound          = -25300
	errSecInteractionNotAllowed = -25308
	errSecMissingEntitlement    = -34018
)

func (s keychainState) String() string {
	switch s {
	case keychainMissing:
		return "missing"
	case keychainProtected:
		return "protected"
	case keychainUnprotected:
		return "unprotected"
	default:
		return "unavailable"
	}
}

func probeKeychain() (keychainState, error) {
	status := int32(C.pasuKCProbe())
	switch status {
	case errSecMissingEntitlement:
		return keychainUnavailable, nil
	case errSecItemNotFound:
		return keychainMissing, nil
	case errSecInteractionNotAllowed:
		return keychainProtected, nil
	case errSecSuccess:
		return keychainUnprotected, nil
	default:
		return keychainUnavailable, fmt.Errorf("Data Protection Keychain 상태 조회 실패: OSStatus %d", status)
	}
}

func keychainErrorBuffer() []byte { return make([]byte, 512) }

func keychainOperationError(errBuf []byte) error {
	msg := cErrString(errBuf)
	return errors.New(msg + lockHint(msg))
}

func keychainRead(reason string) ([]byte, error) {
	cReason := C.CString(reason)
	defer C.free(unsafe.Pointer(cReason))
	var out *C.uint8_t
	var outLen C.int32_t
	errBuf := keychainErrorBuffer()
	rc := C.pasuKCRead(cReason, &out, &outLen,
		(*C.char)(unsafe.Pointer(&errBuf[0])), C.int32_t(len(errBuf)))
	if rc != 0 {
		return nil, keychainOperationError(errBuf)
	}
	if out == nil || outLen <= 0 {
		return nil, errors.New("Keychain 읽기 실패: 빈 결과")
	}
	secret := C.GoBytes(unsafe.Pointer(out), C.int(outLen))
	cs := unsafe.Slice((*byte)(unsafe.Pointer(out)), int(outLen))
	wipe(cs)
	C.free(unsafe.Pointer(out))
	return secret, nil
}

func keychainAdd(secret []byte) error {
	if len(secret) == 0 {
		return errors.New("Keychain에 빈 secret을 저장할 수 없음")
	}
	errBuf := keychainErrorBuffer()
	if C.pasuKCAdd(cbuf(secret), C.int32_t(len(secret)),
		(*C.char)(unsafe.Pointer(&errBuf[0])), C.int32_t(len(errBuf))) != 0 {
		return keychainOperationError(errBuf)
	}
	return nil
}

func keychainUpdate(secret []byte) error {
	if len(secret) == 0 {
		return errors.New("Keychain에 빈 secret을 저장할 수 없음")
	}
	errBuf := keychainErrorBuffer()
	if C.pasuKCUpdate(cbuf(secret), C.int32_t(len(secret)),
		(*C.char)(unsafe.Pointer(&errBuf[0])), C.int32_t(len(errBuf))) != 0 {
		return keychainOperationError(errBuf)
	}
	return nil
}

func keychainDelete() error {
	errBuf := keychainErrorBuffer()
	if C.pasuKCDelete((*C.char)(unsafe.Pointer(&errBuf[0])), C.int32_t(len(errBuf))) != 0 {
		return keychainOperationError(errBuf)
	}
	return nil
}

const (
	v2RegistryAccount        = "registry-v2"
	v2SecretPrefix           = "key-secret-v2:"
	v2UnattendedSecretPrefix = "key-secret-v2-unattended:"
)

func v2SecretAccount(id string, requirePresence bool) string {
	if requirePresence {
		return v2SecretPrefix + id
	}
	return v2UnattendedSecretPrefix + id
}

type accountKeychainStatus int32

func keychainV2Probe(account string) accountKeychainStatus {
	cAccount := C.CString(account)
	defer C.free(unsafe.Pointer(cAccount))
	return accountKeychainStatus(C.pasuKCV2Probe(cAccount))
}

func keychainV2Read(account, reason string) ([]byte, error) {
	cAccount := C.CString(account)
	defer C.free(unsafe.Pointer(cAccount))
	cReason := C.CString(reason)
	defer C.free(unsafe.Pointer(cReason))
	var out *C.uint8_t
	var outLen C.int32_t
	errBuf := keychainErrorBuffer()
	if C.pasuKCV2Read(cAccount, cReason, &out, &outLen,
		(*C.char)(unsafe.Pointer(&errBuf[0])), C.int32_t(len(errBuf))) != 0 {
		return nil, keychainOperationError(errBuf)
	}
	if out == nil || outLen <= 0 {
		return nil, errors.New("Keychain v2 읽기 실패: 빈 결과")
	}
	data := C.GoBytes(unsafe.Pointer(out), C.int(outLen))
	wipe(unsafe.Slice((*byte)(unsafe.Pointer(out)), int(outLen)))
	C.free(unsafe.Pointer(out))
	return data, nil
}

func keychainV2Add(account string, data []byte, requirePresence bool) error {
	if len(data) == 0 {
		return errors.New("Keychain v2에 빈 데이터를 저장할 수 없음")
	}
	cAccount := C.CString(account)
	defer C.free(unsafe.Pointer(cAccount))
	require := C.int32_t(0)
	if requirePresence {
		require = 1
	}
	errBuf := keychainErrorBuffer()
	if C.pasuKCV2Add(cAccount, cbuf(data), C.int32_t(len(data)), require,
		(*C.char)(unsafe.Pointer(&errBuf[0])), C.int32_t(len(errBuf))) != 0 {
		return keychainOperationError(errBuf)
	}
	return nil
}

func keychainV2Update(account string, data []byte) error {
	if len(data) == 0 {
		return errors.New("Keychain v2에 빈 데이터를 저장할 수 없음")
	}
	cAccount := C.CString(account)
	defer C.free(unsafe.Pointer(cAccount))
	errBuf := keychainErrorBuffer()
	if C.pasuKCV2Update(cAccount, cbuf(data), C.int32_t(len(data)),
		(*C.char)(unsafe.Pointer(&errBuf[0])), C.int32_t(len(errBuf))) != 0 {
		return keychainOperationError(errBuf)
	}
	return nil
}

func keychainV2Delete(account string) error {
	cAccount := C.CString(account)
	defer C.free(unsafe.Pointer(cAccount))
	errBuf := keychainErrorBuffer()
	if C.pasuKCV2Delete(cAccount, (*C.char)(unsafe.Pointer(&errBuf[0])), C.int32_t(len(errBuf))) != 0 {
		return keychainOperationError(errBuf)
	}
	return nil
}

type keychainV2Store struct{}

func (keychainV2Store) LoadRegistry() ([]byte, error) {
	if err := keychainV2RegistryProbeError(int32(keychainV2Probe(v2RegistryAccount))); err != nil {
		return nil, err
	}
	return keychainV2Read(v2RegistryAccount, "")
}

func keychainV2RegistryProbeError(status int32) error {
	switch status {
	case errSecItemNotFound:
		return errV2RegistryMissing
	case errSecSuccess:
		return nil
	case errSecInteractionNotAllowed:
		return errors.New("Pasu의 Keychain 관리 정보에 접근할 수 없습니다 (OSStatus -25308). 화면 잠금을 해제하고 다시 시도하세요. 계속되면 Keychain 접근 상태를 확인하세요")
	case errSecMissingEntitlement:
		return errors.New("v2 registry Keychain access group entitlement 없음")
	default:
		return fmt.Errorf("v2 registry Keychain 상태 오류: OSStatus %d", status)
	}
}

func (keychainV2Store) SaveRegistry(data []byte) error {
	status := int32(keychainV2Probe(v2RegistryAccount))
	switch status {
	case errSecItemNotFound:
		return keychainV2Add(v2RegistryAccount, data, false)
	case errSecSuccess:
		return keychainV2Update(v2RegistryAccount, data)
	default:
		return fmt.Errorf("v2 registry를 저장할 수 없는 Keychain 상태: OSStatus %d", status)
	}
}

func (keychainV2Store) AddSecret(id string, payload []byte, requirePresence bool) error {
	return keychainV2Add(v2SecretAccount(id, requirePresence), payload, requirePresence)
}

func (keychainV2Store) ReadSecret(id, reason string, requirePresence bool) ([]byte, error) {
	return keychainV2Read(v2SecretAccount(id, requirePresence), reason)
}

func (keychainV2Store) DeleteSecret(id string, requirePresence bool) error {
	return keychainV2Delete(v2SecretAccount(id, requirePresence))
}

// 테스트에서 production Keychain을 건드리지 않고 상태·저장소를 대체하는
// 간접 호출점. 실환경은 위의 Security.framework 구현을 그대로 쓴다.
var (
	probeKeychainFn  = probeKeychain
	keychainReadFn   = keychainRead
	keychainAddFn    = keychainAdd
	keychainUpdateFn = keychainUpdate
	keychainDeleteFn = keychainDelete
)
