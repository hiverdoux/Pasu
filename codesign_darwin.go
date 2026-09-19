package main

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <mach/message.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

static int pasuCopyCFString(CFTypeRef value, char *out, size_t outLen) {
	if (value == NULL || CFGetTypeID(value) != CFStringGetTypeID()) return 0;
	return CFStringGetCString((CFStringRef)value, out, outLen, kCFStringEncodingUTF8);
}

static OSStatus pasuValidateAttributes(CFDictionaryRef attrs, const char *reqStr) {
	SecCodeRef code = NULL;
	OSStatus st = SecCodeCopyGuestWithAttributes(NULL, attrs, kSecCSDefaultFlags, &code);
	if (st != errSecSuccess) return st;

	CFStringRef reqCF = CFStringCreateWithCString(kCFAllocatorDefault, reqStr, kCFStringEncodingUTF8);
	if (reqCF == NULL) { CFRelease(code); return errSecParam; }
	SecRequirementRef req = NULL;
	st = SecRequirementCreateWithString(reqCF, kSecCSDefaultFlags, &req);
	CFRelease(reqCF);
	if (st != errSecSuccess) { CFRelease(code); return st; }

	st = SecCodeCheckValidity(code, kSecCSDefaultFlags, req);
	CFRelease(req);
	CFRelease(code);
	return st;
}

// pid의 "지금 실행 중인 코드"(SecCode)가 requirement를 만족하는지 검사한다.
// 디스크 파일이 아니라 커널이 추적하는 동적 코드 신원을 보므로,
// exec 이후의 바이너리 교체와 무관하다(검증 도구: experiments/codesign).
static OSStatus pasuValidatePid(pid_t pid, const char *reqStr) {
	CFNumberRef pidNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &pid);
	const void *keys[] = {kSecGuestAttributePid};
	const void *vals[] = {pidNum};
	CFDictionaryRef attrs = CFDictionaryCreate(kCFAllocatorDefault, keys, vals, 1,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	OSStatus st = pasuValidateAttributes(attrs, reqStr);
	CFRelease(attrs);
	CFRelease(pidNum);
	return st;
}

// 직접 소켓 피어는 PID 숫자 대신 pidversion을 포함한 audit token으로 찾는다.
static OSStatus pasuValidateAudit(const uint32_t values[8], const char *reqStr) {
	audit_token_t token;
	memcpy(token.val, values, sizeof(token.val));
	CFDataRef tokenData = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)&token, sizeof(token));
	if (tokenData == NULL) return errSecAllocate;
	const void *keys[] = {kSecGuestAttributeAudit};
	const void *vals[] = {tokenData};
	CFDictionaryRef attrs = CFDictionaryCreate(kCFAllocatorDefault, keys, vals, 1,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFRelease(tokenData);
	if (attrs == NULL) return errSecAllocate;
	OSStatus st = pasuValidateAttributes(attrs, reqStr);
	CFRelease(attrs);
	return st;
}

static OSStatus pasuResolveAudit(const uint32_t values[8]) {
	audit_token_t token;
	memcpy(token.val, values, sizeof(token.val));
	CFDataRef tokenData = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)&token, sizeof(token));
	if (tokenData == NULL) return errSecAllocate;
	const void *keys[] = {kSecGuestAttributeAudit};
	const void *vals[] = {tokenData};
	CFDictionaryRef attrs = CFDictionaryCreate(kCFAllocatorDefault, keys, vals, 1,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFRelease(tokenData);
	if (attrs == NULL) return errSecAllocate;
	SecCodeRef code = NULL;
	OSStatus st = SecCodeCopyGuestWithAttributes(NULL, attrs, kSecCSDefaultFlags, &code);
	CFRelease(attrs);
	if (code != NULL) CFRelease(code);
	return st;
}

static OSStatus pasuCopySigningInfo(CFDictionaryRef attrs,
	char *identifier, size_t identifierLen,
	char *team, size_t teamLen, int *platform) {
	SecCodeRef code = NULL;
	OSStatus st = SecCodeCopyGuestWithAttributes(NULL, attrs, kSecCSDefaultFlags, &code);
	if (st != errSecSuccess) return st;
	CFDictionaryRef info = NULL;
	st = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info);
	CFRelease(code);
	if (st != errSecSuccess) return st;
	identifier[0] = '\0';
	team[0] = '\0';
	*platform = 0;
	if (!pasuCopyCFString(CFDictionaryGetValue(info, kSecCodeInfoIdentifier), identifier, identifierLen)) {
		CFRelease(info);
		return errSecCSReqFailed;
	}
	pasuCopyCFString(CFDictionaryGetValue(info, kSecCodeInfoTeamIdentifier), team, teamLen);
	CFTypeRef platformValue = CFDictionaryGetValue(info, kSecCodeInfoPlatformIdentifier);
	if (platformValue != NULL && CFGetTypeID(platformValue) == CFNumberGetTypeID()) {
		int value = 0;
		if (CFNumberGetValue((CFNumberRef)platformValue, kCFNumberIntType, &value) && value != 0) *platform = 1;
	}
	CFRelease(info);
	return errSecSuccess;
}

static OSStatus pasuSigningInfoPid(pid_t pid,
	char *identifier, size_t identifierLen,
	char *team, size_t teamLen, int *platform) {
	CFNumberRef pidNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &pid);
	const void *keys[] = {kSecGuestAttributePid};
	const void *vals[] = {pidNum};
	CFDictionaryRef attrs = CFDictionaryCreate(kCFAllocatorDefault, keys, vals, 1,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	OSStatus st = pasuCopySigningInfo(attrs, identifier, identifierLen, team, teamLen, platform);
	CFRelease(attrs);
	CFRelease(pidNum);
	return st;
}

static OSStatus pasuSigningInfoAudit(const uint32_t values[8],
	char *identifier, size_t identifierLen,
	char *team, size_t teamLen, int *platform) {
	audit_token_t token;
	memcpy(token.val, values, sizeof(token.val));
	CFDataRef tokenData = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)&token, sizeof(token));
	if (tokenData == NULL) return errSecAllocate;
	const void *keys[] = {kSecGuestAttributeAudit};
	const void *vals[] = {tokenData};
	CFDictionaryRef attrs = CFDictionaryCreate(kCFAllocatorDefault, keys, vals, 1,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFRelease(tokenData);
	if (attrs == NULL) return errSecAllocate;
	OSStatus st = pasuCopySigningInfo(attrs, identifier, identifierLen, team, teamLen, platform);
	CFRelease(attrs);
	return st;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"regexp"
	"unsafe"
)

type codeIdentityKind string

const (
	codeIdentityApple     codeIdentityKind = "apple-platform"
	codeIdentityDeveloper codeIdentityKind = "developer-id"
	codeIdentityUntrusted codeIdentityKind = "untrusted"
)

type codeIdentity struct {
	Kind       codeIdentityKind `json:"kind"`
	TeamID     string           `json:"team_id,omitempty"`
	Identifier string           `json:"identifier"`
}

var errCodeIdentityUntrusted = errors.New("신뢰할 수 있는 코드 신원 없음")

// 설정 파일과 실행 중 코드에서 읽은 신원에 같은 문자 제한을 적용한다.
// 조건식 문법에 영향을 주는 따옴표·역슬래시·제어문자는 허용하지 않는다.
var (
	teamIDPattern = regexp.MustCompile(`^[A-Z0-9]{10}$`)
	signIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

// codesignMatches는 pid 프로세스가 "Apple 뿌리의 Developer ID 인증서로
// 팀 team이 서명했고 identifier가 id인 코드"라는 requirement를 만족하면 true.
//
// identifier는 서명자가 지정할 수 있으므로 Apple이 발급한 인증서의 team과
// 함께 검증한다. 같은 식별자의 임시 서명 비교는 experiments/codesign에 있다.
// field OID 두 개는 Developer ID 중간 CA·리프 인증서 마커다.
//
// v1은 설정에서, v2는 실행 중인 코드의 서명 정보에서 team·id를 얻는다.
// 출처와 관계없이 조건식 생성 시 문자셋을 검사한다. 오류는 전부 불일치 처리한다.
// requirement는 호출마다 생성·해제하며, 공유 객체의 수명 관리를 요구하지 않는다.
func codesignMatches(pid int, team, id string) bool {
	req, err := codesignRequirement(team, id)
	if err != nil {
		return false
	}
	creq := C.CString(req)
	defer C.free(unsafe.Pointer(creq))
	return C.pasuValidatePid(C.pid_t(pid), creq) == C.errSecSuccess
}

func codesignMatchesAudit(token auditToken, team, id string) bool {
	req, err := codesignRequirement(team, id)
	if err != nil {
		return false
	}
	creq := C.CString(req)
	defer C.free(unsafe.Pointer(creq))
	var rawToken [8]C.uint32_t
	for i := range token {
		rawToken[i] = C.uint32_t(token[i])
	}
	return C.pasuValidateAudit(&rawToken[0], creq) == C.errSecSuccess
}

func codesignMatchesProc(proc procInfo, team, id string) bool {
	if proc.hasToken {
		return codesignMatchesAudit(proc.token, team, id)
	}
	return codesignMatches(proc.pid, team, id)
}

func codesignRequirement(team, id string) (string, error) {
	if !teamIDPattern.MatchString(team) || !signIDPattern.MatchString(id) {
		return "", errCodeIdentityUntrusted
	}
	return fmt.Sprintf(`anchor apple generic and identifier "%s" and `+
		`certificate 1[field.1.2.840.113635.100.6.2.6] and `+
		`certificate leaf[field.1.2.840.113635.100.6.1.13] and `+
		`certificate leaf[subject.OU] = "%s"`, id, team), nil
}

func applePlatformRequirement(id string) (string, error) {
	if !signIDPattern.MatchString(id) {
		return "", errCodeIdentityUntrusted
	}
	return fmt.Sprintf(`anchor apple and identifier "%s"`, id), nil
}

func codesignMatchesApple(proc procInfo, id string) bool {
	req, err := applePlatformRequirement(id)
	if err != nil {
		return false
	}
	creq := C.CString(req)
	defer C.free(unsafe.Pointer(creq))
	if proc.hasToken {
		var rawToken [8]C.uint32_t
		for i := range proc.token {
			rawToken[i] = C.uint32_t(proc.token[i])
		}
		return C.pasuValidateAudit(&rawToken[0], creq) == C.errSecSuccess
	}
	return C.pasuValidatePid(C.pid_t(proc.pid), creq) == C.errSecSuccess
}

func signingInfoForProc(proc procInfo) (codeIdentity, error) {
	const fieldSize = 512
	idBuf := make([]byte, fieldSize)
	teamBuf := make([]byte, fieldSize)
	var platform C.int
	var status C.OSStatus
	if proc.hasToken {
		var rawToken [8]C.uint32_t
		for i := range proc.token {
			rawToken[i] = C.uint32_t(proc.token[i])
		}
		status = C.pasuSigningInfoAudit(&rawToken[0],
			(*C.char)(unsafe.Pointer(&idBuf[0])), fieldSize,
			(*C.char)(unsafe.Pointer(&teamBuf[0])), fieldSize, &platform)
	} else {
		status = C.pasuSigningInfoPid(C.pid_t(proc.pid),
			(*C.char)(unsafe.Pointer(&idBuf[0])), fieldSize,
			(*C.char)(unsafe.Pointer(&teamBuf[0])), fieldSize, &platform)
	}
	if status != C.errSecSuccess {
		return codeIdentity{}, fmt.Errorf("코드서명 정보 조회 실패: OSStatus %d", int32(status))
	}
	id := cErrString(idBuf)
	team := cErrString(teamBuf)
	switch {
	case platform != 0 && id != "" && codesignMatchesApple(proc, id):
		return codeIdentity{Kind: codeIdentityApple, Identifier: id}, nil
	case team != "" && id != "" && codesignMatchesProc(proc, team, id):
		return codeIdentity{Kind: codeIdentityDeveloper, TeamID: team, Identifier: id}, nil
	default:
		return codeIdentity{}, errCodeIdentityUntrusted
	}
}

var signingInfoForProcFn = signingInfoForProc

func codesignAuditResolvable(token auditToken) bool {
	var rawToken [8]C.uint32_t
	for i := range token {
		rawToken[i] = C.uint32_t(token[i])
	}
	return C.pasuResolveAudit(&rawToken[0]) == C.errSecSuccess
}
