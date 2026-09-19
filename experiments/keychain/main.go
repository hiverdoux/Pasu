// Keychain·생체 인증·Secure Enclave API의 접근 조건을 비교하는 진단 도구.
//
// 확인하려는 것 (전부 인증 UI 없이 무인으로 판정):
//  1. ad-hoc(hardened runtime 포함) 서명 CLI가 데이터 보호 키체인
//     (kSecUseDataProtectionKeychain, iOS식 키체인)을 쓸 수 있는가
//     — 실행 파일의 서명과 application-identifier 권한 조건을 구분해 확인.
//  2. userPresence ACL(읽을 때 Touch ID/암호 요구)을 붙인 항목의 추가·삭제가
//     무인으로 되는가, 읽기는 사용자 인증을 요구하는가
//     — 읽기를 kSecUseAuthenticationUIFail로 시도해 errSecInteractionNotAllowed(-25308)이
//     나오면 인증 없이 읽을 수 없는 상태임을 확인한다.
//  3. 레거시 파일(로그인) 키체인 경로는 되는가 (별도 API 대조군)
//  4. LAContext.canEvaluatePolicy — 실행 환경에서 생체 인증이 가능한가(정보용)
//  5. Secure Enclave 비영구 키 생성+서명이 ad-hoc CLI에서 되는가 (SE 래핑 후보의 성립 여부)
//
// 실행: go run ./experiments/keychain            (linker ad-hoc 서명 상태)
// ad-hoc 서명에 Hardened Runtime을 추가한 대조군으로 확인하려면:
//
//	go build -o /tmp/pasu-exp-keychain ./experiments/keychain
//	codesign --force --sign - --options runtime /tmp/pasu-exp-keychain
//	/tmp/pasu-exp-keychain
//
// 실험 항목은 service="pasu-experiment"로만 만들고 끝나면 전부 삭제한다.
package main

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation -framework LocalAuthentication -lobjc
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <objc/runtime.h>
#include <objc/message.h>

// generic password 항목의 공통 질의 딕셔너리.
static CFMutableDictionaryRef expBase(const char *service, const char *account, int dataProtection) {
	CFMutableDictionaryRef d = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDictionarySetValue(d, kSecClass, kSecClassGenericPassword);
	CFStringRef s = CFStringCreateWithCString(kCFAllocatorDefault, service, kCFStringEncodingUTF8);
	CFStringRef a = CFStringCreateWithCString(kCFAllocatorDefault, account, kCFStringEncodingUTF8);
	CFDictionarySetValue(d, kSecAttrService, s);
	CFDictionarySetValue(d, kSecAttrAccount, a);
	CFRelease(s);
	CFRelease(a);
	if (dataProtection) CFDictionarySetValue(d, kSecUseDataProtectionKeychain, kCFBooleanTrue);
	return d;
}

// withACL이면 userPresence(읽을 때 Touch ID 또는 로그인 암호 요구) ACL을 붙인다.
static OSStatus expAdd(const char *service, const char *account, const char *secret, int dp, int withACL) {
	CFMutableDictionaryRef d = expBase(service, account, dp);
	CFDataRef data = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)secret, (CFIndex)strlen(secret));
	CFDictionarySetValue(d, kSecValueData, data);
	CFRelease(data);
	if (withACL) {
		CFErrorRef cferr = NULL;
		SecAccessControlRef ac = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
			kSecAttrAccessibleWhenUnlockedThisDeviceOnly, kSecAccessControlUserPresence, &cferr);
		if (ac == NULL) {
			CFRelease(d);
			if (cferr) CFRelease(cferr);
			return errSecParam;
		}
		CFDictionarySetValue(d, kSecAttrAccessControl, ac);
		CFRelease(ac);
	} else if (dp) {
		CFDictionarySetValue(d, kSecAttrAccessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly);
	}
	OSStatus st = SecItemAdd(d, NULL);
	CFRelease(d);
	return st;
}

// noUI면 인증창을 금지하고 읽는다(인증이 필요한 항목이면 -25308을 기대한다).
static OSStatus expRead(const char *service, const char *account, int dp, int noUI, char *out, size_t outLen) {
	CFMutableDictionaryRef d = expBase(service, account, dp);
	CFDictionarySetValue(d, kSecReturnData, kCFBooleanTrue);
	CFDictionarySetValue(d, kSecMatchLimit, kSecMatchLimitOne);
	if (noUI) CFDictionarySetValue(d, kSecUseAuthenticationUI, kSecUseAuthenticationUIFail);
	CFTypeRef result = NULL;
	OSStatus st = SecItemCopyMatching(d, &result);
	CFRelease(d);
	if (st == errSecSuccess && result != NULL && out != NULL && outLen > 0) {
		CFDataRef data = (CFDataRef)result;
		CFIndex n = CFDataGetLength(data);
		if ((size_t)n >= outLen) n = (CFIndex)outLen - 1;
		memcpy(out, CFDataGetBytePtr(data), (size_t)n);
		out[n] = 0;
	}
	if (result) CFRelease(result);
	return st;
}

// 항목이 어느 access group에 들어갔는지 본다(보호 범위 이해용, 정보 조회라 무인).
static OSStatus expReadGroup(const char *service, const char *account, int dp, char *out, size_t outLen) {
	CFMutableDictionaryRef d = expBase(service, account, dp);
	CFDictionarySetValue(d, kSecReturnAttributes, kCFBooleanTrue);
	CFDictionarySetValue(d, kSecMatchLimit, kSecMatchLimitOne);
	CFTypeRef result = NULL;
	OSStatus st = SecItemCopyMatching(d, &result);
	CFRelease(d);
	if (st == errSecSuccess && result != NULL && out != NULL && outLen > 0) {
		CFStringRef g = CFDictionaryGetValue((CFDictionaryRef)result, kSecAttrAccessGroup);
		if (g == NULL || !CFStringGetCString(g, out, (CFIndex)outLen, kCFStringEncodingUTF8)) {
			snprintf(out, outLen, "(없음)");
		}
	}
	if (result) CFRelease(result);
	return st;
}

static OSStatus expDelete(const char *service, const char *account, int dp) {
	CFMutableDictionaryRef d = expBase(service, account, dp);
	OSStatus st = SecItemDelete(d);
	CFRelease(d);
	return st;
}

// LAContext.canEvaluatePolicy — Objective-C 런타임 직접 호출(순수 C에서).
// policy 1=생체 전용, 2=생체+로그인 암호. 반환 1=가능 0=불가 -1=클래스 없음.
static int laCanEvaluate(long policy, long *errCode, long *bioType) {
	Class cls = objc_getClass("LAContext");
	if (cls == NULL) return -1;
	id alloced = ((id(*)(Class, SEL))objc_msgSend)(cls, sel_registerName("alloc"));
	id ctx = ((id(*)(id, SEL))objc_msgSend)(alloced, sel_registerName("init"));
	if (ctx == NULL) return -1;
	id nserr = NULL;
	BOOL ok = ((BOOL(*)(id, SEL, long, id *))objc_msgSend)(ctx,
		sel_registerName("canEvaluatePolicy:error:"), policy, &nserr);
	if (!ok && nserr != NULL && errCode != NULL) {
		*errCode = ((long(*)(id, SEL))objc_msgSend)(nserr, sel_registerName("code"));
	}
	if (bioType != NULL) {
		*bioType = ((long(*)(id, SEL))objc_msgSend)(ctx, sel_registerName("biometryType"));
	}
	((void (*)(id, SEL))objc_msgSend)(ctx, sel_registerName("release"));
	return ok ? 1 : 0;
}

// Secure Enclave 비영구 P-256 키 생성 + 서명 1회. 키체인 무접촉·UI 없음.
// 실패 시 CFError 코드를 돌려준다(-34018=errSecMissingEntitlement 여부가 관심사).
static long seCreateAndSign(void) {
	CFErrorRef cferr = NULL;
	SecAccessControlRef ac = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
		kSecAttrAccessibleWhenUnlockedThisDeviceOnly, kSecAccessControlPrivateKeyUsage, &cferr);
	if (ac == NULL) {
		long c = cferr ? CFErrorGetCode(cferr) : -9999;
		if (cferr) CFRelease(cferr);
		return c;
	}
	CFMutableDictionaryRef priv = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDictionarySetValue(priv, kSecAttrIsPermanent, kCFBooleanFalse);
	CFDictionarySetValue(priv, kSecAttrAccessControl, ac);
	int bits = 256;
	CFNumberRef n = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bits);
	CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDictionarySetValue(attrs, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
	CFDictionarySetValue(attrs, kSecAttrKeySizeInBits, n);
	CFDictionarySetValue(attrs, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
	CFDictionarySetValue(attrs, kSecPrivateKeyAttrs, priv);
	SecKeyRef key = SecKeyCreateRandomKey(attrs, &cferr);
	CFRelease(attrs);
	CFRelease(priv);
	CFRelease(n);
	CFRelease(ac);
	if (key == NULL) {
		long c = cferr ? CFErrorGetCode(cferr) : -9998;
		if (cferr) CFRelease(cferr);
		return c;
	}
	const char *msg = "pasu-exp";
	CFDataRef md = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)msg, (CFIndex)strlen(msg));
	CFDataRef sig = SecKeyCreateSignature(key, kSecKeyAlgorithmECDSASignatureMessageX962SHA256, md, &cferr);
	CFRelease(md);
	long rc = 0;
	if (sig == NULL) rc = cferr ? CFErrorGetCode(cferr) : -9997;
	if (sig) CFRelease(sig);
	if (cferr) CFRelease(cferr);
	CFRelease(key);
	return rc;
}

// SE 키의 "영속 블롭" 실험 결과 묶음.
typedef struct {
	long createErr;       // SE 키 생성 오류 (0=성공)
	int  extRepOK;        // SecKeyCopyExternalRepresentation 성공 여부
	long extRepErr;
	int  blobLen;         // attributes의 kSecValueData 길이 (0=없음)
	int  rebuildOK;       // SecKeyCreateWithData(TokenID=SE)로 재구성 성공
	long rebuildErr;
	int  signVerifyOK;    // 재구성 키 서명 → 원 공개키로 검증 통과
	int  eciesOK;         // ECIES 암호화(공개키) → 재구성 키로 복호 왕복 성공
	long eciesErr;
	char attrKeys[2048];  // SecKeyCopyAttributes에서 관찰된 키 목록
	// 기준선(원본 키)과 정밀 진단.
	int  origSignVerifyOK; // 원본 키 서명 → 검증
	long origSignErr;
	int  origEciesOK;      // 원본 키로 ECIES 복호
	long origEciesErr;
	long rebuiltSignErr;   // 재구성 키 서명의 CFError 코드
	int  rebuildBareOK;    // KeyType 없이 {TokenID,KeyClass}만으로 재구성
	int  bareSignVerifyOK; // bare 재구성 키 서명 → 검증
	long bareSignErr;
} seBlobResult;

// 비영구 SE 키를 만들고, 키체인 없이 "블롭 저장 → 재구성 → 사용"이 되는지 검사.
// CryptoKit(Swift)의 dataRepresentation과 같은 일이 C API로 되는지가 관심사다.
static void seBlobRoundTrip(seBlobResult *r) {
	memset(r, 0, sizeof(*r));
	CFErrorRef cferr = NULL;
	SecAccessControlRef ac = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
		kSecAttrAccessibleWhenUnlockedThisDeviceOnly, kSecAccessControlPrivateKeyUsage, &cferr);
	if (ac == NULL) {
		r->createErr = cferr ? CFErrorGetCode(cferr) : -9999;
		if (cferr) CFRelease(cferr);
		return;
	}
	CFMutableDictionaryRef priv = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDictionarySetValue(priv, kSecAttrIsPermanent, kCFBooleanFalse);
	CFDictionarySetValue(priv, kSecAttrAccessControl, ac);
	int bits = 256;
	CFNumberRef n = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bits);
	CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDictionarySetValue(attrs, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
	CFDictionarySetValue(attrs, kSecAttrKeySizeInBits, n);
	CFDictionarySetValue(attrs, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
	CFDictionarySetValue(attrs, kSecPrivateKeyAttrs, priv);
	SecKeyRef key = SecKeyCreateRandomKey(attrs, &cferr);
	CFRelease(attrs); CFRelease(priv); CFRelease(n); CFRelease(ac);
	if (key == NULL) {
		r->createErr = cferr ? CFErrorGetCode(cferr) : -9998;
		if (cferr) CFRelease(cferr);
		return;
	}
	SecKeyRef pub = SecKeyCopyPublicKey(key);

	CFDataRef ext = SecKeyCopyExternalRepresentation(key, &cferr);
	if (ext != NULL) { r->extRepOK = 1; CFRelease(ext); }
	else { r->extRepErr = cferr ? CFErrorGetCode(cferr) : 0; }
	if (cferr) { CFRelease(cferr); cferr = NULL; }

	// attributes에서 블롭(kSecValueData) 탐색 + 키 목록 기록.
	CFDictionaryRef kattrs = SecKeyCopyAttributes(key);
	CFDataRef blob = NULL;
	if (kattrs != NULL) {
		CFIndex cnt = CFDictionaryGetCount(kattrs);
		const void **keys = malloc(sizeof(void *) * (size_t)cnt);
		CFDictionaryGetKeysAndValues(kattrs, keys, NULL);
		size_t off = 0;
		for (CFIndex i = 0; i < cnt && off + 40 < sizeof(r->attrKeys); i++) {
			char kb[64] = {0};
			CFStringRef desc = CFCopyDescription(keys[i]);
			if (desc) {
				CFStringGetCString(desc, kb, sizeof(kb), kCFStringEncodingUTF8);
				CFRelease(desc);
			}
			off += (size_t)snprintf(r->attrKeys + off, sizeof(r->attrKeys) - off, "%s ", kb);
		}
		free(keys);
		CFTypeRef v = CFDictionaryGetValue(kattrs, kSecValueData);
		if (v == NULL) {
			// 공개 상수(kSecValueData)에 없으면 내부 속성 "toid"도 진단한다.
			// 공개 API가 아니며 CryptoKit dataRepresentation과 같은 형식이라고
			// 가정하지 않는다. 재구성 결과는 원래 공개키로 별도 검증한다.
			CFStringRef toid = CFStringCreateWithCString(kCFAllocatorDefault, "toid", kCFStringEncodingUTF8);
			v = CFDictionaryGetValue(kattrs, toid);
			CFRelease(toid);
		}
		if (v != NULL && CFGetTypeID(v) == CFDataGetTypeID()) {
			blob = CFDataCreateCopy(kCFAllocatorDefault, (CFDataRef)v);
			r->blobLen = (int)CFDataGetLength(blob);
		}
		CFRelease(kattrs);
	}

	// 블롭으로 키 재구성(디스크에 저장했다 다시 읽는 상황의 재현).
	SecKeyRef rebuilt = NULL;
	if (blob != NULL) {
		CFMutableDictionaryRef rattrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
			&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
		CFDictionarySetValue(rattrs, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
		CFDictionarySetValue(rattrs, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
		CFDictionarySetValue(rattrs, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
		rebuilt = SecKeyCreateWithData(blob, rattrs, &cferr);
		CFRelease(rattrs);
		if (rebuilt != NULL) r->rebuildOK = 1;
		else r->rebuildErr = cferr ? CFErrorGetCode(cferr) : -9997;
		if (cferr) { CFRelease(cferr); cferr = NULL; }
	}

	const char *msg = "pasu-se-blob";
	CFDataRef md = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)msg, (CFIndex)strlen(msg));

	// 기준선: 원본 키로 서명·검증.
	if (pub != NULL) {
		CFDataRef sig = SecKeyCreateSignature(key, kSecKeyAlgorithmECDSASignatureMessageX962SHA256, md, &cferr);
		if (sig != NULL) {
			r->origSignVerifyOK = SecKeyVerifySignature(pub, kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
				md, sig, NULL) ? 1 : 0;
			CFRelease(sig);
		} else {
			r->origSignErr = cferr ? CFErrorGetCode(cferr) : -9990;
		}
		if (cferr) { CFRelease(cferr); cferr = NULL; }
	}

	// 재구성 키로 서명 → 원 공개키로 검증.
	if (rebuilt != NULL && pub != NULL) {
		CFDataRef sig = SecKeyCreateSignature(rebuilt, kSecKeyAlgorithmECDSASignatureMessageX962SHA256, md, &cferr);
		if (sig != NULL) {
			r->signVerifyOK = SecKeyVerifySignature(pub, kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
				md, sig, NULL) ? 1 : 0;
			CFRelease(sig);
		} else {
			r->rebuiltSignErr = cferr ? CFErrorGetCode(cferr) : -9991;
		}
		if (cferr) { CFRelease(cferr); cferr = NULL; }
	}

	// KeyType 없이 {TokenID, KeyClass}만으로도 재구성해 본다.
	if (blob != NULL) {
		CFMutableDictionaryRef battrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
			&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
		CFDictionarySetValue(battrs, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
		CFDictionarySetValue(battrs, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
		SecKeyRef bare = SecKeyCreateWithData(blob, battrs, &cferr);
		CFRelease(battrs);
		if (cferr) { CFRelease(cferr); cferr = NULL; }
		if (bare != NULL) {
			r->rebuildBareOK = 1;
			CFDataRef sig = SecKeyCreateSignature(bare, kSecKeyAlgorithmECDSASignatureMessageX962SHA256, md, &cferr);
			if (sig != NULL && pub != NULL) {
				r->bareSignVerifyOK = SecKeyVerifySignature(pub, kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
					md, sig, NULL) ? 1 : 0;
			}
			if (sig) CFRelease(sig);
			else r->bareSignErr = cferr ? CFErrorGetCode(cferr) : -9992;
			if (cferr) { CFRelease(cferr); cferr = NULL; }
			CFRelease(bare);
		}
	}

	// 실사용 패턴: 공개키로 ECIES 암호화 → 원본/재구성 키로 각각 복호.
	if (pub != NULL) {
		const char *secret = "pasu-wrapped-passphrase";
		CFDataRef pt = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)secret, (CFIndex)strlen(secret));
		CFDataRef ct = SecKeyCreateEncryptedData(pub,
			kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM, pt, &cferr);
		if (cferr) { CFRelease(cferr); cferr = NULL; }
		if (ct != NULL) {
			CFDataRef dec = SecKeyCreateDecryptedData(key,
				kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM, ct, &cferr);
			if (dec != NULL) {
				r->origEciesOK = (CFDataGetLength(dec) == (CFIndex)strlen(secret) &&
					memcmp(CFDataGetBytePtr(dec), secret, strlen(secret)) == 0) ? 1 : 0;
				CFRelease(dec);
			} else {
				r->origEciesErr = cferr ? CFErrorGetCode(cferr) : -9993;
			}
			if (cferr) { CFRelease(cferr); cferr = NULL; }
			if (rebuilt != NULL) {
				dec = SecKeyCreateDecryptedData(rebuilt,
					kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM, ct, &cferr);
				if (dec != NULL) {
					r->eciesOK = (CFDataGetLength(dec) == (CFIndex)strlen(secret) &&
						memcmp(CFDataGetBytePtr(dec), secret, strlen(secret)) == 0) ? 1 : 0;
					CFRelease(dec);
				} else {
					r->eciesErr = cferr ? CFErrorGetCode(cferr) : -9996;
				}
				if (cferr) { CFRelease(cferr); cferr = NULL; }
			}
			CFRelease(ct);
		} else {
			r->eciesErr = -9995;
		}
		CFRelease(pt);
	}

	CFRelease(md);
	if (blob) CFRelease(blob);
	if (rebuilt) CFRelease(rebuilt);
	if (pub) CFRelease(pub);
	CFRelease(key);
}

static void secErrStr(int st, char *buf, size_t len) {
	CFStringRef s = SecCopyErrorMessageString((OSStatus)st, NULL);
	if (s == NULL) {
		snprintf(buf, len, "?");
		return;
	}
	if (!CFStringGetCString(s, buf, (CFIndex)len, kCFStringEncodingUTF8)) buf[0] = 0;
	CFRelease(s);
}
*/
import "C"

import (
	"fmt"
	"os"
	"unsafe"
)

const service = "pasu-experiment"

func secErr(st int) string {
	buf := make([]byte, 256)
	C.secErrStr(C.int(st), (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	return fmt.Sprintf("%d (%s)", st, C.GoString((*C.char)(unsafe.Pointer(&buf[0]))))
}

func main() {
	exe, _ := os.Executable()
	fmt.Printf("실행 파일: %s\n\n", exe)

	cs := C.CString(service)
	defer C.free(unsafe.Pointer(cs))
	mk := func(s string) *C.char { return C.CString(s) }

	// 남은 항목이 있으면 미리 청소(결과는 무시).
	for _, acc := range []string{"dp-plain", "dp-acl"} {
		a := mk(acc)
		C.expDelete(cs, a, 1)
		C.free(unsafe.Pointer(a))
	}
	aFile := mk("file-plain")
	C.expDelete(cs, aFile, 0)
	C.free(unsafe.Pointer(aFile))

	fmt.Println("== 1. 데이터 보호 키체인, ACL 없음 (성립의 전제 조건)")
	{
		acc := mk("dp-plain")
		defer C.free(unsafe.Pointer(acc))
		st := int(C.expAdd(cs, acc, mk("dummy-plain"), 1, 0))
		fmt.Printf("  추가:            %s\n", secErr(st))
		if st == 0 {
			buf := make([]byte, 128)
			st = int(C.expRead(cs, acc, 1, 0, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf))))
			got := C.GoString((*C.char)(unsafe.Pointer(&buf[0])))
			fmt.Printf("  무인 읽기:       %s, 왕복=%v\n", secErr(st), got == "dummy-plain")
			gbuf := make([]byte, 256)
			st = int(C.expReadGroup(cs, acc, 1, (*C.char)(unsafe.Pointer(&gbuf[0])), C.size_t(len(gbuf))))
			fmt.Printf("  access group:    %s (조회 %s)\n", C.GoString((*C.char)(unsafe.Pointer(&gbuf[0]))), secErr(st))
			fmt.Printf("  삭제:            %s\n", secErr(int(C.expDelete(cs, acc, 1))))
		}
	}

	fmt.Println("== 2. 데이터 보호 키체인 + userPresence ACL (Touch ID 설계의 심장)")
	{
		acc := mk("dp-acl")
		defer C.free(unsafe.Pointer(acc))
		st := int(C.expAdd(cs, acc, mk("dummy-acl"), 1, 1))
		fmt.Printf("  추가(무인):      %s\n", secErr(st))
		if st == 0 {
			st = int(C.expRead(cs, acc, 1, 1, nil, 0))
			fmt.Printf("  UI금지 읽기:     %s  ← -25308(interaction not allowed)이면 인증 없이 읽기 차단\n", secErr(st))
			fmt.Printf("  삭제(무인):      %s  ← 삭제는 인증 없이 되는지(항목 교체·회전 UX 근거)\n", secErr(int(C.expDelete(cs, acc, 1))))
		}
	}

	fmt.Println("== 3. 레거시 파일(로그인) 키체인 (대체 후보)")
	{
		acc := mk("file-plain")
		defer C.free(unsafe.Pointer(acc))
		st := int(C.expAdd(cs, acc, mk("dummy-file"), 0, 0))
		fmt.Printf("  추가:            %s\n", secErr(st))
		if st == 0 {
			buf := make([]byte, 128)
			st = int(C.expRead(cs, acc, 0, 0, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf))))
			got := C.GoString((*C.char)(unsafe.Pointer(&buf[0])))
			fmt.Printf("  생성자 읽기:     %s, 왕복=%v (생성 앱은 무인 통과가 정상)\n", secErr(st), got == "dummy-file")
			fmt.Printf("  삭제:            %s\n", secErr(int(C.expDelete(cs, acc, 0))))
		}
	}

	fmt.Println("== 4. LAContext.canEvaluatePolicy (이 머신의 생체 인증 가용성)")
	{
		var errCode, bioType C.long
		ok := C.laCanEvaluate(1, &errCode, &bioType)
		fmt.Printf("  생체 전용(1):    가능=%d err=%d biometryType=%d (1=TouchID 2=FaceID)\n", ok, errCode, bioType)
		errCode, bioType = 0, 0
		ok = C.laCanEvaluate(2, &errCode, &bioType)
		fmt.Printf("  생체+암호(2):    가능=%d err=%d\n", ok, errCode)
	}

	fmt.Println("== 5. Secure Enclave 비영구 키 생성+서명 (SE 래핑 후보의 성립 여부)")
	{
		rc := C.seCreateAndSign()
		if rc == 0 {
			fmt.Println("  결과:            성공 (SE 사용 가능)")
		} else {
			fmt.Printf("  결과:            실패 %s\n", secErr(int(rc)))
		}
	}

	fmt.Println("== 6. SE 키 블롭 영속화 (키체인 없이 파일 저장→재구성이 되는가)")
	{
		var r C.seBlobResult
		C.seBlobRoundTrip(&r)
		if r.createErr != 0 {
			fmt.Printf("  키 생성 실패:    %s\n", secErr(int(r.createErr)))
		} else {
			fmt.Printf("  ExternalRep:     성공=%d err=%d (SE 키는 실패가 정상)\n", r.extRepOK, r.extRepErr)
			fmt.Printf("  블롭(toid):      %d바이트 (0이면 이 경로 불성립)\n", r.blobLen)
			fmt.Printf("  [기준선] 원본 서명·검증=%d signErr=%d / 원본 ECIES 복호=%d err=%d\n",
				r.origSignVerifyOK, r.origSignErr, r.origEciesOK, r.origEciesErr)
			fmt.Printf("  재구성(KeyType 포함): 성공=%d err=%d 서명·검증=%d signErr=%d\n",
				r.rebuildOK, r.rebuildErr, r.signVerifyOK, r.rebuiltSignErr)
			fmt.Printf("  재구성(bare):        성공=%d 서명·검증=%d signErr=%d\n",
				r.rebuildBareOK, r.bareSignVerifyOK, r.bareSignErr)
			fmt.Printf("  재구성 ECIES 복호:   성공=%d err=%d (passphrase 래핑 사용 패턴)\n", r.eciesOK, r.eciesErr)
		}
	}
}
