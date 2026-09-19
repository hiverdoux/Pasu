// codesign 실험 — 실행 중 프로세스의 코드서명을 Security framework로 동적 검증.
//
// 확인하려는 것:
//  1. pid만으로 실행 중 프로세스의 SecCode(동적 코드 신원)를 얻고
//     "Developer ID + Team ID + Identifier" requirement로 검증할 수 있는가
//  2. 오답(다른 team, 다른 id)과 ad-hoc 위조 identifier가 확실히 거부되는가
//  3. root 프로세스(launchd)·죽은 pid에서의 거동
//  4. 검사 1회의 지연 시간(매번 requirement 컴파일 vs 사전 컴파일)
//
// 실행: go run ./experiments/codesign   (저장소 루트에서)
// 보조 sleeper는 자동 빌드하며, PASU_EXP_SLEEPER로 미리 빌드한 경로를 줄 수도 있다.
package main

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <stdlib.h>
#include <libproc.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

// pid의 동적 코드 신원(SecCode)을 얻는다.
static OSStatus copyCodeForPid(pid_t pid, SecCodeRef *out) {
	CFNumberRef pidNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &pid);
	const void *keys[] = {kSecGuestAttributePid};
	const void *vals[] = {pidNum};
	CFDictionaryRef attrs = CFDictionaryCreate(kCFAllocatorDefault, keys, vals, 1,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	OSStatus st = SecCodeCopyGuestWithAttributes(NULL, attrs, kSecCSDefaultFlags, out);
	CFRelease(attrs);
	CFRelease(pidNum);
	return st;
}

static OSStatus compileRequirement(const char *reqStr, SecRequirementRef *out) {
	CFStringRef s = CFStringCreateWithCString(kCFAllocatorDefault, reqStr, kCFStringEncodingUTF8);
	if (s == NULL) return errSecParam;
	OSStatus st = SecRequirementCreateWithString(s, kSecCSDefaultFlags, out);
	CFRelease(s);
	return st;
}

// 사전 컴파일된 requirement로 pid를 검증한다.
static OSStatus validatePidWithReq(pid_t pid, SecRequirementRef req) {
	SecCodeRef code = NULL;
	OSStatus st = copyCodeForPid(pid, &code);
	if (st != errSecSuccess) return st;
	st = SecCodeCheckValidity(code, kSecCSDefaultFlags, req);
	CFRelease(code);
	return st;
}

// 전체 사이클(requirement 컴파일 포함)로 pid를 검증한다.
static OSStatus validatePidFull(pid_t pid, const char *reqStr) {
	SecRequirementRef req = NULL;
	OSStatus st = compileRequirement(reqStr, &req);
	if (st != errSecSuccess) return st;
	st = validatePidWithReq(pid, req);
	CFRelease(req);
	return st;
}

// 참고용 서명 정보(팀·식별자·플래그) 추출. 정책 판정이 아니라 관찰 용도.
static OSStatus copySigningInfo(pid_t pid, char *teamBuf, int teamLen,
		char *idBuf, int idLen, uint32_t *flags) {
	SecCodeRef code = NULL;
	OSStatus st = copyCodeForPid(pid, &code);
	if (st != errSecSuccess) return st;
	CFDictionaryRef info = NULL;
	st = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info);
	CFRelease(code);
	if (st != errSecSuccess) return st;
	teamBuf[0] = 0;
	idBuf[0] = 0;
	*flags = 0;
	CFStringRef team = CFDictionaryGetValue(info, kSecCodeInfoTeamIdentifier);
	if (team != NULL) CFStringGetCString(team, teamBuf, teamLen, kCFStringEncodingUTF8);
	CFStringRef ident = CFDictionaryGetValue(info, kSecCodeInfoIdentifier);
	if (ident != NULL) CFStringGetCString(ident, idBuf, idLen, kCFStringEncodingUTF8);
	CFNumberRef fl = CFDictionaryGetValue(info, kSecCodeInfoFlags);
	if (fl != NULL) CFNumberGetValue(fl, kCFNumberSInt32Type, flags);
	CFRelease(info);
	return errSecSuccess;
}

static char *statusMessage(OSStatus st) {
	CFStringRef s = SecCopyErrorMessageString(st, NULL);
	if (s == NULL) return NULL;
	CFIndex n = CFStringGetMaximumSizeForEncoding(CFStringGetLength(s), kCFStringEncodingUTF8) + 1;
	char *buf = malloc(n);
	if (buf != NULL && !CFStringGetCString(s, buf, n, kCFStringEncodingUTF8)) buf[0] = 0;
	CFRelease(s);
	return buf;
}
*/
import "C"

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	anthropicTeam = "Q6L2SF6YDW"
	claudeCodeID  = "com.anthropic.claude-code"
)

// Pasu의 Developer ID 검증과 같은 형식의 requirement 템플릿:
// Apple 뿌리 + Developer ID 중간/리프 인증서 마커 + 팀(subject.OU) + 식별자.
func devIDRequirement(team, id string) string {
	return fmt.Sprintf(`anchor apple generic and identifier "%s" and `+
		`certificate 1[field.1.2.840.113635.100.6.2.6] and `+
		`certificate leaf[field.1.2.840.113635.100.6.1.13] and `+
		`certificate leaf[subject.OU] = "%s"`, id, team)
}

func statusText(st C.OSStatus) string {
	if st == C.errSecSuccess {
		return "성공(0)"
	}
	msg := C.statusMessage(st)
	defer C.free(unsafe.Pointer(msg))
	return fmt.Sprintf("%d %q", int(st), C.GoString(msg))
}

func validate(pid int, req string) C.OSStatus {
	cs := C.CString(req)
	defer C.free(unsafe.Pointer(cs))
	return C.validatePidFull(C.pid_t(pid), cs)
}

func signingInfo(pid int) (team, id string, flags uint32, err error) {
	var teamBuf, idBuf [256]C.char
	var fl C.uint32_t
	st := C.copySigningInfo(C.pid_t(pid), &teamBuf[0], 256, &idBuf[0], 256, &fl)
	if st != C.errSecSuccess {
		return "", "", 0, fmt.Errorf("%s", statusText(st))
	}
	return C.GoString(&teamBuf[0]), C.GoString(&idBuf[0]), uint32(fl), nil
}

func pidPath(pid int) string {
	buf := make([]byte, C.PROC_PIDPATHINFO_MAXSIZE)
	n, _ := C.proc_pidpath(C.int(pid), unsafe.Pointer(&buf[0]), C.uint32_t(len(buf)))
	if n <= 0 {
		return "?"
	}
	return string(buf[:n])
}

func ancestryPids(pid int) []int {
	var chain []int
	seen := map[int]bool{}
	for pid > 0 && !seen[pid] && len(chain) < 32 {
		seen[pid] = true
		chain = append(chain, pid)
		kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
		if err != nil || pid == 1 {
			break
		}
		pid = int(kp.Eproc.Ppid)
	}
	return chain
}

var failed bool
var incomplete bool

func report(name string, ok bool, detail string) {
	mark := "PASS"
	if !ok {
		mark = "FAIL"
		failed = true
	}
	fmt.Printf("  [%s] %s — %s\n", mark, name, detail)
}

func main() {
	fmt.Println("== 1. 내 조상 사슬의 서명 정보(관찰)")
	chain := ancestryPids(os.Getpid())
	var devIDPid int // Anthropic requirement를 통과하는 첫 조상
	anthropicReq := devIDRequirement(anthropicTeam, claudeCodeID)
	for _, pid := range chain {
		team, id, flags, err := signingInfo(pid)
		if err != nil {
			fmt.Printf("  pid %d %s: 정보 조회 실패 (%v)\n", pid, pidPath(pid), err)
			continue
		}
		fmt.Printf("  pid %d %s: team=%q id=%q flags=%#x\n", pid, pidPath(pid), team, id, flags)
		if devIDPid == 0 && validate(pid, anthropicReq) == C.errSecSuccess {
			devIDPid = pid
		}
	}

	fmt.Println("== 2. Developer ID requirement 판정")
	if devIDPid == 0 {
		fmt.Println("  [미검증] 지정된 Developer ID 대조군이 조상 사슬에 없음")
		incomplete = true
	} else {
		report("정답 team+id 허용", true, fmt.Sprintf("pid %d (%s)", devIDPid, pidPath(devIDPid)))
		st := validate(devIDPid, devIDRequirement("0000000000", claudeCodeID))
		report("다른 team 거부", st != C.errSecSuccess, statusText(st))
		st = validate(devIDPid, devIDRequirement(anthropicTeam, "com.example.other"))
		report("다른 id 거부", st != C.errSecSuccess, statusText(st))
	}

	fmt.Println("== 3. ad-hoc 서명(go run 자기 자신) 거부")
	st := validate(os.Getpid(), anthropicReq)
	report("ad-hoc 자기 자신 거부", st != C.errSecSuccess, statusText(st))

	fmt.Println("== 4. root 프로세스(launchd, 다른 UID)")
	team, id, flags, err := signingInfo(1)
	if err != nil {
		fmt.Printf("  launchd 정보 조회 실패: %v (같은 UID 제한이면 pasu에는 무해 — 매칭 불가로만 작동)\n", err)
	} else {
		fmt.Printf("  launchd: team=%q id=%q flags=%#x (다른 UID도 조회 가능함을 확인)\n", team, id, flags)
	}
	st = validate(1, anthropicReq)
	report("launchd는 Anthropic 규칙에 불일치", st != C.errSecSuccess, statusText(st))

	fmt.Println("== 5. 위조 identifier(ad-hoc 재서명) 거부")
	spoofTest()

	fmt.Println("== 6. 죽은 pid")
	deadPidTest()

	fmt.Println("== 7. 지연 시간")
	if devIDPid != 0 {
		latency(devIDPid, anthropicReq)
	} else {
		fmt.Println("  [건너뜀] DevID 대상 없음")
	}

	if failed {
		fmt.Println("\n일부 확인 실패 — 위 FAIL 항목 참조")
		os.Exit(1)
	}
	if incomplete {
		fmt.Println("\n검증 불충분: 대조군이 없어 일부 검사를 수행하지 못했습니다")
		os.Exit(2)
	}
	fmt.Println("\n모든 확인 통과")
}

// sleeper를 복사해 ad-hoc으로 identifier만 위조 서명한 뒤, 그 프로세스가
// Developer ID requirement를 통과하지 못함을 확인한다.
func spoofTest() {
	sleeper := os.Getenv("PASU_EXP_SLEEPER")
	work, err := os.MkdirTemp("", "pasu-codesign")
	if err != nil {
		report("위조 준비(임시 폴더)", false, err.Error())
		return
	}
	defer os.RemoveAll(work)
	if sleeper == "" {
		sleeper = filepath.Join(work, "sleeper")
		out, err := exec.Command("go", "build", "-o", sleeper, "./experiments/codesign/sleeper").CombinedOutput()
		if err != nil {
			report("위조 준비(sleeper 빌드)", false, string(out))
			return
		}
	}
	spoofed := filepath.Join(work, "spoofed")
	data, err := os.ReadFile(sleeper)
	if err == nil {
		err = os.WriteFile(spoofed, data, 0o755)
	}
	if err != nil {
		report("위조 준비(복사)", false, err.Error())
		return
	}
	out, err := exec.Command("codesign", "-f", "-s", "-", "--identifier", claudeCodeID, spoofed).CombinedOutput()
	if err != nil {
		report("위조 준비(ad-hoc 재서명)", false, string(out))
		return
	}
	cmd := exec.Command(spoofed)
	if err := cmd.Start(); err != nil {
		report("위조 준비(실행)", false, err.Error())
		return
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	pid := cmd.Process.Pid
	team, id, _, err := signingInfo(pid)
	if err == nil {
		fmt.Printf("  위조 프로세스 pid %d: team=%q id=%q ← identifier는 자기 신고 값임을 보여줌\n", pid, team, id)
	}
	st := validate(pid, devIDRequirement(anthropicTeam, claudeCodeID))
	report("위조 identifier 거부", st != C.errSecSuccess, statusText(st))
}

func deadPidTest() {
	cmd := exec.Command("/usr/bin/true")
	if err := cmd.Start(); err != nil {
		report("죽은 pid 준비", false, err.Error())
		return
	}
	pid := cmd.Process.Pid
	cmd.Wait()
	time.Sleep(50 * time.Millisecond)
	st := validate(pid, devIDRequirement(anthropicTeam, claudeCodeID))
	report("죽은 pid는 오류로 거부", st != C.errSecSuccess, statusText(st))
}

func latency(pid int, req string) {
	const n = 100
	start := time.Now()
	for i := 0; i < n; i++ {
		validate(pid, req)
	}
	full := time.Since(start)

	cs := C.CString(req)
	defer C.free(unsafe.Pointer(cs))
	var compiled C.SecRequirementRef
	if C.compileRequirement(cs, &compiled) != C.errSecSuccess {
		fmt.Println("  requirement 사전 컴파일 실패")
		return
	}
	start = time.Now()
	for i := 0; i < n; i++ {
		C.validatePidWithReq(C.pid_t(pid), compiled)
	}
	pre := time.Since(start)
	fmt.Printf("  전체 사이클(컴파일 포함): 평균 %v/회\n", full/n)
	fmt.Printf("  requirement 사전 컴파일: 평균 %v/회\n", pre/n)
}
