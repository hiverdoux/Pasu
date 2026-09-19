package main

/*
#cgo LDFLAGS: -lbsm
#include <errno.h>
#include <libproc.h>
#include <mach/message.h>
#include <bsm/libbsm.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

static int pasuPeerAuditToken(int fd, uint32_t out[8], int *pid, uint32_t *uid, int *pidversion) {
	audit_token_t token;
	socklen_t len = sizeof(token);
	if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &len) != 0) return errno;
	if (len != sizeof(token)) return EPROTO;
	memcpy(out, token.val, sizeof(token.val));
	*pid = audit_token_to_pid(token);
	*uid = audit_token_to_euid(token);
	*pidversion = audit_token_to_pidversion(token);
	return 0;
}

static int pasuPidPathAudit(const uint32_t values[8], void *buffer, uint32_t size) {
	audit_token_t token;
	memcpy(token.val, values, sizeof(token.val));
	return proc_pidpath_audittoken(&token, buffer, size);
}
*/
import "C"

import (
	"bytes"
	"fmt"
	"net"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// procInfo는 프로세스 하나의 신원 정보다.
// exePath는 호출자가 전달한 경로 대신 커널(proc_pidpath)에서 조회한 실행 경로다.
type procInfo struct {
	pid       int
	ppid      int
	pgid      int
	tdev      int32
	tpgid     int
	uid       uint32
	startSec  int64
	startUsec int64
	comm      string
	exePath   string
	token     auditToken
	hasToken  bool
}

type auditToken [8]uint32

type peerID struct {
	pid        int
	uid        uint32
	pidVersion int
	token      auditToken
}

// peerIdentity는 유닉스 소켓 반대편 프로세스의 audit token을 커널에서 얻고,
// 별도로 읽은 PID·UID와 서로 일치하는지 확인한다. token의 pidversion은 PID가
// 재사용돼도 직접 피어의 정확한 프로세스 인스턴스를 구분한다.
func peerIdentity(conn *net.UnixConn) (peerID, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return peerID{}, err
	}
	var id peerID
	var gerr error
	cerr := raw.Control(func(fd uintptr) {
		var rawToken [8]C.uint32_t
		var tokenPID C.int
		var tokenUID C.uint32_t
		var pidVersion C.int
		if rc := C.pasuPeerAuditToken(C.int(fd), &rawToken[0], &tokenPID, &tokenUID, &pidVersion); rc != 0 {
			gerr = fmt.Errorf("LOCAL_PEERTOKEN: %w", syscall.Errno(rc))
			return
		}
		pid, e := unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		if e != nil {
			gerr = fmt.Errorf("LOCAL_PEERPID: %w", e)
			return
		}
		cred, e := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if e != nil {
			gerr = fmt.Errorf("LOCAL_PEERCRED: %w", e)
			return
		}
		if pid != int(tokenPID) || cred.Uid != uint32(tokenUID) {
			gerr = fmt.Errorf("피어 신원 불일치: token(pid=%d uid=%d) pid=%d cred(uid=%d)",
				int(tokenPID), uint32(tokenUID), pid, cred.Uid)
			return
		}
		for i := range id.token {
			id.token[i] = uint32(rawToken[i])
		}
		id.pid = pid
		id.uid = cred.Uid
		id.pidVersion = int(pidVersion)
	})
	if cerr != nil {
		return peerID{}, cerr
	}
	return id, gerr
}

// pidPathAudit는 PID 숫자가 아니라 audit token이 가리키는 정확한 프로세스
// 인스턴스의 실행 파일 경로를 얻는다.
func pidPathAudit(token auditToken) (string, error) {
	buf := make([]byte, C.PROC_PIDPATHINFO_MAXSIZE)
	var rawToken [8]C.uint32_t
	for i := range token {
		rawToken[i] = C.uint32_t(token[i])
	}
	n, err := C.pasuPidPathAudit(&rawToken[0], unsafe.Pointer(&buf[0]), C.uint32_t(len(buf)))
	if n <= 0 {
		return "", fmt.Errorf("proc_pidpath_audittoken: %v", err)
	}
	return string(buf[:n]), nil
}

// pidPath는 실행 파일의 실제 경로를 libproc으로 얻는다.
// 명령줄에 적힌 경로 대신 운영체제가 조회한 실행 경로를 사용한다.
// 상대 경로·symlink·다른 UID의 조회 사례는 experiments/procinfo에서 비교한다.
func pidPath(pid int) (string, error) {
	buf := make([]byte, C.PROC_PIDPATHINFO_MAXSIZE)
	n, err := C.proc_pidpath(C.int(pid), unsafe.Pointer(&buf[0]), C.uint32_t(len(buf)))
	if n <= 0 {
		return "", fmt.Errorf("proc_pidpath(%d): %v", pid, err)
	}
	return string(buf[:n]), nil
}

func lookupProc(pid int) procInfo {
	if info, err := lookupProcVerified(pid); err == nil {
		return info
	}
	info := procInfo{pid: pid, ppid: -1}
	if kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid); err == nil {
		info.ppid = int(kp.Eproc.Ppid)
		info.comm = unix.ByteSliceToString(kp.Proc.P_comm[:])
	}
	if p, err := pidPath(pid); err == nil {
		info.exePath = p
	}
	return info
}

func lookupProcVerified(pid int) (procInfo, error) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return procInfo{}, fmt.Errorf("kern.proc.pid(%d): %w", pid, err)
	}
	if int(kp.Proc.P_pid) != pid {
		return procInfo{}, fmt.Errorf("kern.proc.pid(%d): 다른 pid %d 반환", pid, kp.Proc.P_pid)
	}
	p, err := pidPath(pid)
	if err != nil {
		return procInfo{}, err
	}
	return procInfo{
		pid:       pid,
		ppid:      int(kp.Eproc.Ppid),
		pgid:      int(kp.Eproc.Pgid),
		tdev:      kp.Eproc.Tdev,
		tpgid:     int(kp.Eproc.Tpgid),
		uid:       kp.Eproc.Ucred.Uid,
		startSec:  int64(kp.Proc.P_starttime.Sec),
		startUsec: int64(kp.Proc.P_starttime.Usec),
		comm:      unix.ByteSliceToString(kp.Proc.P_comm[:]),
		exePath:   p,
	}, nil
}

const maxAncestors = 32

// ancestry는 pid에서 시작해 부모를 따라 launchd(pid 1)까지 걷는다.
// 사슬 어딘가에서 정보를 얻지 못하면 얻은 데까지만 돌려준다(부족분은 불허 방향).
func ancestry(pid int) []procInfo {
	return ancestryWithLookup(pid, lookupProc)
}

func ancestryWithLookup(pid int, lookup func(int) procInfo) []procInfo {
	var chain []procInfo
	seen := make(map[int]bool)
	for pid > 0 && !seen[pid] && len(chain) < maxAncestors {
		seen[pid] = true
		info := lookup(pid)
		chain = append(chain, info)
		if pid == 1 || info.ppid <= 0 {
			break
		}
		pid = info.ppid
	}
	return chain
}

// verifiedAncestry는 launchd까지 빠짐없이 이어지고 각 프로세스의 경로·시작
// 시각을 모두 읽은 사슬만 돌려준다. 부분 사슬이 우연히 허용 규칙에 맞는 것을
// 막기 위해 조회 실패·순환·깊이 초과는 전부 오류다.
func verifiedAncestry(pid int) ([]procInfo, error) {
	return verifiedAncestryWithLookup(pid, lookupProcVerified)
}

func verifiedAncestryWithLookup(pid int, lookup func(int) (procInfo, error)) ([]procInfo, error) {
	var chain []procInfo
	seen := make(map[int]bool)
	for len(chain) < maxAncestors {
		if pid <= 0 {
			return nil, fmt.Errorf("launchd 전에 잘못된 pid %d", pid)
		}
		if seen[pid] {
			return nil, fmt.Errorf("조상 사슬 순환: pid %d", pid)
		}
		seen[pid] = true
		info, err := lookup(pid)
		if err != nil {
			return nil, err
		}
		chain = append(chain, info)
		if pid == 1 {
			return chain, nil
		}
		if info.ppid <= 0 {
			return nil, fmt.Errorf("launchd 전에 부모가 끊김: pid %d ppid %d", pid, info.ppid)
		}
		pid = info.ppid
	}
	return nil, fmt.Errorf("조상 사슬이 %d단 안에 launchd에 도달하지 않음", maxAncestors)
}

func snapshotVerifiedPeer(id peerID) ([]procInfo, error) {
	chain, err := verifiedAncestry(id.pid)
	if err != nil {
		return nil, err
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("빈 조상 사슬")
	}
	peerPath, err := pidPathAudit(id.token)
	if err != nil {
		return nil, err
	}
	if chain[0].pid != id.pid || chain[0].uid != id.uid || chain[0].exePath != peerPath {
		return nil, fmt.Errorf("직접 피어 불일치: token(pid=%d uid=%d path=%q) snapshot(pid=%d uid=%d path=%q)",
			id.pid, id.uid, peerPath, chain[0].pid, chain[0].uid, chain[0].exePath)
	}
	chain[0].token = id.token
	chain[0].hasToken = true
	return chain, nil
}

// verifiedPeerChain은 인가 판단 전 사슬을 캡처하고, 판단 뒤 같은 audit token과
// PID·PPID·시작 시각·실행 경로가 유지됐는지 다시 확인하는 함수를 함께 돌려준다.
// 두 캡처 사이에 바뀌었다가 되돌아오는 정교한 경합과 조상별 audit token 부재는
// 여전히 남지만, 직접 피어 PID 재사용과 일반적인 exec/부모 변경은 불허한다.
func verifiedPeerChain(conn *net.UnixConn, id peerID) ([]procInfo, func() error, error) {
	before, err := snapshotVerifiedPeer(id)
	if err != nil {
		return nil, nil, err
	}
	verify := func() error {
		afterID, err := peerIdentity(conn)
		if err != nil {
			return err
		}
		if afterID != id {
			return fmt.Errorf("피어 audit token 변경: pid %d(version %d) -> pid %d(version %d)",
				id.pid, id.pidVersion, afterID.pid, afterID.pidVersion)
		}
		after, err := snapshotVerifiedPeer(afterID)
		if err != nil {
			return err
		}
		if !sameProcChain(before, after) {
			return fmt.Errorf("피어 조상 사슬 변경")
		}
		return nil
	}
	return before, verify, nil
}

func sameProcChain(a, b []procInfo) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// normalizePath는 존재하는 경로면 symlink를 해소해 실제 경로로 만든다.
func normalizePath(p string) string {
	p = filepath.Clean(p)
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved
	}
	return p
}

func chainString(chain []procInfo) string {
	var b bytes.Buffer
	for i, p := range chain {
		if i > 0 {
			b.WriteString(" < ")
		}
		name := p.exePath
		if name == "" {
			if p.comm != "" {
				name = p.comm + "?"
			} else {
				name = "?"
			}
		}
		fmt.Fprintf(&b, "%s(%d)", safeText(name), p.pid)
	}
	return b.String()
}
