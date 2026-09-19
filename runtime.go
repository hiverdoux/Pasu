package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// redirectProcessOutput은 launchd가 넘긴 기존 표준 출력 대신 pasu가 UID를
// 확인한 뒤 연 파일을 사용한다. os.Stdout/os.Stderr 변수만 바꾸면 Go 런타임이
// 파일 설명자 2번에 직접 쓰는 패닉은 빠져나가므로 실제 설명자 둘을 복제한다.
// 호출자가 f를 닫아도 복제된 1·2번 설명자는 프로세스 종료까지 유지된다.
func redirectProcessOutput(f *os.File) error {
	if f == nil {
		return errors.New("표준 출력 대상 파일이 nil임")
	}
	if err := unix.Dup2(int(f.Fd()), syscall.Stdout); err != nil {
		return fmt.Errorf("표준 출력 리다이렉트 실패: %w", err)
	}
	if err := unix.Dup2(int(f.Fd()), syscall.Stderr); err != nil {
		return fmt.Errorf("표준 오류 리다이렉트 실패: %w", err)
	}
	return nil
}

// requestTracker는 종료 시 새 요청을 막고, 이미 보안 판정을 시작한 요청과
// 알림이 감사 로그를 다 쓸 때까지 기다린다. 유휴 연결 자체는 기다리지 않는다.
type requestTracker struct {
	mu       sync.Mutex
	cond     *sync.Cond
	stopping bool
	active   int
}

func newRequestTracker() *requestTracker {
	r := &requestTracker{}
	r.cond = sync.NewCond(&r.mu)
	return r
}

func (r *requestTracker) begin() bool {
	if r == nil {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopping {
		return false
	}
	r.active++
	return true
}

func (r *requestTracker) done() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.active--
	if r.stopping && r.active == 0 {
		r.cond.Broadcast()
	}
	r.mu.Unlock()
}

func (r *requestTracker) stop() {
	r.mu.Lock()
	r.stopping = true
	if r.active == 0 {
		r.cond.Broadcast()
	}
	r.mu.Unlock()
}

func (r *requestTracker) wait() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for r.active > 0 {
		r.cond.Wait()
	}
}

// acquireInstanceLock은 낡은 소켓 판정·삭제·listen 전체를 직렬화한다. 잠금
// 파일은 지우지 않고 프로세스 수명 동안 flock을 보유해 동시 기동 경쟁을 막는다.
func acquireInstanceLock(sockPath string) (*os.File, error) {
	path := sockPath + ".lock"
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("기동 잠금 파일 열기 실패: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		f.Close()
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, fmt.Errorf("이미 다른 에이전트가 %s에서 기동 중이거나 실행 중", sockPath)
		}
		return nil, fmt.Errorf("기동 잠금 획득 실패: %w", err)
	}
	return f, nil
}

var umaskMu sync.Mutex

// listenPrivateUnix는 bind 순간부터 소켓을 0600으로 만든다. 사후 chmod만 쓰면
// 아주 짧게 더 넓은 권한으로 보일 수 있으므로 생성 동안 umask를 제한한다.
func listenPrivateUnix(sockPath string) (net.Listener, error) {
	umaskMu.Lock()
	oldMask := syscall.Umask(0o177)
	l, err := net.Listen("unix", sockPath)
	syscall.Umask(oldMask)
	umaskMu.Unlock()
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(sockPath, 0o600); err != nil {
		_ = l.Close()
		_ = os.Remove(sockPath)
		return nil, err
	}
	return l, nil
}

// openAgentListener는 잠금 아래에서 살아 있는 인스턴스와 낡은 소켓을 구분한
// 뒤 새 listener를 만든다. 반환된 lock은 listener가 닫힌 뒤에도 요청 drain이
// 끝날 때까지 호출자가 보유해야 한다.
func openAgentListener(sockPath string) (net.Listener, *os.File, error) {
	lock, err := acquireInstanceLock(sockPath)
	if err != nil {
		return nil, nil, err
	}
	fail := func(err error) (net.Listener, *os.File, error) {
		_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
		_ = lock.Close()
		return nil, nil, err
	}
	if _, err := os.Stat(sockPath); err == nil {
		if c, err := net.DialTimeout("unix", sockPath, 250*time.Millisecond); err == nil {
			_ = c.Close()
			return fail(fmt.Errorf("이미 다른 에이전트가 %s에서 실행 중", sockPath))
		}
		if err := os.Remove(sockPath); err != nil && !os.IsNotExist(err) {
			return fail(err)
		}
	} else if !os.IsNotExist(err) {
		return fail(err)
	}
	l, err := listenPrivateUnix(sockPath)
	if err != nil {
		return fail(err)
	}
	return l, lock, nil
}

func releaseInstanceLock(lock *os.File) {
	if lock == nil {
		return
	}
	_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	_ = lock.Close()
}

// stoppedAgentCommand는 Keychain·sewrap·설정 지문을 바꾸는 관리 명령을
// 가려낸다. modeCount 검사가 동시에 하나만 허용하므로 첫 참 값이면 충분하다.
func stoppedAgentCommand(setup, remove, trust, migrate, removeLegacy bool) string {
	switch {
	case setup:
		return "-setup-touchid"
	case remove:
		return "-remove-touchid"
	case trust:
		return "-trust-conf"
	case migrate:
		return "-migrate-keychain"
	case removeLegacy:
		return "-remove-legacy-sewrap"
	default:
		return ""
	}
}

// acquireStoppedAgentLock은 상태 변경 관리 명령 전체 동안 기동 잠금을
// 보유한다. 새 버전은 lock으로 기동 중 단계까지 막고, lock을 모르는 옛
// 버전은 live socket 연결로 잡는다. 낡은 소켓은 연결에 실패하므로 방해하지
// 않는다.
func acquireStoppedAgentLock(sockPath, command string) (*os.File, error) {
	stoppedError := func() error {
		return fmt.Errorf("%s 전에 실행 중인 pasu를 중지해야 함: ./scripts/launchd.sh stop", command)
	}
	lock, err := acquireInstanceLock(sockPath)
	if err != nil {
		return nil, stoppedError()
	}
	c, err := net.DialTimeout("unix", sockPath, 250*time.Millisecond)
	if err != nil {
		return lock, nil
	}
	_ = c.Close()
	releaseInstanceLock(lock)
	return nil, stoppedError()
}
