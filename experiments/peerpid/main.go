// 소켓 피어 신원 검증: 유닉스 소켓 서버가 접속해 온 상대(피어)의 PID와 UID를
// getsockopt(SOL_LOCAL, LOCAL_PEERPID / LOCAL_PEERCRED)로 얻을 수 있는지 확인한다.
package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

func peerInfo(c net.Conn) (pid int, uid uint32, err error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, 0, fmt.Errorf("unix conn 아님: %T", c)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var gerr error
	cerr := raw.Control(func(fd uintptr) {
		pid, gerr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		if gerr != nil {
			return
		}
		cred, e := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if e != nil {
			gerr = e
			return
		}
		uid = cred.Uid
	})
	if cerr != nil {
		return 0, 0, cerr
	}
	return pid, uid, gerr
}

func main() {
	dir, err := os.MkdirTemp("", "pasu-e1-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s.sock")

	l, err := net.Listen("unix", sock)
	if err != nil {
		panic(err)
	}
	defer l.Close()

	// 사례 1: 같은 프로세스가 스스로 접속 → 피어 PID는 자기 자신이어야 한다.
	go func() {
		c, err := net.Dial("unix", sock)
		if err != nil {
			fmt.Println("self dial 실패:", err)
			return
		}
		time.Sleep(3 * time.Second)
		c.Close()
	}()
	c1, err := l.Accept()
	if err != nil {
		panic(err)
	}
	pid, uid, err := peerInfo(c1)
	fmt.Printf("[자기 접속]     peer pid=%d uid=%d err=%v  (기대: pid=%d uid=%d)\n",
		pid, uid, err, os.Getpid(), os.Getuid())
	c1.Close()

	// 사례 2: 외부 프로세스(nc)가 접속 → 피어 PID는 nc의 것이어야 한다.
	nc := exec.Command("/usr/bin/nc", "-U", sock)
	devnull, _ := os.Open(os.DevNull)
	nc.Stdin = devnull
	if err := nc.Start(); err != nil {
		fmt.Println("nc 실행 실패:", err)
		return
	}
	defer func() { nc.Process.Kill(); nc.Wait() }()
	c2, err := l.Accept()
	if err != nil {
		panic(err)
	}
	pid2, uid2, err := peerInfo(c2)
	fmt.Printf("[외부 접속(nc)] peer pid=%d uid=%d err=%v  (기대: pid=%d)\n",
		pid2, uid2, err, nc.Process.Pid)
	c2.Close()
}
