// 프로세스 조회 비교: PID로부터 (a) 부모 PID·실사용자 — sysctl kern.proc.pid,
// (b) 실행 파일 경로와 argv — sysctl kern.procargs2,
// (c) 실행 파일 경로 — libproc proc_pidpath(cgo)
// 를 얻어 서로 비교한다. root 소유 프로세스, 상대 경로로 실행된 프로세스 등
// 경계 사례에서 각 방법이 어떻게 다른지 관찰하는 것이 목적이다.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"time"

	"golang.org/x/sys/unix"
)

type procArgs struct {
	execPath string
	argv     []string
}

func kinfo(pid int) (*unix.KinfoProc, error) {
	return unix.SysctlKinfoProc("kern.proc.pid", pid)
}

// kern.procargs2 버퍼 배치: [argc int32][실행 파일 경로 \0][패딩 \0...][argv[0] \0][argv[1] \0]...[환경변수...]
func procargs2(pid int) (*procArgs, error) {
	buf, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return nil, err
	}
	if len(buf) < 4 {
		return nil, fmt.Errorf("버퍼가 너무 짧음 (%d바이트)", len(buf))
	}
	argc := int(binary.LittleEndian.Uint32(buf[:4]))
	rest := buf[4:]
	i := bytes.IndexByte(rest, 0)
	if i < 0 {
		return nil, fmt.Errorf("실행 파일 경로 종결자 없음")
	}
	pa := &procArgs{execPath: string(rest[:i])}
	rest = rest[i:]
	for len(rest) > 0 && rest[0] == 0 {
		rest = rest[1:]
	}
	for len(pa.argv) < argc && len(rest) > 0 {
		j := bytes.IndexByte(rest, 0)
		if j < 0 {
			break
		}
		pa.argv = append(pa.argv, string(rest[:j]))
		rest = rest[j+1:]
	}
	return pa, nil
}

func report(label string, pid int) {
	fmt.Printf("--- %s (pid %d)\n", label, pid)
	kp, err := kinfo(pid)
	if err != nil {
		fmt.Printf("  kinfo:     err=%v\n", err)
	} else {
		fmt.Printf("  kinfo:     ppid=%d ruid=%d comm=%q\n",
			kp.Eproc.Ppid, kp.Eproc.Pcred.P_ruid, unix.ByteSliceToString(kp.Proc.P_comm[:]))
	}
	pa, err := procargs2(pid)
	if err != nil {
		fmt.Printf("  procargs2: err=%v\n", err)
	} else {
		fmt.Printf("  procargs2: exec=%q argv=%q\n", pa.execPath, pa.argv)
	}
	p, err := pidPathCgo(pid)
	if err != nil {
		fmt.Printf("  libproc:   err=%v\n", err)
	} else {
		fmt.Printf("  libproc:   path=%q\n", p)
	}
}

func main() {
	self := os.Getpid()
	report("자기 자신", self)
	report("부모", os.Getppid())
	report("launchd(root 소유)", 1)

	// 자식 프로세스 실험은 직접 빌드한 sleeper를 사용한다.
	// 시스템 실행 파일 복사본의 실행·서명 제약이 경로 조회 결과에 섞이지 않게 한다.
	sleeper := os.Getenv("PASU_EXP_SLEEPER")
	if sleeper == "" {
		fmt.Println("(PASU_EXP_SLEEPER 미설정 — 자식 프로세스 실험 생략)")
		chainWalk(self)
		return
	}
	dir, err := os.MkdirTemp("", "pasu-e2-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	if err := exec.Command("/bin/cp", sleeper, dir+"/sleepy").Run(); err != nil {
		panic(err)
	}

	abs := exec.Command(dir+"/sleepy", "30")
	if err := abs.Start(); err != nil {
		panic(err)
	}
	defer func() { abs.Process.Kill(); abs.Wait() }()

	rel := exec.Command("./sleepy", "30")
	rel.Dir = dir
	if err := rel.Start(); err != nil {
		panic(err)
	}
	defer func() { rel.Process.Kill(); rel.Wait() }()

	time.Sleep(300 * time.Millisecond)
	report("절대 경로로 실행한 자식", abs.Process.Pid)
	report("상대 경로(./sleepy)로 실행한 자식", rel.Process.Pid)

	chainWalk(self)
}

func chainWalk(self int) {
	fmt.Println("--- 조상 사슬 걷기 (자기 자신 → launchd)")
	pid := self
	for hop := 0; hop < 32 && pid > 0; hop++ {
		kp, err := kinfo(pid)
		if err != nil {
			fmt.Printf("  pid=%d kinfo err=%v\n", pid, err)
			break
		}
		path := "?"
		if p, err := pidPathCgo(pid); err == nil {
			path = p
		}
		fmt.Printf("  pid=%-6d comm=%-16s path=%s\n",
			pid, unix.ByteSliceToString(kp.Proc.P_comm[:]), path)
		if pid == 1 {
			break
		}
		pid = int(kp.Eproc.Ppid)
	}
}
