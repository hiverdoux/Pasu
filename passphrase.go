package main

import (
	"bytes"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
)

var readPassphraseFn = readPassphrase

// readPassphrase는 제어 터미널(/dev/tty)에서 에코를 끄고 한 줄을 읽는다.
// 표준 입력이 아니라 /dev/tty를 직접 여는 이유: 파이프로 시작돼도
// 일반 실행 모드의 passphrase 입력을 제어 터미널로 제한하기 위해서다.
func readPassphrase(prompt string) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("터미널(/dev/tty) 열기 실패 — pasu는 터미널에서 실행해야 함: %w", err)
	}
	defer tty.Close()
	fd := int(tty.Fd())
	old, err := unix.IoctlGetTermios(fd, unix.TIOCGETA)
	if err != nil {
		return nil, err
	}
	noEcho := *old
	noEcho.Lflag &^= unix.ECHO
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(interrupts)
	if err := unix.IoctlSetTermios(fd, unix.TIOCSETA, &noEcho); err != nil {
		return nil, err
	}
	defer unix.IoctlSetTermios(fd, unix.TIOCSETA, old)

	fmt.Fprint(tty, prompt)
	defer fmt.Fprintln(tty)
	return readSecretLine(tty, interrupts)
}

func readSecretLine(r *os.File, interrupts <-chan os.Signal) ([]byte, error) {
	var buf bytes.Buffer
	b := make([]byte, 1)
	for {
		select {
		case sig := <-interrupts:
			return nil, fmt.Errorf("passphrase 입력 중 %s 신호를 받아 취소", sig)
		default:
		}
		poll := []unix.PollFd{{Fd: int32(r.Fd()), Events: unix.POLLIN}}
		if _, err := unix.Poll(poll, 100); err != nil {
			if err == unix.EINTR {
				continue
			}
			return nil, err
		}
		if poll[0].Revents == 0 {
			continue
		}
		if poll[0].Revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
			return nil, fmt.Errorf("passphrase 입력 장치 오류(revents=%d)", poll[0].Revents)
		}
		n, err := r.Read(b)
		if n > 0 {
			if b[0] == '\n' || b[0] == '\r' {
				break
			}
			buf.WriteByte(b[0])
		}
		if err != nil {
			if buf.Len() > 0 {
				break
			}
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// readLineStdin은 -passphrase-stdin 옵션용: 표준 입력에서 한 줄을 읽는다.
// 터미널 보호(에코 끄기)가 없으므로 자동화·테스트에서만 쓴다.
func readLineStdin() ([]byte, error) {
	var buf bytes.Buffer
	b := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(b)
		if n > 0 {
			if b[0] == '\n' || b[0] == '\r' {
				break
			}
			buf.WriteByte(b[0])
		}
		if err != nil {
			if buf.Len() > 0 {
				break
			}
			return nil, fmt.Errorf("표준 입력에서 passphrase 읽기 실패: %w", err)
		}
	}
	return buf.Bytes(), nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
