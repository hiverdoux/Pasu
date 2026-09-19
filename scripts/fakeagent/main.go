// 직접 SSH 서명을 요청하는 시험 클라이언트.
// v1 통합 시험에서 approvals.conf 승인 경로를 재현하는 데 사용한다.
package main

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func main() {
	if len(os.Args) != 3 || os.Args[1] != "-T" {
		fmt.Fprintln(os.Stderr, "사용법: fakeagent -T <public-key>")
		os.Exit(2)
	}
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		fmt.Fprintln(os.Stderr, "SSH_AUTH_SOCK가 없습니다")
		os.Exit(1)
	}
	data, err := os.ReadFile(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer conn.Close()
	message := []byte("pasu direct client verification")
	sig, err := agent.NewClient(conn).Sign(pub, message)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := pub.Verify(message, sig); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
