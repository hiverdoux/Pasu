// SSH agent 인터페이스 검증: golang.org/x/crypto/ssh/agent의 서버 인터페이스로
// "서명·목록만 되고 추가·삭제·잠금은 전부 거부하는" 에이전트를 만들 수 있는지 확인한다.
// Go 클라이언트와 진짜 /usr/bin/ssh-add 양쪽으로 검증한다.
package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var errDenied = errors.New("pasu-exp: 변경 연산 거부")

type gateAgent struct {
	signer ssh.Signer
}

func (g *gateAgent) List() ([]*agent.Key, error) {
	pub := g.signer.PublicKey()
	return []*agent.Key{{Format: pub.Type(), Blob: pub.Marshal(), Comment: "pasu-exp"}}, nil
}

func (g *gateAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return g.SignWithFlags(key, data, 0)
}

func (g *gateAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	if !bytes.Equal(key.Marshal(), g.signer.PublicKey().Marshal()) {
		return nil, errors.New("모르는 키")
	}
	fmt.Println("  (서버) 서명 요청 수신 → 서명 수행")
	return g.signer.Sign(rand.Reader, data)
}

func (g *gateAgent) Add(key agent.AddedKey) error   { return errDenied }
func (g *gateAgent) Remove(key ssh.PublicKey) error { return errDenied }
func (g *gateAgent) RemoveAll() error               { return errDenied }
func (g *gateAgent) Lock(passphrase []byte) error   { return errDenied }
func (g *gateAgent) Unlock(passphrase []byte) error { return errDenied }
func (g *gateAgent) Signers() ([]ssh.Signer, error) { return nil, errDenied }
func (g *gateAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

func main() {
	dir, err := os.MkdirTemp("", "pasu-e4-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	keyPath := filepath.Join(dir, "key")
	gen := exec.Command("/usr/bin/ssh-keygen", "-t", "ed25519", "-f", keyPath, "-N", "", "-C", "pasu-exp")
	if out, err := gen.CombinedOutput(); err != nil {
		fmt.Printf("ssh-keygen 실패: %v\n%s", err, out)
		return
	}
	pemBytes, err := os.ReadFile(keyPath)
	if err != nil {
		panic(err)
	}
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		panic(err)
	}

	sock := filepath.Join(dir, "agent.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		panic(err)
	}
	defer l.Close()
	g := &gateAgent{signer: signer}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go agent.ServeAgent(g, c)
		}
	}()

	fmt.Println("[Go 클라이언트로 접속]")
	c, err := net.Dial("unix", sock)
	if err != nil {
		panic(err)
	}
	cl := agent.NewClient(c)
	keys, err := cl.List()
	fmt.Printf("  List: 키 %d개 err=%v\n", len(keys), err)
	data := []byte("agent sign roundtrip")
	sig, err := cl.Sign(signer.PublicKey(), data)
	fmt.Printf("  Sign: err=%v\n", err)
	if err == nil {
		fmt.Printf("  서명 검증: err=%v\n", signer.PublicKey().Verify(data, sig))
	}
	fmt.Printf("  RemoveAll(거부 기대): err=%v\n", cl.RemoveAll())
	fmt.Printf("  Lock(거부 기대): err=%v\n", cl.Lock([]byte("x")))
	c.Close()

	fmt.Println("[진짜 ssh-add로 접속]")
	env := append(os.Environ(), "SSH_AUTH_SOCK="+sock)
	for _, args := range [][]string{{"-l"}, {"-T", keyPath + ".pub"}, {"-D"}} {
		cmd := exec.Command("/usr/bin/ssh-add", args...)
		cmd.Env = env
		out, cmdErr := cmd.CombinedOutput()
		fmt.Printf("  ssh-add %v → err=%v 출력=%s\n", args, cmdErr, bytes.TrimSpace(out))
	}
}
