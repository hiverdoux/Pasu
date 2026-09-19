// 암호화 키 처리 검증: passphrase로 암호화된 OpenSSH 형식 ed25519 개인키를
// golang.org/x/crypto/ssh로 읽고 서명까지 되는지 확인한다.
// Go의 암호화 키 파일 생성(Marshal)과 재파싱도 함께 확인한다.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

func main() {
	dir, err := os.MkdirTemp("", "pasu-e3-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	keyPath := filepath.Join(dir, "key")

	pass := "test-passphrase-123"
	gen := exec.Command("/usr/bin/ssh-keygen", "-t", "ed25519", "-f", keyPath, "-N", pass, "-C", "pasu-exp")
	if out, err := gen.CombinedOutput(); err != nil {
		fmt.Printf("ssh-keygen 실패: %v\n%s", err, out)
		return
	}
	pemBytes, err := os.ReadFile(keyPath)
	if err != nil {
		panic(err)
	}

	signer, err := ssh.ParsePrivateKeyWithPassphrase(pemBytes, []byte(pass))
	fmt.Printf("[정상 passphrase]  err=%v\n", err)
	if err != nil {
		return
	}
	fmt.Printf("  키 종류=%s 지문=%s\n", signer.PublicKey().Type(), ssh.FingerprintSHA256(signer.PublicKey()))

	_, err = ssh.ParsePrivateKeyWithPassphrase(pemBytes, []byte("wrong"))
	fmt.Printf("[틀린 passphrase]  err=%v\n", err)

	_, err = ssh.ParsePrivateKey(pemBytes)
	_, isMissing := err.(*ssh.PassphraseMissingError)
	fmt.Printf("[passphrase 없이]  err=%v (PassphraseMissingError=%v)\n", err, isMissing)

	data := []byte("pasu sign test")
	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		panic(err)
	}
	fmt.Printf("[서명+검증 왕복]   err=%v\n", signer.PublicKey().Verify(data, sig))

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "pasu-marshal-exp", []byte(pass))
	fmt.Printf("[Go로 암호화 키 생성] err=%v\n", err)
	if err == nil {
		signer2, perr := ssh.ParsePrivateKeyWithPassphrase(pem.EncodeToMemory(block), []byte(pass))
		if perr != nil {
			fmt.Printf("[재파싱] err=%v\n", perr)
		} else {
			fmt.Printf("[재파싱] ok, 키 종류=%s\n", signer2.PublicKey().Type())
		}
	}
}
