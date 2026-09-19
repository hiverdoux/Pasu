package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestReadSecretLine(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	interrupts := make(chan os.Signal, 1)
	go func() {
		_, _ = w.Write([]byte("secret\n"))
		_ = w.Close()
	}()
	got, err := readSecretLine(r, interrupts)
	if err != nil || string(got) != "secret" {
		t.Fatalf("비밀 한 줄 읽기=%q err=%v", got, err)
	}
}

func TestReadSecretLineInterruptsPromptly(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	interrupts := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() {
		_, err := readSecretLine(r, interrupts)
		done <- err
	}()
	interrupts <- os.Interrupt
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "취소") {
			t.Fatalf("인터럽트 오류 이상: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("인터럽트 뒤 읽기가 끝나지 않음")
	}
}
