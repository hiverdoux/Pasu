package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 봉인(무인)과 파일 왕복. 실제 SE를 쓰므로 SE 없는 환경이면 건너뛴다.
func TestSEWrapSealAndFileCodec(t *testing.T) {
	secret := []byte("test-passphrase")
	w, err := seSeal(secret, sewrapV1)
	if err != nil {
		// 화면 잠금 중에는 SE 키 생성이 -25308로 실패한다.
		t.Skipf("SE 봉인 불가(화면 잠금 또는 SE 없음)로 건너뜀: %v", err)
	}
	if len(w.Blob) == 0 || len(w.Eph) == 0 || len(w.Ct) == 0 {
		t.Fatalf("봉인 결과 필드 누락: %+v", w)
	}
	if bytes.Contains(w.Ct, secret) {
		t.Fatal("암호문에 평문이 노출됨")
	}
	path := filepath.Join(t.TempDir(), "sewrap")
	if err := writeSEWrap(path, w); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("권한 = %o, 기대 600", st.Mode().Perm())
	}
	got, err := readSEWrap(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Blob, w.Blob) || !bytes.Equal(got.Eph, w.Eph) || !bytes.Equal(got.Ct, w.Ct) {
		t.Fatal("파일 왕복 후 필드 불일치")
	}
}

func TestReadSEWrapRejectsCorrupt(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"not-json":    "garbage",
		"bad-version": `{"v":99,"se_blob":"AA==","eph_pub":"AA==","ct":"AA=="}`,
		"missing":     `{"v":1,"se_blob":"","eph_pub":"AA==","ct":"AA=="}`,
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readSEWrap(p); err == nil {
			t.Errorf("%s: 손상 파일인데 통과", name)
		}
	}
	// v2는 유효한 버전으로 읽혀야 한다(내용물 프레이밍은 open 이후의 일).
	p := filepath.Join(dir, "v2")
	if err := os.WriteFile(p, []byte(`{"v":2,"se_blob":"AA==","eph_pub":"AA==","ct":"AA=="}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if w, err := readSEWrap(p); err != nil || w.V != sewrapV2 {
		t.Errorf("v2 판독 실패: %+v err=%v", w, err)
	}
}

// 내용물 프레이밍: v1은 전체가 passphrase, v2는 마지막 32바이트가 K.
func TestSplitSealedPayload(t *testing.T) {
	pass, k := []byte("secret-pass"), bytes.Repeat([]byte{7}, bindKeyLen)
	payload := append(append([]byte{}, pass...), k...)
	gotPass, gotK, err := splitSealedPayload(payload, sewrapV2)
	if err != nil || !bytes.Equal(gotPass, pass) || !bytes.Equal(gotK, k) {
		t.Fatalf("v2 분리 실패: pass=%q k=%x err=%v", gotPass, gotK, err)
	}
	gotPass, gotK, err = splitSealedPayload([]byte("only-pass"), sewrapV1)
	if err != nil || string(gotPass) != "only-pass" || gotK != nil {
		t.Fatalf("v1 분리 실패: pass=%q k=%v err=%v", gotPass, gotK, err)
	}
	// K조차 안 담기는 길이의 v2 내용물은 형식 오류다(빈 passphrase 방지 포함).
	for _, n := range []int{0, 1, bindKeyLen} {
		if _, _, err := splitSealedPayload(bytes.Repeat([]byte{1}, n), sewrapV2); err == nil {
			t.Errorf("길이 %d v2 내용물인데 통과", n)
		}
	}
}

// 실제 Touch ID 해제 왕복 — 프롬프트가 뜨므로 명시적으로 켤 때만 실행:
//
//	PASU_TEST_TOUCHID=1 go test -run SEWrapOpen -v
func TestSEWrapOpenRoundTrip(t *testing.T) {
	if os.Getenv("PASU_TEST_TOUCHID") != "1" {
		t.Skip("Touch ID 프롬프트가 필요 — PASU_TEST_TOUCHID=1로 실행할 때만")
	}
	secret := []byte("touchid-round-trip")
	w, err := seSeal(secret, sewrapV1)
	if err != nil {
		t.Fatal(err)
	}
	got, err := w.open("pasu 테스트: SE 해제 왕복")
	if err != nil {
		t.Fatal(err)
	}
	defer wipe(got)
	if !bytes.Equal(got, secret) {
		t.Fatal("해제 결과 불일치")
	}
}

// 다른 봉인의 암호문을 열려고 하면(파일 뒤섞임 재현) 복호화가 실패해야 한다.
func TestSEWrapOpenWrongCiphertext(t *testing.T) {
	if os.Getenv("PASU_TEST_TOUCHID") != "1" {
		t.Skip("Touch ID 프롬프트가 필요 — PASU_TEST_TOUCHID=1로 실행할 때만")
	}
	w1, err := seSeal([]byte("first"), sewrapV1)
	if err != nil {
		t.Fatal(err)
	}
	w2, err := seSeal([]byte("second"), sewrapV1)
	if err != nil {
		t.Fatal(err)
	}
	mixed := &seWrap{V: 1, Blob: w1.Blob, Eph: w2.Eph, Ct: w2.Ct}
	if _, err := mixed.open("pasu 테스트: 뒤섞인 봉인(실패해야 정상)"); err == nil {
		t.Fatal("다른 키의 봉인이 열림")
	} else if !strings.Contains(err.Error(), "해제 실패") {
		t.Logf("실패 사유(참고): %v", err)
	}
}
