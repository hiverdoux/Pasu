package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	v2SecretDomain         = "pasu-key-secret-v2\x00"
	publicKeyCommentPrefix = "pasu-"
)

func canonicalPublicKeyLine(pub ssh.PublicKey, name string) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " " + name + "\n"
}

func managedPublicKeyLine(pub ssh.PublicKey, name string) string {
	return canonicalPublicKeyLine(pub, publicKeyCommentPrefix+name)
}

func supportedManagedPublicKeyLine(pub ssh.PublicKey, name, line string) bool {
	// v2.1.0은 표시 이름 자체를 comment로 저장했다. 기존 registry·파일 값은
	// 유지하고 새 생성·이름 변경부터 접두사를 적용한다.
	return line == managedPublicKeyLine(pub, name) || line == canonicalPublicKeyLine(pub, name)
}

func encodeV2Secret(id, fingerprint string, passphrase []byte) ([]byte, error) {
	if !validKeyID(id) || fingerprint == "" || len(fingerprint) > 65535 || len(passphrase) == 0 {
		return nil, errors.New("잘못된 v2 secret 입력")
	}
	buf := make([]byte, 0, len(v2SecretDomain)+36+2+len(fingerprint)+len(passphrase))
	buf = append(buf, v2SecretDomain...)
	buf = append(buf, id...)
	var n [2]byte
	binary.BigEndian.PutUint16(n[:], uint16(len(fingerprint)))
	buf = append(buf, n[:]...)
	buf = append(buf, fingerprint...)
	buf = append(buf, passphrase...)
	return buf, nil
}

func decodeV2Secret(payload []byte) (id, fingerprint string, passphrase []byte, err error) {
	prefix := len(v2SecretDomain)
	if len(payload) < prefix+36+2+1 || string(payload[:prefix]) != v2SecretDomain {
		return "", "", nil, errors.New("v2 secret 형식 오류")
	}
	id = string(payload[prefix : prefix+36])
	if !validKeyID(id) {
		return "", "", nil, errors.New("v2 secret UUID 오류")
	}
	off := prefix + 36
	length := int(binary.BigEndian.Uint16(payload[off : off+2]))
	off += 2
	if length == 0 || off+length >= len(payload) {
		return "", "", nil, errors.New("v2 secret 지문 길이 오류")
	}
	fingerprint = string(payload[off : off+length])
	passphrase = append([]byte(nil), payload[off+length:]...)
	return id, fingerprint, passphrase, nil
}

type managedKeyRuntime struct {
	manage   sync.Mutex
	mu       sync.Mutex
	cond     *sync.Cond
	record   managedKeyRecord
	pub      ssh.PublicKey
	keyPath  string
	store    v2Store
	signer   ssh.Signer
	fatal    error
	active   int
	deleting bool
}

func newManagedKeyRuntime(record managedKeyRecord, keyPath string, pub ssh.PublicKey, store v2Store) *managedKeyRuntime {
	k := &managedKeyRuntime{record: record, keyPath: keyPath, pub: pub, store: store}
	k.cond = sync.NewCond(&k.mu)
	return k
}

func (k *managedKeyRuntime) PublicKey() ssh.PublicKey { return k.pub }

func (k *managedKeyRuntime) beginSign() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.deleting {
		return false
	}
	k.active++
	return true
}

func (k *managedKeyRuntime) endSign() {
	k.mu.Lock()
	k.active--
	if k.deleting && k.active == 0 {
		k.cond.Broadcast()
	}
	k.mu.Unlock()
}

func (k *managedKeyRuntime) stopAndWait() {
	k.pauseAndWait(true)
}

func (k *managedKeyRuntime) pauseAndWait(clearSigner bool) {
	k.mu.Lock()
	k.deleting = true
	if clearSigner {
		k.signer = nil
	}
	for k.active > 0 {
		k.cond.Wait()
	}
	k.mu.Unlock()
}

func (k *managedKeyRuntime) resume() {
	k.mu.Lock()
	k.deleting = false
	k.mu.Unlock()
}

func (k *managedKeyRuntime) lock() {
	k.mu.Lock()
	k.signer = nil
	k.mu.Unlock()
}

func (k *managedKeyRuntime) unlocked() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.record.AuthMode == keyAuthCached && k.signer != nil
}

func (k *managedKeyRuntime) recordSnapshot() managedKeyRecord {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.record
}

func (k *managedKeyRuntime) updateRecord(record managedKeyRecord) {
	k.mu.Lock()
	k.record = record
	k.signer = nil
	k.fatal = nil
	k.mu.Unlock()
}

func (k *managedKeyRuntime) loadSigner(record managedKeyRecord, reason string) (ssh.Signer, error) {
	payload, err := k.store.ReadSecret(record.ID, reason, record.AuthMode.requiresPresence())
	if err != nil {
		return nil, err
	}
	defer wipe(payload)
	id, fingerprint, passphrase, err := decodeV2Secret(payload)
	if err != nil {
		return nil, err
	}
	defer wipe(passphrase)
	if id != record.ID || fingerprint != record.Fingerprint {
		return nil, fmt.Errorf("%w: Keychain secret 신원이 registry와 불일치", errKeyMaterialInvalid)
	}
	data, err := os.ReadFile(k.keyPath)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKeyWithPassphrase(data, passphrase)
	if err != nil {
		return nil, fmt.Errorf("%w: 개인키 복호화 실패: %v", errKeyMaterialInvalid, err)
	}
	if err := requireEd25519PublicKey(signer.PublicKey(), k.keyPath); err != nil {
		return nil, fmt.Errorf("%w: %v", errKeyMaterialInvalid, err)
	}
	if !bytes.Equal(signer.PublicKey().Marshal(), k.pub.Marshal()) ||
		ssh.FingerprintSHA256(signer.PublicKey()) != record.Fingerprint {
		return nil, fmt.Errorf("%w: 개인키·공개키·registry 지문 불일치", errKeyMaterialInvalid)
	}
	return signer, nil
}

func (k *managedKeyRuntime) signerForRequest(reason string) (ssh.Signer, error) {
	k.mu.Lock()
	record := k.record
	if k.deleting {
		k.mu.Unlock()
		return nil, errors.New("키 상태 변경 중")
	}
	if record.AuthMode != keyAuthCached {
		k.mu.Unlock()
		return k.loadSigner(record, reason)
	}
	defer k.mu.Unlock()
	if k.signer != nil {
		return k.signer, nil
	}
	if k.fatal != nil {
		return nil, k.fatal
	}
	signer, err := k.loadSigner(record, reason)
	if err != nil {
		if errors.Is(err, errKeyMaterialInvalid) {
			k.fatal = err
		}
		return nil, err
	}
	k.signer = signer
	return signer, nil
}

type v2KeyManager struct {
	mu      sync.RWMutex
	baseDir string
	keysDir string
	trash   string
	store   v2Store
	reg     *v2Registry
	keys    map[string]*managedKeyRuntime
	now     func() time.Time
}

func newV2KeyManager(baseDir, trash string, reg *v2Registry, store v2Store) (*v2KeyManager, error) {
	m := &v2KeyManager{
		baseDir: baseDir, keysDir: filepath.Join(baseDir, "keys"), trash: trash,
		store: store, reg: reg, keys: make(map[string]*managedKeyRuntime), now: time.Now,
	}
	if err := os.MkdirAll(m.keysDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(m.keysDir, 0o700); err != nil {
		return nil, err
	}
	for _, record := range reg.keys() {
		runtime, err := m.loadRuntime(record)
		if err != nil {
			return nil, fmt.Errorf("키 %s 로드 실패: %w", record.ID, err)
		}
		if record.AuthMode != keyAuthNone {
			if err := store.DeleteSecret(record.ID, false); err != nil {
				return nil, fmt.Errorf("키 %s의 이전 인증 없음 secret 정리 실패: %w", record.ID, err)
			}
		}
		m.keys[record.ID] = runtime
	}
	return m, nil
}

func requireOwnedRegular(path string, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("일반 파일이 아님: %s", path)
	}
	if info.Mode().Perm() != mode {
		return fmt.Errorf("권한이 %04o가 아님: %s", mode, path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() || stat.Nlink != 1 {
		return fmt.Errorf("소유자 또는 hard link 수가 잘못됨: %s", path)
	}
	return nil
}

func requireOwnedDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 ||
		!ok || int(stat.Uid) != os.Getuid() || stat.Nlink < 1 {
		return fmt.Errorf("키 디렉터리 소유권·권한 오류: %s", path)
	}
	return nil
}

func (m *v2KeyManager) loadRuntime(record managedKeyRecord) (*managedKeyRuntime, error) {
	dir := filepath.Join(m.keysDir, record.ID)
	if err := requireOwnedDir(dir); err != nil {
		return nil, err
	}
	keyPath := filepath.Join(dir, "key")
	pubPath := filepath.Join(dir, "key.pub")
	if err := requireOwnedRegular(keyPath, 0o600); err != nil {
		return nil, err
	}
	if err := requireOwnedRegular(pubPath, 0o600); err != nil {
		return nil, err
	}
	if _, err := readEncryptedKey(keyPath); err != nil {
		return nil, err
	}
	pub, err := loadPublicKey(pubPath)
	if err != nil {
		return nil, err
	}
	pubData, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, err
	}
	recordPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(record.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("registry 공개키 해석 실패: %w", err)
	}
	if ssh.FingerprintSHA256(pub) != record.Fingerprint ||
		!bytes.Equal(pub.Marshal(), recordPub.Marshal()) {
		return nil, errors.New("registry·key.pub 공개키 불일치")
	}
	if !supportedManagedPublicKeyLine(recordPub, record.Name, record.PublicKey) {
		return nil, errors.New("registry 이름·공개키 주석 불일치")
	}
	canonical := record.PublicKey
	if string(pubData) != canonical {
		if err := replaceOwnedFile(pubPath, []byte(canonical)); err != nil {
			return nil, fmt.Errorf("key.pub 이름 주석 복구 실패: %w", err)
		}
	}
	return newManagedKeyRuntime(record, keyPath, pub, m.store), nil
}

func (m *v2KeyManager) runtime(id string) (*managedKeyRuntime, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key, ok := m.keys[id]
	return key, ok
}

func (m *v2KeyManager) runtimes() []*managedKeyRuntime {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*managedKeyRuntime, 0, len(m.keys))
	for _, record := range m.reg.keys() {
		if key := m.keys[record.ID]; key != nil {
			out = append(out, key)
		}
	}
	return out
}

func validateKeyName(name string, existing []managedKeyRecord, ignoredID string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len([]byte(name)) > 128 {
		return "", errors.New("키 이름은 1~128바이트여야 함")
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return "", errors.New("키 이름에 제어문자를 사용할 수 없음")
		}
	}
	for _, key := range existing {
		if key.ID != ignoredID && strings.EqualFold(key.Name, name) {
			return "", errors.New("같은 이름의 키가 이미 있음")
		}
	}
	return name, nil
}

func validateNewKeyName(name string, existing []managedKeyRecord) (string, error) {
	return validateKeyName(name, existing, "")
}

func replaceOwnedFile(path string, data []byte) error {
	if err := requireOwnedRegular(path, 0o600); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := requireOwnedDir(dir); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".replace-")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func validateSecretIdentity(record managedKeyRecord, payload []byte) error {
	id, fingerprint, passphrase, err := decodeV2Secret(payload)
	if passphrase != nil {
		defer wipe(passphrase)
	}
	if err != nil {
		return err
	}
	if id != record.ID || fingerprint != record.Fingerprint {
		return fmt.Errorf("%w: Keychain secret 신원이 registry와 불일치", errKeyMaterialInvalid)
	}
	return nil
}

func (m *v2KeyManager) create(name string, authMode keyAuthMode, passphrase []byte) (managedKeyRecord, error) {
	name, err := validateNewKeyName(name, m.reg.keys())
	if err != nil {
		return managedKeyRecord{}, err
	}
	if !authMode.valid() || len(passphrase) < 16 {
		return managedKeyRecord{}, errors.New("인증 방식이 잘못됐거나 passphrase가 16바이트보다 짧음")
	}
	id, err := newKeyID()
	if err != nil {
		return managedKeyRecord{}, err
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return managedKeyRecord{}, err
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		return managedKeyRecord{}, err
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(private, name, passphrase)
	if err != nil {
		return managedKeyRecord{}, err
	}
	privatePEM := pem.EncodeToMemory(block)
	defer wipe(privatePEM)
	pubLine := managedPublicKeyLine(signer.PublicKey(), name)
	record := managedKeyRecord{
		ID: id, Name: name, Fingerprint: ssh.FingerprintSHA256(signer.PublicKey()), PublicKey: pubLine,
		AuthMode: authMode, Enabled: true, CreatedAt: m.now().UTC(),
	}
	tmpDir, err := os.MkdirTemp(m.keysDir, ".new-")
	if err != nil {
		return managedKeyRecord{}, err
	}
	cleanupDir := true
	defer func() {
		if cleanupDir {
			_ = os.RemoveAll(tmpDir)
		}
	}()
	if err := os.Chmod(tmpDir, 0o700); err != nil {
		return managedKeyRecord{}, err
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "key"), privatePEM, 0o600); err != nil {
		return managedKeyRecord{}, err
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "key.pub"), []byte(pubLine), 0o600); err != nil {
		return managedKeyRecord{}, err
	}
	secret, err := encodeV2Secret(id, record.Fingerprint, passphrase)
	if err != nil {
		return managedKeyRecord{}, err
	}
	defer wipe(secret)
	if err := m.store.AddSecret(id, secret, true); err != nil {
		return managedKeyRecord{}, err
	}
	protectedAdded := true
	unattendedAdded := false
	defer func() {
		if unattendedAdded {
			_ = m.store.DeleteSecret(id, false)
		}
		if protectedAdded {
			_ = m.store.DeleteSecret(id, true)
		}
	}()
	verifySecret := func(requirePresence bool, reason string) error {
		got, err := m.store.ReadSecret(id, reason, requirePresence)
		if err != nil {
			return err
		}
		same := bytes.Equal(got, secret)
		wipe(got)
		if !same {
			return errors.New("새 키 Keychain 왕복 값 불일치")
		}
		return nil
	}
	if err := verifySecret(true, "Pasu 새 키 관리 보호 확인: "+name); err != nil {
		return managedKeyRecord{}, err
	}
	if authMode == keyAuthNone {
		if err := m.store.AddSecret(id, secret, false); err != nil {
			return managedKeyRecord{}, err
		}
		unattendedAdded = true
		if err := verifySecret(false, "Pasu 인증 없음 저장 확인: "+name); err != nil {
			return managedKeyRecord{}, err
		}
	}
	finalDir := filepath.Join(m.keysDir, id)
	if err := os.Rename(tmpDir, finalDir); err != nil {
		return managedKeyRecord{}, err
	}
	cleanupDir = false
	if err := m.reg.appendKey(record); err != nil {
		_ = os.Rename(finalDir, tmpDir)
		cleanupDir = true
		return managedKeyRecord{}, err
	}
	runtime, err := m.loadRuntime(record)
	if err != nil {
		_ = m.reg.removeKey(id)
		_ = os.Rename(finalDir, tmpDir)
		cleanupDir = true
		return managedKeyRecord{}, err
	}
	m.mu.Lock()
	m.keys[id] = runtime
	m.mu.Unlock()
	protectedAdded = false
	unattendedAdded = false
	return record, nil
}

func (m *v2KeyManager) importLegacy(name, keyPath, pubPath string, passphrase []byte) (managedKeyRecord, error) {
	signer, err := ensureKeyMatches(keyPath, passphrase, false)
	if err != nil {
		return managedKeyRecord{}, err
	}
	fingerprint := ssh.FingerprintSHA256(signer.PublicKey())
	for _, existing := range m.reg.keys() {
		if existing.Fingerprint == fingerprint {
			return existing, nil
		}
	}
	name, err = validateNewKeyName(name, m.reg.keys())
	if err != nil {
		return managedKeyRecord{}, err
	}
	privatePEM, err := os.ReadFile(keyPath)
	if err != nil {
		return managedKeyRecord{}, err
	}
	defer wipe(privatePEM)
	pub, err := loadPublicKey(pubPath)
	if err != nil {
		return managedKeyRecord{}, err
	}
	if !bytes.Equal(pub.Marshal(), signer.PublicKey().Marshal()) {
		return managedKeyRecord{}, errors.New("v1 개인키와 공개키가 일치하지 않음")
	}
	id, err := newKeyID()
	if err != nil {
		return managedKeyRecord{}, err
	}
	pubLine := managedPublicKeyLine(pub, name)
	record := managedKeyRecord{
		ID: id, Name: name, Fingerprint: fingerprint, PublicKey: pubLine,
		AuthMode: keyAuthCached, Enabled: true, CreatedAt: m.now().UTC(),
	}
	tmpDir, err := os.MkdirTemp(m.keysDir, ".migrate-")
	if err != nil {
		return managedKeyRecord{}, err
	}
	cleanupDir := true
	defer func() {
		if cleanupDir {
			_ = os.RemoveAll(tmpDir)
		}
	}()
	if err := os.Chmod(tmpDir, 0o700); err != nil {
		return managedKeyRecord{}, err
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "key"), privatePEM, 0o600); err != nil {
		return managedKeyRecord{}, err
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "key.pub"), []byte(pubLine), 0o600); err != nil {
		return managedKeyRecord{}, err
	}
	secret, err := encodeV2Secret(id, fingerprint, passphrase)
	if err != nil {
		return managedKeyRecord{}, err
	}
	defer wipe(secret)
	if err := m.store.AddSecret(id, secret, true); err != nil {
		return managedKeyRecord{}, err
	}
	secretAdded := true
	defer func() {
		if secretAdded {
			_ = m.store.DeleteSecret(id, true)
		}
	}()
	finalDir := filepath.Join(m.keysDir, id)
	if err := os.Rename(tmpDir, finalDir); err != nil {
		return managedKeyRecord{}, err
	}
	cleanupDir = false
	if err := m.reg.appendKey(record); err != nil {
		_ = os.Rename(finalDir, tmpDir)
		cleanupDir = true
		return managedKeyRecord{}, err
	}
	runtime, err := m.loadRuntime(record)
	if err != nil {
		_ = m.reg.removeKey(id)
		_ = os.Rename(finalDir, tmpDir)
		cleanupDir = true
		return managedKeyRecord{}, err
	}
	m.mu.Lock()
	m.keys[id] = runtime
	m.mu.Unlock()
	secretAdded = false
	return record, nil
}

func (m *v2KeyManager) rename(id, requestedName string) error {
	key, ok := m.runtime(id)
	if !ok {
		return errors.New("모르는 키 runtime")
	}
	key.manage.Lock()
	defer key.manage.Unlock()
	record, ok := m.reg.key(id)
	if !ok {
		return errors.New("모르는 키")
	}
	name, err := validateKeyName(requestedName, m.reg.keys(), id)
	if err != nil {
		return err
	}
	if name == record.Name {
		return nil
	}
	pubLine := managedPublicKeyLine(key.PublicKey(), name)
	pubPath := filepath.Join(m.keysDir, id, "key.pub")
	oldData, err := os.ReadFile(pubPath)
	if err != nil {
		return err
	}
	if err := replaceOwnedFile(pubPath, []byte(pubLine)); err != nil {
		return err
	}
	if err := m.reg.renameKey(id, name, pubLine); err != nil {
		if rollbackErr := replaceOwnedFile(pubPath, oldData); rollbackErr != nil {
			return fmt.Errorf("registry 이름 저장 실패: %v; 공개키 주석 rollback 실패: %w", err, rollbackErr)
		}
		return err
	}
	record.Name = name
	record.PublicKey = pubLine
	key.mu.Lock()
	key.record.Name = name
	key.record.PublicKey = pubLine
	key.mu.Unlock()
	return nil
}

func (m *v2KeyManager) setAuthMode(id string, next keyAuthMode) error {
	if !next.valid() {
		return errors.New("잘못된 인증 방식")
	}
	key, ok := m.runtime(id)
	if !ok {
		return errors.New("모르는 키 runtime")
	}
	key.manage.Lock()
	defer key.manage.Unlock()
	record, ok := m.reg.key(id)
	if !ok {
		return errors.New("모르는 키")
	}
	if record.AuthMode == next {
		return nil
	}
	key.stopAndWait()
	defer key.resume()

	payload, err := m.store.ReadSecret(id, "Pasu 인증 방식 변경 확인: "+record.Name, true)
	if err != nil {
		return err
	}
	defer wipe(payload)
	if err := validateSecretIdentity(record, payload); err != nil {
		return err
	}

	switch {
	case next == keyAuthNone:
		if err := m.store.AddSecret(id, payload, false); err != nil {
			return err
		}
		added := true
		defer func() {
			if added {
				_ = m.store.DeleteSecret(id, false)
			}
		}()
		got, err := m.store.ReadSecret(id, "Pasu 인증 없음 저장 확인: "+record.Name, false)
		if err != nil {
			return err
		}
		same := bytes.Equal(got, payload)
		identityErr := validateSecretIdentity(record, got)
		wipe(got)
		if !same || identityErr != nil {
			return fmt.Errorf("새 인증 방식 Keychain 왕복 검증 실패: %v", identityErr)
		}
		if err := m.reg.setAuthMode(id, next); err != nil {
			return err
		}
		added = false
	case record.AuthMode == keyAuthNone:
		if err := m.reg.setAuthMode(id, next); err != nil {
			return err
		}
		if err := m.store.DeleteSecret(id, false); err != nil {
			rollbackErr := m.reg.setAuthMode(id, record.AuthMode)
			if rollbackErr != nil {
				updated, _ := m.reg.key(id)
				key.updateRecord(updated)
				return fmt.Errorf("인증 없음 secret 정리 실패: %v; registry rollback 실패: %w", err, rollbackErr)
			}
			return fmt.Errorf("인증 없음 secret 정리 실패: %w", err)
		}
	default:
		if err := m.reg.setAuthMode(id, next); err != nil {
			return err
		}
	}
	updated, ok := m.reg.key(id)
	if !ok {
		return errors.New("인증 방식 저장 뒤 키가 registry에서 사라짐")
	}
	key.updateRecord(updated)
	return nil
}

func (m *v2KeyManager) setEnabled(id string, enabled bool) error {
	key, ok := m.runtime(id)
	if !ok {
		return errors.New("모르는 키")
	}
	if !enabled {
		key.lock()
	}
	if err := m.reg.setEnabled(id, enabled); err != nil {
		return err
	}
	return nil
}

func (m *v2KeyManager) lock(id string) error {
	key, ok := m.runtime(id)
	if !ok {
		return errors.New("모르는 키")
	}
	key.lock()
	return nil
}

func (m *v2KeyManager) unlock(id string) error {
	key, ok := m.runtime(id)
	if !ok {
		return errors.New("모르는 키")
	}
	record := key.recordSnapshot()
	if record.AuthMode != keyAuthCached {
		return errors.New("cached 키만 지속적으로 잠금 해제할 수 있음")
	}
	_, err := key.signerForRequest("Pasu 키 미리 잠금 해제: " + record.Name)
	return err
}

func (m *v2KeyManager) authenticate(id, reason string) error {
	record, ok := m.reg.key(id)
	if !ok {
		return errors.New("모르는 키")
	}
	payload, err := m.store.ReadSecret(id, reason, true)
	if err != nil {
		return err
	}
	if err := validateSecretIdentity(record, payload); err != nil {
		wipe(payload)
		return err
	}
	wipe(payload)
	return nil
}

func (m *v2KeyManager) delete(id string) (string, error) {
	key, ok := m.runtime(id)
	if !ok {
		return "", errors.New("모르는 키")
	}
	key.manage.Lock()
	defer key.manage.Unlock()
	if err := m.setEnabled(id, false); err != nil {
		return "", err
	}
	key.stopAndWait()
	record := key.recordSnapshot()
	if err := m.authenticate(id, "Pasu 키 삭제 확인: "+record.Name); err != nil {
		key.resume()
		return "", err
	}
	if err := os.MkdirAll(m.trash, 0o700); err != nil {
		key.resume()
		return "", err
	}
	safeName := strings.Map(func(r rune) rune {
		if r == '/' || r == ':' || r < 0x20 {
			return '-'
		}
		return r
	}, record.Name)
	target := filepath.Join(m.trash, fmt.Sprintf("Pasu-%s-%s-%s", safeName, id, m.now().Format("20060102-150405")))
	source := filepath.Join(m.keysDir, id)
	if err := os.Rename(source, target); err != nil {
		key.resume()
		return "", err
	}
	currentPresence := record.AuthMode.requiresPresence()
	if err := m.store.DeleteSecret(id, !currentPresence); err != nil {
		_ = os.Rename(target, source)
		key.resume()
		return "", err
	}
	if err := m.store.DeleteSecret(id, currentPresence); err != nil {
		_ = os.Rename(target, source)
		key.resume()
		return "", err
	}
	if err := m.reg.removeKey(id); err != nil {
		return target, fmt.Errorf("키 파일은 휴지통으로 이동하고 secret은 삭제했지만 registry 정리 실패: %w", err)
	}
	m.mu.Lock()
	delete(m.keys, id)
	m.mu.Unlock()
	return target, nil
}

// 진행 중 요청은 이전 방식으로 끝내고, 저장 이후 새 요청부터 새 방식을 쓴다.
// 인증 방식이나 보관 중인 signer, 규칙 원본은 바꾸지 않는다.
func (m *v2KeyManager) setChainCheckMode(id string, next chainCheckMode) error {
	if next != chainCheckFull && next != chainCheckResponsible {
		return errors.New("잘못된 사슬 검사 방식")
	}
	key, ok := m.runtime(id)
	if !ok {
		return errors.New("모르는 키")
	}
	key.manage.Lock()
	defer key.manage.Unlock()
	record, ok := m.reg.key(id)
	if !ok {
		return errors.New("모르는 키")
	}
	if record.ChainCheckMode.effective() == next {
		return nil
	}
	key.pauseAndWait(false)
	defer key.resume()
	payload, err := m.store.ReadSecret(id, "Pasu 사슬 검사 방식 변경 확인: "+record.Name, true)
	if err != nil {
		return err
	}
	defer wipe(payload)
	if err := validateSecretIdentity(record, payload); err != nil {
		return err
	}
	if err := m.reg.setChainCheckMode(id, next); err != nil {
		return err
	}
	key.mu.Lock()
	key.record.ChainCheckMode = next
	key.mu.Unlock()
	return nil
}
