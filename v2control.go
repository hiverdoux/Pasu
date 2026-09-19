package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const controlProtocolVersion = 2

type v2KeyView struct {
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	Fingerprint    string         `json:"fingerprint"`
	PublicKey      string         `json:"public_key"`
	PublicKeyPath  string         `json:"public_key_path"`
	AuthMode       keyAuthMode    `json:"auth_mode"`
	ChainCheckMode chainCheckMode `json:"chain_check_mode"`
	Enabled        bool           `json:"enabled"`
	Unlocked       bool           `json:"unlocked"`
	CreatedAt      time.Time      `json:"created_at"`
	LastUsed       *time.Time     `json:"last_used,omitempty"`
	Rules          []chainRule    `json:"rules"`
}

type v2ControlRequest struct {
	Version        int    `json:"version"`
	Action         string `json:"action"`
	KeyID          string `json:"key_id,omitempty"`
	RuleID         string `json:"rule_id,omitempty"`
	Name           string `json:"name,omitempty"`
	Passphrase     string `json:"passphrase,omitempty"`
	AuthMode       string `json:"auth_mode,omitempty"`
	ChainCheckMode string `json:"chain_check_mode,omitempty"`
	Enabled        *bool  `json:"enabled,omitempty"`
	Limit          int    `json:"limit,omitempty"`
}

type v2ControlResponse struct {
	Version          int         `json:"version"`
	OK               bool        `json:"ok"`
	Error            string      `json:"error,omitempty"`
	Keys             []v2KeyView `json:"keys,omitempty"`
	MigrationPending bool        `json:"migration_pending,omitempty"`
	Logs             []string    `json:"logs,omitempty"`
	TrashPath        string      `json:"trash_path,omitempty"`
	AgentVersion     string      `json:"agent_version,omitempty"`
	StartedAt        *time.Time  `json:"started_at,omitempty"`
}

type v2ControlServer struct {
	listener  net.Listener
	lock      *os.File
	manager   *v2KeyManager
	registry  *v2Registry
	audit     *auditLog
	authorize func(*net.UnixConn) error
	migrate   func() error
	startedAt time.Time
	stop      chan struct{}
	done      chan struct{}
	wg        sync.WaitGroup
}

func authorizePasuGUI(conn *net.UnixConn) error {
	id, err := peerIdentity(conn)
	if err != nil {
		return err
	}
	if id.uid != uint32(os.Getuid()) {
		return fmt.Errorf("GUI UID 불일치: %d", id.uid)
	}
	path, err := pidPathAudit(id.token)
	if err != nil {
		return err
	}
	if normalizePath(path) != "/Applications/Pasu.app/Contents/MacOS/Pasu" {
		return fmt.Errorf("GUI 실행 경로 불일치: %s", path)
	}
	identity, err := signingInfoForProc(procInfo{pid: id.pid, uid: id.uid, exePath: path, token: id.token, hasToken: true})
	if err != nil {
		return err
	}
	if identity.Kind != codeIdentityDeveloper || identity.TeamID != pasuTeamID || identity.Identifier != pasuGUIIdentifier {
		return fmt.Errorf("GUI 코드 신원 불일치: %+v", identity)
	}
	return nil
}

func newV2ControlServer(sockPath string, manager *v2KeyManager, registry *v2Registry,
	audit *auditLog) (*v2ControlServer, error) {
	listener, lock, err := openAgentListener(sockPath)
	if err != nil {
		return nil, err
	}
	return &v2ControlServer{
		listener: listener, lock: lock, manager: manager, registry: registry, audit: audit,
		authorize: authorizePasuGUI, startedAt: time.Now().UTC(),
		stop: make(chan struct{}), done: make(chan struct{}),
	}, nil
}

func (s *v2ControlServer) serve() {
	defer close(s.done)
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.stop:
				return
			default:
				s.audit.logf("CONTROL accept-fail err=%v", err)
				continue
			}
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(conn)
		}()
	}
}

func (s *v2ControlServer) close() {
	select {
	case <-s.stop:
		return
	default:
		close(s.stop)
	}
	_ = s.listener.Close()
	<-s.done
	s.wg.Wait()
	releaseInstanceLock(s.lock)
}

func readControlMessage(conn net.Conn) ([]byte, error) {
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for len(buf) <= maxControlMessage {
		n, err := conn.Read(tmp)
		if n > 0 {
			if i := bytes.IndexByte(tmp[:n], '\n'); i >= 0 {
				buf = append(buf, tmp[:i]...)
				return buf, nil
			}
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(buf) > 0 {
				return buf, nil
			}
			return nil, err
		}
	}
	return nil, errors.New("control 메시지가 안전 크기 한도를 넘음")
}

func writeControlResponse(conn net.Conn, response v2ControlResponse) {
	data, err := json.Marshal(response)
	if err != nil {
		data = []byte(fmt.Sprintf(`{"version":%d,"ok":false,"error":"응답 직렬화 실패"}`, controlProtocolVersion))
	}
	if len(data) > maxControlMessage {
		data = []byte(fmt.Sprintf(`{"version":%d,"ok":false,"error":"응답이 안전 크기 한도를 넘음"}`, controlProtocolVersion))
	}
	data = append(data, '\n')
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, _ = conn.Write(data)
}

func decodeControlRequest(data []byte) (v2ControlRequest, error) {
	var request v2ControlRequest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return v2ControlRequest{}, fmt.Errorf("잘못된 control 요청: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return v2ControlRequest{}, errors.New("control 요청 뒤에 잉여 데이터가 있음")
	}
	return request, nil
}

func (s *v2ControlServer) handleConn(raw net.Conn) {
	defer raw.Close()
	conn, ok := raw.(*net.UnixConn)
	if !ok {
		return
	}
	if s.authorize != nil {
		if err := s.authorize(conn); err != nil {
			s.audit.logf("CONTROL deny err=%v", err)
			writeControlResponse(conn, v2ControlResponse{Version: controlProtocolVersion, Error: "Pasu GUI 신원 검증 실패"})
			return
		}
	}
	data, err := readControlMessage(conn)
	if err != nil {
		writeControlResponse(conn, v2ControlResponse{Version: controlProtocolVersion, Error: err.Error()})
		return
	}
	request, err := decodeControlRequest(data)
	if err != nil {
		writeControlResponse(conn, v2ControlResponse{Version: controlProtocolVersion, Error: err.Error()})
		return
	}
	if request.Version != controlProtocolVersion {
		writeControlResponse(conn, v2ControlResponse{Version: controlProtocolVersion, Error: "지원하지 않는 control protocol version"})
		return
	}
	response := s.handle(request)
	response.Version = controlProtocolVersion
	response.OK = response.Error == ""
	writeControlResponse(conn, response)
}

func (s *v2ControlServer) keyViews() []v2KeyView {
	records := s.registry.keys()
	views := make([]v2KeyView, 0, len(records))
	for _, record := range records {
		unlocked := false
		if runtime, ok := s.manager.runtime(record.ID); ok {
			unlocked = runtime.unlocked()
		}
		rules := record.Rules
		if rules == nil {
			rules = []chainRule{}
		}
		views = append(views, v2KeyView{
			ID: record.ID, Name: record.Name, Fingerprint: record.Fingerprint,
			PublicKey: record.PublicKey, PublicKeyPath: filepath.Join(s.manager.keysDir, record.ID, "key.pub"),
			AuthMode: record.AuthMode, ChainCheckMode: record.ChainCheckMode.effective(), Enabled: record.Enabled, Unlocked: unlocked,
			CreatedAt: record.CreatedAt, LastUsed: record.LastUsed, Rules: rules,
		})
	}
	return views
}

func (s *v2ControlServer) handle(request v2ControlRequest) v2ControlResponse {
	fail := func(err error) v2ControlResponse { return v2ControlResponse{Error: err.Error()} }
	// 키 목록과 함께 agent 버전·기동 시각을 돌려준다. GUI가 GUI·agent 버전 불일치와
	// 가동 시간을 표시하기 위한 읽기 전용 정보이며 정책 판정에는 쓰지 않는다.
	withKeys := func() v2ControlResponse {
		response := v2ControlResponse{
			Keys: s.keyViews(), MigrationPending: s.registry.snapshot().MigrationPending, AgentVersion: version,
		}
		if !s.startedAt.IsZero() {
			started := s.startedAt
			response.StartedAt = &started
		}
		return response
	}
	switch request.Action {
	case "status", "list_keys":
		return withKeys()
	case "create_key":
		passphrase := []byte(request.Passphrase)
		defer wipe(passphrase)
		if _, err := s.manager.create(request.Name, keyAuthMode(request.AuthMode), passphrase); err != nil {
			return fail(err)
		}
		s.audit.logf("CONTROL create-key name=%s", safeText(request.Name))
		return withKeys()
	case "rename_key":
		if err := s.manager.rename(request.KeyID, request.Name); err != nil {
			return fail(err)
		}
		renamed, _ := s.registry.key(request.KeyID)
		s.audit.logf("CONTROL rename-key key_id=%s name=%s", request.KeyID, safeText(renamed.Name))
		return withKeys()
	case "set_auth_mode":
		if err := s.manager.setAuthMode(request.KeyID, keyAuthMode(request.AuthMode)); err != nil {
			return fail(err)
		}
		s.audit.logf("CONTROL set-auth-mode key_id=%s mode=%s", request.KeyID, safeText(request.AuthMode))
		return withKeys()
	case "set_chain_check_mode":
		if err := s.manager.setChainCheckMode(request.KeyID, chainCheckMode(request.ChainCheckMode)); err != nil {
			return fail(err)
		}
		s.audit.logf("CONTROL set-chain-check-mode key_id=%s mode=%s", request.KeyID, safeText(request.ChainCheckMode))
		return withKeys()
	case "set_enabled":
		if request.Enabled == nil {
			return fail(errors.New("enabled 값 없음"))
		}
		if *request.Enabled {
			if err := s.manager.authenticate(request.KeyID, "Pasu 키 활성화 확인"); err != nil {
				return fail(err)
			}
		}
		if err := s.manager.setEnabled(request.KeyID, *request.Enabled); err != nil {
			return fail(err)
		}
		s.audit.logf("CONTROL set-enabled key_id=%s enabled=%t", request.KeyID, *request.Enabled)
		return withKeys()
	case "lock_key":
		if err := s.manager.lock(request.KeyID); err != nil {
			return fail(err)
		}
		s.audit.logf("CONTROL lock key_id=%s", request.KeyID)
		return withKeys()
	case "unlock_key":
		if err := s.manager.unlock(request.KeyID); err != nil {
			return fail(err)
		}
		s.audit.logf("CONTROL unlock key_id=%s", request.KeyID)
		return withKeys()
	case "delete_rule":
		if err := s.manager.authenticate(request.KeyID, "Pasu 사슬 규칙 삭제 확인"); err != nil {
			return fail(err)
		}
		if err := s.registry.deleteRule(request.KeyID, request.RuleID); err != nil {
			return fail(err)
		}
		s.audit.logf("CONTROL delete-rule key_id=%s rule_id=%s", request.KeyID, request.RuleID)
		return withKeys()
	case "delete_key":
		path, err := s.manager.delete(request.KeyID)
		if err != nil {
			return fail(err)
		}
		s.audit.logf("CONTROL delete-key key_id=%s trash=%s", request.KeyID, safeText(path))
		response := withKeys()
		response.TrashPath = path
		return response
	case "logs":
		limit := request.Limit
		if limit <= 0 || limit > 500 {
			limit = 200
		}
		lines, err := readKeyAuditLines(s.audit.path, request.KeyID, limit)
		if err != nil {
			return fail(err)
		}
		return v2ControlResponse{Logs: lines}
	case "migrate_v1":
		if s.migrate == nil {
			return fail(errors.New("v1 이전을 사용할 수 없음"))
		}
		if err := s.migrate(); err != nil {
			return fail(err)
		}
		return withKeys()
	default:
		return fail(errors.New("지원하지 않는 control action"))
	}
}

func readKeyAuditLines(path, keyID string, limit int) ([]string, error) {
	var all []string
	for _, candidate := range []string{path + ".old", path} {
		data, err := os.ReadFile(candidate)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		if len(data) > 2*maxControlMessage {
			data = data[len(data)-2*maxControlMessage:]
		}
		for _, line := range strings.Split(string(data), "\n") {
			if line == "" || (keyID != "" && !strings.Contains(line, "key_id="+keyID)) {
				continue
			}
			all = append(all, line)
		}
	}
	if len(all) > limit {
		all = all[len(all)-limit:]
	}
	return all, nil
}
