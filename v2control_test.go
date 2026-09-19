package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestControlServer(t *testing.T) (*v2ControlServer, *v2KeyManager, *v2Registry) {
	t.Helper()
	store := newMemoryV2Store()
	registry, err := createV2Registry(store, false)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := newV2KeyManager(filepath.Join(t.TempDir(), "pasu"), filepath.Join(t.TempDir(), "Trash"), registry, store)
	if err != nil {
		t.Fatal(err)
	}
	audit := discardAuditLog(t)
	return &v2ControlServer{manager: manager, registry: registry, audit: audit}, manager, registry
}

func TestV2ControlEmptyRulesEncodeAsArray(t *testing.T) {
	server, _, _ := newTestControlServer(t)
	created := server.handle(v2ControlRequest{
		Version: controlProtocolVersion, Action: "create_key", Name: "Empty Rules",
		Passphrase: "empty rules passphrase", AuthMode: string(keyAuthCached),
	})
	if created.Error != "" || len(created.Keys) != 1 {
		t.Fatalf("create response=%+v", created)
	}
	data, err := json.Marshal(created)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) == "" || !json.Valid(data) {
		t.Fatal("control 응답 JSON 오류")
	}
	var decoded struct {
		Keys []struct {
			Rules []chainRule `json:"rules"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil || decoded.Keys[0].Rules == nil {
		t.Fatalf("빈 rules가 배열이 아님: %s err=%v", data, err)
	}
}

func TestDecodeControlRequestRejectsUnknownAndTrailingData(t *testing.T) {
	if _, err := decodeControlRequest([]byte(`{"version":2,"action":"status","unexpected":true}`)); err == nil {
		t.Fatal("unknown field를 허용함")
	}
	if _, err := decodeControlRequest([]byte(`{"version":2,"action":"status"} {"action":"second"}`)); err == nil {
		t.Fatal("두 번째 JSON 값을 허용함")
	}
	request, err := decodeControlRequest([]byte(`{"version":2,"action":"status"}`))
	if err != nil || request.Action != "status" {
		t.Fatalf("정상 요청 실패: %+v err=%v", request, err)
	}
}

func TestV2ControlCreateAndToggle(t *testing.T) {
	server, _, _ := newTestControlServer(t)
	response := server.handle(v2ControlRequest{
		Version: controlProtocolVersion, Action: "create_key", Name: "GUI Key",
		Passphrase: "a sufficiently strong passphrase", AuthMode: string(keyAuthCached),
	})
	if response.Error != "" || len(response.Keys) != 1 || !response.Keys[0].Enabled {
		t.Fatalf("create response=%+v", response)
	}
	disabled := false
	response = server.handle(v2ControlRequest{
		Version: controlProtocolVersion, Action: "set_enabled", KeyID: response.Keys[0].ID, Enabled: &disabled,
	})
	if response.Error != "" || response.Keys[0].Enabled {
		t.Fatalf("disable response=%+v", response)
	}
}

func TestV2ControlRenamesAndChangesAuthentication(t *testing.T) {
	server, _, _ := newTestControlServer(t)
	created := server.handle(v2ControlRequest{
		Version: controlProtocolVersion, Action: "create_key", Name: "Before",
		Passphrase: "a sufficiently strong passphrase", AuthMode: string(keyAuthCached),
	})
	if created.Error != "" {
		t.Fatal(created.Error)
	}
	keyID := created.Keys[0].ID
	renamed := server.handle(v2ControlRequest{
		Version: controlProtocolVersion, Action: "rename_key", KeyID: keyID, Name: "After",
	})
	if renamed.Error != "" || renamed.Keys[0].Name != "After" {
		t.Fatalf("rename response=%+v", renamed)
	}
	changed := server.handle(v2ControlRequest{
		Version: controlProtocolVersion, Action: "set_auth_mode", KeyID: keyID, AuthMode: string(keyAuthNone),
	})
	if changed.Error != "" || changed.Keys[0].AuthMode != keyAuthNone || changed.Keys[0].Unlocked {
		t.Fatalf("auth response=%+v", changed)
	}
}

func TestV2ControlDeletesRuleAfterAuthentication(t *testing.T) {
	server, _, registry := newTestControlServer(t)
	created := server.handle(v2ControlRequest{
		Version: controlProtocolVersion, Action: "create_key", Name: "Rules",
		Passphrase: "another sufficiently strong passphrase", AuthMode: string(keyAuthPerSign),
	})
	if created.Error != "" {
		t.Fatal(created.Error)
	}
	keyID := created.Keys[0].ID
	rule, err := registry.addRule(keyID, ruleDeny, testStableChain(t, ttyForeground))
	if err != nil {
		t.Fatal(err)
	}
	response := server.handle(v2ControlRequest{
		Version: controlProtocolVersion, Action: "delete_rule", KeyID: keyID, RuleID: rule.ID,
	})
	if response.Error != "" || len(response.Keys[0].Rules) != 0 {
		t.Fatalf("delete response=%+v", response)
	}
}

func TestV2ControlStatusReportsAgentVersionAndStart(t *testing.T) {
	server, _, _ := newTestControlServer(t)
	server.startedAt = time.Date(2026, 9, 2, 5, 57, 35, 0, time.UTC)
	status := server.handle(v2ControlRequest{Version: controlProtocolVersion, Action: "status"})
	if status.Error != "" || status.AgentVersion != version || status.StartedAt == nil ||
		!status.StartedAt.Equal(server.startedAt) {
		t.Fatalf("status response=%+v", status)
	}
	data, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"agent_version":`) || !strings.Contains(string(data), `"started_at":"2026-09-02T05:57:35Z"`) {
		t.Fatalf("status JSON에 버전·기동 시각이 없음: %s", data)
	}
	logs := server.handle(v2ControlRequest{Version: controlProtocolVersion, Action: "logs"})
	if logs.Error != "" || logs.AgentVersion != "" || logs.StartedAt != nil {
		t.Fatalf("logs 응답에 키 목록용 필드가 섞임: %+v", logs)
	}
	unset := &v2ControlServer{manager: server.manager, registry: server.registry, audit: server.audit}
	if got := unset.handle(v2ControlRequest{Version: controlProtocolVersion, Action: "status"}); got.StartedAt != nil {
		t.Fatalf("기동 시각이 없는 서버가 zero time을 돌려줌: %+v", got)
	}
}
