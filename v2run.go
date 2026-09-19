package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const v2ProductionAgentBinary = "/Applications/Pasu.app/Contents/Library/LoginItems/PasuAgent.app/Contents/MacOS/pasu"

func launchPasuGUI() error {
	return exec.Command("/usr/bin/open", "/Applications/Pasu.app").Run()
}

func runV2(args []string) error {
	flags := flag.NewFlagSet("pasu", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	showVersion := flags.Bool("version", false, "버전 출력")
	showBuildIdentity := flags.Bool("build-identity", false, "빌드에 고정된 팀·관리 앱·agent 식별자")
	showBuildMode := flags.Bool("build-mode", false, "실행 파일의 final/migration 모드")
	showDataLayout := flags.Bool("data-layout", false, "자료 폴더 형식 버전")
	checkOnly := flags.Bool("check", false, "읽기 전용 검사")
	checkLegacyData := flags.Bool("check-legacy-data", false, "이전 폴더의 자료를 읽기 전용 검사")
	showKCState := flags.Bool("keychain-status", false, "Keychain 상태")
	removeLegacyKeychain := flags.Bool("remove-legacy-keychain", false, "이전이 끝난 v1 Keychain 항목 삭제")
	verifySecrets := flags.Bool("verify-keychain-secrets", false, "키체인 이전 후 인증·복호화 검증")
	serviceMode := flags.Bool("service", false, "SMAppService 실행")
	groupStatus := flags.Bool("keychain-group-status", false, "이전·새 그룹 항목 수")
	verifyOldGroup := flags.Bool("verify-old-keychain-access", false, "이전 그룹의 실제 항목 접근 검사")
	moveGroup := flags.Bool("migrate-keychain-group", false, "키체인 그룹 이전")
	rollbackGroup := flags.Bool("rollback-keychain-group", false, "키체인 그룹 복원")
	launchUID := flags.Int("launchd-uid", -1, "내부 launchd UID")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("예상하지 않은 인수")
	}
	modes := 0
	for _, enabled := range []bool{*showVersion, *showBuildIdentity, *showBuildMode, *showDataLayout, *verifySecrets, *checkOnly, *checkLegacyData, *showKCState, *removeLegacyKeychain, *serviceMode, *groupStatus, *verifyOldGroup, *moveGroup, *rollbackGroup, *launchUID >= 0} {
		if enabled {
			modes++
		}
	}
	if modes > 1 {
		return errors.New("실행 모드는 한 번에 하나만 지정하세요")
	}
	if *showVersion {
		fmt.Println("pasu", version)
		return nil
	}
	if *showBuildIdentity {
		fmt.Println(pasuTeamID, pasuGUIIdentifier, pasuAgentIdentifier)
		return nil
	}
	if *showBuildMode {
		fmt.Println(keychainBuildMode())
		return nil
	}
	if *showDataLayout {
		fmt.Println(1)
		return nil
	}
	if *launchUID < -1 {
		return errors.New("-launchd-uid는 0 이상의 UID여야 함")
	}
	if *launchUID >= 0 && *launchUID != os.Getuid() {
		return nil
	}
	if *removeLegacyKeychain && (*checkOnly || *showKCState || *launchUID >= 0) {
		return errors.New("-remove-legacy-keychain은 다른 실행 모드와 함께 사용할 수 없음")
	}
	kcState, err := probeKeychainFn()
	if err != nil {
		return err
	}
	if *showKCState {
		registryStatus := int32(keychainV2Probe(v2RegistryAccount))
		fmt.Printf("keychain legacy=%s registry-v2=%d\n", kcState, registryStatus)
		return nil
	}
	if kcState == keychainUnavailable {
		return errors.New("Pasu v2 agent는 Developer ID와 Keychain access group이 있는 배포 앱에서만 실행할 수 있음")
	}
	if *launchUID >= 0 || *serviceMode {
		if err := redirectLaunchOutput(); err != nil {
			return err
		}
	}
	home, err := resolveHomeDir(true)
	if err != nil {
		return err
	}
	runtimeDir := pasuRuntimeDirectory(home)
	baseDir := pasuDataDirectory(home)
	if *verifyOldGroup {
		return verifyOldGroupAccess()
	}
	if *groupStatus {
		oldCount, newCount, err := keychainGroupCounts()
		if err != nil {
			return err
		}
		fmt.Printf("KEYCHAIN-GROUP old=%d new=%d\n", oldCount, newCount)
		return nil
	}
	if *moveGroup || *rollbackGroup {
		return runKeychainGroupMove(baseDir, *rollbackGroup)
	}
	if err := guardKeychainBridge(); err != nil {
		return err
	}
	if *removeLegacyKeychain {
		lock, err := acquireStoppedAgentLock(filepath.Join(runtimeDir, "agent.sock"), "-remove-legacy-keychain")
		if err != nil {
			return err
		}
		defer releaseInstanceLock(lock)
		return runRemoveLegacyV1Keychain()
	}
	if *verifySecrets {
		return verifyMigratedSecrets(baseDir)
	}
	if *checkOnly || *checkLegacyData {
		if *checkLegacyData {
			baseDir = runtimeDir
		}
		result, err := checkV2Configuration(baseDir, keychainV2Store{})
		if err != nil {
			return err
		}
		fmt.Println(result)
		return nil
	}
	if err := preparePasuDirectories(home); err != nil {
		return err
	}

	store := keychainV2Store{}
	registry, err := loadV2Registry(store)
	if errors.Is(err, errV2RegistryMissing) {
		if err := guardMissingRegistry(baseDir); err != nil {
			return err
		}
		pending := legacyV1Present(baseDir) && kcState == keychainProtected
		registry, err = createV2Registry(store, pending)
	}
	if err != nil {
		return err
	}
	settings := registry.snapshot().Settings
	logPath := filepath.Join(baseDir, "pasu.log")
	audit, err := newAuditLog(logPath, settings.LogSize, stdoutIsTerminal())
	if err != nil {
		return err
	}
	defer audit.Close()
	log.SetOutput(libWriter{a: audit})

	manager, err := newV2KeyManager(baseDir, filepath.Join(home, ".Trash"), registry, store)
	if err != nil {
		return err
	}
	requests := newRequestTracker()
	prompt := newV2PromptCoordinator(settings.AskCooldown, nil, audit.logf)
	controlPath := filepath.Join(runtimeDir, "control.sock")
	control, err := newV2ControlServer(controlPath, manager, registry, audit)
	if err != nil {
		return err
	}
	control.migrate = func() error {
		if err := migrateV1ToV2(baseDir, manager, registry); err != nil {
			return err
		}
		audit.logf("MIGRATE v1-to-v2 complete keys=%d", len(registry.keys()))
		return nil
	}
	go control.serve()
	defer control.close()

	agentPath := filepath.Join(runtimeDir, "agent.sock")
	listener, instanceLock, err := openAgentListener(agentPath)
	if err != nil {
		return err
	}
	defer releaseInstanceLock(instanceLock)
	notify := func(subtitle, body string) {
		if err := macNotifyFn(subtitle, body); err != nil {
			audit.logf("NOTIFY-FAIL err=%v", err)
		}
	}
	core := newV2AgentCore(manager, registry, prompt, audit, notify, requests, uint32(os.Getuid()))
	defer core.close()
	osProduct, osBuild := macOSInfo()
	audit.logf("START version=%s mode=v2 socket=%s control=%s keys=%d migration-pending=%t os=%s os-build=%s",
		version, agentPath, controlPath, len(registry.keys()), registry.snapshot().MigrationPending, osProduct, osBuild)
	if registry.snapshot().MigrationPending {
		go func() {
			if err := launchPasuGUI(); err != nil {
				audit.logf("GUI launch-for-migration-fail err=%v", err)
			}
		}()
	}
	if stdoutIsTerminal() {
		fmt.Printf("Pasu %s v2 agent 가동 중 — 키 %d개\n", version, len(registry.keys()))
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		sig := <-sigCh
		audit.logf("STOP signal=%v", sig)
		requests.stop()
		_ = listener.Close()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				requests.stop()
				requests.wait()
				log.SetOutput(io.Discard)
				return nil
			}
			audit.logf("ACCEPT-FAIL err=%v", err)
			continue
		}
		unixConn, ok := conn.(*net.UnixConn)
		if !ok {
			_ = conn.Close()
			continue
		}
		gate := &v2Gatekeeper{core: core, conn: unixConn}
		go func() {
			defer unixConn.Close()
			agent.ServeAgent(gate, unixConn)
		}()
	}
}

func checkV2Configuration(baseDir string, store v2Store) (string, error) {
	registry, err := loadV2Registry(store)
	if errors.Is(err, errV2RegistryMissing) {
		if guardErr := guardMissingRegistry(baseDir); guardErr != nil {
			return "", guardErr
		}
		if _, statErr := os.Lstat(baseDir); os.IsNotExist(statErr) {
			return "CHECK v2 new-install keys=0", nil
		}
	}
	if errors.Is(err, errV2RegistryMissing) && legacyV1Present(baseDir) {
		return "CHECK v2 migration-ready keys=0 migration-pending=true", nil
	}
	if err != nil {
		return "", err
	}
	ruleCount := 0
	for _, record := range registry.keys() {
		ruleCount += len(record.Rules)
		dir := filepath.Join(baseDir, "keys", record.ID)
		if err := requireOwnedDir(dir); err != nil {
			return "", err
		}
		if err := requireOwnedRegular(filepath.Join(dir, "key"), 0o600); err != nil {
			return "", err
		}
		if err := requireOwnedRegular(filepath.Join(dir, "key.pub"), 0o600); err != nil {
			return "", err
		}
		if _, err := readEncryptedKey(filepath.Join(dir, "key")); err != nil {
			return "", err
		}
		pub, err := loadPublicKey(filepath.Join(dir, "key.pub"))
		if err != nil || ssh.FingerprintSHA256(pub) != record.Fingerprint {
			return "", fmt.Errorf("키 %s 공개키·registry 불일치", record.ID)
		}
		if !supportedManagedPublicKeyLine(pub, record.Name, record.PublicKey) {
			return "", fmt.Errorf("키 %s 이름·registry 공개키 주석 불일치", record.ID)
		}
		if _, production := store.(keychainV2Store); production {
			protected := int32(keychainV2Probe(v2SecretAccount(record.ID, true)))
			if protected != errSecInteractionNotAllowed {
				return "", fmt.Errorf("키 %s 관리 보호 secret 상태=%d, 필요=%d", record.ID, protected, errSecInteractionNotAllowed)
			}
			unattended := int32(keychainV2Probe(v2SecretAccount(record.ID, false)))
			expectedUnattended := int32(errSecItemNotFound)
			if record.AuthMode == keyAuthNone {
				expectedUnattended = errSecSuccess
			}
			if unattended != expectedUnattended {
				return "", fmt.Errorf("키 %s 인증 없음 secret 상태=%d, 필요=%d", record.ID, unattended, expectedUnattended)
			}
		}
	}
	return fmt.Sprintf("CHECK v2 ok keys=%d rules=%d migration-pending=%t",
		len(registry.keys()), ruleCount, registry.snapshot().MigrationPending), nil
}
