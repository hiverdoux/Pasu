// Pasu(파수) — 프로세스 사슬 정책을 적용하는 다중 키 SSH 문지기.
// ssh-agent 프로토콜 서버로 동작하면서 키별 사슬 검사 방식과 승인 규칙에
// 따라 서명하고, 별도 GUI가 키·정책·감사 상태를 관리한다.
// 기능과 보안 경계는 README.md, API 검증 방법은 experiments/README.md 참조.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// 빌드 시 -ldflags "-X main.version=..."로 주입된다. 버전의 기준은 VERSION 파일이다.
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "pasu:", err)
		if !stdoutIsTerminal() {
			if nerr := macNotifyFn("기동 실패", safeText(err.Error())); nerr != nil {
				fmt.Fprintln(os.Stderr, "pasu: 기동 실패 알림 전송 실패:", nerr)
			}
		}
		os.Exit(1)
	}
}

func run() error {
	if usesV2Runtime(version) {
		return runV2(os.Args[1:])
	}
	return runLegacy()
}

func usesV2Runtime(value string) bool {
	major, err := strconv.Atoi(strings.SplitN(value, ".", 2)[0])
	return err == nil && major >= 2
}

func runLegacy() error {
	var (
		showVersion  = flag.Bool("version", false, "버전을 출력하고 종료")
		baseDir      = flag.String("dir", "", "기본 디렉토리 (기본: ~/.ssh/pasu)")
		sockFlag     = flag.String("socket", "", "소켓 경로 (기본: <dir>/agent.sock)")
		keyFlag      = flag.String("key", "", "개인키 경로 (기본: <dir>/key)")
		confFlag     = flag.String("config", "", "allowlist 설정 경로 (기본: <dir>/pasu.conf)")
		logFlag      = flag.String("log", "", "감사 로그 경로 (기본: <dir>/pasu.log)")
		passStdin    = flag.Bool("passphrase-stdin", false, "passphrase를 표준 입력에서 한 줄 읽음 (자동화·테스트용 — 평소에는 터미널 입력을 쓸 것)")
		setupTouchID = flag.Bool("setup-touchid", false, "passphrase와 설정 결속 키를 앱 전용 Keychain에 저장하고 종료")
		rmTouchID    = flag.Bool("remove-touchid", false, "앱 전용 Keychain 잠금 해제 설정과 설정 지문을 삭제하고 종료")
		trustConf    = flag.Bool("trust-conf", false, "현재 pasu.conf·approvals.conf를 신뢰 기준으로 기록하고 종료 (Touch ID 1회 — 설정을 직접 고친 뒤 실행)")
		migrateKC    = flag.Bool("migrate-keychain", false, "기존 sewrap을 Developer ID 앱 전용 Keychain으로 이전하고 종료")
		rmLegacyWrap = flag.Bool("remove-legacy-sewrap", false, "새 Keychain 검증 뒤 기존 sewrap을 삭제하고 종료")
		showKCState  = flag.Bool("keychain-status", false, "앱 전용 Data Protection Keychain 보호 상태만 출력하고 종료")
		checkOnly    = flag.Bool("check", false, "기동 파일을 무인·읽기 전용으로 검사하고 종료 (Touch ID 없음)")
		launchUID    = flag.Int("launchd-uid", -1, "내부용: 시스템 LaunchAgent를 설치한 UID에서만 실행")
	)
	flag.Parse()
	if *showVersion {
		fmt.Println("pasu", version)
		return nil
	}
	if *launchUID < -1 {
		return errors.New("-launchd-uid는 0 이상의 UID여야 함")
	}
	if *launchUID >= 0 && *launchUID != os.Getuid() {
		// /Library/LaunchAgents의 항목은 모든 GUI 사용자에게 발견된다. 설치한
		// 사용자 외의 로그인에서는 정상 종료해 Keychain 조회·재기동을 막는다.
		return nil
	}
	visited := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { visited[f.Name] = true })
	kcState, err := probeKeychainFn()
	if err != nil {
		return err
	}
	production := kcState != keychainUnavailable
	if *launchUID >= 0 {
		if !production {
			return errors.New("-launchd-uid는 Developer ID production 앱의 내부 옵션임")
		}
		if err := redirectLaunchOutput(); err != nil {
			return err
		}
	}
	if production {
		if err := productionFlagError(visited); err != nil {
			return err
		}
		if kcState == keychainUnprotected {
			return errors.New("pasu Keychain 항목에 userPresence가 없음 — Keychain Access에서 항목을 삭제하고 -setup-touchid로 다시 설정하세요")
		}
	}
	modeCount := 0
	for _, enabled := range []bool{*setupTouchID, *rmTouchID, *trustConf, *migrateKC, *rmLegacyWrap, *showKCState, *checkOnly} {
		if enabled {
			modeCount++
		}
	}
	if modeCount > 1 {
		return errors.New("-setup-touchid, -remove-touchid, -trust-conf, -migrate-keychain, -remove-legacy-sewrap, -keychain-status, -check는 하나만 사용할 수 있음")
	}
	if *showKCState {
		fmt.Println("keychain", kcState)
		return nil
	}
	home, err := resolveHomeDir(production)
	if err != nil {
		return err
	}
	if *baseDir == "" {
		*baseDir = filepath.Join(home, ".ssh", "pasu")
	}
	orDefault := func(v, name string) string {
		if v != "" {
			return v
		}
		return filepath.Join(*baseDir, name)
	}
	sockPath := orDefault(*sockFlag, "agent.sock")
	keyPath := orDefault(*keyFlag, "key")
	confPath := orDefault(*confFlag, "pasu.conf")
	logPath := orDefault(*logFlag, "pasu.log")
	wrapPath := filepath.Join(*baseDir, "sewrap")
	approvalsPath := filepath.Join(*baseDir, "approvals.conf")
	macPath := filepath.Join(*baseDir, "conf.hmac")
	if err := legacySetupConflict(*setupTouchID, production, visited["dir"], productionInstallExists()); err != nil {
		return err
	}
	if *checkOnly {
		if *passStdin {
			return errors.New("-check는 -passphrase-stdin과 함께 쓸 수 없음")
		}
		result, err := checkConfiguration(home, keyPath, wrapPath, confPath, macPath, kcState)
		if err != nil {
			return err
		}
		fmt.Println(result)
		return nil
	}

	if err := os.MkdirAll(*baseDir, 0o700); err != nil {
		return err
	}
	// 폴더가 이전부터 있었어도 소유자 전용을 강제한다.
	if err := os.Chmod(*baseDir, 0o700); err != nil {
		return err
	}
	if command := stoppedAgentCommand(*setupTouchID, *rmTouchID, *trustConf, *migrateKC, *rmLegacyWrap); command != "" {
		managementLock, err := acquireStoppedAgentLock(sockPath, command)
		if err != nil {
			return err
		}
		defer releaseInstanceLock(managementLock)
	}

	if *setupTouchID {
		if production {
			return runSetupKeychain(keyPath, confPath, approvalsPath, macPath)
		}
		return runSetupLegacyTouchID(keyPath, wrapPath, confPath, approvalsPath, macPath)
	}
	if *rmTouchID {
		if production {
			return runRemoveKeychain(macPath)
		}
		return runRemoveLegacyTouchID(wrapPath, macPath)
	}
	if *trustConf {
		if production {
			return runTrustConfKeychain(keyPath, confPath, approvalsPath, macPath)
		}
		return runTrustLegacyConf(wrapPath, confPath, approvalsPath, macPath)
	}
	if *migrateKC {
		if !production {
			return errors.New("-migrate-keychain은 Developer ID로 서명된 Pasu.app에서만 사용할 수 있음")
		}
		return runMigrateKeychain(keyPath, wrapPath, confPath, approvalsPath, macPath)
	}
	if *rmLegacyWrap {
		if !production {
			return errors.New("-remove-legacy-sewrap은 Developer ID로 서명된 Pasu.app에서만 사용할 수 있음")
		}
		return runRemoveLegacySEWrap(keyPath, wrapPath, confPath, approvalsPath, macPath)
	}

	// 설정 파일들은 원문 그대로 한 번만 읽어 정책 해석과 결속(confBinding)에
	// 같은 바이트를 공유한다 — 두 번 읽으면 그 사이의 변조가 검증을 비껴간다.
	confData, err := os.ReadFile(confPath)
	if err != nil {
		return fmt.Errorf("설정 로드 실패: %w", err)
	}
	rules, err := parseAllowlist(bytes.NewReader(confData), home)
	if err != nil {
		return fmt.Errorf("설정 로드 실패: %w", err)
	}
	if len(rules.rules) == 0 {
		fmt.Fprintln(os.Stderr, "pasu: 경고 — allowlist가 비어 있어 모든 서명 요청이 거부됩니다")
	}

	// 로그 크기 한도는 conf(limit logsize)에서 오므로 allowlist 파싱이
	// 로그 열기보다 먼저여야 한다.
	var sizeLimit int64
	sizeDesc := "off"
	if rules.logSize != nil {
		sizeLimit = int64(*rules.logSize)
		sizeDesc = rules.logSize.String()
	}

	// stdout 미러링은 터미널 실행일 때만 — launchd 무인 기동에서는 stdout이
	// launchd.log로 리다이렉트되므로 켜면 감사 로그가 이중 기록된다.
	audit, err := newAuditLog(logPath, sizeLimit, stdoutIsTerminal())
	if err != nil {
		return fmt.Errorf("로그 열기 실패: %w", err)
	}
	defer audit.Close()
	log.SetFlags(0)
	log.SetOutput(libWriter{a: audit})
	denyLog := newDenyRecorder(denySummaryWindow, audit.logf)
	defer denyLog.Close()
	requests := newRequestTracker()

	notifySync := func(subtitle, body string) {
		if err := macNotifyFn(subtitle, body); err != nil {
			audit.logf("NOTIFY-FAIL err=%v", err)
		}
	}
	notify := func(subtitle, body string) {
		if !requests.begin() {
			return
		}
		go func() {
			defer requests.done()
			notifySync(subtitle, body)
		}()
	}

	// 승인 기록 원문 — 결속과 asker가 공유한다. 판독 실패는 기동을 막지 않고
	// 빈 상태로 간다(승인이 무시되어 다시 물어보는 쪽이 불허 방향).
	apprData, err := os.ReadFile(approvalsPath)
	if err != nil {
		if !os.IsNotExist(err) {
			audit.logf("BIND approvals-read-fail path=%s err=%v", approvalsPath, err)
		}
		apprData = nil
	}
	bind := newConfBinding(macPath, confData, apprData, audit.logf)
	bind.notify = notify

	key, passSource, err := newKeySource(keyPath, wrapPath, *passStdin, kcState, audit, bind)
	if err != nil {
		return err
	}

	// 잠금 아래에서 낡은 소켓 정리와 listen을 한 덩어리로 수행해 동시 기동
	// 둘이 서로의 새 소켓을 지우는 경쟁을 막는다.
	l, instanceLock, err := openAgentListener(sockPath)
	if err != nil {
		return err
	}
	defer releaseInstanceLock(instanceLock)

	// 서명 rate limit — 설정은 conf(limit 지시어)에서 오고, 상태는 모든
	// 연결이 공유하는 리미터 하나에 담긴다(전역 합산).
	var limiter *signLimiter
	rateDesc := "off"
	if rules.limit != nil {
		limiter = newSignLimiter(*rules.limit)
		rateDesc = rules.limit.String()
	}

	askDesc := "off"
	if rules.ask {
		askDesc = "on"
	}
	askCooldownDesc := durationDesc(rules.askCooldown)
	notifyCooldownDesc := durationDesc(rules.notifyCooldown)
	osProduct, osBuild := macOSInfo()
	audit.logf("START version=%s socket=%s key=%s rules=%d rate-limit=%s log-size=%s ask=%s ask-cooldown=%s notify-cooldown=%s bind=%s passphrase-source=%s os=%s os-build=%s",
		version, sockPath, ssh.FingerprintSHA256(key.PublicKey()), len(rules.rules), rateDesc, sizeDesc,
		askDesc, askCooldownDesc, notifyCooldownDesc, bind.modeDesc(), passSource, osProduct, osBuild)

	// 승인 창(ask) — START 뒤에 만들어 approvals.conf 로드 기록(ASK load)이
	// 기동 표식 다음에 남게 한다. 상태는 모든 연결이 공유한다(전역 1창).
	var ask *asker
	if rules.ask {
		ask = newAsker(approvalsPath, apprData, bind, audit.logf)
		if rules.askCooldown != nil {
			ask.cooldown = *rules.askCooldown
		}
	}
	notifyCooldown := time.Duration(0)
	if rules.notifyCooldown != nil {
		notifyCooldown = *rules.notifyCooldown
	}
	denyNtf := newDenyNotifyLimiter(notifyCooldown)
	fmt.Printf("pasu %s 가동 중 — 종료: Ctrl-C\n", version)
	if _, lazy := key.(*lazyKey); lazy {
		fmt.Println("Touch ID 모드: 키는 잠긴 채 대기, 첫 허용 서명 요청 때 잠금 해제 프롬프트가 표시됩니다")
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		s := <-sigCh
		audit.logf("STOP signal=%v", s)
		requests.stop()
		l.Close()
	}()

	selfUID := uint32(os.Getuid())
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				requests.stop()
				requests.wait()
				// 유휴 agent 연결 goroutine은 프로세스 종료까지 남을 수 있다.
				// 이후 라이브러리 진단이 닫힐 감사 파일을 건드리지 않게 분리한다.
				log.SetOutput(io.Discard)
				return nil
			}
			audit.logf("ACCEPT-FAIL err=%v", err)
			continue
		}
		uc, ok := c.(*net.UnixConn)
		if !ok {
			c.Close()
			continue
		}
		g := &gatekeeper{
			key:      key,
			rules:    rules,
			limit:    limiter,
			ask:      ask,
			denyLog:  denyLog,
			denyNtf:  denyNtf,
			audit:    audit,
			notify:   notify,
			selfUID:  selfUID,
			conn:     uc,
			requests: requests,
		}
		go func() {
			defer uc.Close()
			agent.ServeAgent(g, uc)
		}()
	}
}

const productionInstallBinary = "/Applications/Pasu.app/Contents/MacOS/pasu"

func productionInstallExists() bool {
	_, err := os.Stat(productionInstallBinary)
	return err == nil
}

func legacySetupConflict(setup, production, explicitDir, installed bool) error {
	if setup && !production && !explicitDir && installed {
		return errors.New("ad-hoc 개발 바이너리의 -setup-touchid가 설치본의 기본 ~/.ssh/pasu를 덮어쓸 수 있음; production 설정은 /Applications/Pasu.app/Contents/MacOS/pasu -setup-touchid를 사용하고, legacy 테스트는 -dir로 별도 경로를 명시하세요")
	}
	return nil
}

func redirectLaunchOutput() error {
	home, err := resolveHomeDir(true)
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".ssh", "pasu")
	if usesV2Runtime(version) {
		if err := preparePasuDirectories(home); err != nil {
			return err
		}
		dir = pasuDataDirectory(home)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("launchd 로그 폴더 준비 실패: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, "launchd.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("launchd 로그 열기 실패: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		f.Close()
		return err
	}
	if err := redirectProcessOutput(f); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("launchd 로그 원본 파일 설명자 닫기 실패: %w", err)
	}
	return nil
}

// resolveHomeDir는 Developer ID 앱에서 공격자가 주입할 수 있는 HOME 환경
// 변수를 신뢰하지 않는다. 현재 커널 UID를 macOS 사용자 데이터베이스에서
// 조회해 production 보안 경로를 고정한다. ad-hoc 개발 빌드만 테스트 편의를
// 위해 기존 HOME 동작을 유지한다.
func resolveHomeDir(production bool) (string, error) {
	if !production {
		return os.UserHomeDir()
	}
	uid := strconv.Itoa(os.Getuid())
	account, err := user.LookupId(uid)
	if err != nil {
		return "", fmt.Errorf("현재 UID %s의 시스템 홈 경로 조회 실패: %w", uid, err)
	}
	if account.Uid != uid || !filepath.IsAbs(account.HomeDir) {
		return "", fmt.Errorf("현재 UID의 시스템 홈 경로가 유효하지 않음: uid=%q home=%q", account.Uid, account.HomeDir)
	}
	return filepath.Clean(account.HomeDir), nil
}

// newKeySource는 v1 호환 경로의 키 로드 방식을 고른다. 우선순위:
//  1. Developer ID 앱 + protected Keychain → 앱 결속 Touch ID 지연 해제.
//  2. ad-hoc 개발 빌드의 -passphrase-stdin → 테스트용 즉시 로드.
//  3. ad-hoc 개발 빌드 + <dir>/sewrap → 마이그레이션 전 호환 지연 해제.
//  4. 그 외 ad-hoc 개발 빌드 → 터미널 passphrase 즉시 로드.
//
// 지연 모드에서도 키 파일·공개키 파일의 구성 오류는 기동 시점에 잡는다
// (launchd 무인 기동에서 문제를 첫 서명까지 숨기지 않기 위해).
//
// 설정 결속(bind)은 Keychain 또는 legacy sewrap 모드에서 활성화된다. Developer
// ID 앱은 Keychain 부재·보호 누락 때 다른 모드로 물러서지 않고 실패한다.
// 터미널 모드는 off — 재기동에 passphrase 입력이 필요해 무인 편승이 안 된다.
func newKeySource(keyPath, wrapPath string, passStdin bool, kcState keychainState, audit *auditLog, bind *confBinding) (keySource, string, error) {
	if kcState != keychainUnavailable {
		if passStdin {
			return nil, "", errors.New("Developer ID 설치본은 -passphrase-stdin을 허용하지 않음")
		}
		if kcState != keychainProtected {
			return nil, "", fmt.Errorf("앱 전용 Keychain 설정이 준비되지 않음(state=%s) — -setup-touchid 또는 -migrate-keychain 실행", kcState)
		}
		pub, err := loadPublicKey(keyPath + ".pub")
		if err != nil {
			return nil, "", fmt.Errorf("Keychain 모드에는 공개키 파일이 필요: %w", err)
		}
		pemBytes, err := readEncryptedKey(keyPath)
		if err != nil {
			return nil, "", err
		}
		bind.setMode("on")
		lk := &lazyKey{
			pub: pub,
			unlock: func() (ssh.Signer, error) {
				payload, err := keychainReadFn("SSH 키(pasu) 잠금 해제")
				if err != nil {
					return nil, err
				}
				defer wipe(payload)
				pass, bindKey, err := splitSealedPayload(payload, sewrapV2)
				if err != nil {
					return nil, fmt.Errorf("%w: Keychain 내용 형식 오류: %v", errKeyMaterialInvalid, err)
				}
				s, err := ssh.ParsePrivateKeyWithPassphrase(pemBytes, pass)
				if err != nil {
					return nil, fmt.Errorf("%w: Keychain passphrase로 SSH 키 복호화 실패: %v", errKeyMaterialInvalid, err)
				}
				if err := bind.verify(bindKey); err != nil {
					return nil, err
				}
				audit.logf("UNLOCK method=keychain key=%s", ssh.FingerprintSHA256(s.PublicKey()))
				return s, nil
			},
		}
		return lk, "keychain(touchid)", nil
	}
	if !passStdin {
		w, err := readSEWrap(wrapPath)
		switch {
		case err == nil:
			pub, err := loadPublicKey(keyPath + ".pub")
			if err != nil {
				return nil, "", fmt.Errorf("Touch ID 모드에는 공개키 파일이 필요: %w", err)
			}
			pemBytes, err := readEncryptedKey(keyPath)
			if err != nil {
				return nil, "", err
			}
			if w.V >= sewrapV2 {
				bind.setMode("on")
			} else {
				bind.setMode("upgrade")
			}
			lk := &lazyKey{
				pub: pub,
				unlock: func() (ssh.Signer, error) {
					payload, err := w.open("SSH 키(pasu) 잠금 해제")
					if err != nil {
						return nil, err
					}
					defer wipe(payload)
					pass, bindKey, err := splitSealedPayload(payload, w.V)
					if err != nil {
						return nil, fmt.Errorf("%w: 봉인 내용 형식 오류: %v", errKeyMaterialInvalid, err)
					}
					s, err := ssh.ParsePrivateKeyWithPassphrase(pemBytes, pass)
					if err != nil {
						return nil, fmt.Errorf("%w: 복호화 실패 — 키를 바꿨다면 -setup-touchid 재실행 필요: %v", errKeyMaterialInvalid, err)
					}
					if bindKey != nil {
						// 결속 검증 — 실패하면 서명 키를 내주지 않는다. 검사가
						// Touch ID 뒤·서명 앞이라, 승인된 프롬프트에 편승한
						// 변조 설정도 서명을 얻지 못한다.
						if err := bind.verify(bindKey); err != nil {
							return nil, err
						}
					} else if err := upgradeSewrap(pass, wrapPath, bind); err != nil {
						// 승격 실패는 서명을 막지 않는다 — 결속이 없던 기존
						// 상태 그대로 가고, 다음 재기동의 첫 해제에서 재시도한다.
						audit.logf("BIND upgrade-fail err=%v", err)
					}
					audit.logf("UNLOCK method=touchid key=%s", ssh.FingerprintSHA256(s.PublicKey()))
					return s, nil
				},
			}
			return lk, "sewrap(touchid)", nil
		case !os.IsNotExist(err):
			// 손상된 설정을 조용히 무시하고 터미널 모드로 빠지면 launchd
			// 무인 기동에서 원인 불명으로 죽는다. 명시적으로 실패시킨다.
			return nil, "", fmt.Errorf("Touch ID 설정 읽기 실패 — -setup-touchid 재실행 또는 -remove-touchid: %w", err)
		}
	}
	signer, err := loadSigner(keyPath, passStdin)
	if err != nil {
		return nil, "", err
	}
	src := "tty"
	if passStdin {
		src = "stdin"
	}
	return eagerKey{signer: signer}, src, nil
}

// upgradeSewrap은 v1 봉인을 v2(passphrase‖K)로 자동 승격하고 현재 설정의
// 지문을 기록한다 — 첫 잠금 해제(사용자 인증 성공 직후)에서만 불린다. 순서는
// 지문 먼저, 봉인 나중: 중간에 죽으면 v1+잔여 지문으로 남는데 이는 다음
// 승격이 새 K로 덮어써 무해하다(역순이었다면 v2+지문 없음 = 서명 불능).
func upgradeSewrap(pass []byte, wrapPath string, bind *confBinding) error {
	k, err := newBindKey()
	if err != nil {
		return err
	}
	if err := bind.adoptNewKey(k, "upgrade"); err != nil {
		return err
	}
	payload := append(append([]byte{}, pass...), k...)
	defer wipe(payload)
	w, err := seSeal(payload, sewrapV2)
	if err != nil {
		return err
	}
	return writeSEWrap(wrapPath, w)
}

// readEncryptedKey는 키 파일을 읽고 "passphrase로 암호화된 OpenSSH 키"임을
// 확인한다. 암호화되지 않은 키는 거부한다(pasu의 전제).
func readEncryptedKey(keyPath string) ([]byte, error) {
	pemBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("개인키 읽기 실패 (ssh-keygen으로 먼저 생성 필요): %w", err)
	}
	if _, err := ssh.ParsePrivateKey(pemBytes); err == nil {
		return nil, fmt.Errorf("%s: passphrase 없는 키 — pasu는 암호화된 키만 사용", keyPath)
	} else if _, ok := err.(*ssh.PassphraseMissingError); !ok {
		return nil, fmt.Errorf("개인키 해석 실패: %w", err)
	}
	return pemBytes, nil
}

// loadSigner는 passphrase로 암호화된 OpenSSH 개인키를 읽어 복호화한다.
// 복호화된 키는 프로세스 메모리에만 존재한다.
func loadSigner(keyPath string, passFromStdin bool) (ssh.Signer, error) {
	pemBytes, err := readEncryptedKey(keyPath)
	if err != nil {
		return nil, err
	}
	var pass []byte
	if passFromStdin {
		pass, err = readLineStdin()
	} else {
		pass, err = readPassphraseFn(fmt.Sprintf("%s passphrase: ", keyPath))
	}
	if err != nil {
		return nil, err
	}
	defer wipe(pass)
	signer, err := ssh.ParsePrivateKeyWithPassphrase(pemBytes, pass)
	if err != nil {
		return nil, fmt.Errorf("복호화 실패 (passphrase 확인): %w", err)
	}
	if err := requireEd25519PublicKey(signer.PublicKey(), keyPath); err != nil {
		return nil, err
	}
	return signer, nil
}
