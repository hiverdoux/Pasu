# 소스 빌드와 서명 앱 제작

소스에서 개발용 프로그램을 만들고 검사하는 방법을 설명합니다. 실제 SSH 키를 사용할 앱을 만들려면 별도의 코드 서명 조건이 필요합니다. 완성된 앱을 받았다면 [사용자 안내서의 설치 절차](USER_GUIDE.md#앱-설치)로 시작하세요.

## 준비물

- macOS 27. 화면·인증 관련 검사에는 로그인한 사용자 세션이 필요합니다.
- Go 1.26.6 이상.
- Xcode 또는 Command Line Tools. `xcrun swiftc`로 Swift 컴파일러를 실행할 수 있어야 합니다.

명령은 저장소를 복제하거나 소스 압축 파일을 푼 폴더에서 실행합니다. 외부 Go 모듈의 버전은 `go.mod`에 고정되어 있으며, 처음 빌드할 때는 다운로드가 필요합니다.

스크립트는 `/opt/homebrew/bin`, `/usr/local/go/bin`, `/usr/local/bin`과 macOS의 표준 도구 경로를 사용합니다. 다른 위치에 설치된 Go는 자동으로 찾지 않습니다.

## 개발용 빌드

```sh
./build.sh
```

다음 파일이 생성됩니다.

| 파일 | 용도 |
|---|---|
| `pasu` | SSH 서명을 처리하는 agent 실행 파일 |
| `PasuGUI` | 관리 화면 실행 파일 |
| `libpasuse.a` | Go 실행 파일에 연결하는 Swift 라이브러리 |
| `signing_identity_generated.go`, `.build/signing/` | 설정에서 생성한 빌드용 신원과 앱 구성 파일 |
| `swift_build_stamp.go` | Swift 코드 변경 시 Go가 다시 빌드하도록 하는 생성 파일 |

개발용 파일에는 임시 서명(ad-hoc)이 적용됩니다. 제작자 인증서가 없는 이 서명으로는 실제 Pasu Keychain 저장소에 접근할 수 없어, `pasu`를 일반 SSH agent로 실행하거나 설치 스크립트로 설치할 수 없습니다. 관리 화면은 아래 샘플 미리보기를 사용하세요.

```sh
./scripts/gui-preview.sh --run
```

화면을 이미지로 저장하려면 다음을 실행합니다. 실제 키·로그 대신 합성 데이터를 사용하며 결과는 `dist/gui-preview/`에 저장됩니다.

```sh
./scripts/gui-preview.sh
```

## 자동 검사

```sh
./scripts/check.sh
./scripts/verify.sh
```

- `check.sh`: Go 코드 형식, 빌드, 정적 검사와 동시 실행 오류 검사를 수행합니다. 서명 설정·프로파일 조건과 합성 환경의 설치·제작자 전환·자료 이동·복원 검사도 포함합니다.
- `verify.sh`: v2 키·규칙 동작, 설치 설정과 스크립트 형식, 합성 데이터의 Keychain 그룹 이전, 개발용 서명의 접근 제한을 검사합니다.

키와 규칙 시험은 합성 데이터를 사용합니다. 운영체제 기능을 확인하는 시험은 실제 프로세스 정보와 macOS 보안 기능을 사용하며, 보안 하드웨어·로그인 상태·비교 대상 앱에 따라 일부 시험을 건너뛰거나 실패할 수 있습니다. 화면 없는 자동 빌드 환경은 별도로 검증되지 않았습니다.

Swift 라이브러리를 먼저 만들어야 하므로 깨끗한 소스에서 `go test`만 실행하지 말고 위 스크립트부터 사용하세요. 선택적으로 `git config core.hooksPath .githooks`를 설정하면 커밋할 파일의 기본 검사를 커밋 전에 자동 실행합니다.

## 서명 앱 제작

실제 키를 사용할 앱에는 Apple의 Developer ID 코드 서명과 Keychain 접근 권한이 필요합니다. 권한은 프로파일(provisioning profile)이라는 Apple 발급 파일로 부여됩니다.

자신의 인증서로 앱을 만들고 같은 서명 팀·앱 식별자를 유지해 업데이트할 수 있도록 구현되어 있습니다. 제작자를 바꾸어 설치하면 각 제작자의 자료를 분리해 보존합니다. **다른 개발자 팀의 유효한 인증서로 실제 서명·설치·업데이트하는 시험은 아직 하지 못했습니다.** 설정 생성과 잘못된 설정 거부를 확인하는 자동 검사는 실제 환경 검증을 대신하지 않습니다.

### Apple 서명 자료 준비

다음은 서명 자료를 준비하는 순서입니다. 실제 다른 개발자 계정에서의 발급부터 설치까지는 아직 검증하지 못했습니다.

1. **발급 자격을 확인합니다.** 일반적인 개인 개발자는 Apple Developer Program 가입이 필요합니다. 로컬 Developer ID 인증서 발급에는 개발자 팀의 계정 소유자(Account Holder) 권한이 필요합니다. 가입 비용과 자격은 [Apple 가입 안내](https://developer.apple.com/programs/enroll/)와 [Developer ID 안내](https://developer.apple.com/help/account/certificates/create-developer-id-certificates)를 확인하세요.
2. **Developer ID Application 인증서를 준비합니다.** 새로 발급한다면 Mac의 키체인 접근 앱에서 인증서 서명 요청(CSR)을 만들고 개발자 계정에 제출합니다. 내려받은 인증서는 그 요청을 만든 개인키와 함께 키체인에 있어야 합니다. `Developer ID Installer`는 다른 종류의 인증서입니다. [CSR 생성](https://developer.apple.com/help/account/certificates/create-a-certificate-signing-request/) · [인증서 발급](https://developer.apple.com/help/account/certificates/create-developer-id-certificates)
3. **agent의 앱 식별자를 등록합니다.** 개발자 계정의 Identifiers에서 명시적 App ID를 만들고 Bundle ID에 `<bundle_id>.agent`를 넣습니다. 아래 예시라면 `org.example.pasu.agent`입니다. [App ID 등록](https://developer.apple.com/help/account/identifiers/register-an-app-id)
4. **agent용 Developer ID 프로파일을 준비합니다.** 등록한 agent App ID와 사용할 인증서를 허용하는 macOS Developer ID 배포 프로파일이 필요합니다. 프로파일의 Keychain 허용 목록에는 `<team_id>.<bundle_id>.agent` 또는 해당 팀의 와일드카드 그룹이 있어야 합니다. [프로파일의 대상·인증서·권한 조건](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles)

현재 개발자 포털의 전체 화면 순서와 Keychain Sharing 항목의 표시 여부는 확인하지 못했습니다. 내려받은 프로파일이 실제 조건을 충족하는지는 빌드 스크립트가 검사합니다. 관리 앱에는 프로파일이 필요하지 않습니다. 프로파일은 Keychain 접근 권한을 사용하는 agent에만 포함합니다.

### 자신의 서명 정보 설정

다음 파일을 복사하고 예시 값을 자신의 정보로 바꿉니다.

```sh
cp signing.example.json signing.local.json
```

```json
{
  "team_id": "ABCDE12345",
  "bundle_id": "org.example.pasu",
  "sign_identity": "Developer ID Application: Example Developer (ABCDE12345)",
  "profile": "example.provisionprofile"
}
```

| 항목 | 넣을 값 |
|---|---|
| `team_id` | Apple 개발자 팀의 영문 대문자·숫자 10자 식별자 |
| `bundle_id` | 관리 앱의 고유 식별자. 예: `org.example.pasu` |
| `sign_identity` | 키체인에 개인키와 함께 등록된 같은 팀의 Developer ID Application 인증서 이름 또는 40자리 인증서 지문 |
| `profile` | agent용 Developer ID 프로파일 파일 경로. 상대 경로는 설정 파일의 폴더 기준 |

agent의 앱 식별자는 `<bundle_id>.agent`, Keychain 접근 그룹은 `<team_id>.<bundle_id>.agent`로 생성됩니다. 프로파일은 이 agent의 App ID와 Keychain 그룹을 허용해야 합니다. 인증서 이름을 생략하면 같은 팀에서 사용 가능한 Developer ID Application 인증서가 정확히 하나일 때만 자동 선택합니다. 같은 이름의 인증서가 여러 개라면 `security find-identity -v -p codesigning`에 표시되는 40자리 지문을 `sign_identity`에 넣어 구분합니다. 지문은 인증서의 고유한 요약값입니다.

`signing.local.json`, 프로파일과 생성된 `.build/` 폴더는 Git 추적에서 제외됩니다. 설정 파일에는 인증서 개인키나 암호를 넣지 않습니다. `profile`에 `~`나 `$HOME`을 쓰면 확장하지 않으므로 상대 경로나 실제 절대 경로를 사용하세요.

다른 설정 파일은 `PASU_SIGNING_CONFIG`로 지정할 수 있습니다. `PASU_SIGNING_CONFIG`를 지정하지 않고 `signing.local.json`도 없으면 `packaging/signing.json`의 공식 앱 식별자로 개발용 빌드를 만듭니다. `PASU_PROFILE`과 `PASU_SIGN_IDENTITY`는 각각 프로파일 경로와 인증서 이름·지문을 덮어쓰는 빌드용 환경 변수입니다. 빌드 스크립트에서 `PASU_PROFILE`의 상대 경로는 소스 폴더 기준입니다. 설정 파일의 `profile`은 그 설정 파일의 폴더 기준이므로 두 기준을 구분하세요. 명시한 설정 파일이 없으면 오류로 끝나며 다른 설정으로 대체하지 않습니다.

### 앱 제작과 설치

```sh
./scripts/build-release.sh
./scripts/launchd.sh verify-app
```

일반 사용자 권한으로 실행합니다. 서명 시 Apple 서버에서 서명 시각을 확인하므로 인터넷 연결이 필요합니다.

키체인이 `codesign`의 개인키 사용을 요청하면 자신이 시작한 빌드인지 확인하세요. `허용`은 이번 사용을 허가하고, `항상 허용`은 해당 도구의 이후 사용도 허용 목록에 등록합니다. 이 창은 개발자의 **코드 서명 개인키** 사용 요청이며 Pasu의 SSH 키 인증창과는 다릅니다. [Apple의 서명 신원·승인창 설명](https://developer.apple.com/forums/thread/712005)

빌드는 프로파일의 유효기간·팀·앱·Keychain 권한과 선택한 인증서를 확인한 뒤 `dist/Pasu.app`을 만듭니다. 생성한 팀·앱 식별자는 Go와 Swift 실행 파일, 앱 설정과 실행 권한에 함께 반영됩니다. `packaging/`의 plist는 빌드 시 설정값을 넣는 원본이며, 완성된 구성 파일은 `.build/signing/`에 저장됩니다. 설치된 앱은 로컬 서명 설정이나 환경 변수로 신뢰할 제작자를 바꾸지 않습니다.

이 스크립트는 Apple **공증**을 수행하지 않습니다. 공증은 완성된 앱을 Apple 서버에 제출해 검사받는 별도 절차입니다. `verify-app` 통과는 다운로드한 앱의 실행 허가를 보장하지 않으며, 다른 Mac에 전달하면 Gatekeeper에 의해 실행이 차단될 수 있습니다. 배포 전에는 공증과 수신자 환경의 설치·실행 검증이 필요합니다. [공증 절차](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution) · [macOS 앱 실행 정책](https://support.apple.com/en-us/102445)

완성된 앱의 설치는 [사용자 안내서](USER_GUIDE.md#앱-설치)를 따릅니다. 앱을 받는 사람에게는 `Pasu.app`과 같은 버전의 공개 소스 폴더를 전달하면 됩니다. 인증서·개인키·프로파일 원본·`signing.local.json`은 전달할 필요가 없습니다. 앱 내부에는 실행 권한 확인에 필요한 프로파일 사본이 포함됩니다.

### 같은 제작자의 업데이트

후속 버전에서도 `team_id`와 `bundle_id`를 유지하고 다시 빌드합니다. 인증서를 갱신했다면 `sign_identity`와 해당 인증서를 허용하는 프로파일을 함께 갱신합니다. 업데이트는 개별 인증서의 이름이나 지문을 고정하지 않고, 같은 Developer ID 팀과 앱 식별자를 요구합니다. 인증서 갱신 후 실제 데이터 접근 시험도 아직 수행하지 못했습니다.

일반 `install`은 같은 팀·앱 식별자의 업데이트만 허용합니다. 다른 제작자로 전환할 때는 `install --switch-developer`를 명시합니다. 앱은 `/Applications/Pasu.app` 하나만 설치하고, 파일은 `~/.ssh/pasu/profiles/<team_id>.<bundle_id>/`에 보존합니다. Keychain 항목도 기존 제작자별 접근 그룹을 유지하며 서로 복사하거나 병합하지 않습니다.

구형 앱의 파일은 설치 과정에서 해당 제작자 폴더로 옮기고, 앱 복원 시 경로도 되돌립니다. 구형 공식 v2.1.1은 아래의 그룹 이전을 먼저 완료해야 다른 제작자로 전환할 수 있습니다. 자세한 순서는 [제작자 전환](USER_GUIDE.md#제작자-전환)을 참고하세요.

### 기존 데이터가 있는 환경의 추가 검사

```sh
./scripts/check.sh --release
```

기본 검사에 최신 Go 취약점 조회, 서명 앱 빌드와 `verify-release.sh`를 추가합니다. 네트워크 접속과 서명 인증서가 필요합니다.

`verify-release.sh`는 **이미 Pasu를 설정한 계정의 `registry-v2` 관리 항목**을 읽어 해당 서명 앱의 Keychain 접근을 확인합니다. 이 항목이 없는 새 환경에서는 통과하지 않으므로 최초 설치 검사를 대신할 수 없습니다. 서명된 앱의 복사본을 임시 서명으로 바꾸어 접근이 차단되는지도 확인합니다.

자동 검사를 통과한 뒤에도 설치, 로그인 후 자동 실행, 키 인증, SSH 연결, 업데이트·복원은 실제 사용 환경에서 확인해야 합니다.

### 서명 문제 해결

| 증상 | 확인할 내용 |
|---|---|
| 프로파일 미설정·파일 없음 | `signing.local.json`의 `profile`과 `PASU_PROFILE`, 각각의 상대 경로 기준을 확인합니다. 공식 앱 식별자로 빌드할 때도 프로파일을 직접 지정해야 합니다. |
| 사용 가능한 인증서 없음 | `security find-identity -v -p codesigning`에서 같은 팀의 Developer ID Application 인증서가 보이는지 확인합니다. 인증서와 대응하는 개인키가 함께 있어야 합니다. 예시 이름을 실제 값으로 바꾸세요. |
| 같은 이름의 인증서가 여러 개 | 사용할 인증서의 40자리 지문을 `sign_identity`에 넣습니다. 동일 인증서가 여러 키체인에 표시되는 것은 중복으로 처리합니다. |
| agent 실행 실패·종료 코드 137 | 서명·프로파일의 유효성 및 macOS 진단 기록을 확인합니다. 종료 코드만으로 원인을 확정할 수 없습니다. |
| `-34018` 또는 배포 앱에서만 실행할 수 있다는 오류 | 임시 서명 빌드인지, agent의 팀·앱 식별자·Keychain 권한과 프로파일이 맞는지 확인합니다. 권한 검사를 생략해 해결하지 않습니다. |

### 구버전 이전용 앱 제작

기존 공식 Pasu v2.1.1의 Keychain 접근 그룹에서 v2.2로 옮기려면 두 그룹에 접근할 수 있는 별도 이전용 앱이 필요합니다. 기존 공식 팀·앱 식별자와 일치하는 서명 조건에서만 다음을 실행합니다. 다른 팀의 설정에서는 이 빌드를 거부합니다.

```sh
PASU_RELEASE_MODE=migration ./scripts/build-release.sh
./scripts/build-release.sh
```

첫 명령은 `dist/migration/Pasu.app`, 두 번째 명령은 `dist/Pasu.app`을 만듭니다. 최종 앱에는 이전용 권한과 실행 기능이 포함되지 않습니다. 두 앱을 사용하는 순서는 [구버전에서 이전](USER_GUIDE.md#구버전에서-이전)에 있습니다.

## 코드 찾아보기

- `scripts/signing-config/`, `scripts/signing-common.sh`: 서명 설정 생성과 빌드·설치 검사.
- `v2model.go`, `v2registry.go`, `v2keys.go`: 키·규칙 저장과 키 생성·변경·삭제.
- `v2agent.go`, `peer_darwin.go`, `codesign_darwin.go`: 서명 요청과 호출 프로그램 검사.
- `v2prompt.go`, `v2control.go`, `gui/`: 승인창과 관리 화면 통신.
- `v2migration.go`, `v2run.go`, `keychain_group_darwin.*`: 시작과 데이터 이전.
- `keychain_darwin.*`, `keychain_setup.go`, `sewrap_*`: Keychain 및 구버전 저장 방식 호환.
- [experiments/](../experiments/README.md): macOS 기능을 개별적으로 확인하는 도구.

## 용어

- **빌드**: 소스 코드를 실행 파일로 만드는 작업입니다.
- **agent / GUI**: 각각 백그라운드 서명 서비스와 사용자가 조작하는 관리 화면입니다.
- **코드 서명**: 제작자 신원과 서명 이후 코드가 변경되지 않았는지 확인하는 정보입니다.
- **Developer ID / 서명 팀**: Apple이 발급한 앱 서명 인증서와 그 인증서가 속한 개발자 계정의 식별 정보입니다.
- **Keychain 접근 그룹**: 같은 보안 저장 항목을 읽을 수 있는 서명된 앱의 범위입니다.
- **registry-v2**: Pasu의 키 목록·설정·규칙을 보관하는 Keychain 관리 항목입니다.
- **합성 데이터**: 실제 사용자의 키나 운영 기록과 무관하게 시험용으로 만든 값입니다.
