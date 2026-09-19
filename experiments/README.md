# macOS 기능 검증 도구

Pasu가 사용하는 운영체제 기능을 개별적으로 확인하는 개발 도구입니다. 앱 설치와 일반 사용에는 필요하지 않습니다. 명령은 [빌드 환경](../docs/BUILDING.md#준비물)을 준비한 뒤 소스 폴더에서 실행합니다.

시험 키는 합성 데이터입니다. 프로세스 조회 결과에는 실제 사용자 경로와 실행 중인 프로그램 정보가 나올 수 있으므로, 출력을 공유하기 전에 확인하세요.

## 도구 선택

| 경로 | 확인하는 기능 | 실행 영향 |
|---|---|---|
| `peerpid` | 로컬 소켓에 연결한 프로세스와 사용자 식별 | 임시 소켓과 보조 프로세스 사용 |
| `procinfo` | 부모 관계·실행 경로·명령 인수 조회 | 실행 중인 프로세스 정보 출력 |
| `keyload` | 암호화 SSH 키의 복호화와 서명 검증 | 임시 시험 키 생성 |
| `agentserve` | SSH agent의 목록·서명 요청 | 임시 agent와 시험 키 사용 |
| `codesign` | 실행 중인 프로그램의 코드 서명 검증 | 보조 프로그램 빌드·실행, 서명 정보 조회 |
| `keychain` | Keychain·생체 인증·Secure Enclave 접근 조건 | 시험용 보안 항목 생성·삭제 |
| `keychain-group` | Keychain 접근 그룹 이전 | 정식 서명·사용자 인증·시험 항목 필요 |
| `askalert` | 승인창의 버튼·선택·취소 동작 | 창을 열고 입력 대기 |

각 도구는 아래에서 개별 실행합니다. Keychain과 화면 관련 도구는 인증이나 창 표시가 가능한 시험 환경에서 사용하세요.

## 프로세스와 소켓

```sh
go run ./experiments/peerpid
go build -o /tmp/pasu-example-sleeper ./experiments/procinfo/sleeper
PASU_EXP_SLEEPER=/tmp/pasu-example-sleeper go run ./experiments/procinfo
```

`peerpid`는 소켓에 연결한 상대의 프로세스 번호(PID)와 사용자 번호(UID)를 확인합니다. `procinfo`는 운영체제의 조회 방식별로 실행 경로와 부모 관계를 비교합니다. 명령줄 인수는 호출자가 지정할 수 있으므로 신원 판정 근거로 쓰지 않습니다.

제품의 직접 연결 프로세스 검사와 사슬 변경 검사는 `peer_darwin_test.go`에 있습니다.

## 키와 SSH agent

```sh
go run ./experiments/keyload
go run ./experiments/agentserve
```

`keyload`는 시험용 암호화 키를 생성·복호화하고 서명을 원래 공개키로 검증합니다. `agentserve`는 목록과 서명 요청을 처리하고 키 추가·삭제 등 지원하지 않는 요청을 거부하는지 확인합니다.

## 코드 서명

```sh
go run ./experiments/codesign
```

프로그램 식별자만 바꾼 임시 서명 앱, 다른 서명 팀, 종료된 프로세스를 거부하는지 확인합니다. 허용 판정의 비교 대상은 Claude Code의 공개 서명 신원이며, 제품의 기본 허용 규칙은 아닙니다.

실험 실행 파일은 모두 통과하면 종료 코드 `0`, 실패하면 `1`, 비교 대상 앱이 실행 사슬에 없어 일부 검사를 생략하면 `2`를 반환합니다. `go run`으로 실행하면 비정상 종료는 자체 코드 `1`로 반환하므로 출력의 `exit status`도 확인하세요.

`codesign/sleeper`는 서명·디버거 시험용 대기 프로그램입니다. 다음은 같은 프로그램에 macOS의 실행 보호 기능인 Hardened Runtime을 적용하기 전후를 비교하는 준비 명령입니다.

```sh
go build -o /tmp/pasu-example-plain ./experiments/codesign/sleeper
cp /tmp/pasu-example-plain /tmp/pasu-example-hardened
codesign --force --sign - --options runtime /tmp/pasu-example-hardened
codesign --display --verbose=4 /tmp/pasu-example-plain
codesign --display --verbose=4 /tmp/pasu-example-hardened
```

디버거 접근을 시험할 때는 두 시험 프로그램을 각각 실행하고 해당 PID를 지정하세요.

## Keychain

```sh
go run ./experiments/keychain
```

개발용 임시 서명에서 보안 저장과 인증 기능을 사용할 수 있는지 확인합니다. 사용자 인증을 요구하는 상태와 앱 서명 권한이 없어 거부되는 상태를 구분해 출력합니다.

그룹 이전 시험은 기존 공식 Pasu v2.1.1의 두 접근 그룹을 대상으로 합니다. [구버전 이전용 앱 제작](../docs/BUILDING.md#구버전-이전용-앱-제작)의 공식 팀·앱 식별자와 서명 설정이 필요하며, 다른 팀의 설정에서는 실행을 거부합니다.

```sh
./scripts/test-keychain-group.sh
```

별도 시험 서비스 이름과 임의 식별값을 사용해 항목의 접근 그룹을 변경합니다. 그룹 이전의 중단·복원 로직을 합성 데이터로 검사하는 시험은 `tests/keychain-group-tests.swift`이며, `scripts/verify.sh`에 포함되어 있습니다.

## 승인창

창을 열지 않고 구성을 검사하려면 다음을 실행합니다.

```sh
osascript experiments/askalert/probe-headless.applescript "example"
```

창을 직접 비교하려면 같은 폴더의 `probe-dialog.applescript`, `probe-3buttons.applescript`, `probe-pulldown.applescript`, `probe-panel.applescript` 중 하나를 실행합니다. 버튼 순서·선택 결과·기본 버튼과 취소 동작을 확인할 수 있습니다. 실제 Pasu 승인창은 `v2prompt.go`에 구현되어 있습니다.

## 용어

- **코드 서명**: 제작자와 코드의 무결성을 확인하는 정보입니다.
- **임시 서명(ad-hoc)**: 제작자 인증서 없이 실행 파일에 적용하는 개발용 서명입니다.
- **Keychain 접근 그룹**: 같은 보안 저장 항목을 읽을 수 있는 앱의 범위입니다.
- **Secure Enclave**: 암호 연산과 키 보호에 사용하는 Apple의 보안 하드웨어입니다.
- **디버거**: 실행 중인 프로그램의 상태를 검사하는 개발 도구입니다.
- **종료 코드**: 프로그램이 끝날 때 실행 결과를 전달하는 숫자입니다.
