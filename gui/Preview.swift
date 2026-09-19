// 시각 검증용 미리보기. -D PASU_PREVIEW로 컴파일할 때만 존재하며 배포 빌드에는
// 한 줄도 들어가지 않는다. agent·Keychain·실제 소켓을 건드리지 않고 메모리의
// 샘플 데이터로 화면을 띄우거나 PNG로 저장한다.
#if PASU_PREVIEW
import AppKit
import CryptoKit
import SwiftUI

extension KeyView {
	func updated(name: String? = nil, authMode: String? = nil, chainCheckMode: String? = nil, enabled: Bool? = nil,
		unlocked: Bool? = nil, rules: [ChainRule]? = nil) -> KeyView {
		KeyView(id: id, name: name ?? self.name, fingerprint: fingerprint,
			publicKey: name.map { pubBody + " " + $0 + "\n" } ?? publicKey,
			publicKeyPath: publicKeyPath, authMode: authMode ?? self.authMode,
			chainCheckMode: chainCheckMode ?? self.chainCheckMode,
			enabled: enabled ?? self.enabled, unlocked: unlocked ?? self.unlocked,
			createdAt: createdAt, lastUsed: lastUsed, rules: rules ?? self.rules)
	}

	private var pubBody: String {
		let parts = publicKey.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: " ")
		return parts.prefix(2).joined(separator: " ")
	}
}

enum SampleData {
	static let keyA = "00000000-0000-4000-8000-000000000001"
	static let keyB = "00000000-0000-4000-8000-000000000002"
	static let keyC = "00000000-0000-4000-8000-000000000003"
	static let sampleHome = "/Users/sample"

	// 실제 키나 로그를 복사하지 않고 고정된 예시 이름에서 표시 데이터를 만든다.
	// 개인키는 생성하지 않는다. 지문은 표시하는 공개키 바이트와 일치한다.
	static func examplePublicKey(_ id: String) -> (body: String, fingerprint: String) {
		var wire = Data([0, 0, 0, 11])
		wire.append(Data("ssh-ed25519".utf8))
		wire.append(contentsOf: [0, 0, 0, 32])
		wire.append(contentsOf: SHA256.hash(data: Data("pasu-preview-example-\(id)".utf8)))
		let fingerprint = Data(SHA256.hash(data: wire)).base64EncodedString().replacingOccurrences(of: "=", with: "")
		return (wire.base64EncodedString(), "SHA256:" + fingerprint)
	}

	static func stamp(minutesAgo: Double) -> String {
		let f = ISO8601DateFormatter()
		f.formatOptions = [.withInternetDateTime]
		return f.string(from: Date().addingTimeInterval(-minutesAgo * 60))
	}

	static func apple(_ path: String, _ id: String) -> StableProcess {
		StableProcess(path: path, uid: 1001, identity: CodeIdentity(kind: "apple-platform", teamId: nil, identifier: id))
	}

	static func dev(_ path: String, _ team: String, _ id: String) -> StableProcess {
		StableProcess(path: path, uid: 1001, identity: CodeIdentity(kind: "developer-id", teamId: team, identifier: id))
	}

	static let launchd = apple("/sbin/launchd", "com.apple.xpc.launchd")

	static let iterm = StableChain(tty: "foreground", members: [
		apple("/usr/bin/ssh", "com.apple.ssh"),
		apple("/bin/zsh", "com.apple.zsh"),
		apple("/usr/bin/login", "com.apple.login"),
		dev("\(sampleHome)/Library/Application Support/iTerm2/iTermServer-example", "H7V7XYVQ7D", "com.googlecode.iterm2.iTermServer"),
		dev("/Applications/iTerm.app/Contents/MacOS/iTerm2", "H7V7XYVQ7D", "com.googlecode.iterm2"),
		launchd,
	])

	static let codex = StableChain(tty: "none", members: [
		apple("/usr/bin/ssh", "com.apple.ssh"),
		dev("/Applications/ChatGPT.app/Contents/Resources/codex", "2DC432GLL2", "com.openai.chat.codex"),
		dev("/Applications/ChatGPT.app/Contents/MacOS/ChatGPT", "2DC432GLL2", "com.openai.chat"),
		launchd,
	])

	static let codexShell = StableChain(tty: "none", members: [
		apple("/usr/bin/ssh", "com.apple.ssh"),
		apple("/bin/zsh", "com.apple.zsh"),
		dev("/Applications/ChatGPT.app/Contents/Resources/codex", "2DC432GLL2", "com.openai.chat.codex"),
		dev("/Applications/ChatGPT.app/Contents/MacOS/ChatGPT", "2DC432GLL2", "com.openai.chat"),
		launchd,
	])

	static let untrustedWrapper = StableChain(tty: "background", members: [
		apple("/usr/bin/ssh", "com.apple.ssh"),
		StableProcess(path: "\(sampleHome)/bin/ssh-wrapper", uid: 1001,
			identity: CodeIdentity(kind: "untrusted", teamId: nil, identifier: "untrusted")),
		apple("/bin/zsh", "com.apple.zsh"),
		dev("/Applications/iTerm.app/Contents/MacOS/iTerm2", "H7V7XYVQ7D", "com.googlecode.iterm2"),
		launchd,
	])

	static func rule(_ id: String, _ decision: String, _ chain: StableChain, createdMinutesAgo: Double, usedMinutesAgo: Double?) -> ChainRule {
		ChainRule(id: id, decision: decision, chain: chain, createdAt: stamp(minutesAgo: createdMinutesAgo),
			lastUsed: usedMinutesAgo.map { stamp(minutesAgo: $0) })
	}

	static func key(id: String, name: String, mode: String, enabled: Bool, unlocked: Bool,
		createdMinutesAgo: Double, usedMinutesAgo: Double?, rules: [ChainRule]) -> KeyView {
		let publicKey = examplePublicKey(id)
		return KeyView(id: id, name: name, fingerprint: publicKey.fingerprint,
			publicKey: "ssh-ed25519 \(publicKey.body) pasu-\(name)\n",
			publicKeyPath: "\(sampleHome)/.ssh/pasu/profiles/ABCDE12345.org.example.pasu/keys/\(id)/key.pub", authMode: mode, enabled: enabled,
			unlocked: unlocked, createdAt: stamp(minutesAgo: createdMinutesAgo),
			lastUsed: usedMinutesAgo.map { stamp(minutesAgo: $0) }, rules: rules)
	}

	static var keys: [KeyView] {
		[
			key(id: keyA, name: "기존 Pasu 키", mode: "cached",
				enabled: true, unlocked: true, createdMinutesAgo: 60 * 24 * 12, usedMinutesAgo: 14, rules: [
					rule("1111111111111111111111111111111111111111111111111111111111111111", "allow", iterm, createdMinutesAgo: 60 * 24 * 3, usedMinutesAgo: 14),
					rule("2222222222222222222222222222222222222222222222222222222222222222", "allow", codex, createdMinutesAgo: 60 * 24 * 2, usedMinutesAgo: 95),
					rule("3333333333333333333333333333333333333333333333333333333333333333", "deny", codexShell, createdMinutesAgo: 60 * 30, usedMinutesAgo: nil),
					rule("4444444444444444444444444444444444444444444444444444444444444444", "deny", untrustedWrapper, createdMinutesAgo: 60 * 5, usedMinutesAgo: nil),
				]),
			key(id: keyB, name: "배포 서버", mode: "per-sign",
				enabled: true, unlocked: false, createdMinutesAgo: 60 * 24, usedMinutesAgo: 60 * 6, rules: [
					rule("5555555555555555555555555555555555555555555555555555555555555555", "allow", iterm, createdMinutesAgo: 60 * 20, usedMinutesAgo: 60 * 6),
				]),
			key(id: keyC, name: "임시 CI", mode: "none",
				enabled: false, unlocked: false, createdMinutesAgo: 60 * 3, usedMinutesAgo: nil, rules: []),
		]
	}

	static func chainText(_ chain: StableChain, pids: [Int]) -> String {
		zip(chain.members, pids).map { "\($0.path)(\($1))" }.joined(separator: " < ")
	}

	static var logs: [String] {
		let a = keyA, fpA = examplePublicKey(keyA).fingerprint
		let b = keyB, fpB = examplePublicKey(keyB).fingerprint
		let itermChain = chainText(iterm, pids: [101, 102, 103, 104, 105, 1])
		let codexChain = chainText(codex, pids: [201, 202, 203, 1])
		let shellChain = chainText(codexShell, pids: [301, 302, 202, 203, 1])
		let wrapperChain = chainText(untrustedWrapper, pids: [401, 402, 403, 105, 1])
		let ruleA = "1111111111111111111111111111111111111111111111111111111111111111"
		let ruleB = "2222222222222222222222222222222222222222222222222222222222222222"
		let lines: [(Double, String)] = [
			(60 * 26, "STOP signal=terminated"),
			(60 * 26 - 1, "START version=\(previewBuildVersion) mode=v2 socket=\(sampleHome)/.ssh/pasu/agent.sock control=\(sampleHome)/.ssh/pasu/control.sock keys=3 migration-pending=false os=example os-build=example-build"),
			(60 * 25, "LIST peer=101 uid=1001 keys=2 chain=\(itermChain)"),
			(60 * 25, "ASK-V2 show key_id=\(a) key_fp=\(fpA) chain_id=6666666666666666666666666666666666666666666666666666666666666666 chain=\(itermChain)"),
			(60 * 25 - 0.1, "ASK-V2 result=always key_id=\(a) chain_id=6666666666666666666666666666666666666666666666666666666666666666"),
			(60 * 25 - 0.2, "ALLOW sign key_id=\(a) key_fp=\(fpA) rule_id=\(ruleA) peer=101 exe=/usr/bin/ssh choice=always chain=\(itermChain)"),
			(60 * 24, "EXTENSION unsupported type=session-bind@openssh.com"),
			(60 * 24, "LIST peer=201 uid=1001 keys=2 chain=\(codexChain)"),
			(60 * 24 - 0.1, "ALLOW sign key_id=\(a) key_fp=\(fpA) rule_id=\(ruleB) peer=201 exe=/usr/bin/ssh choice=always chain=\(codexChain)"),
			(60 * 22, "LIST peer=301 uid=1001 keys=2 chain=\(shellChain)"),
			(60 * 22, "ASK-V2 show key_id=\(a) key_fp=\(fpA) chain_id=7777777777777777777777777777777777777777777777777777777777777777 chain=\(shellChain)"),
			(60 * 22 - 0.2, "ASK-V2 result=deny key_id=\(a) chain_id=7777777777777777777777777777777777777777777777777777777777777777"),
			(60 * 22 - 0.2, "DENY sign key_id=\(a) key_fp=\(fpA) peer=301 uid=1001 exe=/usr/bin/ssh reason=사용자_영구_거부 detail=<nil> chain=\(shellChain)"),
			(60 * 21, "LIST-FILTER key_id=\(a) key_fp=\(fpA) peer=303 decision=deny rule_id=3333333333333333333333333333333333333333333333333333333333333333"),
			(60 * 21, "LIST peer=303 uid=1001 keys=1 chain=\(shellChain)"),
			(60 * 20, "CONTROL create-key name=배포 서버"),
			(60 * 19, "LIST peer=501 uid=1001 keys=2 chain=\(itermChain)"),
			(60 * 19, "ASK-V2 show key_id=\(b) key_fp=\(fpB) chain_id=8888888888888888888888888888888888888888888888888888888888888888 chain=\(itermChain)"),
			(60 * 19 - 0.1, "ASK-V2 result=always key_id=\(b) chain_id=8888888888888888888888888888888888888888888888888888888888888888"),
			(60 * 19 - 0.2, "ALLOW sign key_id=\(b) key_fp=\(fpB) rule_id=5555555555555555555555555555555555555555555555555555555555555555 peer=501 exe=/usr/bin/ssh choice=always chain=\(itermChain)"),
			(60 * 6, "ALLOW sign key_id=\(b) key_fp=\(fpB) rule_id=5555555555555555555555555555555555555555555555555555555555555555 peer=502 exe=/usr/bin/ssh choice=always chain=\(itermChain)"),
			(60 * 5, "LIST peer=401 uid=1001 keys=2 chain=\(wrapperChain)"),
			(60 * 5, "ASK-V2 show key_id=\(a) key_fp=\(fpA) chain_id=9999999999999999999999999999999999999999999999999999999999999999 chain=\(wrapperChain)"),
			(60 * 5 - 0.3, "ASK-V2 result=deny key_id=\(a) chain_id=9999999999999999999999999999999999999999999999999999999999999999"),
			(60 * 5 - 0.3, "DENY sign key_id=\(a) key_fp=\(fpA) peer=401 uid=1001 exe=/usr/bin/ssh reason=사용자_영구_거부 detail=<nil> chain=\(wrapperChain)"),
			(60 * 3, "CONTROL create-key name=임시 CI"),
			(60 * 3 - 0.5, "CONTROL set-enabled key_id=\(keyC) enabled=false"),
			(80, "CONTROL lock key_id=\(a)"),
			(75, "LIST peer=601 uid=1001 keys=2 chain=\(itermChain)"),
			(75, "DENY sign key_id=\(a) key_fp=\(fpA) peer=601 uid=1001 exe=/usr/bin/ssh reason=키_잠금_해제_실패 detail=사용자가 인증을 취소함 chain=\(itermChain)"),
			(40, "CONTROL unlock key_id=\(a)"),
			(30, "CONTROL rename-key key_id=\(a) name=기존 Pasu 키"),
			(14, "LIST peer=701 uid=1001 keys=2 chain=\(itermChain)"),
			(14, "ALLOW sign key_id=\(a) key_fp=\(fpA) rule_id=\(ruleA) peer=701 exe=/usr/bin/ssh choice=always chain=\(itermChain)"),
			(2, "CONTROL deny err=GUI 코드 신원 불일치: {Kind:untrusted TeamID: Identifier:untrusted}"),
		]
		return lines.map { "\(stamp(minutesAgo: $0.0)) \($0.1)" }
	}
}

final class PreviewStore: @unchecked Sendable {
	private let lock = NSLock()
	private var keys: [KeyView]
	private var logs: [String]
	private var migrationPending: Bool
	private var connected: Bool
	private let agentVersion: String
	private let startedAt: String

	init(keys: [KeyView] = SampleData.keys, logs: [String] = SampleData.logs, migrationPending: Bool = false,
		connected: Bool = true, agentVersion: String = previewBuildVersion, startedMinutesAgo: Double = 60 * 26 - 1) {
		self.keys = keys
		self.logs = logs
		self.migrationPending = migrationPending
		self.connected = connected
		self.agentVersion = agentVersion
		self.startedAt = SampleData.stamp(minutesAgo: startedMinutesAgo)
	}

	private func response(keys: [KeyView]? = nil, logs: [String]? = nil, trashPath: String? = nil) -> ControlResponse {
		ControlResponse(version: controlProtocolVersion, ok: true, error: nil, keys: keys,
			migrationPending: keys == nil ? nil : migrationPending, logs: logs, trashPath: trashPath,
			agentVersion: keys == nil ? nil : agentVersion, startedAt: keys == nil ? nil : startedAt)
	}

	private func log(_ line: String) {
		logs.append("\(SampleData.stamp(minutesAgo: 0)) \(line)")
	}

	private func update(_ id: String?, _ change: (KeyView) -> KeyView) throws {
		guard let index = keys.firstIndex(where: { $0.id == id }) else { throw ControlError.message("모르는 키") }
		keys[index] = change(keys[index])
	}

	@Sendable
	func handle(_ request: ControlRequest) throws -> ControlResponse {
		lock.lock()
		defer { lock.unlock() }
		guard connected else {
			throw ControlError.message("Pasu agent에 연결하지 못했습니다: No such file or directory")
		}
		switch request.action {
		case "status", "list_keys":
			return response(keys: keys)
		case "logs":
			let limit = request.limit ?? 200
			let filtered = logs.filter { line in
				guard let id = request.keyId else { return true }
				return line.contains("key_id=\(id)")
			}
			return response(logs: Array(filtered.suffix(limit)))
		case "create_key":
			let name = (request.name ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
			if keys.contains(where: { $0.name.lowercased() == name.lowercased() }) {
				throw ControlError.message("같은 이름의 키가 이미 있음")
			}
			let id = UUID().uuidString.lowercased()
			keys.append(SampleData.key(id: id, name: name, mode: request.authMode ?? "cached",
				enabled: true, unlocked: false, createdMinutesAgo: 0, usedMinutesAgo: nil, rules: []))
			log("CONTROL create-key name=\(name)")
			return response(keys: keys)
		case "rename_key":
			try update(request.keyId) { $0.updated(name: request.name) }
			log("CONTROL rename-key key_id=\(request.keyId ?? "") name=\(request.name ?? "")")
			return response(keys: keys)
		case "set_auth_mode":
			try update(request.keyId) { $0.updated(authMode: request.authMode, unlocked: false) }
			log("CONTROL set-auth-mode key_id=\(request.keyId ?? "") mode=\(request.authMode ?? "")")
			return response(keys: keys)
		case "set_chain_check_mode":
			try update(request.keyId) { $0.updated(chainCheckMode: request.chainCheckMode) }
			return response(keys: keys)
		case "set_enabled":
			let enabled = request.enabled ?? true
			try update(request.keyId) { $0.updated(enabled: enabled, unlocked: enabled ? nil : false) }
			log("CONTROL set-enabled key_id=\(request.keyId ?? "") enabled=\(enabled)")
			return response(keys: keys)
		case "lock_key":
			try update(request.keyId) { $0.updated(unlocked: false) }
			log("CONTROL lock key_id=\(request.keyId ?? "")")
			return response(keys: keys)
		case "unlock_key":
			try update(request.keyId) { key in
				key.authMode == "cached" ? key.updated(unlocked: true) : key
			}
			log("CONTROL unlock key_id=\(request.keyId ?? "")")
			return response(keys: keys)
		case "delete_rule":
			try update(request.keyId) { $0.updated(rules: $0.rules.filter { $0.id != request.ruleId }) }
			log("CONTROL delete-rule key_id=\(request.keyId ?? "") rule_id=\(request.ruleId ?? "")")
			return response(keys: keys)
		case "delete_key":
			guard let key = keys.first(where: { $0.id == request.keyId }) else { throw ControlError.message("모르는 키") }
			keys.removeAll { $0.id == key.id }
			let trash = "\(SampleData.sampleHome)/.Trash/Pasu-\(key.name)-\(key.id)-20260902-150000"
			log("CONTROL delete-key key_id=\(key.id) trash=\(trash)")
			return response(keys: keys, trashPath: trash)
		case "migrate_v1":
			migrationPending = false
			keys.append(SampleData.key(id: UUID().uuidString.lowercased(), name: "기존 Pasu 키",
				mode: "cached", enabled: true,
				unlocked: false, createdMinutesAgo: 0, usedMinutesAgo: nil, rules: []))
			log("MIGRATE v1-to-v2 complete keys=\(keys.count)")
			return response(keys: keys)
		default:
			throw ControlError.message("지원하지 않는 control action")
		}
	}
}

// 사이드바 재질은 오프스크린 캐시에 그려지지 않으므로 같은 행을 일반 목록으로 렌더한다.
struct SidebarPreview: View {
	@ObservedObject var model: PasuModel

	var body: some View {
		List(selection: $model.selection) {
			Label("개요", systemImage: "rectangle.3.group").tag(SidebarItem.overview)
			Section("키 \(model.keys.count)개") {
				ForEach(model.keys) { key in
					KeyRow(key: key, isSelected: model.selection == .key(key.id)).tag(SidebarItem.key(key.id))
				}
			}
		}
		.listStyle(.inset)
		.safeAreaInset(edge: .bottom) { ConnectionFooter(model: model) }
	}
}

struct PreviewApp: App {
	@NSApplicationDelegateAdaptor(PasuApplicationDelegate.self) private var appDelegate
	@StateObject private var model = PasuModel(transport: PreviewStore().handle)

	var body: some Scene {
		WindowGroup {
			ContentView(model: model)
		}
		.commands { CommandGroup(replacing: .newItem) {} }
	}
}

@MainActor
enum Snapshotter {
	struct Scenario {
		let name: String
		let store: PreviewStore
		let selection: SidebarItem?
		let tab: DetailTab
		let dark: Bool
		var size: CGSize? = nil
	}

	static func scenarios() -> [Scenario] {
		var list: [Scenario] = [
			Scenario(name: "overview", store: PreviewStore(), selection: .overview, tab: .overview, dark: false),
			Scenario(name: "overview-disconnected", store: PreviewStore(connected: false), selection: .overview, tab: .overview, dark: false),
			Scenario(name: "overview-migration", store: PreviewStore(keys: [], logs: [], migrationPending: true), selection: .overview, tab: .overview, dark: false),
			Scenario(name: "overview-empty", store: PreviewStore(keys: [], logs: []), selection: .overview, tab: .overview, dark: false),
			Scenario(name: "overview-version-mismatch", store: PreviewStore(agentVersion: "2.0.0"), selection: .overview, tab: .overview, dark: false),
			Scenario(name: "key-overview", store: PreviewStore(), selection: .key(SampleData.keyA), tab: .overview, dark: false),
			Scenario(name: "key-rules", store: PreviewStore(), selection: .key(SampleData.keyA), tab: .rules, dark: false),
			Scenario(name: "key-logs", store: PreviewStore(), selection: .key(SampleData.keyA), tab: .logs, dark: false),
			Scenario(name: "key-persign", store: PreviewStore(), selection: .key(SampleData.keyB), tab: .overview, dark: false),
			Scenario(name: "key-none-disabled", store: PreviewStore(), selection: .key(SampleData.keyC), tab: .overview, dark: false),
			Scenario(name: "key-rules-empty", store: PreviewStore(), selection: .key(SampleData.keyC), tab: .rules, dark: false),
			Scenario(name: "overview-dark", store: PreviewStore(), selection: .overview, tab: .overview, dark: true),
			Scenario(name: "key-rules-dark", store: PreviewStore(), selection: .key(SampleData.keyA), tab: .rules, dark: true),
			Scenario(name: "key-overview-dark", store: PreviewStore(), selection: .key(SampleData.keyA), tab: .overview, dark: true),
			Scenario(name: "key-overview-min", store: PreviewStore(), selection: .key(SampleData.keyA), tab: .overview, dark: false,
				size: CGSize(width: 980, height: 620)),
		]
		list.append(Scenario(name: "key-responsible", store: PreviewStore(keys: SampleData.keys.map { $0.updated(chainCheckMode: "responsible-only") }), selection: .key(SampleData.keyA), tab: .overview, dark: false))
		list.append(Scenario(name: "key-overview-wide", store: PreviewStore(), selection: .key(SampleData.keyA), tab: .overview, dark: false, size: CGSize(width: 1500, height: 820)))
		list.append(Scenario(name: "key-long-description", store: PreviewStore(keys: SampleData.keys.map { $0.id == SampleData.keyA ? $0.updated(name: String(repeating: "sample description ", count: 6)) : $0 }), selection: .key(SampleData.keyA), tab: .overview, dark: false))
		return list
	}

	static func run(outputDir: String) {
		let app = NSApplication.shared
		app.setActivationPolicy(.accessory)
		try? FileManager.default.createDirectory(atPath: outputDir, withIntermediateDirectories: true)
		let size = CGSize(width: 1120, height: 720)
		for scenario in scenarios() {
			let model = PasuModel(transport: scenario.store.handle)
			model.selection = scenario.selection
			model.detailTab = scenario.tab
			render(ContentView(model: model), size: scenario.size ?? size, dark: scenario.dark,
				to: "\(outputDir)/\(scenario.name).png", settle: 1.6)
		}
		let sheetModel = PasuModel(transport: PreviewStore().handle)
		render(CreateKeySheet(model: sheetModel), size: CGSize(width: 560, height: 640), dark: false,
			to: "\(outputDir)/create-sheet.png", settle: 0.8)
		let ruleModel = PasuModel(transport: PreviewStore().handle)
		if let key = SampleData.keys.first, let rule = key.rules.first, let denied = key.denyRules.last {
			let expanded = Form {
				Section("항상 허용") { RuleRow(model: ruleModel, key: key, rule: rule, initiallyExpanded: true) }
				Section("항상 거부") { RuleRow(model: ruleModel, key: key, rule: denied, initiallyExpanded: true) }
			}.formStyle(.grouped)
			render(expanded, size: CGSize(width: 900, height: 760), dark: false,
				to: "\(outputDir)/rule-expanded.png", settle: 0.8)
		}
		let sidebarModel = PasuModel(transport: PreviewStore().handle)
		sidebarModel.selection = .key(SampleData.keyA)
		sidebarModel.refresh()
		render(SidebarPreview(model: sidebarModel), size: CGSize(width: 290, height: 360), dark: false,
			to: "\(outputDir)/sidebar-rows.png", settle: 1.2)
		print("스냅샷 \(scenarios().count + 3)장 저장: \(outputDir)")
		exit(0)
	}

	private static func pump(_ seconds: TimeInterval) {
		RunLoop.main.run(until: Date().addingTimeInterval(seconds))
	}

	static func render<V: View>(_ view: V, size: CGSize, dark: Bool, to path: String, settle: TimeInterval) {
		let hosting = NSHostingView(rootView: view)
		hosting.sceneBridgingOptions = [.toolbars, .title]
		hosting.frame = CGRect(origin: .zero, size: size)
		let window = NSWindow(contentRect: hosting.frame,
			styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
			backing: .buffered, defer: false)
		window.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
		window.titlebarAppearsTransparent = false
		window.contentView = hosting
		// 사이드바 재질과 목록은 화면에 붙은 창에서만 그려지므로, 보이지 않게(알파 0)
		// 실제 화면 안에 올려 두고 뷰 자체의 그리기 결과만 캐시한다.
		window.alphaValue = 0
		window.setFrameOrigin(NSPoint(x: 120, y: 120))
		window.orderFrontRegardless()
		pump(settle)
		hosting.layoutSubtreeIfNeeded()
		window.displayIfNeeded()
		pump(0.3)
		let target: NSView = window.contentView?.superview ?? hosting
		guard let rep = target.bitmapImageRepForCachingDisplay(in: target.bounds) else {
			print("렌더 실패: \(path)")
			return
		}
		target.cacheDisplay(in: target.bounds, to: rep)
		if let png = rep.representation(using: .png, properties: [:]) {
			do {
				try png.write(to: URL(fileURLWithPath: path))
				print("저장: \(path) \(rep.pixelsWide)x\(rep.pixelsHigh)")
			} catch {
				print("저장 실패: \(path) \(error)")
			}
		}
		window.orderOut(nil)
		window.close()
	}
}

@main
struct PreviewMain {
	static func main() {
		let args = CommandLine.arguments
		if let index = args.firstIndex(of: "--snapshot"), index + 1 < args.count {
			let dir = args[index + 1]
			MainActor.assumeIsolated { Snapshotter.run(outputDir: dir) }
			return
		}
		MainActor.assumeIsolated { PreviewApp.main() }
	}
}
#endif
