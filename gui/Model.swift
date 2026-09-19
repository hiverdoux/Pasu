import AppKit
import Combine
import Foundation
import SwiftUI

// agent의 상태를 화면용으로 해석하고 관리 요청을 순서대로 보낸다.
// 허용·거부와 키 관리는 agent가 판정한다.

enum AuthMode: String, CaseIterable, Identifiable {
	case cached
	case perSign = "per-sign"
	case none

	var id: String { rawValue }

	var label: String {
		switch self {
		case .cached: "첫 인증 후 agent 종료까지"
		case .perSign: "매번 인증"
		case .none: "인증 없음"
		}
	}

	var summary: String {
		switch self {
		case .cached:
			"처음 서명할 때 Touch ID 또는 로그인 암호로 열고, 잠그거나 agent가 종료될 때까지 열린 채로 둡니다."
		case .perSign:
			"서명할 때마다 Touch ID 또는 로그인 암호를 요구합니다."
		case .none:
			"허용된 요청은 Touch ID 없이 서명합니다. 보호 수준이 낮아지며 키 관리 확인에는 계속 인증합니다."
		}
	}
}

enum ChainCheckMode: String, CaseIterable, Identifiable {
	case full = "full-chain"
	case responsible = "responsible-only"
	var id: String { rawValue }
	var label: String {
		switch self {
		case .full: "전체 사슬 검사"
		case .responsible: "책임 프로세스만"
		}
	}
	var summary: String {
		switch self {
		case .full: "전체 실행 계보의 경로·서명 신원·사용자·순서와 터미널 상태가 같을 때 규칙을 적용합니다."
		case .responsible: "책임 프로세스(launchd 바로 아래 프로그램)의 경로·서명 신원·사용자를 비교합니다. 중간 프로그램이나 터미널 상태가 달라도 적용하며, 허용과 거부가 겹치면 거부합니다."
		}
	}
}

enum KeyState {
	case disabled, locked, unlocked, perSign, unattended

	var label: String {
		switch self {
		case .disabled: "비활성"
		case .locked: "잠김"
		case .unlocked: "열림"
		case .perSign: "매번 인증"
		case .unattended: "인증 없음"
		}
	}

	var symbol: String {
		switch self {
		case .disabled: "key.slash"
		case .locked: "lock.fill"
		case .unlocked: "lock.open.fill"
		case .perSign: "touchid"
		case .unattended: "hand.raised.slash.fill"
		}
	}

	var color: Color {
		switch self {
		case .disabled: .secondary
		case .locked: .secondary
		case .unlocked: .green
		case .perSign: .blue
		case .unattended: .orange
		}
	}

	var explanation: String {
		switch self {
		case .disabled: "SSH에 사용할 키 목록에서 빠지고 서명 요청도 거부합니다."
		case .locked: "다음 허용 또는 미지 요청에서 Touch ID 또는 로그인 암호로 엽니다."
		case .unlocked: "허용된 사슬은 추가 인증 없이 서명합니다. 수동 잠금이나 agent 종료까지 유지됩니다."
		case .perSign: "열림 상태가 없습니다. 서명마다 인증합니다."
		case .unattended: "잠금 해제 상태를 유지하지 않습니다. 허용된 요청은 사용자 인증 없이 서명합니다."
		}
	}
}

extension KeyView {
	var chainMode: ChainCheckMode { ChainCheckMode(rawValue: chainCheckMode ?? "") ?? .full }

	var mode: AuthMode { AuthMode(rawValue: authMode) ?? .cached }

	var state: KeyState {
		guard enabled else { return .disabled }
		switch mode {
		case .cached: return unlocked ? .unlocked : .locked
		case .perSign: return .perSign
		case .none: return .unattended
		}
	}

	var subtitle: String {
		switch state {
		case .disabled: "비활성 · \(mode.label)"
		case .locked, .unlocked: "\(mode.label) · \(state.label)"
		case .perSign, .unattended: mode.label
		}
	}

	var allowRules: [ChainRule] { rules.filter(\.isAllow) }
	var denyRules: [ChainRule] { rules.filter { !$0.isAllow } }
	var createdDate: Date? { Dates.parse(createdAt) }
	var lastUsedDate: Date? { lastUsed.flatMap(Dates.parse) }

	var homeRelativePublicKeyPath: String {
		let home = pasuHomeDirectory.path
		if publicKeyPath.hasPrefix(home + "/") {
			return "~" + publicKeyPath.dropFirst(home.count)
		}
		return publicKeyPath
	}
}

extension ChainRule {
	var isAllow: Bool { decision == "allow" }
	var decisionLabel: String { isAllow ? "항상 허용" : "항상 거부" }
	var createdDate: Date? { Dates.parse(createdAt) }
	var lastUsedDate: Date? { lastUsed.flatMap(Dates.parse) }
}

func processName(fromPath path: String) -> String {
	let name = (path as NSString).lastPathComponent
	return name.isEmpty ? path : name
}

extension StableChain {
	var lowest: StableProcess? { members.first }

	// 승인창과 같은 정의: launchd 바로 아래가 책임 프로세스다.
	var responsible: StableProcess? {
		guard let last = members.last else { return nil }
		if members.count >= 2, last.path == "/sbin/launchd" {
			return members[members.count - 2]
		}
		return members.first
	}

	var summary: String {
		guard let lowest, let responsible else { return "빈 사슬" }
		return "\(processName(fromPath: responsible.path)) > \(processName(fromPath: lowest.path))"
	}

	// agent의 chainTTY와 같은 뜻: 직접 요청 프로세스가 제어 터미널의 포그라운드 작업이었는지다.
	var ttyLabel: String {
		switch tty {
		case "foreground": "터미널 포그라운드"
		case "background": "터미널 백그라운드"
		case "none": "터미널 없음"
		default: tty
		}
	}

	var ttyExplanation: String {
		switch tty {
		case "foreground":
			"터미널의 포그라운드 작업 그룹에서 실행된 요청입니다. 사람이 직접 입력했는지는 확인하지 않습니다."
		case "background":
			"제어 터미널이 있지만 포그라운드 작업 그룹에 속하지 않은 요청입니다."
		case "none":
			"제어 터미널이 없었습니다. GUI 앱·자동화·백그라운드 서비스처럼 터미널 밖에서 실행된 요청입니다."
		default:
			"알 수 없는 TTY 값입니다."
		}
	}

	var allTrusted: Bool {
		!members.isEmpty && members.allSatisfy { $0.identity.kind == "apple-platform" || $0.identity.kind == "developer-id" }
	}

	func role(of index: Int) -> String? {
		guard members.indices.contains(index) else { return nil }
		var roles: [String] = []
		if index == 0 { roles.append("최하위") }
		if let responsible, members[index] == responsible, index != 0 || members.count == 1 { roles.append("책임") }
		if members[index].path == "/sbin/launchd" { roles.append("launchd") }
		return roles.isEmpty ? nil : roles.joined(separator: " · ")
	}
}

extension CodeIdentity {
	var kindLabel: String {
		switch kind {
		case "apple-platform": "Apple 플랫폼"
		case "developer-id": "Developer ID"
		case "untrusted": "미검증"
		default: kind
		}
	}

	var trusted: Bool { kind == "apple-platform" || kind == "developer-id" }

	var detail: String {
		if let teamId, !teamId.isEmpty { return "\(identifier) · Team \(teamId)" }
		return identifier
	}
}

enum Dates {
	private static let fractional: ISO8601DateFormatter = {
		let f = ISO8601DateFormatter()
		f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
		return f
	}()
	private static let plain: ISO8601DateFormatter = {
		let f = ISO8601DateFormatter()
		f.formatOptions = [.withInternetDateTime]
		return f
	}()
	private static let relativeFormatter: RelativeDateTimeFormatter = {
		let f = RelativeDateTimeFormatter()
		f.unitsStyle = .short
		return f
	}()

	// Go time.Time은 RFC3339Nano로 나오므로 소수점 자릿수가 일정하지 않다.
	static func parse(_ text: String) -> Date? {
		if let date = plain.date(from: text) { return date }
		guard let dot = text.firstIndex(of: "."),
			let zoneStart = text[dot...].firstIndex(where: { $0 == "Z" || $0 == "+" || $0 == "-" })
		else { return nil }
		let digits = text[text.index(after: dot)..<zoneStart]
		let padded = (String(digits) + "000").prefix(3)
		let normalized = text[..<dot] + "." + padded + text[zoneStart...]
		return fractional.date(from: String(normalized))
	}

	static func relative(_ date: Date, now: Date) -> String {
		if abs(now.timeIntervalSince(date)) < 60 { return "방금" }
		return relativeFormatter.localizedString(for: date, relativeTo: now)
	}

	static func absolute(_ date: Date) -> String {
		date.formatted(date: .abbreviated, time: .shortened)
	}

	// 로그 파일과 같은 24시간 표기. 오늘이 아니면 월·일을 앞에 붙인다.
	static func logStamp(_ date: Date, now: Date) -> String {
		let time = date.formatted(.dateTime.hour(.twoDigits(amPM: .omitted)).minute(.twoDigits).second(.twoDigits))
		if Calendar.current.isDate(date, inSameDayAs: now) {
			return time
		}
		return date.formatted(.dateTime.month(.abbreviated).day()) + " " + time
	}
}

enum LogKind: CaseIterable {
	case allow, deny, ask, control, list, lifecycle, other

	var label: String {
		switch self {
		case .allow: "허용"
		case .deny: "거부"
		case .ask: "승인"
		case .control: "관리"
		case .list: "목록"
		case .lifecycle: "agent"
		case .other: "기타"
		}
	}

	var color: Color {
		switch self {
		case .allow: .green
		case .deny: .red
		case .ask: .orange
		case .control: .blue
		case .list: .secondary
		case .lifecycle: .purple
		case .other: .secondary
		}
	}
}

enum LogFilter: String, CaseIterable, Identifiable {
	case all, allow, deny, ask, control

	var id: String { rawValue }

	var label: String {
		switch self {
		case .all: "전체"
		case .allow: "허용"
		case .deny: "거부"
		case .ask: "승인"
		case .control: "관리"
		}
	}

	func includes(_ entry: LogEntry) -> Bool {
		switch self {
		case .all: true
		case .allow: entry.kind == .allow
		case .deny: entry.kind == .deny
		case .ask: entry.kind == .ask
		case .control: entry.kind == .control
		}
	}
}

struct LogEntry: Identifiable, Hashable {
	let id: Int
	let raw: String
	let timestamp: Date?
	let event: String
	let kind: LogKind
	let title: String
	let detail: String
	let keyId: String?

	static func parse(_ line: String, index: Int) -> LogEntry {
		let parts = line.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
		guard parts.count == 2, let stamp = Dates.parse(String(parts[0])) else {
			return LogEntry(id: index, raw: line, timestamp: nil, event: "", kind: .other, title: line, detail: "", keyId: nil)
		}
		let body = String(parts[1])
		let words = body.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
		let event = words.first.map(String.init) ?? ""
		let rest = words.count > 1 ? String(words[1]) : ""
		let fields = LogFields(rest)
		let keyId = fields["key_id"]
		let chainSummary = fields.chainSummary
		let reason = fields["reason"]?.replacingOccurrences(of: "_", with: " ")

		var kind = LogKind.other
		var title = body
		var detail = ""
		switch event {
		case "ALLOW":
			kind = .allow
			title = "서명 허용"
			if let choice = fields["choice"] {
				title += " · " + (choice == "always" ? "항상 허용 규칙" : choice == "once" ? "이번만 허용" : choice)
			}
			detail = chainSummary ?? ""
		case "DENY":
			kind = .deny
			let op = rest.split(separator: " ").first.map(String.init) ?? ""
			title = op == "sign" ? "서명 거부" : op == "list" ? "목록 요청 거부" : "거부 (\(op))"
			if let reason { title += " · " + reason }
			detail = chainSummary ?? fields["detail"] ?? fields["err"] ?? ""
		case "ASK-V2":
			kind = .ask
			let op = rest.split(separator: " ").first.map(String.init) ?? ""
			if op == "show" {
				title = "승인창 표시"
				detail = chainSummary ?? ""
			} else if let result = fields["result"] {
				let choice: String
				switch result {
				case "always": choice = "이 사슬 항상 허용"
				case "once": choice = "이번만 허용"
				case "deny": choice = "이 사슬 항상 거부"
				case "timeout": choice = "응답 없음"
				default: choice = result
				}
				title = "승인 결과 · " + choice
			} else if op == "detail" {
				title = "승인 진행 상세"
				detail = fields["err"] ?? ""
			}
		case "LIST":
			kind = .list
			title = "키 목록 조회"
			if let keys = fields["keys"] { title += " · 후보 \(keys)개" }
			detail = chainSummary ?? ""
		case "LIST-FILTER":
			kind = .list
			title = "목록에서 숨김"
			if let decision = fields["decision"] { title += " · " + (decision == "deny" ? "영구 거부 사슬" : decision) }
		case "CONTROL":
			kind = .control
			let op = rest.split(separator: " ").first.map(String.init) ?? ""
			title = LogEntry.controlTitle(op, fields: fields)
			detail = op == "deny" ? (fields["err"] ?? "") : ""
		case "START":
			kind = .lifecycle
			title = "agent 시작"
			if let version = fields["version"] { title += " · 버전 \(version)" }
			if let keys = fields["keys"] { detail = "키 \(keys)개" }
		case "STOP":
			kind = .lifecycle
			title = "agent 종료"
			if let signal = fields["signal"] { detail = "신호 \(signal)" }
		case "MIGRATE":
			kind = .control
			title = "v1 키 이전 완료"
			if let keys = fields["keys"] { detail = "키 \(keys)개" }
		case "EXTENSION":
			kind = .other
			title = "지원하지 않는 SSH 확장 (정상 협상)"
			detail = fields["type"] ?? ""
		case "POLICY":
			kind = .deny
			title = "정책 저장 실패"
			detail = rest
		case "LOG":
			kind = .lifecycle
			title = "로그 회전"
			detail = rest
		default:
			kind = .other
			title = body
		}
		return LogEntry(id: index, raw: line, timestamp: stamp, event: event, kind: kind,
			title: title, detail: detail, keyId: keyId)
	}

	private static func controlTitle(_ op: String, fields: LogFields) -> String {
		switch op {
		case "create-key": "관리 · 키 생성" + (fields["name"].map { " · \($0)" } ?? "")
		case "rename-key": "관리 · 이름 변경" + (fields["name"].map { " → \($0)" } ?? "")
		case "set-auth-mode": "관리 · 인증 방식 변경" + (fields["mode"].flatMap { AuthMode(rawValue: $0)?.label }.map { " → \($0)" } ?? "")
		case "set-enabled": "관리 · " + (fields["enabled"] == "true" ? "활성화" : "비활성화")
		case "lock": "관리 · 잠금"
		case "unlock": "관리 · 미리 잠금 해제"
		case "delete-rule": "관리 · 규칙 삭제"
		case "delete-key": "관리 · 키 삭제 (휴지통)"
		case "deny": "관리 요청 거부 · GUI 신원 검증 실패"
		case "accept-fail": "관리 연결 수락 실패"
		default: "관리 · \(op)"
		}
	}
}

// `k=v` 토큰의 느슨한 해석. 값에 공백이 있는 name=·err=·chain=은 다음
// 알려진 키 앞까지 또는 줄 끝까지를 값으로 본다.
struct LogFields {
	private var values: [String: String] = [:]

	init(_ text: String) {
		let knownKeys = ["key_id", "key_fp", "rule_id", "peer", "uid", "exe", "choice", "chain", "reason", "detail",
			"err", "result", "chain_id", "keys", "decision", "name", "mode", "enabled", "trash", "version",
			"signal", "type", "socket", "control", "migration-pending", "os", "os-build", "limit", "rotated"]
		var remaining = Substring(text)
		while let eq = remaining.firstIndex(of: "=") {
			let keyStart = remaining[..<eq].lastIndex(of: " ").map { remaining.index(after: $0) } ?? remaining.startIndex
			let key = String(remaining[keyStart..<eq])
			var valueEnd = remaining.endIndex
			var search = remaining.index(after: eq)
			while search < remaining.endIndex {
				guard let nextEq = remaining[search...].firstIndex(of: "=") else { break }
				let nextKeyStart = remaining[..<nextEq].lastIndex(of: " ").map { remaining.index(after: $0) } ?? nextEq
				let nextKey = String(remaining[nextKeyStart..<nextEq])
				if key == "chain" {
					break
				}
				if knownKeys.contains(nextKey), nextKeyStart > remaining.index(after: eq) {
					valueEnd = remaining.index(before: nextKeyStart)
					break
				}
				search = remaining.index(after: nextEq)
			}
			let value = String(remaining[remaining.index(after: eq)..<valueEnd]).trimmingCharacters(in: .whitespaces)
			if values[key] == nil { values[key] = value }
			if valueEnd >= remaining.endIndex { break }
			remaining = remaining[valueEnd...]
		}
	}

	subscript(key: String) -> String? { values[key] }

	var chainSummary: String? {
		guard let chain = values["chain"], !chain.isEmpty else { return nil }
		let members = chain.components(separatedBy: " < ").map { member -> String in
			var name = member
			if let paren = name.lastIndex(of: "("), name.hasSuffix(")") { name = String(name[..<paren]) }
			return processName(fromPath: name)
		}
		guard let lowest = members.first else { return nil }
		let responsible = members.count >= 2 && members.last == "launchd" ? members[members.count - 2] : lowest
		return "\(responsible) > \(lowest)"
	}
}

enum SidebarItem: Hashable {
	case overview
	case key(String)
}

enum DetailTab: Hashable {
	case overview, rules, logs
}

enum ConnectionState: Equatable {
	case unknown
	case connected
	case disconnected(String)
}

struct AgentInfo: Equatable {
	var version: String?
	var startedAt: Date?
}

@MainActor
final class PasuModel: ObservableObject {
	@Published var keys: [KeyView] = []
	@Published var selection: SidebarItem? = .overview
	@Published var detailTab: DetailTab = .overview
	@Published var connection: ConnectionState = .unknown
	@Published var agent = AgentInfo()
	@Published var lastRefresh: Date?
	@Published var migrationPending = false
	@Published var keyLogs: [LogEntry] = []
	@Published var keyLogsFor: String?
	@Published var activity: [LogEntry] = []
	@Published var actionError: String?
	@Published var trashNotice: String?
	@Published var working = false
	@Published var now = Date()

	private var refreshing = false
	private var tick = 0
	let transport: ControlTransport
	let guiVersion: String?

	init(transport: @escaping ControlTransport = sendControl) {
		self.transport = transport
		self.guiVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
	}

	var selectedKeyID: String? {
		if case let .key(id) = selection { return id }
		return nil
	}

	var selectedKey: KeyView? { keys.first { $0.id == selectedKeyID } }

	var versionMismatch: Bool {
		guard let guiVersion, let agentVersion = agent.version else { return false }
		return guiVersion != agentVersion
	}

	func keyName(for id: String?) -> String? {
		guard let id else { return nil }
		return keys.first { $0.id == id }?.name
	}

	private func request(_ action: String) -> ControlRequest {
		ControlRequest(version: controlProtocolVersion, action: action)
	}

	private func apply(_ response: ControlResponse) {
		if let values = response.keys {
			let previousIDs = Set(keys.map(\.id))
			keys = values
			if let id = selectedKeyID, !values.contains(where: { $0.id == id }) {
				selection = .overview
			}
			let created = values.filter { !previousIDs.contains($0.id) }
			if creatingKey, created.count == 1, let key = created.first {
				selection = .key(key.id)
				detailTab = .overview
			}
			creatingKey = false
		}
		migrationPending = response.migrationPending ?? migrationPending
		if let version = response.agentVersion {
			agent.version = version
			agent.startedAt = response.startedAt.flatMap(Dates.parse)
		}
	}

	private var creatingKey = false

	func tick(refreshEvery seconds: Int = 5) {
		now = Date()
		tick += 1
		if tick % seconds == 0 { refresh() }
	}

	func refresh() {
		guard !refreshing else { return }
		refreshing = true
		let transport = transport
		let status = request("status")
		Task {
			do {
				let response = try await Task.detached { try transport(status) }.value
				apply(response)
				connection = .connected
				lastRefresh = Date()
				await fetchLogs()
			} catch {
				connection = .disconnected(error.localizedDescription)
			}
			refreshing = false
		}
	}

	func loadLogs() {
		Task { await fetchLogs() }
	}

	private func fetchLogs() async {
		let transport = transport
		let keyID = selectedKeyID
		var logsRequest = request("logs")
		logsRequest.keyId = keyID
		logsRequest.limit = keyID == nil ? 120 : 200
		do {
			let response = try await Task.detached { try transport(logsRequest) }.value
			let lines = response.logs ?? []
			let entries = lines.enumerated().map { LogEntry.parse($0.element, index: $0.offset) }.reversed()
			if keyID == selectedKeyID {
				if let keyID {
					keyLogs = Array(entries)
					keyLogsFor = keyID
				} else {
					activity = Array(entries)
				}
			}
		} catch {
			// 기록 조회 실패는 상태 폴링이 다음 주기에 연결 상태로 드러낸다.
		}
	}

	func run(_ request: ControlRequest, then: ((ControlResponse) -> Void)? = nil) {
		working = true
		let transport = transport
		Task {
			do {
				let response = try await Task.detached { try transport(request) }.value
				apply(response)
				connection = .connected
				lastRefresh = Date()
				then?(response)
				await fetchLogs()
			} catch {
				creatingKey = false
				actionError = error.localizedDescription
			}
			working = false
			// 실패한 토글·선택이 화면에 남지 않도록 agent의 실제 상태를 바로 다시 읽는다.
			refresh()
		}
	}

	func createKey(name: String, passphrase: String, mode: AuthMode) {
		var req = request("create_key")
		req.name = name
		req.passphrase = passphrase
		req.authMode = mode.rawValue
		creatingKey = true
		run(req)
	}

	func renameKey(_ key: KeyView, name: String) {
		var req = request("rename_key")
		req.keyId = key.id
		req.name = name
		run(req)
	}

	func setAuthMode(_ key: KeyView, mode: AuthMode) {
		var req = request("set_auth_mode")
		req.keyId = key.id
		req.authMode = mode.rawValue
		run(req)
	}

	func setChainCheckMode(_ key: KeyView, mode: ChainCheckMode) {
		guard mode != key.chainMode else { return }
		var req = request("set_chain_check_mode")
		req.keyId = key.id
		req.chainCheckMode = mode.rawValue
		run(req)
	}

	func setEnabled(_ key: KeyView, _ enabled: Bool) {
		var req = request("set_enabled")
		req.keyId = key.id
		req.enabled = enabled
		run(req)
	}

	func lock(_ key: KeyView) {
		var req = request("lock_key")
		req.keyId = key.id
		run(req)
	}

	func unlock(_ key: KeyView) {
		var req = request("unlock_key")
		req.keyId = key.id
		run(req)
	}

	func deleteRule(_ key: KeyView, _ rule: ChainRule) {
		var req = request("delete_rule")
		req.keyId = key.id
		req.ruleId = rule.id
		run(req)
	}

	func deleteKey(_ key: KeyView) {
		var req = request("delete_key")
		req.keyId = key.id
		run(req) { [weak self] response in
			self?.trashNotice = response.trashPath ?? ""
		}
	}

	func migrateV1() {
		run(request("migrate_v1"))
	}
}

enum Clipboard {
	static func copy(_ text: String) {
		NSPasteboard.general.clearContents()
		NSPasteboard.general.setString(text, forType: .string)
	}
}

enum Reveal {
	static func inFinder(_ path: String) {
		NSWorkspace.shared.selectFile(path, inFileViewerRootedAtPath: "")
	}
}
