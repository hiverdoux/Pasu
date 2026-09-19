import AppKit
import Combine
import SwiftUI

// 관리 화면. 왼쪽은 개요와 키 목록, 오른쪽은 개요 또는 키 상세(개요·규칙·기록 탭)다.
// 모든 상태 변경은 PasuModel을 거쳐 agent가 결정하며, 이 파일은 표시와 입력만 맡는다.

struct ContentView: View {
	@ObservedObject var model: PasuModel
	@State private var showCreate = false
	@State private var showMigration = false
	@State private var migrationPrompted = false
	private let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

	private var errorPresented: Binding<Bool> {
		Binding(get: { model.actionError != nil }, set: { if !$0 { model.actionError = nil } })
	}

	private var trashPresented: Binding<Bool> {
		Binding(get: { model.trashNotice != nil }, set: { if !$0 { model.trashNotice = nil } })
	}

	var body: some View {
		NavigationSplitView {
			SidebarView(model: model, showCreate: $showCreate)
		} detail: {
			if let key = model.selectedKey {
				KeyDetailView(model: model, key: key)
			} else {
				OverviewView(model: model, showCreate: $showCreate)
			}
		}
		.frame(minWidth: 980, minHeight: 620)
		.sheet(isPresented: $showCreate) { CreateKeySheet(model: model) }
		.alert("작업을 완료하지 못했습니다", isPresented: errorPresented) {
			Button("확인", role: .cancel) { model.actionError = nil }
		} message: {
			Text(model.actionError ?? "")
		}
		.alert("키를 휴지통으로 옮겼습니다", isPresented: trashPresented) {
			Button("Finder에서 보기") {
				if let path = model.trashNotice, !path.isEmpty { Reveal.inFinder(path) }
				model.trashNotice = nil
			}
			Button("확인", role: .cancel) { model.trashNotice = nil }
		} message: {
			Text((model.trashNotice ?? "") + "\n\nKeychain 항목은 삭제했습니다. 원격 authorized_keys의 공개키는 직접 정리하세요.")
		}
		.alert("기존 Pasu 키를 v2로 복사할까요?", isPresented: $showMigration) {
			Button("나중에", role: .cancel) {}
			Button("Touch ID로 이전") { model.migrateV1() }
		} message: {
			Text("기존 파일과 Keychain 항목은 자동 삭제하지 않습니다. 복사한 키로 SSH 연결을 확인한 뒤 정리하세요. 허용 규칙은 새로 설정합니다.")
		}
		.onAppear { model.refresh() }
		.onReceive(timer) { _ in
			model.tick()
			if model.migrationPending && !migrationPrompted {
				migrationPrompted = true
				showMigration = true
			}
		}
		.onChange(of: model.selection) { _, _ in model.loadLogs() }
	}
}

// MARK: - 사이드바

struct SidebarView: View {
	@ObservedObject var model: PasuModel
	@Binding var showCreate: Bool

	var body: some View {
		List(selection: $model.selection) {
			Label("개요", systemImage: "rectangle.3.group")
				.tag(SidebarItem.overview)
			Section {
				ForEach(model.keys) { key in
					KeyRow(key: key, isSelected: model.selection == .key(key.id)).tag(SidebarItem.key(key.id))
				}
				if model.keys.isEmpty {
					Text("아직 키가 없습니다").font(.callout).foregroundStyle(.secondary)
				}
			} header: {
				Text(model.keys.isEmpty ? "키" : "키 \(model.keys.count)개")
			}
		}
		.listStyle(.sidebar)
		.navigationTitle("Pasu")
		.navigationSplitViewColumnWidth(min: 260, ideal: 290, max: 380)
		.toolbar {
			ToolbarItem(placement: .primaryAction) {
				Button { showCreate = true } label: { Label("새 키", systemImage: "plus") }
					.keyboardShortcut("n", modifiers: .command)
					.help("새 SSH 키 만들기 (⌘N)")
			}
		}
		.safeAreaInset(edge: .bottom) { ConnectionFooter(model: model) }
	}
}

struct KeyRow: View {
	let key: KeyView
	var isSelected = false

	var body: some View {
		HStack(spacing: 10) {
			Image(systemName: key.state.symbol)
				.foregroundStyle(isSelected ? Color.white : key.state.color)
				.frame(width: 20)
			VStack(alignment: .leading, spacing: 2) {
				Text(key.name).fontWeight(.medium).lineLimit(1)
				Text(key.subtitle).font(.caption).foregroundStyle(.secondary).lineLimit(1)
			}
			Spacer(minLength: 4)
			RuleCounts(allow: key.allowRules.count, deny: key.denyRules.count, isSelected: isSelected)
		}
		.padding(.vertical, 2)
		.opacity(isSelected || key.enabled ? 1 : 0.65)
	}
}

struct RuleCounts: View {
	let allow: Int
	let deny: Int
	var isSelected = false

	var body: some View {
		HStack(spacing: 6) {
			if allow > 0 {
				Label("\(allow)", systemImage: "checkmark.shield.fill").foregroundStyle(isSelected ? Color.white : Color.green)
			}
			if deny > 0 {
				Label("\(deny)", systemImage: "xmark.shield.fill").foregroundStyle(isSelected ? Color.white : Color.red)
			}
		}
		.font(.caption)
		.monospacedDigit()
	}
}

struct ConnectionFooter: View {
	@ObservedObject var model: PasuModel

	private var color: Color {
		switch model.connection {
		case .connected: .green
		case .disconnected: .red
		case .unknown: .secondary
		}
	}

	private var title: String {
		switch model.connection {
		case .connected: "agent 연결됨"
		case .disconnected: "agent에 연결할 수 없음"
		case .unknown: "agent 연결 확인 중"
		}
	}

	private var subtitle: String {
		switch model.connection {
		case .connected:
			var parts: [String] = []
			if let version = model.agent.version { parts.append("버전 \(version)") }
			if let refresh = model.lastRefresh { parts.append("갱신 \(Dates.relative(refresh, now: model.now))") }
			return parts.joined(separator: " · ")
		case let .disconnected(message):
			return message
		case .unknown:
			return "control socket에 연결하는 중입니다."
		}
	}

	var body: some View {
		HStack(spacing: 8) {
			Circle().fill(color).frame(width: 8, height: 8)
			VStack(alignment: .leading, spacing: 1) {
				Text(title).font(.caption).fontWeight(.medium)
				Text(subtitle).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
			}
			Spacer(minLength: 0)
		}
		.padding(.horizontal, 14)
		.padding(.vertical, 8)
		.background(.bar)
	}
}

// MARK: - 개요

struct OverviewView: View {
	@ObservedObject var model: PasuModel
	@Binding var showCreate: Bool
	@State private var filter: LogFilter = .all

	private var filteredActivity: [LogEntry] { model.activity.filter(filter.includes) }

	var body: some View {
		Form {
			Section("agent") {
				AgentStatusRows(model: model)
			}
			if model.migrationPending {
				Section {
					VStack(alignment: .leading, spacing: 8) {
						Text("기존 v1 키가 발견되어 v2로 복사를 기다리고 있습니다.")
						Text("기존 파일과 Keychain 항목은 그대로 두고 사본을 만듭니다. 허용 목록은 옮기지 않습니다.")
							.font(.callout).foregroundStyle(.secondary)
						Button("Touch ID로 이전") { model.migrateV1() }
							.buttonStyle(.borderedProminent)
							.disabled(model.working)
					}
					.padding(.vertical, 4)
				} header: {
					Label("v1 키 이전 대기", systemImage: "arrow.triangle.2.circlepath")
				}
			}
			Section("키") {
				if model.keys.isEmpty {
					VStack(alignment: .leading, spacing: 8) {
						Text("아직 키가 없습니다.")
						Button("새 키 만들기…") { showCreate = true }
					}
					.padding(.vertical, 4)
				} else {
					KeyStats(keys: model.keys)
					ForEach(model.keys) { key in
						KeySummaryRow(key: key, now: model.now) {
							model.selection = .key(key.id)
							model.detailTab = .overview
						}
					}
				}
			}
			Section {
				if filteredActivity.isEmpty {
					Text(model.activity.isEmpty ? "표시할 기록이 없습니다." : "이 필터에 해당하는 기록이 없습니다.")
						.foregroundStyle(.secondary)
				}
				ForEach(filteredActivity.prefix(60)) { entry in
					LogRow(entry: entry, now: model.now, keyName: model.keyName(for: entry.keyId))
				}
			} header: {
				HStack {
					Text("최근 활동 · 모든 키")
					Spacer()
					LogFilterPicker(filter: $filter)
					Button("로그 파일 보기") { Reveal.inFinder(auditLogPath) }
						.font(.caption)
				}
			}
		}
		.formStyle(.grouped)
		.navigationTitle("Pasu")
		.navigationSubtitle("개요")
	}
}

struct AgentStatusRows: View {
	@ObservedObject var model: PasuModel

	var body: some View {
		switch model.connection {
		case .connected:
			HStack(alignment: .top, spacing: 10) {
				Image(systemName: "checkmark.circle.fill").foregroundStyle(.green).font(.title3)
				VStack(alignment: .leading, spacing: 3) {
					Text("서명 서비스가 실행 중이며 관리 앱과 서로 신원을 확인했습니다.").fontWeight(.medium)
					Text(startedText).font(.callout).foregroundStyle(.secondary)
				}
			}
			LabeledContent("agent 버전") {
				Text(model.agent.version ?? "알 수 없음")
			}
			LabeledContent("GUI 버전") {
				Text(model.guiVersion ?? "개발 빌드")
			}
			if model.versionMismatch {
				Label("GUI와 agent 버전이 다릅니다. 같은 릴리스를 다시 설치하세요.",
					systemImage: "exclamationmark.triangle.fill")
					.foregroundStyle(.orange)
			}
			LabeledContent("SSH agent 소켓") {
				Text("~/.ssh/pasu/agent.sock").font(.system(.body, design: .monospaced)).textSelection(.enabled)
			}
		case let .disconnected(message):
			HStack(alignment: .top, spacing: 10) {
				Image(systemName: "xmark.octagon.fill").foregroundStyle(.red).font(.title3)
				VStack(alignment: .leading, spacing: 4) {
					Text("agent에 연결할 수 없습니다.").fontWeight(.medium)
					Text(message).font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
					Text("5초마다 다시 시도합니다. 터미널에서 ./scripts/launchd.sh status 로 확인하세요.")
						.font(.callout).foregroundStyle(.secondary)
				}
			}
			.padding(.vertical, 2)
		case .unknown:
			HStack(spacing: 10) {
				ProgressView().controlSize(.small)
				Text("서명 서비스에 연결하는 중입니다.").foregroundStyle(.secondary)
			}
		}
	}

	private var startedText: String {
		guard let started = model.agent.startedAt else { return "기동 시각을 아직 받지 못했습니다." }
		return "\(Dates.relative(started, now: model.now)) 시작 · \(Dates.absolute(started))"
	}
}

struct KeyStats: View {
	let keys: [KeyView]

	var body: some View {
		HStack(spacing: 28) {
			Stat(value: keys.count, label: "키")
			Stat(value: keys.filter(\.enabled).count, label: "활성")
			Stat(value: keys.filter { $0.state == .unlocked }.count, label: "열림")
			Stat(value: keys.filter { $0.enabled && $0.mode == .none }.count, label: "인증 없음", highlight: .orange)
			Stat(value: keys.reduce(0) { $0 + $1.rules.count }, label: "규칙")
			Spacer()
		}
		.padding(.vertical, 4)
	}

	private struct Stat: View {
		let value: Int
		let label: String
		var highlight: Color? = nil

		var body: some View {
			VStack(alignment: .leading, spacing: 1) {
				Text("\(value)")
					.font(.title2.weight(.semibold))
					.monospacedDigit()
					.foregroundStyle(value > 0 ? (highlight ?? .primary) : .secondary)
				Text(label).font(.caption).foregroundStyle(.secondary)
			}
		}
	}
}

struct KeySummaryRow: View {
	let key: KeyView
	let now: Date
	let open: () -> Void

	var body: some View {
		Button(action: open) {
			HStack(spacing: 10) {
				Image(systemName: key.state.symbol).foregroundStyle(key.state.color).frame(width: 20)
				VStack(alignment: .leading, spacing: 2) {
					Text(key.name).fontWeight(.medium)
					Text(key.subtitle).font(.caption).foregroundStyle(.secondary)
				}
				Spacer()
				RuleCounts(allow: key.allowRules.count, deny: key.denyRules.count)
				Text(key.lastUsedDate.map { "마지막 사용 \(Dates.relative($0, now: now))" } ?? "사용 기록 없음")
					.font(.caption).foregroundStyle(.secondary)
					.frame(width: 150, alignment: .trailing)
				Image(systemName: "chevron.right").font(.caption).foregroundStyle(.tertiary)
			}
			.contentShape(Rectangle())
		}
		.buttonStyle(.plain)
	}
}

// MARK: - 키 상세

struct KeyDetailView: View {
	@ObservedObject var model: PasuModel
	let key: KeyView

	var body: some View {
		VStack(spacing: 0) {
			KeyHeaderView(model: model, key: key)
				.padding(.horizontal, 20)
				.padding(.top, 14)
				.padding(.bottom, 10)
			Picker("", selection: $model.detailTab) {
				Text("개요").tag(DetailTab.overview)
				Text("규칙").tag(DetailTab.rules)
				Text("기록").tag(DetailTab.logs)
			}
			.pickerStyle(.segmented)
			.labelsHidden()
			.frame(maxWidth: 360)
			.padding(.bottom, 10)
			Divider()
			switch model.detailTab {
			case .overview: KeyOverviewTab(model: model, key: key)
			case .rules: RulesTab(model: model, key: key)
			case .logs: LogsTab(model: model, key: key)
			}
		}
		.navigationTitle("Pasu")
		.navigationSubtitle(key.name)
	}
}

struct KeyHeaderView: View {
	@ObservedObject var model: PasuModel
	let key: KeyView
	@State private var editingName = false
	@State private var draftName = ""
	@State private var hoveringLock = false
	@FocusState private var nameFocused: Bool

	private func beginNameEditing() {
		draftName = key.name
		editingName = true
		DispatchQueue.main.async { nameFocused = true }
	}

	private func finishNameEditing(save: Bool) {
		guard editingName else { return }
		editingName = false
		nameFocused = false
		let requested = draftName.trimmingCharacters(in: .whitespacesAndNewlines)
		if save, !requested.isEmpty, requested != key.name {
			model.renameKey(key, name: requested)
		}
	}

	// 활성 cached 키만 자물쇠를 눌러 잠그거나 미리 열 수 있다. 다른 상태의 아이콘은 표시 전용이다.
	private var lockToggleable: Bool { key.mode == .cached && key.enabled }

	private var stateHelp: String {
		if lockToggleable {
			return key.unlocked
				? "열림 · 클릭하면 잠급니다. signer를 버리고 다음 요청에서 다시 인증합니다."
				: "잠김 · 클릭하면 지금 Touch ID로 미리 잠금 해제합니다. 다음 허용 요청에서 인증 창이 뜨지 않습니다."
		}
		return "\(key.state.label) · \(key.state.explanation)"
	}

	private var stateIcon: some View {
		Image(systemName: key.state.symbol)
			.font(.title)
			.foregroundStyle(key.state.color)
			.frame(width: 36, height: 36)
	}

	var body: some View {
		VStack(alignment: .leading, spacing: 8) {
			HStack(alignment: .center, spacing: 12) {
				Group {
					if lockToggleable {
						Button {
							key.unlocked ? model.lock(key) : model.unlock(key)
						} label: {
							stateIcon
								.background(hoveringLock ? Color.primary.opacity(0.08) : Color.clear,
									in: RoundedRectangle(cornerRadius: 8))
						}
						.buttonStyle(.plain)
						.disabled(model.working)
						.onHover { hoveringLock = $0 }
						.accessibilityLabel(key.unlocked ? "잠그기" : "미리 잠금 해제")
					} else {
						stateIcon
					}
				}
				.help(stateHelp)
				if editingName {
					TextField("키 이름", text: $draftName)
						.font(.title.weight(.bold))
						.textFieldStyle(.roundedBorder)
						.focused($nameFocused)
						.onSubmit { finishNameEditing(save: true) }
						.onExitCommand { finishNameEditing(save: false) }
						.onChange(of: nameFocused) { _, focused in
							if !focused { finishNameEditing(save: true) }
						}
				} else {
					Text(key.name)
						.font(.title.weight(.bold))
						.lineLimit(1)
						.contentShape(Rectangle())
						.onTapGesture { beginNameEditing() }
						.help("클릭해서 이름 변경")
					Button(action: beginNameEditing) { Image(systemName: "pencil") }
						.buttonStyle(.borderless)
						.foregroundStyle(.secondary)
						.help("이름 변경 — 표시 이름은 그대로 쓰고 key.pub 주석은 pasu-<이름>으로 바뀝니다")
						.accessibilityLabel("이름 변경")
				}
				Spacer()
				if model.working {
					ProgressView().controlSize(.small)
				}
				Toggle("활성", isOn: Binding(
					get: { key.enabled },
					set: { model.setEnabled(key, $0) }
				))
				.toggleStyle(.switch)
				.disabled(model.working)
				.help("비활성 키는 List에서 빠지고 직접 Sign도 거부합니다. 활성화에는 Touch ID 확인이 필요합니다.")
			}
			HStack(spacing: 8) {
				Text(key.fingerprint)
					.font(.system(.callout, design: .monospaced))
					.foregroundStyle(.secondary)
					.textSelection(.enabled)
					.lineLimit(1)
				CopyButton(text: key.fingerprint, help: "지문 복사")
				Spacer()
			}
		}
	}
}

struct KeyOverviewTab: View {
	@ObservedObject var model: PasuModel
	let key: KeyView
	@State private var confirmDelete = false

	// 상태와 인증 방식을 함께 표시하고 인증 선택 열의 폭을 유지한다.
	private let authColumnWidth: CGFloat = 250
	private let columnGap: CGFloat = 14

	private var publicKeyLine: String {
		key.publicKey.trimmingCharacters(in: .whitespacesAndNewlines)
	}

	var body: some View {
		Form {
			Section {
				HStack(alignment: .top, spacing: 0) {
					StatusColumn(model: model, key: key)
						.frame(maxWidth: .infinity, alignment: .leading)
					Divider()
						.padding(.horizontal, columnGap)
					AuthModeColumn(model: model, key: key)
						.frame(width: authColumnWidth, alignment: .leading)
				}
			} header: {
				HStack(spacing: 0) {
					Text("상태").frame(maxWidth: .infinity, alignment: .leading)
					Text("인증 방식").frame(width: authColumnWidth, alignment: .leading)
				}
			}
			Section("사슬 검사 방식") {
				Picker("규칙 적용 범위", selection: Binding(
					get: { key.chainMode },
					set: { model.setChainCheckMode(key, mode: $0) }
				)) {
					ForEach(ChainCheckMode.allCases) { mode in Text(mode.label).tag(mode) }
				}
				.pickerStyle(.segmented)
				.labelsHidden()
				.disabled(model.working)
				Text(key.chainMode.summary).font(.callout).foregroundStyle(.secondary)
			}
			Section("공개키") {
				HStack(spacing: 12) {
					PublicKeyText(line: publicKeyLine)
						.frame(maxWidth: .infinity, alignment: .leading)
					CopyButton(text: publicKeyLine, help: "공개키 복사 (authorized_keys에 넣을 한 줄)")
					Button { Reveal.inFinder(key.publicKeyPath) } label: { Image(systemName: "folder") }
						.buttonStyle(.borderless)
						.foregroundStyle(.secondary)
						.help("Finder에서 보기: \(key.homeRelativePublicKeyPath)")
						.accessibilityLabel("Finder에서 보기")
				}
			}
			Section("삭제") {
				Button("이 키 삭제…") { confirmDelete = true }
					.tint(.red)
					.disabled(model.working)
			}
		}
		.formStyle(.grouped)
		.alert("키를 Pasu에서 삭제하시겠습니까?", isPresented: $confirmDelete) {
			Button("취소", role: .cancel) {}
			Button("비활성화하고 휴지통으로 이동", role: .destructive) { model.deleteKey(key) }
		} message: {
			Text("\(key.name)\n\(key.fingerprint)\n\n키 디렉터리는 macOS 휴지통으로 옮기고 Keychain 항목은 삭제합니다. 원격 authorized_keys의 공개키는 자동으로 철회되지 않습니다.")
		}
	}
}

// 상태 열. 각 행의 자세한 뜻은 툴팁으로만 보여 준다.
struct StatusColumn: View {
	@ObservedObject var model: PasuModel
	let key: KeyView

	var body: some View {
		VStack(alignment: .leading, spacing: 0) {
			row("활성", help: key.enabled
				? "활성 키는 List에 나타나고 서명 요청을 받습니다. 헤더의 스위치로 바꿉니다."
				: KeyState.disabled.explanation + " 헤더의 스위치로 다시 켭니다.") {
				Text(key.enabled ? "예" : "아니오")
					.foregroundStyle(key.enabled ? .primary : .secondary)
			}
			Divider()
			row("잠금", help: lockExplanation) {
				Text(lockTitle)
			}
			Divider()
			row("만든 날짜") {
				Text(key.createdDate.map(Dates.absolute) ?? key.createdAt)
			}
			Divider()
			row("마지막 서명") {
				Text(key.lastUsedDate.map { "\(Dates.relative($0, now: model.now)) · \(Dates.absolute($0))" } ?? "아직 없음")
			}
			Divider()
			row("UUID") {
				Text(key.id)
					.font(.system(.callout, design: .monospaced))
					.textSelection(.enabled)
					.lineLimit(1)
					.minimumScaleFactor(0.85)
			}
		}
	}

	@ViewBuilder
	private func row<Content: View>(_ label: String, help: String? = nil, @ViewBuilder content: () -> Content) -> some View {
		let base = LabeledContent(label) { content() }
			.padding(.vertical, 7)
		if let help {
			base.help(help)
		} else {
			base
		}
	}

	private var lockTitle: String {
		switch key.mode {
		case .cached: key.enabled ? key.state.label : "잠김"
		case .perSign, .none: "해당 없음"
		}
	}

	private var lockExplanation: String {
		switch key.mode {
		case .cached:
			key.enabled
				? key.state.explanation + " 헤더의 자물쇠를 눌러 바꿉니다."
				: "비활성 키는 signer를 보관하지 않습니다. 활성화하면 다음 요청에서 다시 인증합니다."
		case .perSign: KeyState.perSign.explanation
		case .none: KeyState.unattended.explanation
		}
	}
}

// 인증 방식 열. 항목은 제목만 보이고, 선택된 방식의 설명이 아래에 나온다.
struct AuthModeColumn: View {
	@ObservedObject var model: PasuModel
	let key: KeyView

	var body: some View {
		VStack(alignment: .leading, spacing: 2) {
			AuthModeRows(current: key.mode, disabled: model.working) { model.setAuthMode(key, mode: $0) }
			AuthModeSummary(mode: key.mode)
		}
		.padding(.vertical, 5)
	}
}

struct AuthModeSummary: View {
	let mode: AuthMode

	var body: some View {
		Text(mode.summary)
			.font(.caption)
			.foregroundStyle(.secondary)
			.fixedSize(horizontal: false, vertical: true)
			.padding(.top, 8)
	}
}

// 복사 완료 상태를 잠시 표시하는 버튼.
struct CopyButton: View {
	let text: String
	let help: String
	@State private var copied = false
	@State private var revert: Task<Void, Never>?

	var body: some View {
		Button {
			Clipboard.copy(text)
			withAnimation { copied = true }
			revert?.cancel()
			revert = Task { @MainActor in
				try? await Task.sleep(for: .seconds(1.5))
				guard !Task.isCancelled else { return }
				withAnimation { copied = false }
			}
		} label: {
			// 두 심벌은 높이가 달라 그대로 바꾸면 행 높이가 흔들린다. 둘 다 자리를 잡아 두고 하나만 보인다.
			ZStack {
				Image(systemName: "doc.on.doc").hidden()
				Image(systemName: "checkmark").hidden()
				Image(systemName: copied ? "checkmark" : "doc.on.doc")
					.foregroundStyle(copied ? Color.green : Color.secondary)
					.contentTransition(.symbolEffect(.replace))
			}
		}
		.buttonStyle(.borderless)
		.help(help)
		.accessibilityLabel(copied ? "복사됨" : help)
	}
}

// 공개키 한 줄을 축약해 보여 준다. 실제 값은 복사 버튼으로 가져가므로 본문 가운데를 줄인다.
// type과 설명은 온전히 유지하고 본문에만 남은 폭과 가운데 생략을 적용한다.
struct PublicKeyText: View {
	let line: String
	private var parts: (type: String, body: String, comment: String) {
		let tokens = line.split(maxSplits: 2, omittingEmptySubsequences: true, whereSeparator: { $0.isWhitespace }).map(String.init)
		guard tokens.count >= 2 else { return ("", line, "") }
		return (tokens[0], tokens[1], tokens.count > 2 ? tokens[2] : "")
	}
	var body: some View {
		let p = parts
		PublicKeyLayout {
			Text(p.type).foregroundStyle(.secondary).fixedSize()
			Text(p.body).lineLimit(1).truncationMode(.middle)
			Text(p.comment).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
		}
		.font(.system(.callout, design: .monospaced))
		.help(line)
		.accessibilityElement(children: .ignore)
		.accessibilityLabel(line)
	}
}

// 매우 긴 설명은 다음 줄에 온전히 표시한다. 일반적인 한 줄에서는 본문이
// 복사 버튼 앞까지 남은 폭을 모두 사용하고 창 크기에 따라 자동으로 늘어난다.
struct PublicKeyLayout: Layout {
	private let gap: CGFloat = 8
	private func metrics(_ subviews: Subviews, width: CGFloat) -> (type: CGSize, comment: CGSize, bodyWidth: CGFloat, wrapped: Bool, rowHeight: CGFloat) {
		let type = subviews[0].sizeThatFits(.unspecified)
		let comment = subviews[2].sizeThatFits(.unspecified)
		let commentGap = comment.width > 0 ? gap : 0
		let wrapped = type.width + gap + 24 + commentGap + comment.width > width
		let bodyWidth = max(0, width - type.width - gap - (wrapped ? 0 : comment.width + commentGap))
		let body = subviews[1].sizeThatFits(ProposedViewSize(width: bodyWidth, height: nil))
		let fittedComment = wrapped ? subviews[2].sizeThatFits(ProposedViewSize(width: width, height: nil)) : comment
		return (type, fittedComment, bodyWidth, wrapped, max(type.height, body.height, wrapped ? 0 : comment.height))
	}
	func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
		let width = proposal.width ?? subviews.reduce(2 * gap) { $0 + $1.sizeThatFits(.unspecified).width }
		let m = metrics(subviews, width: width)
		return CGSize(width: width, height: m.rowHeight + (m.wrapped ? gap + m.comment.height : 0))
	}
	func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
		let m = metrics(subviews, width: bounds.width)
		subviews[0].place(at: bounds.origin, proposal: ProposedViewSize(m.type))
		subviews[1].place(at: CGPoint(x: bounds.minX + m.type.width + gap, y: bounds.minY),
			proposal: ProposedViewSize(width: m.bodyWidth, height: m.rowHeight))
		subviews[2].place(at: CGPoint(x: m.wrapped ? bounds.minX : bounds.maxX - m.comment.width,
			y: bounds.minY + (m.wrapped ? m.rowHeight + gap : 0)), proposal: ProposedViewSize(m.comment))
	}
}

struct AuthModeRows: View {
	let current: AuthMode
	let disabled: Bool
	let onSelect: (AuthMode) -> Void

	var body: some View {
		ForEach(AuthMode.allCases) { mode in
			Button {
				if mode != current { onSelect(mode) }
			} label: {
				HStack(spacing: 10) {
					Image(systemName: mode == current ? "circle.inset.filled" : "circle")
						.foregroundStyle(mode == current ? Color.accentColor : Color.secondary)
					Text(mode.label).fontWeight(mode == current ? .semibold : .regular)
					Spacer(minLength: 0)
				}
				.padding(.vertical, 4)
				.contentShape(Rectangle())
			}
			.buttonStyle(.plain)
			.disabled(disabled)
		}
	}
}

// MARK: - 규칙

struct RulesTab: View {
	@ObservedObject var model: PasuModel
	let key: KeyView

	var body: some View {
		if key.rules.isEmpty {
			ContentUnavailableView {
				Label("저장된 규칙 없음", systemImage: "shield")
			} description: {
				Text("규칙은 승인창에서 ‘이 사슬 항상 허용’ 또는 ‘이 사슬 항상 거부’를 고를 때 만들어집니다.")
			}
		} else {
			Form {
				if !key.allowRules.isEmpty {
					Section {
						ForEach(key.allowRules) { rule in
							RuleRow(model: model, key: key, rule: rule)
						}
					} header: {
						Label("항상 허용 \(key.allowRules.count)", systemImage: "checkmark.shield.fill")
					}
				}
				if !key.denyRules.isEmpty {
					Section {
						ForEach(key.denyRules) { rule in
							RuleRow(model: model, key: key, rule: rule)
						}
					} header: {
						Label("항상 거부 \(key.denyRules.count)", systemImage: "xmark.shield.fill")
					}
				}
			}
			.formStyle(.grouped)
		}
	}
}

struct RuleRow: View {
	@ObservedObject var model: PasuModel
	let key: KeyView
	let rule: ChainRule
	@State private var expanded: Bool

	init(model: PasuModel, key: KeyView, rule: ChainRule, initiallyExpanded: Bool = false) {
		self.model = model
		self.key = key
		self.rule = rule
		_expanded = State(initialValue: initiallyExpanded)
	}

	var body: some View {
		DisclosureGroup(isExpanded: $expanded) {
			VStack(alignment: .leading, spacing: 12) {
				ChainTable(chain: rule.chain)
				HStack {
					Text("규칙 ID \(rule.id.prefix(12))…")
						.font(.caption).foregroundStyle(.secondary)
						.help(rule.id)
					Spacer()
					Button("이 규칙 삭제…") { model.deleteRule(key, rule) }
						.tint(.red)
						.disabled(model.working)
						.help("인증 후 삭제합니다. 다른 일치 규칙이 없으면 다음 요청에서 다시 묻습니다.")
				}
			}
			.padding(.top, 8)
		} label: {
			HStack(alignment: .center, spacing: 10) {
				Image(systemName: rule.isAllow ? "checkmark.shield.fill" : "xmark.shield.fill")
					.foregroundStyle(rule.isAllow ? .green : .red)
					.font(.title3)
					.frame(width: 24)
				VStack(alignment: .leading, spacing: 4) {
					Text(rule.chain.summary).fontWeight(.semibold)
					HStack(spacing: 6) {
						Chip(text: rule.chain.ttyLabel).help(rule.chain.ttyExplanation)
						Chip(text: rule.chain.allTrusted ? "코드 신원 모두 검증됨" : "미검증 구성원 포함",
							color: rule.chain.allTrusted ? .green : .orange)
						Text("구성원 \(rule.chain.members.count)")
							.font(.caption).foregroundStyle(.secondary)
					}
				}
				Spacer()
				VStack(alignment: .trailing, spacing: 2) {
					Text("만듦 " + (rule.createdDate.map { Dates.relative($0, now: model.now) } ?? rule.createdAt))
					Text(rule.lastUsedDate.map { "마지막 사용 \(Dates.relative($0, now: model.now))" } ?? "아직 사용 안 함")
				}
				.font(.caption)
				.foregroundStyle(.secondary)
			}
			.padding(.vertical, 2)
		}
	}
}

struct ChainTable: View {
	let chain: StableChain

	var body: some View {
		VStack(alignment: .leading, spacing: 6) {
			Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 8) {
				ForEach(Array(chain.members.enumerated()), id: \.offset) { index, member in
					if index > 0 { Divider() }
					GridRow(alignment: .top) {
						Text("\(index + 1)")
							.font(.caption).monospacedDigit().foregroundStyle(.secondary)
						VStack(alignment: .leading, spacing: 2) {
							HStack(spacing: 6) {
								Text(processName(fromPath: member.path)).fontWeight(.medium)
								if let role = chain.role(of: index) {
									Chip(text: role, color: .accentColor)
								}
							}
							Text(member.path)
								.font(.system(.caption, design: .monospaced))
								.foregroundStyle(.secondary)
								.textSelection(.enabled)
						}
						VStack(alignment: .leading, spacing: 2) {
							Label(member.identity.kindLabel,
								systemImage: member.identity.trusted ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
								.foregroundStyle(member.identity.trusted ? Color.primary : Color.orange)
							Text(member.identity.detail)
								.font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
						}
						Text("UID \(member.uid)")
							.font(.caption).foregroundStyle(.secondary)
					}
				}
			}
		}
	}
}

// MARK: - 기록

struct LogsTab: View {
	@ObservedObject var model: PasuModel
	let key: KeyView
	@State private var filter: LogFilter = .all

	private var loading: Bool { model.keyLogsFor != key.id }
	private var loaded: [LogEntry] { loading ? [] : model.keyLogs }
	private var entries: [LogEntry] { loaded.filter(filter.includes) }

	var body: some View {
		Form {
			Section {
				if loading {
					HStack(spacing: 10) {
						ProgressView().controlSize(.small)
						Text("기록을 불러오는 중입니다.").foregroundStyle(.secondary)
					}
				} else if entries.isEmpty {
					Text(loaded.isEmpty
						? "이 키의 UUID가 들어간 감사 기록이 아직 없습니다."
						: "이 필터에 해당하는 기록이 없습니다.")
						.foregroundStyle(.secondary)
				}
				ForEach(entries) { entry in
					LogRow(entry: entry, now: model.now, keyName: nil)
				}
			} header: {
				HStack(spacing: 12) {
					LogFilterPicker(filter: $filter)
					Spacer()
					Text("\(entries.count)건").font(.callout).foregroundStyle(.secondary).monospacedDigit()
					Button("로그 파일 보기") { Reveal.inFinder(auditLogPath) }
						.font(.caption)
				}
			}
		}
		.formStyle(.grouped)
	}
}

struct LogFilterPicker: View {
	@Binding var filter: LogFilter

	var body: some View {
		Picker("필터", selection: $filter) {
			ForEach(LogFilter.allCases) { Text($0.label).tag($0) }
		}
		.pickerStyle(.segmented)
		.labelsHidden()
		.fixedSize()
	}
}

struct LogRow: View {
	let entry: LogEntry
	let now: Date
	let keyName: String?
	@State private var expanded = false

	private var detailText: String {
		var parts: [String] = []
		if let keyName { parts.append("키 \(keyName)") }
		if !entry.detail.isEmpty { parts.append(entry.detail) }
		return parts.joined(separator: " · ")
	}

	var body: some View {
		DisclosureGroup(isExpanded: $expanded) {
			Text(entry.raw)
				.font(.system(.caption, design: .monospaced))
				.foregroundStyle(.secondary)
				.textSelection(.enabled)
				.frame(maxWidth: .infinity, alignment: .leading)
				.padding(.top, 4)
		} label: {
			HStack(spacing: 10) {
				Text(entry.timestamp.map { Dates.logStamp($0, now: now) } ?? "")
					.font(.system(.caption, design: .monospaced))
					.foregroundStyle(.secondary)
					.frame(width: 112, alignment: .leading)
				KindBadge(kind: entry.kind)
				VStack(alignment: .leading, spacing: 1) {
					Text(entry.title).lineLimit(1)
					if !detailText.isEmpty {
						Text(detailText).font(.caption).foregroundStyle(.secondary).lineLimit(1)
					}
				}
				Spacer(minLength: 0)
			}
		}
	}
}

struct KindBadge: View {
	let kind: LogKind

	var body: some View {
		Text(kind.label)
			.font(.caption2.weight(.semibold))
			.padding(.horizontal, 6)
			.padding(.vertical, 2)
			.frame(minWidth: 38)
			.background(kind.color.opacity(0.14), in: Capsule())
			.foregroundStyle(kind.color)
	}
}

struct Chip: View {
	let text: String
	var color: Color = .secondary

	var body: some View {
		Text(text)
			.font(.caption.weight(.medium))
			.padding(.horizontal, 7)
			.padding(.vertical, 3)
			.background(color.opacity(0.14), in: Capsule())
			.foregroundStyle(color)
			.lineLimit(1)
	}
}

// MARK: - 키 생성

struct CreateKeySheet: View {
	@Environment(\.dismiss) private var dismiss
	@ObservedObject var model: PasuModel
	@State private var name = ""
	@State private var passphrase = ""
	@State private var confirmation = ""
	@State private var mode: AuthMode = .cached

	private var passphraseBytes: Int { passphrase.utf8.count }
	private var passphraseLongEnough: Bool { passphraseBytes >= 16 }
	private var passphraseMatches: Bool { !confirmation.isEmpty && passphrase == confirmation }
	private var nameValid: Bool {
		let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
		return !trimmed.isEmpty && trimmed.utf8.count <= 128
	}
	private var canCreate: Bool { nameValid && passphraseLongEnough && passphraseMatches && !model.working }

	private func clear() {
		passphrase = ""
		confirmation = ""
	}

	var body: some View {
		VStack(spacing: 0) {
			HStack {
				Text("새 SSH 키").font(.title2.weight(.bold))
				Spacer()
			}
			.padding(.horizontal, 20)
			.padding(.top, 18)
			.padding(.bottom, 8)
			Form {
				Section("이름") {
					TextField("이름", text: $name, prompt: Text("예: 집 서버, 배포용"))
				}
				Section {
					SecureField("passphrase", text: $passphrase)
					SecureField("passphrase 다시 입력", text: $confirmation)
					HStack(spacing: 12) {
						Label(passphraseLongEnough ? "\(passphraseBytes)바이트" : "\(passphraseBytes)바이트 · 최소 16바이트",
							systemImage: passphraseLongEnough ? "checkmark.circle.fill" : "circle")
							.foregroundStyle(passphraseLongEnough ? Color.green : Color.secondary)
						if !confirmation.isEmpty {
							Label(passphraseMatches ? "일치" : "불일치",
								systemImage: passphraseMatches ? "checkmark.circle.fill" : "xmark.circle.fill")
								.foregroundStyle(passphraseMatches ? Color.green : Color.red)
						}
					}
					.font(.caption)
				} header: {
					Text("passphrase")
				} footer: {
					Text("개인키 파일을 암호화합니다. Keychain에 보관되어 다시 묻지 않지만 백업·복구에 필요하니 따로 안전하게 적어 두세요.")
				}
				Section("인증 방식") {
					AuthModeRows(current: mode, disabled: false) { mode = $0 }
					AuthModeSummary(mode: mode)
				}
			}
			.formStyle(.grouped)
			HStack {
				Spacer()
				Button("취소") { clear(); dismiss() }
					.keyboardShortcut(.cancelAction)
				Button("생성") {
					model.createKey(name: name.trimmingCharacters(in: .whitespacesAndNewlines), passphrase: passphrase, mode: mode)
					clear()
					dismiss()
				}
				.buttonStyle(.borderedProminent)
				.keyboardShortcut(.defaultAction)
				.disabled(!canCreate)
			}
			.padding(.horizontal, 20)
			.padding(.vertical, 14)
		}
		.frame(width: 560, height: 640)
	}
}
