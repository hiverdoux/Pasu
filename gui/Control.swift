import Darwin
import Foundation
import Security

// control socket 프로토콜과 상호 인증 클라이언트. GUI는 이 채널로만 agent와
// 대화하며 개인키·signer는 절대 오가지 않는다.

let controlProtocolVersion = 2
let pasuHomeDirectory = FileManager.default.homeDirectoryForCurrentUser
let controlSocketPath = pasuHomeDirectory.appending(path: ".ssh/pasu/control.sock").path
let agentSocketPath = pasuHomeDirectory.appending(path: ".ssh/pasu/agent.sock").path
let auditLogPath = pasuHomeDirectory.appending(path: ".ssh/pasu/profiles/\(PasuIdentity.teamID).\(PasuIdentity.guiID)/pasu.log").path
let expectedAgentTeam = PasuIdentity.teamID
let expectedAgentIdentifier = PasuIdentity.agentID
let expectedAgentPath = "/Applications/Pasu.app/Contents/Library/LoginItems/PasuAgent.app/Contents/MacOS/pasu"
let maxControlMessage = 1 << 20

struct CodeIdentity: Codable, Hashable {
	let kind: String
	let teamId: String?
	let identifier: String
}

struct StableProcess: Codable, Hashable, Identifiable {
	var id: String { "\(path)|\(uid)|\(identity.kind)|\(identity.teamId ?? "")|\(identity.identifier)" }
	let path: String
	let uid: UInt32
	let identity: CodeIdentity
}

struct StableChain: Codable, Hashable {
	let tty: String
	let members: [StableProcess]
}

struct ChainRule: Codable, Hashable, Identifiable {
	let id: String
	let decision: String
	let chain: StableChain
	let createdAt: String
	let lastUsed: String?
}

struct KeyView: Codable, Hashable, Identifiable {
	let id: String
	let name: String
	let fingerprint: String
	let publicKey: String
	let publicKeyPath: String
	let authMode: String
	var chainCheckMode: String? = nil
	let enabled: Bool
	let unlocked: Bool
	let createdAt: String
	let lastUsed: String?
	let rules: [ChainRule]
}

struct ControlRequest: Codable {
	let version: Int
	let action: String
	var keyId: String? = nil
	var ruleId: String? = nil
	var name: String? = nil
	var passphrase: String? = nil
	var authMode: String? = nil
	var chainCheckMode: String? = nil
	var enabled: Bool? = nil
	var limit: Int? = nil
}

struct ControlResponse: Codable {
	let version: Int
	let ok: Bool
	let error: String?
	let keys: [KeyView]?
	let migrationPending: Bool?
	let logs: [String]?
	let trashPath: String?
	let agentVersion: String?
	let startedAt: String?
}

enum ControlError: LocalizedError {
	case message(String)

	var errorDescription: String? {
		switch self {
		case let .message(value): value
		}
	}
}

typealias ControlTransport = @Sendable (ControlRequest) throws -> ControlResponse

private func verifyAgent(fd: Int32) throws {
	var token = audit_token_t()
	var length = socklen_t(MemoryLayout<audit_token_t>.size)
	guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &length) == 0,
		length == MemoryLayout<audit_token_t>.size
	else {
		throw ControlError.message("agent audit token을 읽지 못했습니다.")
	}
	let peerPID = audit_token_to_pid(token)
	var pathBuffer = [CChar](repeating: 0, count: 4096)
	guard proc_pidpath(peerPID, &pathBuffer, UInt32(pathBuffer.count)) > 0,
		String(cString: pathBuffer) == expectedAgentPath
	else {
		throw ControlError.message("연결된 agent의 실행 경로가 정식 설치 경로가 아닙니다.")
	}
	let tokenData = withUnsafeBytes(of: &token) { Data($0) } as CFData
	let attrs = [kSecGuestAttributeAudit: tokenData] as CFDictionary
	var code: SecCode?
	let copyStatus = SecCodeCopyGuestWithAttributes(nil, attrs, [], &code)
	guard copyStatus == errSecSuccess, let code else {
		throw ControlError.message("agent 코드 신원을 찾지 못했습니다: \(copyStatus)")
	}
	let requirementText = "anchor apple generic and identifier \"\(expectedAgentIdentifier)\" and " +
		"certificate 1[field.1.2.840.113635.100.6.2.6] and " +
		"certificate leaf[field.1.2.840.113635.100.6.1.13] and " +
		"certificate leaf[subject.OU] = \"\(expectedAgentTeam)\""
	var requirement: SecRequirement?
	let requirementStatus = SecRequirementCreateWithString(requirementText as CFString, [], &requirement)
	guard requirementStatus == errSecSuccess, let requirement else {
		throw ControlError.message("agent 검증 requirement를 만들지 못했습니다.")
	}
	let validation = SecCodeCheckValidity(code, [], requirement)
	guard validation == errSecSuccess else {
		throw ControlError.message("연결된 프로세스가 정식 Pasu agent가 아닙니다: \(validation)")
	}
}

private func connectControlSocket() throws -> Int32 {
	let fd = socket(AF_UNIX, SOCK_STREAM, 0)
	guard fd >= 0 else { throw ControlError.message("control socket을 만들지 못했습니다.") }
	var address = sockaddr_un()
	address.sun_family = sa_family_t(AF_UNIX)
	let pathBytes = Array(controlSocketPath.utf8CString)
	guard pathBytes.count <= MemoryLayout.size(ofValue: address.sun_path) else {
		close(fd)
		throw ControlError.message("control socket 경로가 너무 깁니다.")
	}
	withUnsafeMutableBytes(of: &address.sun_path) { raw in
		raw.initializeMemory(as: UInt8.self, repeating: 0)
		for (index, byte) in pathBytes.enumerated() { raw[index] = UInt8(bitPattern: byte) }
	}
	let result = withUnsafePointer(to: &address) { pointer in
		pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
			connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
		}
	}
	guard result == 0 else {
		let detail = String(cString: strerror(errno))
		close(fd)
		throw ControlError.message("Pasu agent에 연결하지 못했습니다: \(detail)")
	}
	try verifyAgent(fd: fd)
	return fd
}

private func writeAll(fd: Int32, data: Data) throws {
	try data.withUnsafeBytes { raw in
		guard var pointer = raw.baseAddress else { return }
		var remaining = raw.count
		while remaining > 0 {
			let count = Darwin.write(fd, pointer, remaining)
			guard count > 0 else { throw ControlError.message("control 요청 전송 실패") }
			pointer = pointer.advanced(by: count)
			remaining -= count
		}
	}
}

private func readResponse(fd: Int32) throws -> Data {
	var data = Data()
	var buffer = [UInt8](repeating: 0, count: 4096)
	while data.count <= maxControlMessage {
		let count = Darwin.read(fd, &buffer, buffer.count)
		if count < 0 { throw ControlError.message("control 응답 읽기 실패") }
		if count == 0 { break }
		data.append(buffer, count: count)
		if data.last == 0x0A { break }
	}
	guard data.count <= maxControlMessage else {
		throw ControlError.message("control 응답이 안전 크기 한도를 넘었습니다.")
	}
	return data
}

@Sendable
func sendControl(_ request: ControlRequest) throws -> ControlResponse {
	let encoder = JSONEncoder()
	encoder.keyEncodingStrategy = .convertToSnakeCase
	var payload = try encoder.encode(request)
	payload.append(0x0A)
	guard payload.count <= maxControlMessage else {
		throw ControlError.message("control 요청이 안전 크기 한도를 넘었습니다.")
	}
	let fd = try connectControlSocket()
	defer { close(fd) }
	try writeAll(fd: fd, data: payload)
	shutdown(fd, SHUT_WR)
	let data = try readResponse(fd: fd)
	let decoder = JSONDecoder()
	decoder.keyDecodingStrategy = .convertFromSnakeCase
	let response = try decoder.decode(ControlResponse.self, from: data)
	guard response.version == controlProtocolVersion else {
		throw ControlError.message("agent control protocol version이 다릅니다.")
	}
	guard response.ok else {
		throw ControlError.message(response.error ?? "Pasu agent 요청 실패")
	}
	return response
}
