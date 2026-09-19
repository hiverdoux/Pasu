// Developer ID 앱 전용 Data Protection Keychain 저장소.
//
// v1은 passphrase와 설정 인증 키 K를 한 항목에, v2는 관리 정보와 키별 비밀을
// 별도 항목에 저장한다. 접근은 Apple 발급 프로파일의 앱 전용 그룹으로 제한한다.
// 관리 보호 항목은 Touch ID 또는 로그인 암호가 필요하며, v2의 인증 없음 키에는
// 화면 잠금 해제만 요구하는 별도 서명용 항목이 있다.

import Foundation
import LocalAuthentication
import Security

private let pasuKCService = PasuIdentity.keychainService
private let pasuKCAccount = "ssh-key-unlock-v1"
private let pasuKCAccessGroup = PasuIdentity.accessGroup

private func pasuKCQuery() -> [String: Any] {
	pasuKCQuery(account: pasuKCAccount)
}

private func pasuKCQuery(account: String) -> [String: Any] {
	[
		kSecClass as String: kSecClassGenericPassword,
		kSecAttrService as String: pasuKCService,
		kSecAttrAccount as String: account,
		kSecAttrAccessGroup as String: pasuKCAccessGroup,
		kSecUseDataProtectionKeychain as String: true,
	]
}

private func pasuKCAccountString(_ account: UnsafePointer<CChar>?) -> String? {
	guard let account else { return nil }
	let value = String(cString: account)
	guard !value.isEmpty, value.utf8.count <= 160 else { return nil }
	return value
}

private func pasuKCError(_ operation: String, _ status: OSStatus) -> String {
	let detail = SecCopyErrorMessageString(status, nil) as String? ?? "알 수 없는 오류"
	return "\(operation): OSStatus \(status) (\(detail))"
}

private func pasuKCWriteError(
	_ message: String,
	_ errorBuffer: UnsafeMutablePointer<CChar>?,
	_ errorLength: Int32
) -> Int32 {
	if let errorBuffer, errorLength > 0 {
		_ = message.withCString { strlcpy(errorBuffer, $0, Int(errorLength)) }
	}
	return 1
}

private func pasuKCCopyOut(
	_ data: Data,
	_ output: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
	_ outputLength: UnsafeMutablePointer<Int32>?
) -> Bool {
	guard let output, let outputLength else { return false }
	guard data.count <= Int(Int32.max), let buffer = malloc(max(data.count, 1)) else {
		return false
	}
	data.withUnsafeBytes { raw in
		if let baseAddress = raw.baseAddress, raw.count > 0 {
			memcpy(buffer, baseAddress, raw.count)
		}
	}
	output.pointee = buffer.assumingMemoryBound(to: UInt8.self)
	outputLength.pointee = Int32(data.count)
	return true
}

// 반환값은 SecItemCopyMatching의 OSStatus 원문이다.
// 정상 보호 항목이면 interactionNotAllowed(-25308), 항목이 없으면
// itemNotFound(-25300), entitlement 없는 ad-hoc 빌드는 -34018이 된다.
@_cdecl("pasuKCProbe")
public func pasuKCProbe() -> Int32 {
	var query = pasuKCQuery()
	query[kSecReturnData as String] = true
	query[kSecMatchLimit as String] = kSecMatchLimitOne
	let context = LAContext()
	context.interactionNotAllowed = true
	query[kSecUseAuthenticationContext as String] = context
	var result: CFTypeRef?
	let status = SecItemCopyMatching(query as CFDictionary, &result)
	if let data = result as? NSMutableData, data.length > 0 {
		data.resetBytes(in: NSRange(location: 0, length: data.length))
	}
	return status
}

@_cdecl("pasuKCRead")
public func pasuKCRead(
	_ reason: UnsafePointer<CChar>?,
	_ output: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
	_ outputLength: UnsafeMutablePointer<Int32>?,
	_ errorBuffer: UnsafeMutablePointer<CChar>?,
	_ errorLength: Int32
) -> Int32 {
	var query = pasuKCQuery()
	query[kSecReturnData as String] = true
	query[kSecMatchLimit as String] = kSecMatchLimitOne
	let context = LAContext()
	if let reason {
		context.localizedReason = String(cString: reason)
	}
	query[kSecUseAuthenticationContext as String] = context
	var result: CFTypeRef?
	let status = SecItemCopyMatching(query as CFDictionary, &result)
	guard status == errSecSuccess else {
		return pasuKCWriteError(pasuKCError("Keychain 읽기 실패", status), errorBuffer, errorLength)
	}
	guard let data = result as? Data, !data.isEmpty else {
		return pasuKCWriteError("Keychain 읽기 실패: 빈 데이터", errorBuffer, errorLength)
	}
	guard pasuKCCopyOut(data, output, outputLength) else {
		return pasuKCWriteError("Keychain 읽기 실패: 출력 버퍼 할당 실패", errorBuffer, errorLength)
	}
	// SecItemCopyMatching은 불변 CFData를 돌려줄 수 있어 Data.resetBytes를
	// 호출하면 copy-on-write 사본만 지워진다. 원본을 변조한다고 가장하지 않고
	// 이 함수 범위를 벗어나자마자 Foundation 소유 참조가 해제되게 둔다. C 출력
	// 버퍼와 Go 사본은 호출자가 명시적으로 0으로 덮는다.
	result = nil
	return 0
}

@_cdecl("pasuKCAdd")
public func pasuKCAdd(
	_ secret: UnsafePointer<UInt8>?,
	_ secretLength: Int32,
	_ errorBuffer: UnsafeMutablePointer<CChar>?,
	_ errorLength: Int32
) -> Int32 {
	guard let secret, secretLength > 0 else {
		return pasuKCWriteError("Keychain 추가 실패: 빈 secret", errorBuffer, errorLength)
	}
	var cfError: Unmanaged<CFError>?
	guard let access = SecAccessControlCreateWithFlags(
		nil,
		kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
		.userPresence,
		&cfError
	) else {
		let detail = cfError?.takeRetainedValue().localizedDescription ?? "알 수 없는 오류"
		return pasuKCWriteError("Keychain ACL 생성 실패: \(detail)", errorBuffer, errorLength)
	}
	let data = NSMutableData(bytes: secret, length: Int(secretLength))
	defer { data.resetBytes(in: NSRange(location: 0, length: data.length)) }
	var item = pasuKCQuery()
	item[kSecValueData as String] = data
	item[kSecAttrAccessControl as String] = access
	item[kSecAttrLabel as String] = "pasu SSH 키 잠금 해제"
	item[kSecAttrDescription as String] = "Developer ID 앱 전용 passphrase와 설정 결속 키"
	item[kSecAttrSynchronizable as String] = false
	let status = SecItemAdd(item as CFDictionary, nil)
	guard status == errSecSuccess else {
		return pasuKCWriteError(pasuKCError("Keychain 추가 실패", status), errorBuffer, errorLength)
	}
	return 0
}

@_cdecl("pasuKCUpdate")
public func pasuKCUpdate(
	_ secret: UnsafePointer<UInt8>?,
	_ secretLength: Int32,
	_ errorBuffer: UnsafeMutablePointer<CChar>?,
	_ errorLength: Int32
) -> Int32 {
	guard let secret, secretLength > 0 else {
		return pasuKCWriteError("Keychain 갱신 실패: 빈 secret", errorBuffer, errorLength)
	}
	let data = NSMutableData(bytes: secret, length: Int(secretLength))
	defer { data.resetBytes(in: NSRange(location: 0, length: data.length)) }
	let attributes: [String: Any] = [kSecValueData as String: data]
	let status = SecItemUpdate(pasuKCQuery() as CFDictionary, attributes as CFDictionary)
	guard status == errSecSuccess else {
		return pasuKCWriteError(pasuKCError("Keychain 갱신 실패", status), errorBuffer, errorLength)
	}
	return 0
}

@_cdecl("pasuKCDelete")
public func pasuKCDelete(
	_ errorBuffer: UnsafeMutablePointer<CChar>?,
	_ errorLength: Int32
) -> Int32 {
	let status = SecItemDelete(pasuKCQuery() as CFDictionary)
	guard status == errSecSuccess || status == errSecItemNotFound else {
		return pasuKCWriteError(pasuKCError("Keychain 삭제 실패", status), errorBuffer, errorLength)
	}
	return 0
}

// v2는 registry metadata와 키별 secret을 서로 다른 account에 저장한다.
// metadata는 앱 신원만으로 읽는다. 모든 키의 관리 보호 secret은 userPresence를
// 요구하고, 인증 없음 키의 추가 서명 secret은 WhenUnlockedThisDeviceOnly만 사용한다. 아래
// 함수들은 기존 v1 고정 account API를 그대로 보존하면서 account를 인자로 받는다.
@_cdecl("pasuKCV2Probe")
public func pasuKCV2Probe(_ account: UnsafePointer<CChar>?) -> Int32 {
	guard let account = pasuKCAccountString(account) else { return errSecParam }
	var query = pasuKCQuery(account: account)
	query[kSecReturnData as String] = true
	query[kSecMatchLimit as String] = kSecMatchLimitOne
	let context = LAContext()
	context.interactionNotAllowed = true
	context.touchIDAuthenticationAllowableReuseDuration = 0
	query[kSecUseAuthenticationContext as String] = context
	var result: CFTypeRef?
	let status = SecItemCopyMatching(query as CFDictionary, &result)
	if let data = result as? NSMutableData, data.length > 0 {
		data.resetBytes(in: NSRange(location: 0, length: data.length))
	}
	return status
}

@_cdecl("pasuKCV2Read")
public func pasuKCV2Read(
	_ accountPtr: UnsafePointer<CChar>?,
	_ reason: UnsafePointer<CChar>?,
	_ output: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
	_ outputLength: UnsafeMutablePointer<Int32>?,
	_ errorBuffer: UnsafeMutablePointer<CChar>?,
	_ errorLength: Int32
) -> Int32 {
	guard let account = pasuKCAccountString(accountPtr) else {
		return pasuKCWriteError("Keychain 읽기 실패: 잘못된 account", errorBuffer, errorLength)
	}
	var query = pasuKCQuery(account: account)
	query[kSecReturnData as String] = true
	query[kSecMatchLimit as String] = kSecMatchLimitOne
	let context = LAContext()
	context.touchIDAuthenticationAllowableReuseDuration = 0
	if let reason { context.localizedReason = String(cString: reason) }
	query[kSecUseAuthenticationContext as String] = context
	var result: CFTypeRef?
	let status = SecItemCopyMatching(query as CFDictionary, &result)
	guard status == errSecSuccess else {
		return pasuKCWriteError(pasuKCError("Keychain 읽기 실패", status), errorBuffer, errorLength)
	}
	guard let data = result as? Data, !data.isEmpty else {
		return pasuKCWriteError("Keychain 읽기 실패: 빈 데이터", errorBuffer, errorLength)
	}
	guard pasuKCCopyOut(data, output, outputLength) else {
		return pasuKCWriteError("Keychain 읽기 실패: 출력 버퍼 할당 실패", errorBuffer, errorLength)
	}
	result = nil
	return 0
}

@_cdecl("pasuKCV2Add")
public func pasuKCV2Add(
	_ accountPtr: UnsafePointer<CChar>?,
	_ secret: UnsafePointer<UInt8>?,
	_ secretLength: Int32,
	_ requirePresence: Int32,
	_ errorBuffer: UnsafeMutablePointer<CChar>?,
	_ errorLength: Int32
) -> Int32 {
	guard let account = pasuKCAccountString(accountPtr), let secret, secretLength > 0 else {
		return pasuKCWriteError("Keychain 추가 실패: 잘못된 account 또는 빈 secret", errorBuffer, errorLength)
	}
	let data = NSMutableData(bytes: secret, length: Int(secretLength))
	defer { data.resetBytes(in: NSRange(location: 0, length: data.length)) }
	var item = pasuKCQuery(account: account)
	let isSecret = account.hasPrefix("key-secret-v2:") || account.hasPrefix("key-secret-v2-unattended:")
	item[kSecValueData as String] = data
	item[kSecAttrLabel as String] = isSecret ? "Pasu SSH 키 secret" : "Pasu v2 키 registry"
	item[kSecAttrDescription as String] = isSecret ? "키별 passphrase와 지문" : "키 목록, 상태와 정확 사슬 정책"
	item[kSecAttrSynchronizable as String] = false
	if requirePresence != 0 {
		var cfError: Unmanaged<CFError>?
		guard let access = SecAccessControlCreateWithFlags(
			nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .userPresence, &cfError
		) else {
			let detail = cfError?.takeRetainedValue().localizedDescription ?? "알 수 없는 오류"
			return pasuKCWriteError("Keychain ACL 생성 실패: \(detail)", errorBuffer, errorLength)
		}
		item[kSecAttrAccessControl as String] = access
	} else {
		item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
	}
	let status = SecItemAdd(item as CFDictionary, nil)
	guard status == errSecSuccess else {
		return pasuKCWriteError(pasuKCError("Keychain 추가 실패", status), errorBuffer, errorLength)
	}
	return 0
}

@_cdecl("pasuKCV2Update")
public func pasuKCV2Update(
	_ accountPtr: UnsafePointer<CChar>?,
	_ secret: UnsafePointer<UInt8>?,
	_ secretLength: Int32,
	_ errorBuffer: UnsafeMutablePointer<CChar>?,
	_ errorLength: Int32
) -> Int32 {
	guard let account = pasuKCAccountString(accountPtr), let secret, secretLength > 0 else {
		return pasuKCWriteError("Keychain 갱신 실패: 잘못된 account 또는 빈 secret", errorBuffer, errorLength)
	}
	let data = NSMutableData(bytes: secret, length: Int(secretLength))
	defer { data.resetBytes(in: NSRange(location: 0, length: data.length)) }
	let status = SecItemUpdate(
		pasuKCQuery(account: account) as CFDictionary,
		[kSecValueData as String: data] as CFDictionary
	)
	guard status == errSecSuccess else {
		return pasuKCWriteError(pasuKCError("Keychain 갱신 실패", status), errorBuffer, errorLength)
	}
	return 0
}

@_cdecl("pasuKCV2Delete")
public func pasuKCV2Delete(
	_ accountPtr: UnsafePointer<CChar>?,
	_ errorBuffer: UnsafeMutablePointer<CChar>?,
	_ errorLength: Int32
) -> Int32 {
	guard let account = pasuKCAccountString(accountPtr) else {
		return pasuKCWriteError("Keychain 삭제 실패: 잘못된 account", errorBuffer, errorLength)
	}
	let status = SecItemDelete(pasuKCQuery(account: account) as CFDictionary)
	guard status == errSecSuccess || status == errSecItemNotFound else {
		return pasuKCWriteError(pasuKCError("Keychain 삭제 실패", status), errorBuffer, errorLength)
	}
	return 0
}
