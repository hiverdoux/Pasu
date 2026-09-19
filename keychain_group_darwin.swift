import Foundation
import Security
import LocalAuthentication

// The bridge is built separately and never shipped in the final app. It can
// change only Pasu's two fixed groups, without exporting any secret bytes.
private let oldPasuGroup = "AYTVXW6P5Q.com.dennis.pasu"
private let newPasuGroup = "AYTVXW6P5Q.com.dennis.pasu.agent"

private func groupQuery(_ group: String) -> [String: Any] {
    [kSecClass as String: kSecClassGenericPassword,
     kSecUseDataProtectionKeychain as String: true,
     kSecAttrAccessGroup as String: group,
     kSecAttrService as String: "com.dennis.pasu",
     kSecAttrSynchronizable as String: false]
}

private func groupContext() throws -> LAContext {
    let context = LAContext()
    context.touchIDAuthenticationAllowableReuseDuration = 0
    context.localizedReason = "Pasu 키체인 접근 그룹 이전·항목 확인"
    // A bulk protected-item query may return interactionNotAllowed without
    // presenting UI. Authenticate this management operation explicitly first.
    let completed = DispatchSemaphore(value: 0)
    var accepted = false
    context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: context.localizedReason) { success, _ in
        accepted = success
        completed.signal()
    }
    completed.wait()
    guard accepted else { throw GroupError.status(errSecUserCanceled) }
    return context
}

private func groupInventory(_ group: String, context: LAContext) throws -> [String] {
    var query = groupQuery(group)
    query[kSecReturnAttributes as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitAll
    query[kSecUseAuthenticationContext as String] = context
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound { return [] }
    guard status == errSecSuccess else { throw GroupError.status(status) }
    guard let items = result as? [[String: Any]], items.count <= 4096 else {
        throw GroupError.invalid
    }
    return try validatedPasuGroupAccounts(items)
}

func validatedPasuGroupAccounts(_ items: [[String: Any]]) throws -> [String] {
    let accounts = try items.map { item -> String in
        guard let account = item[kSecAttrAccount as String] as? String else { throw GroupError.invalid }
        if account == "registry-v2" || account == "ssh-key-unlock-v1" { return account }
        for prefix in ["key-secret-v2:", "key-secret-v2-unattended:"] {
            if account.hasPrefix(prefix), UUID(uuidString: String(account.dropFirst(prefix.count))) != nil {
                return account
            }
        }
        throw GroupError.invalid
    }
    guard Set(accounts).count == accounts.count else { throw GroupError.invalid }
    return accounts.sorted()
}

private enum GroupError: Error { case status(OSStatus), invalid, conflict, rollbackFailed }

// Diagnose access to existing, separately-created secrets before attempting an
// update. Only the current item's ACL is evaluated; no protection is replaced.
private func verifyGroupAccess(_ group: String, context: LAContext) throws {
    let accounts = try groupInventory(group, context: context)
    for account in accounts {
        var query = groupQuery(group)
        query[kSecAttrAccount as String] = account
        query[kSecUseAuthenticationContext as String] = context
        query[kSecReturnAttributes as String] = true
        var attributes: CFTypeRef?
        let attributeStatus = SecItemCopyMatching(query as CFDictionary, &attributes)
        guard attributeStatus == errSecSuccess else { throw GroupError.status(attributeStatus) }
        if let dict = attributes as? [String: Any], let access = dict[kSecAttrAccessControl as String] {
            let done = DispatchSemaphore(value: 0)
            var allowed = false
            context.evaluateAccessControl(access as! SecAccessControl, operation: .useItem,
                                          localizedReason: "Pasu 기존 키체인 항목 접근 확인") { ok, _ in
                allowed = ok; done.signal()
            }
            done.wait()
            guard allowed else { throw GroupError.status(errSecAuthFailed) }
        }
        query.removeValue(forKey: kSecReturnAttributes as String)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var secret: CFTypeRef?
        let readStatus = SecItemCopyMatching(query as CFDictionary, &secret)
        if let data = secret as? NSMutableData { data.resetBytes(in: NSRange(location: 0, length: data.length)) }
        secret = nil
        guard readStatus == errSecSuccess else { throw GroupError.status(readStatus) }
    }
}

@_cdecl("pasuKCVerifyOldGroup")
public func pasuKCVerifyOldGroup(_ buffer: UnsafeMutablePointer<CChar>?, _ length: Int32) -> Int32 {
#if PASU_KEYCHAIN_MIGRATION
    do {
        try verifyGroupAccess(oldPasuGroup, context: groupContext())
        return 0
    } catch { return groupError(error, buffer, length) }
#else
    return groupError(GroupError.status(errSecMissingEntitlement), buffer, length)
#endif
}

private func groupError(_ error: Error, _ buffer: UnsafeMutablePointer<CChar>?, _ length: Int32) -> Int32 {
    let message: String
    switch error {
    case GroupError.status(let status): message = "Keychain 그룹 작업 실패: OSStatus \(status)"
    case GroupError.conflict: message = "키체인 항목이 중복되거나 registry 목록과 일치하지 않습니다. 변경하지 않습니다."
    case GroupError.rollbackFailed: message = "항목별 이전 중 복원 실패: 두 그룹의 항목을 보존했습니다. agent를 시작하지 말고 이전·복원을 재개하세요."
    default: message = "Pasu Keychain 항목 목록 검증 실패. 변경하지 않습니다."
    }
    if let buffer, length > 0 { _ = message.withCString { strlcpy(buffer, $0, Int(length)) } }
    return 1
}

@_cdecl("pasuKCGroupBridgeEnabled")
public func pasuKCGroupBridgeEnabled() -> Int32 {
#if PASU_KEYCHAIN_MIGRATION
    return 1
#else
    return 0
#endif
}

@_cdecl("pasuKCGroupCounts")
public func pasuKCGroupCounts(_ oldCount: UnsafeMutablePointer<Int32>?, _ newCount: UnsafeMutablePointer<Int32>?,
                             _ buffer: UnsafeMutablePointer<CChar>?, _ length: Int32) -> Int32 {
#if PASU_KEYCHAIN_MIGRATION
    do {
        let context = try groupContext()
        oldCount?.pointee = Int32(try groupInventory(oldPasuGroup, context: context).count)
        newCount?.pointee = Int32(try groupInventory(newPasuGroup, context: context).count)
        return 0
    } catch { return groupError(error, buffer, length) }
#else
    return groupError(GroupError.status(errSecMissingEntitlement), buffer, length)
#endif
}

@_cdecl("pasuKCMoveGroup")
public func pasuKCMoveGroup(_ reverse: Int32, _ buffer: UnsafeMutablePointer<CChar>?, _ length: Int32) -> Int32 {
#if PASU_KEYCHAIN_MIGRATION
    do {
        let context = try groupContext()
        try verifyGroupAccess(reverse == 0 ? oldPasuGroup : newPasuGroup, context: context)
        let expected = try expectedGroupAccounts(context: context)
        try movePasuGroup(reverse: reverse != 0, expected: expected,
                          inventory: { try groupInventory($0, context: context) }) { source, target, account in
            var query = groupQuery(source)
            query[kSecAttrAccount as String] = account
            query[kSecUseAuthenticationContext as String] = context
            let status = SecItemUpdate(query as CFDictionary,
                                       [kSecAttrAccessGroup as String: target] as CFDictionary)
            if status != errSecSuccess { fputs("KEYCHAIN-GROUP update status=\(status)\n", stderr) }
            return status
        }
        return 0
    } catch { return groupError(error, buffer, length) }
#else
    return groupError(GroupError.status(errSecMissingEntitlement), buffer, length)
#endif
}

// The authoritative registry supplies the full expected set. A split store is
// resumable only when every expected account exists exactly once in the union.
private func expectedGroupAccounts(context: LAContext) throws -> [String] {
    let old = try groupInventory(oldPasuGroup, context: context)
    let new = try groupInventory(newPasuGroup, context: context)
    guard old.contains("registry-v2") != new.contains("registry-v2") else { throw GroupError.conflict }
    var query = groupQuery(old.contains("registry-v2") ? oldPasuGroup : newPasuGroup)
    query[kSecAttrAccount as String] = "registry-v2"
    query[kSecReturnData as String] = true
    query[kSecUseAuthenticationContext as String] = context
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess else { throw GroupError.status(status) }
    guard let data = result as? Data, data.count <= 1024 * 1024,
          let registry = try JSONSerialization.jsonObject(with: data) as? [String: Any],
          registry["version"] as? Int == 2 else { throw GroupError.invalid }
    let keys = registry["keys"] as? [[String: Any]] ?? []
    var expected = ["registry-v2"]
    for key in keys {
        guard let id = key["id"] as? String, UUID(uuidString: id) != nil,
              let mode = key["auth_mode"] as? String, ["cached", "per-sign", "none"].contains(mode) else { throw GroupError.invalid }
        expected.append("key-secret-v2:" + id)
        if mode == "none" { expected.append("key-secret-v2-unattended:" + id) }
    }
    if old.contains("ssh-key-unlock-v1") || new.contains("ssh-key-unlock-v1") { expected.append("ssh-key-unlock-v1") }
    return expected.sorted()
}

func movePasuGroup(reverse: Bool, expected: [String], inventory: (String) throws -> [String],
                   update: (String, String, String) -> OSStatus) throws {
    let source = reverse ? newPasuGroup : oldPasuGroup
    let target = reverse ? oldPasuGroup : newPasuGroup
    let before = try inventory(source)
    let destination = try inventory(target)
    guard expected.contains("registry-v2"), Set(expected).count == expected.count,
          Set(before).isDisjoint(with: Set(destination)),
          (before + destination).sorted() == expected.sorted() else { throw GroupError.conflict }
    var moved: [String] = []
    do {
        // Keep the registry as the completion marker and move it last.
        let ordered = before.filter { $0 != "registry-v2" }.sorted() + before.filter { $0 == "registry-v2" }
        for account in ordered {
            let status = update(source, target, account)
            guard status == errSecSuccess else { throw GroupError.status(status) }
            moved.append(account)
        }
        guard try inventory(source).isEmpty, try inventory(target).sorted() == expected.sorted() else { throw GroupError.invalid }
    } catch {
        for account in moved.reversed() {
            guard update(target, source, account) == errSecSuccess else { throw GroupError.rollbackFailed }
        }
        guard try inventory(source) == before, try inventory(target) == destination else { throw GroupError.rollbackFailed }
        throw error
    }
}
