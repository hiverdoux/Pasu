import Foundation
import Security
import LocalAuthentication

// Signed diagnostic: isolated synthetic service, never production Pasu items.
let oldGroup = "AYTVXW6P5Q.com.dennis.pasu"
let newGroup = "AYTVXW6P5Q.com.dennis.pasu.agent"
let service = "com.dennis.pasu.migration-test." + UUID().uuidString
var context = LAContext()
context.touchIDAuthenticationAllowableReuseDuration = 0
func waitAuth(_ evaluate: (@escaping (Bool, Error?) -> Void) -> Void) -> Bool {
    let done = DispatchSemaphore(value: 0)
    var success = false
    evaluate { ok, _ in success = ok; done.signal() }
    done.wait()
    return success
}
func query(_ group: String, _ account: String) -> [String: Any] {
    [kSecClass as String: kSecClassGenericPassword,
     kSecUseDataProtectionKeychain as String: true,
     kSecAttrService as String: service,
     kSecAttrAccessGroup as String: group,
     kSecAttrAccount as String: account,
     kSecAttrSynchronizable as String: false,
     kSecUseAuthenticationContext as String: context]
}
let authenticated = waitAuth { reply in
    context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Pasu 합성 데이터 그룹 이전 진단", reply: reply)
}
guard authenticated else { print("authentication cancelled"); exit(1) }
for mode in ["plain", "protected-policy", "protected-access-control"] {
    defer {
        for group in [oldGroup, newGroup] {
            let status = SecItemDelete(query(group, mode) as CFDictionary)
            print("cleanup \(mode) \(group == oldGroup ? "old" : "new") status=\(status)")
        }
    }
    var item = query(oldGroup, mode)
    item[kSecValueData as String] = Data("synthetic sample".utf8)
    if mode == "plain" {
        item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    } else {
        var error: Unmanaged<CFError>?
        let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .userPresence, &error)!
        item[kSecAttrAccessControl as String] = access
    }
    let add = SecItemAdd(item as CFDictionary, nil)
    print("add \(mode) status=\(add)")
    guard add == errSecSuccess else { continue }
    if mode == "protected-access-control" {
        var attributesQuery = query(oldGroup, mode)
        attributesQuery[kSecReturnAttributes as String] = true
        var attributes: CFTypeRef?
        let status = SecItemCopyMatching(attributesQuery as CFDictionary, &attributes)
        print("attributes status=\(status)")
        if status == errSecSuccess, let dict = attributes as? [String: Any], let access = dict[kSecAttrAccessControl as String] {
            let ok = waitAuth { reply in
                context.evaluateAccessControl(access as! SecAccessControl, operation: .useItem,
                                              localizedReason: "Pasu 합성 보호 항목 이전 진단", reply: reply)
            }
            print("access-control authenticated=\(ok)")
        }
    }
    let update = SecItemUpdate(query(oldGroup, mode) as CFDictionary,
                               [kSecAttrAccessGroup as String: newGroup] as CFDictionary)
    print("move \(mode) status=\(update)")
}

// Repeat the production-shaped query: metadata + two userPresence secrets,
// one update selected by service/group rather than by account.
for account in ["batch-registry", "batch-secret-1", "batch-secret-2"] {
    var item = query(oldGroup, account)
    item.removeValue(forKey: kSecUseAuthenticationContext as String)
    item[kSecValueData as String] = Data("synthetic batch".utf8)
    if account == "batch-registry" {
        item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    } else {
        var error: Unmanaged<CFError>?
        item[kSecAttrAccessControl as String] = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .userPresence, &error)!
    }
    print("batch add \(account) status=\(SecItemAdd(item as CFDictionary, nil))")
}
context = LAContext()
context.touchIDAuthenticationAllowableReuseDuration = 0
let batchAuthenticated = waitAuth { reply in
    context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Pasu 합성 기존 항목 일괄 이전 진단", reply: reply)
}
print("fresh batch authentication=\(batchAuthenticated)")
var bulk = query(oldGroup, "")
bulk.removeValue(forKey: kSecAttrAccount as String)
print("batch move status=\(SecItemUpdate(bulk as CFDictionary, [kSecAttrAccessGroup as String: newGroup] as CFDictionary))")
for account in ["batch-registry", "batch-secret-1", "batch-secret-2"] {
    for group in [oldGroup, newGroup] {
        print("batch cleanup \(account) \(group == oldGroup ? "old" : "new") status=\(SecItemDelete(query(group, account) as CFDictionary))")
    }
}
