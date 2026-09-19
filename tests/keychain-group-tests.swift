import Foundation
import Security

@main
enum KeychainGroupTests {
    static func main() throws {
        let old = "AYTVXW6P5Q.com.dennis.pasu"
        let new = "AYTVXW6P5Q.com.dennis.pasu.agent"
        let accounts = ["registry-v2", "key-secret-v2:00000000-0000-4000-8000-000000000001"].sorted()
        var store = [old: accounts, new: [String]()]
        var updates = 0
        func move(_ reverse: Bool = false, status: OSStatus = errSecSuccess) throws {
            try movePasuGroup(reverse: reverse, expected: accounts, inventory: { store[$0]! }) { source, target, account in
                updates += 1
                if status == errSecSuccess { store[target]!.append(account); store[target]!.sort(); store[source]!.removeAll { $0 == account } }
                return status
            }
        }
        try move()
        precondition(store[new] == accounts && store[old] == [] && updates == 2)
        try move()
        precondition(updates == 2) // Resume after an already-completed move.
        try move(true)
        precondition(store[old] == accounts && store[new] == [])
        store[new] = ["registry-v2"]
        let beforeConflict = updates
        do { try move(); fatalError("mixed stores accepted") } catch {}
        precondition(updates == beforeConflict)
        store[new] = []
        do { try move(status: errSecAuthFailed); fatalError("authentication failure ignored") } catch {}
        precondition(store[old] == accounts && store[new] == [])
        do {
            try movePasuGroup(reverse: false, expected: accounts, inventory: { store[$0]! }, update: { _, _, _ in errSecSuccess })
            fatalError("postcondition not verified")
        } catch {}
        store[old] = []
        do { try move(); fatalError("empty stores accepted") } catch {}
        let valid = accounts.map { [kSecAttrAccount as String: $0] as [String: Any] }
        let validated = try validatedPasuGroupAccounts(valid)
        precondition(validated == accounts)
        for items in [valid + valid, [[kSecAttrAccount as String: "unrelated"]], [[kSecAttrAccount as String: "key-secret-v2:invalid"]]] {
            do { _ = try validatedPasuGroupAccounts(items); fatalError("invalid inventory accepted") } catch {}
        }
        // Resume an interruption after one secret has moved, registry remains old.
        store = [old: ["registry-v2"], new: accounts.filter { $0 != "registry-v2" }]
        try move()
        precondition(store[new] == accounts && store[old] == [])
        // A later-item failure must restore earlier moves.
        store = [old: accounts, new: []]
        do {
            try movePasuGroup(reverse: false, expected: accounts, inventory: { store[$0]! }) { source, target, account in
                if source == old && account == "registry-v2" { return errSecAuthFailed }
                store[target]!.append(account); store[target]!.sort()
                store[source]!.removeAll { $0 == account }
                return errSecSuccess
            }
            fatalError("mid-move failure ignored")
        } catch {}
        precondition(store[old] == accounts && store[new] == [])
        print("Keychain group transition tests passed (synthetic data only)")
    }
}
