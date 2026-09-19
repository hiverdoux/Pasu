import Foundation
import ServiceManagement

// Invoke the installed GUI executable directly; no management window or Keychain
// entitlement is needed to register this app's bundled launch agent.
enum PasuServiceCommand {
    static func run(_ arguments: [String]) -> Int32 {
        guard arguments.count == 2, arguments[0] == "--service",
              Bundle.main.bundleIdentifier == PasuIdentity.guiID,
              Bundle.main.bundleURL.standardizedFileURL.path == "/Applications/Pasu.app",
              getuid() != 0 else {
            fputs("service: 설치된 Pasu GUI를 로그인 사용자로 실행하세요.\n", stderr)
            return 1
        }
        let service = SMAppService.agent(plistName: PasuIdentity.agentID + ".plist")
        do {
            switch arguments[1] {
            case "status": break
            case "register":
                if service.status == .notRegistered || service.status == .notFound { try service.register() }
            case "unregister":
                if service.status != .notRegistered { try service.unregister() }
            default:
                fputs("service: status, register, unregister 중 하나를 지정하세요.\n", stderr)
                return 1
            }
            switch service.status {
            case .enabled: print("enabled")
            case .notRegistered: print("notRegistered")
            case .requiresApproval: print("requiresApproval")
            case .notFound: print("notFound")
            @unknown default: print("unknown")
            }
            return 0
        } catch {
            fputs("service: \(error.localizedDescription)\n", stderr)
            return 1
        }
    }
}
