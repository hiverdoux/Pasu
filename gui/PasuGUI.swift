import AppKit
import SwiftUI

// 배포 GUI 진입점. Keychain entitlement가 없으며 control socket으로만 agent와
// 대화한다. 미리보기 빌드(-D PASU_PREVIEW)는 Preview.swift의 진입점을 대신 쓴다.

final class PasuApplicationDelegate: NSObject, NSApplicationDelegate {
	func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

#if !PASU_PREVIEW
struct PasuGUIApp: App {
	@NSApplicationDelegateAdaptor(PasuApplicationDelegate.self) private var appDelegate
	@StateObject private var model = PasuModel()

	var body: some Scene {
		WindowGroup {
			ContentView(model: model)
		}
		.commands { CommandGroup(replacing: .newItem) {} }
	}
}

@main
enum PasuEntry {
    static func main() {
        let arguments = Array(CommandLine.arguments.dropFirst())
        if arguments == ["--build-identity"] {
            print(PasuIdentity.teamID, PasuIdentity.guiID, PasuIdentity.agentID)
            exit(0)
        }
        if arguments.first == "--service" {
            exit(PasuServiceCommand.run(arguments))
        }
        PasuGUIApp.main()
    }
}
#endif
