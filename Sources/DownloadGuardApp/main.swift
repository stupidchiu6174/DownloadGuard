import AppKit
import DownloadGuard

// 單獨執行下載掃描的視窗
let app = NSApplication.shared
app.setActivationPolicy(.regular)
MainActor.assumeIsolated {
    DownloadGuardController.shared.restore()
    DownloadGuardWindowController.shared.show()
}
app.run()
