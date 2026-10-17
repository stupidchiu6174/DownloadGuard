import Foundation
import CryptoKit

/// 收集一個下載檔的客觀資料。全程不執行、不打開檔案:
/// 只讀位元組、讀延伸屬性、跑 Apple 的檢查工具(codesign / spctl / hdiutil 唯讀掛載 / zipinfo)。
public enum FileInspector {

    static let mediaExts: Set<String> = ["jpg", "jpeg", "png", "gif", "heic", "heif", "webp", "tif", "tiff", "bmp",
                                         "svg", "mp4", "mov", "m4v", "mkv", "avi", "webm", "mp3", "m4a", "wav",
                                         "aac", "flac", "aif", "aiff", "ogg", "opus"]
    static let documentExts: Set<String> = ["pdf", "txt", "md", "rtf", "csv", "json", "yaml", "yml", "xml",
                                            "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pages", "numbers",
                                            "key", "epub", "srt", "ttf", "otf", "vrm", "vroid", "fbx", "obj",
                                            "glb", "gltf", "blend", "psd", "kra", "unitypackage"]
    static let scriptExts: Set<String> = ["sh", "command", "tool", "zsh", "bash", "py", "pl", "rb", "scpt",
                                          "applescript", "scptd", "jxa", "terminal", "workflow", "js", "jar"]
    static let diskImageExts: Set<String> = ["dmg", "iso", "img", "sparseimage", "sparsebundle", "cdr"]
    static let packageExts: Set<String> = ["pkg", "mpkg"]
    static let archiveExts: Set<String> = ["zip", "tar", "gz", "tgz", "bz2", "xz", "7z", "rar", "zst"]

    static let maxListing = 300

    public static func inspect(_ url: URL) -> FileFacts {
        let path = url.path
        let name = url.lastPathComponent
        let ext = url.pathExtension.lowercased()
        var isDir: ObjCBool = false
        FileManager.default.fileExists(atPath: path, isDirectory: &isDir)

        var facts = FileFacts(path: path, name: name, ext: ext, size: 0, sha256: nil,
                              fileType: isDir.boolValue ? "directory" : "", category: .other,
                              disguised: false, quarantine: xattrString(path, "com.apple.quarantine"),
                              whereFroms: whereFroms(path), signature: nil, contents: nil,
                              nestedSignatures: nil)

        if isDir.boolValue {
            facts.size = directorySize(url)
            facts.category = ext == "app" ? .appBundle : (diskImageExts.contains(ext) ? .diskImage : .folder)
            facts.contents = listDirectory(url)
            if facts.category == .appBundle {
                facts.signature = signature(of: path, kind: .exec)
            } else {
                facts.nestedSignatures = nestedAppSignatures(in: url, listing: facts.contents ?? [])
            }
            return facts
        }

        facts.size = (try? FileManager.default.attributesOfItem(atPath: path)[.size] as? Int64) ?? 0
        facts.sha256 = sha256(of: url)
        let type = Shell.run("/usr/bin/file", ["-b", path], timeout: 10)
        facts.fileType = type.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        facts.category = category(ext: ext, fileType: facts.fileType, head: head(url, 4))
        let looksHarmless = mediaExts.contains(ext) || documentExts.contains(ext)
        facts.disguised = looksHarmless && (facts.category == .executable || facts.category == .script)

        switch facts.category {
        case .executable:
            facts.signature = signature(of: path, kind: .exec)
        case .installerPackage:
            facts.signature = packageSignature(path)
            let listing = Shell.run("/usr/bin/xar", ["-tf", path], timeout: 20)
            facts.contents = lines(listing.stdout)
        case .diskImage:
            facts.signature = signature(of: path, kind: .open)
            inspectDiskImage(url, into: &facts)
        case .archive:
            facts.contents = archiveListing(url, ext: ext)
        default:
            break
        }
        return facts
    }

    // MARK: - 分類

    static func category(ext: String, fileType: String, head: Data) -> FileCategory {
        let t = fileType.lowercased()
        if t.contains("mach-o") { return .executable }
        if head.starts(with: [0x23, 0x21]) { return .script }            // "#!"
        if t.contains("script") && !t.contains("postscript") { return .script }
        if t.contains("applescript") { return .script }
        if packageExts.contains(ext) || t.contains("xar archive") { return .installerPackage }
        if diskImageExts.contains(ext) { return .diskImage }
        if scriptExts.contains(ext) { return .script }
        if archiveExts.contains(ext) || t.contains("zip archive") || t.contains("gzip") || t.contains("tar archive")
            || t.contains("7-zip") || t.contains("rar archive") { return .archive }
        if mediaExts.contains(ext) { return .media }
        if documentExts.contains(ext) { return .document }
        return .other
    }

    // MARK: - 延伸屬性

    static func xattrData(_ path: String, _ name: String) -> Data? {
        let size = getxattr(path, name, nil, 0, 0, 0)
        guard size > 0 else { return nil }
        var buf = [UInt8](repeating: 0, count: size)
        let read = getxattr(path, name, &buf, size, 0, 0)
        guard read > 0 else { return nil }
        return Data(buf.prefix(read))
    }

    static func xattrString(_ path: String, _ name: String) -> String? {
        xattrData(path, name).map { String(decoding: $0, as: UTF8.self) }
    }

    static func whereFroms(_ path: String) -> [String] {
        guard let data = xattrData(path, "com.apple.metadata:kMDItemWhereFroms"),
              let list = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String]
        else { return [] }
        return list
    }

    // MARK: - 雜湊與內容

    static func sha256(of url: URL) -> String? {
        guard let h = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? h.close() }
        var hasher = SHA256()
        while let chunk = try? h.read(upToCount: 4 << 20), !chunk.isEmpty { hasher.update(data: chunk) }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    static func head(_ url: URL, _ count: Int) -> Data {
        guard let h = try? FileHandle(forReadingFrom: url) else { return Data() }
        defer { try? h.close() }
        return (try? h.read(upToCount: count)) ?? Data()
    }

    static func lines(_ text: String) -> [String] {
        Array(text.split(separator: "\n").map(String.init).prefix(maxListing))
    }

    static func directorySize(_ url: URL) -> Int64 {
        var total: Int64 = 0
        let e = FileManager.default.enumerator(at: url, includingPropertiesForKeys: [.fileSizeKey])
        var n = 0
        while let f = e?.nextObject() as? URL, n < 20_000 {
            total += Int64((try? f.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0)
            n += 1
        }
        return total
    }

    /// 資料夾清單:相對路徑,最多兩層(.app 內部只列到 Contents/MacOS 這一層就夠判斷)
    static func listDirectory(_ url: URL, depth: Int = 3) -> [String] {
        var out: [String] = []
        let base = url.standardizedFileURL.path
        let e = FileManager.default.enumerator(at: url, includingPropertiesForKeys: nil, options: [])
        while let f = e?.nextObject() as? URL, out.count < maxListing {
            let rel = String(f.standardizedFileURL.path.dropFirst(base.count + 1))
            if rel.split(separator: "/").count > depth { e?.skipDescendants(); continue }
            out.append(rel)
        }
        return out
    }

    static func archiveListing(_ url: URL, ext: String) -> [String]? {
        let r: Shell.Result
        if ext == "zip" || ext.isEmpty {
            r = Shell.run("/usr/bin/zipinfo", ["-1", url.path], timeout: 20)
        } else if ["tar", "gz", "tgz", "bz2", "xz"].contains(ext) {
            r = Shell.run("/usr/bin/tar", ["-tf", url.path], timeout: 20)
        } else {
            return nil   // 7z / rar 沒有系統工具,交給 Claude 依檔名判斷
        }
        return r.status == 0 ? lines(r.stdout) : nil
    }

    // MARK: - 簽章

    enum AssessType: String { case exec, open, install }

    static func signature(of path: String, kind: AssessType) -> SignatureInfo {
        let d = Shell.run("/usr/bin/codesign", ["-dvvv", path], timeout: 20)
        let text = d.stderr
        var info = SignatureInfo(status: .unsigned)
        if text.contains("not signed at all") {
            info.status = .unsigned
        } else {
            for line in text.split(separator: "\n") {
                if line.hasPrefix("TeamIdentifier="), !line.hasSuffix("not set") {
                    info.teamID = String(line.dropFirst("TeamIdentifier=".count))
                } else if line.hasPrefix("Identifier=") {
                    info.identifier = String(line.dropFirst("Identifier=".count))
                } else if line.hasPrefix("Authority=") {
                    info.authorities.append(String(line.dropFirst("Authority=".count)))
                }
            }
            if text.contains("Signature=adhoc") {
                info.status = .adhoc
            } else {
                let v = Shell.run("/usr/bin/codesign", ["--verify", "--deep", "--strict", path], timeout: 60)
                info.status = v.status == 0 ? .valid : .invalid
            }
        }
        var args = ["-a", "-vvv", "-t", kind.rawValue]
        if kind == .open { args += ["--context", "context:primary-signature"] }
        let g = Shell.run("/usr/sbin/spctl", args + [path], timeout: 30)
        info.gatekeeperAccepted = g.stderr.contains(": accepted")
        if let line = g.stderr.split(separator: "\n").first(where: { $0.hasPrefix("source=") }) {
            info.gatekeeperSource = String(line.dropFirst("source=".count))
        }
        return info
    }

    static func packageSignature(_ path: String) -> SignatureInfo {
        let r = Shell.run("/usr/sbin/pkgutil", ["--check-signature", path], timeout: 20)
        var info = SignatureInfo(status: .unsigned)
        if r.stdout.contains("Status: signed") {
            info.status = .valid
            // "1. Developer ID Installer: Name (TEAMID1234)"
            let lines = r.stdout.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
            info.authorities = lines.filter { $0.first?.isNumber == true }
            if let leaf = info.authorities.first, let open = leaf.lastIndex(of: "("), let close = leaf.lastIndex(of: ")"),
               open < close {
                info.teamID = String(leaf[leaf.index(after: open)..<close])
            }
            info.gatekeeperAccepted = r.stdout.contains("notarized") ? true : nil
            if r.stdout.contains("Notarization: trusted by the Apple notary service") {
                info.gatekeeperSource = "Notarized Developer ID"
            }
        } else if r.stdout.contains("Status: signed by untrusted") || r.stdout.contains("invalid") {
            info.status = .invalid
        }
        let g = Shell.run("/usr/sbin/spctl", ["-a", "-vvv", "-t", "install", path], timeout: 30)
        info.gatekeeperAccepted = g.stderr.contains(": accepted")
        if let line = g.stderr.split(separator: "\n").first(where: { $0.hasPrefix("source=") }) {
            info.gatekeeperSource = String(line.dropFirst("source=".count))
        }
        return info
    }

    static func nestedAppSignatures(in root: URL, listing: [String]) -> [String: SignatureInfo]? {
        let apps = listing.filter { $0.hasSuffix(".app") && !$0.dropLast(4).contains(".app/") }.prefix(5)
        guard !apps.isEmpty else { return nil }
        var out: [String: SignatureInfo] = [:]
        for rel in apps { out[rel] = signature(of: root.appendingPathComponent(rel).path, kind: .exec) }
        return out
    }

    // MARK: - 磁碟映像(唯讀掛載,不自動開啟、不出現在 Finder)

    static func inspectDiskImage(_ url: URL, into facts: inout FileFacts) {
        withMountedImage(url) { mount, note in
            guard let mount else {
                if let note { facts.notes.append(note) }
                return
            }
            facts.contents = listDirectory(mount)
            facts.nestedSignatures = nestedAppSignatures(in: mount, listing: facts.contents ?? [])
        }
    }

    /// 唯讀掛載磁碟映像後執行 body,結束一定卸載。
    /// 有授權條款(SLA)的映像會在 stdin 等「Y」,這裡直接回覆,避免卡住。
    static func withMountedImage(_ url: URL, _ body: (URL?, String?) -> Void) {
        let r = Shell.run("/usr/bin/hdiutil",
                          ["attach", "-readonly", "-nobrowse", "-noautoopen", "-noverify",
                           "-mountrandom", NSTemporaryDirectory(), "-plist", url.path],
                          input: "Y\n", timeout: 90)
        guard r.status == 0,
              let start = r.stdout.range(of: "<?xml"),
              let plist = try? PropertyListSerialization.propertyList(
                from: Data(r.stdout[start.lowerBound...].utf8), format: nil) as? [String: Any],
              let entities = plist["system-entities"] as? [[String: Any]],
              let mount = entities.compactMap({ $0["mount-point"] as? String }).first
        else {
            body(nil, r.timedOut ? "掛載磁碟映像逾時(可能有密碼)" : "無法掛載磁碟映像")
            return
        }
        defer { Shell.run("/usr/bin/hdiutil", ["detach", mount, "-force"], timeout: 30) }
        body(URL(fileURLWithPath: mount), nil)
    }
}
