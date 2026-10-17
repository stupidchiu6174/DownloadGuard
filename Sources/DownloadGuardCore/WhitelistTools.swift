import Foundation

/// 給「你自己的」Claude Code 對話用的白名單工具(liri-scan whitelist-mcp)。
/// 這組工具只在你主動跟 Claude 對話時使用,背景掃描的 Claude 拿不到它。
/// 改完直接寫回 whitelist.json,LiriOS 會偵測到檔案變動並重新載入。
public final class WhitelistTools: MCPToolProvider {
    let file: URL

    public init(file: URL = GuardPaths.whitelist) {
        self.file = file
    }

    public let serverName = "liri-whitelist"
    public let instructions = "Manage LiriOS download-scan whitelist. Matching downloads skip the Claude scan and are released from the holding folder immediately, so only add sources the user explicitly trusts."

    public let toolDefinitions: [[String: Any]] = [
        [
            "name": "whitelist_list",
            "description": "Show the current download-scan whitelist (domains, developer Team IDs, SHA-256 hashes, file extensions).",
            "inputSchema": ["type": "object", "properties": [String: Any]()],
        ],
        [
            "name": "whitelist_add",
            "description": "Add a rule. kind: domain (matches the download URL or referring page host, including subdomains), teamID (code-signing Team ID; only notarized software with a valid signature matches), sha256 (one exact file), extension (only applies to files whose content really is a document or media).",
            "inputSchema": [
                "type": "object",
                "properties": [
                    "kind": ["type": "string", "enum": ["domain", "teamID", "sha256", "extension"]],
                    "value": ["type": "string"],
                ],
                "required": ["kind", "value"],
            ],
        ],
        [
            "name": "whitelist_remove",
            "description": "Remove a rule.",
            "inputSchema": [
                "type": "object",
                "properties": [
                    "kind": ["type": "string", "enum": ["domain", "teamID", "sha256", "extension"]],
                    "value": ["type": "string"],
                ],
                "required": ["kind", "value"],
            ],
        ],
    ]

    public func call(_ name: String, _ args: [String: Any]) throws -> String {
        var list = Whitelist.load(from: file)
        switch name {
        case "whitelist_list":
            return describe(list)
        case "whitelist_add", "whitelist_remove":
            guard let kind = args["kind"] as? String, let value = args["value"] as? String,
                  !value.trimmingCharacters(in: .whitespaces).isEmpty else {
                throw MCPToolError(message: "需要 kind 和 value")
            }
            let adding = name == "whitelist_add"
            if kind == "extension" {
                let v = value.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ". "))
                if adding { list.addExtension(v) } else { list.extensions.removeAll { $0 == v } }
            } else if let k = WhitelistSuggestion.Kind(rawValue: kind) {
                if adding {
                    list.add(k, value)
                } else {
                    let v = Whitelist.normalize(k, value)
                    switch k {
                    case .domain: list.domains.removeAll { $0 == v }
                    case .teamID: list.teamIDs.removeAll { $0 == v }
                    case .sha256: list.sha256.removeAll { $0 == v }
                    }
                }
            } else {
                throw MCPToolError(message: "kind 必須是 domain / teamID / sha256 / extension")
            }
            try list.save(to: file)
            return (adding ? "已加入。" : "已移除。") + "\n" + describe(list)
        default:
            throw MCPToolError(message: "沒有這個工具:\(name)")
        }
    }

    func describe(_ w: Whitelist) -> String {
        func row(_ title: String, _ items: [String]) -> String {
            "\(title):" + (items.isEmpty ? "(無)" : items.joined(separator: ", "))
        }
        return [row("網域", w.domains), row("開發者 Team ID", w.teamIDs),
                row("SHA-256", w.sha256), row("副檔名", w.extensions)].joined(separator: "\n")
    }
}
