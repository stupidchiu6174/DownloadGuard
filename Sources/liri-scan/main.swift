import Foundation
import DownloadGuardCore

// liri-scan:LiriOS 下載掃描的輔助程式(放在 LiriOS.app/Contents/MacOS 裡)
//
//   liri-scan mcp --target <檔案> --verdict-out <json> [--facts <json>]
//       掃描用 MCP 伺服器(LiriOS 背景呼叫 claude 時用,一次只看一個檔案)
//   liri-scan whitelist-mcp
//       白名單 MCP 伺服器(註冊到你的 Claude Code,讓你在對話裡管理白名單)
//   liri-scan facts <檔案>       只做本機檢查,印出 JSON
//   liri-scan scan <檔案> [--model <模型>]
//       完整掃一次(白名單 → 本機規則 → Claude),印出結果,不搬動檔案

func value(after flag: String, in args: [String]) -> String? {
    guard let i = args.firstIndex(of: flag), i + 1 < args.count else { return nil }
    return args[i + 1]
}

func printJSON<T: Encodable>(_ value: T) {
    let enc = JSONEncoder()
    enc.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
    enc.dateEncodingStrategy = .iso8601
    if let data = try? enc.encode(value) { print(String(decoding: data, as: UTF8.self)) }
}

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(2)
}

let args = Array(CommandLine.arguments.dropFirst())
let selfPath = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath().path

switch args.first {
case "mcp":
    guard let target = value(after: "--target", in: args), let out = value(after: "--verdict-out", in: args) else {
        fail("用法:liri-scan mcp --target <檔案> --verdict-out <json> [--facts <json>]")
    }
    let tools = ScanTools(target: URL(fileURLWithPath: target), verdictOut: URL(fileURLWithPath: out),
                          factsFile: value(after: "--facts", in: args).map { URL(fileURLWithPath: $0) })
    MCPServer(tools: tools).runStdio()

case "whitelist-mcp":
    let file = value(after: "--file", in: args).map { URL(fileURLWithPath: $0) } ?? GuardPaths.whitelist
    MCPServer(tools: WhitelistTools(file: file)).runStdio()

case "facts":
    guard args.count >= 2 else { fail("用法:liri-scan facts <檔案>") }
    let url = URL(fileURLWithPath: args[1])
    let facts = FileInspector.inspect(url)
    let ioc = IOCScanner.scan(path: url.path, facts: facts)
    struct Out: Encodable {
        let facts: FileFacts
        let signals: [Signal]
        let localVerdict: Verdict
        let whitelistMatch: String?
    }
    let signals = LocalRules.signals(facts: facts, ioc: ioc)
    printJSON(Out(facts: facts, signals: signals, localVerdict: LocalRules.verdict(for: signals),
                  whitelistMatch: Whitelist.load(from: GuardPaths.whitelist).match(facts)))

case "scan":
    guard args.count >= 2 else { fail("用法:liri-scan scan <檔案> [--model <模型>]") }
    guard let claude = ScanRunner.findClaude() else { fail("找不到 claude 指令") }
    let runner = ScanRunner(claudePath: claude, helperPath: selfPath,
                            model: value(after: "--model", in: args) ?? ScanRunner.defaultModel,
                            whitelist: Whitelist.load(from: GuardPaths.whitelist))
    printJSON(runner.scan(URL(fileURLWithPath: args[1])))

default:
    fail("用法:liri-scan mcp | whitelist-mcp | facts <檔案> | scan <檔案>")
}
