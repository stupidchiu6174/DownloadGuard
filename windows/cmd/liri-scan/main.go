// liri-scan:DownloadGuard 的輔助程式(和 DownloadGuard.exe 放在同一個資料夾)
//
//	liri-scan mcp --target <檔案> --verdict-out <json> [--facts <json>]
//	    掃描用 MCP 伺服器(背景呼叫 claude 時用,一次只看一個檔案)
//	liri-scan whitelist-mcp [--file <json>]
//	    白名單 MCP 伺服器(註冊到你的 Claude Code,讓你在對話裡管理白名單)
//	liri-scan facts <檔案>       只做本機檢查,印出 JSON
//	liri-scan scan <檔案> [--model <模型>]
//	    完整掃一次(白名單 → 本機規則 → Claude),印出結果,不搬動檔案
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"downloadguard/internal/core"
)

func value(flag string, args []string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func printJSON(v any) {
	data, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(data))
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(2)
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fail("用法:liri-scan mcp | whitelist-mcp | facts <檔案> | scan <檔案>")
	}
	switch args[0] {
	case "mcp":
		target, out := value("--target", args), value("--verdict-out", args)
		if target == "" || out == "" {
			fail("用法:liri-scan mcp --target <檔案> --verdict-out <json> [--facts <json>]")
		}
		core.RunStdio(core.NewScanTools(target, out, value("--facts", args)), os.Stdin, os.Stdout)

	case "whitelist-mcp":
		file := value("--file", args)
		if file == "" {
			file = core.WhitelistFile()
		}
		core.RunStdio(&core.WhitelistTools{File: file}, os.Stdin, os.Stdout)

	case "facts":
		if len(args) < 2 {
			fail("用法:liri-scan facts <檔案>")
		}
		f := core.Inspect(args[1])
		ioc := core.ScanPath(args[1], f)
		signals := core.LocalSignals(f, ioc)
		printJSON(map[string]any{"facts": f, "signals": signals, "localVerdict": core.LocalVerdict(signals),
			"whitelistMatch": core.LoadWhitelist(core.WhitelistFile()).Match(f)})

	case "scan":
		if len(args) < 2 {
			fail("用法:liri-scan scan <檔案> [--model <模型>]")
		}
		claude, err := core.FindClaude()
		if err != nil {
			fail(err.Error())
		}
		self, _ := os.Executable()
		self, _ = filepath.EvalSymlinks(self)
		model := value("--model", args)
		if model == "" {
			model = core.DefaultModel
		}
		runner := core.ScanRunner{Claude: claude, HelperPath: self, Model: model,
			Whitelist: core.LoadWhitelist(core.WhitelistFile())}
		printJSON(runner.Scan(args[1]))

	default:
		fail("用法:liri-scan mcp | whitelist-mcp | facts <檔案> | scan <檔案>")
	}
}
