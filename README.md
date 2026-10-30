# DownloadGuard

macOS 下載掃描。新下載的檔案先關進 `~/小黑屋`,由背景的 Claude Code 檢查,安全才送回原本的資料夾,可疑的留下來等你決定。白名單裡的來源直接放行。

- 關著的期間會拿掉執行權限。
- 背景的 Claude 只拿得到 `liri-scan` 這個 MCP 伺服器的工具,不能用 Bash 或寫檔,檔案內容一律當成不可信的資料。
- 判斷僅供參考,不能取代防毒軟體。

## 需求

- macOS 26 以上、Swift 6.2
- 已登入的 [Claude Code](https://claude.com/claude-code) CLI(掃描會用到你的額度)

## 使用

```bash
swift build
swift run DownloadGuardApp
swift test
```

`liri-scan` 要和主程式放在同一個資料夾(`swift build` 預設如此)。系統通知只有打包成 .app 才會出現。

也可以當函式庫用:啟動時呼叫 `DownloadGuardController.shared.restore()`,用 `DownloadGuardWindowController.shared.show()` 開視窗。

原本是 LiriOS 的一部分,部分文字和資料夾名稱還會提到 LiriOS。
