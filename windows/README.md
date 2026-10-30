# DownloadGuard for Windows

Windows 版下載掃描。新下載的檔案先關進 `%USERPROFILE%\小黑屋`,由背景的 Claude Code 檢查,安全才送回原本的資料夾,可疑的留下來等你決定,惡意的移到隔離區。白名單裡的來源直接放行。

和 macOS 版同一套流程,用 Go 重寫,換成 Windows 的機制:

| | macOS 版 | Windows 版 |
|---|---|---|
| 認出下載 | `com.apple.quarantine` + `kMDItemWhereFroms` | `Zone.Identifier`(Mark of the Web,ZoneId ≥ 3 且有 http(s) 網址) |
| 監看資料夾 | FSEvents | ReadDirectoryChangesW |
| 關著時不能執行 | 拿掉執行權限 | 對 Everyone 拒絕「執行檔案」(icacls) |
| 簽章 | codesign / spctl(Team ID) | Authenticode(發行者) |
| 看壓縮檔、映像檔 | zipinfo / hdiutil 掛載 | 直接讀 ZIP、tar、ISO 9660 / Joliet,不解壓、不掛載 |
| 介面 | 選單列 + SwiftUI 視窗 | 系統匣 + 本機網頁(只聽 127.0.0.1) |
| 通知 | UserNotifications | Windows toast(按鈕可直接放行 / 隔離) |

另外針對 Windows 常見手法加了本機規則:雙重副檔名(`發票.pdf.exe`)、檔名反向字元、ISO / ZIP 裡夾帶 `.lnk` `.js` `.vbs` `.hta`、含巨集的 Office 檔,以及 PowerShell 編碼指令、Defender 排除、刪陰影複製、Telegram / Discord 外傳等字串。

- 背景的 Claude 只拿得到 `liri-scan` 這個 MCP 伺服器的工具,不能用 Bash 或寫檔,檔案內容一律當成不可信的資料。
- 判斷僅供參考,不能取代 Windows Defender。

## 需求

- Windows 10 1809 以上或 Windows 11(x64 或 ARM64),NTFS 磁碟
- 已登入的 [Claude Code](https://claude.com/claude-code) CLI(掃描會用到你的額度)。原生安裝(`claude.exe`)和 npm 安裝都可以

## 使用

1. 解壓縮,`DownloadGuard.exe` 和 `liri-scan.exe` 要放在同一個資料夾
2. 執行 `DownloadGuard.exe`。程式沒有數位簽章,SmartScreen 會跳出「Windows 已保護您的電腦」,按「其他資訊 → 仍要執行」
3. 瀏覽器會打開介面;之後從系統匣的綠色盾牌圖示打開

設定裡可以開「登入 Windows 時自動執行」。資料(白名單、紀錄、隔離區)在 `%APPDATA%\DownloadGuard`。

通知借用 Windows PowerShell 的身分發送,所以通知上會寫「Windows PowerShell」。

命令列:

```
liri-scan facts <檔案>      只做本機檢查,印出 JSON
liri-scan scan <檔案>       完整掃一次(白名單 → 本機規則 → Claude),不搬動檔案
```

## 從原始碼編譯

需要 Go 1.24 以上,在任何平台都能交叉編譯:

```bash
cd windows
./build.sh        # 產生 dist/DownloadGuard-windows-amd64.zip 與 -arm64.zip
go test ./...
```

在 Linux / macOS 上 `go run ./cmd/DownloadGuard` 也跑得起來(不放系統匣,直接印出介面網址),方便開發介面。
