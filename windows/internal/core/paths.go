package core

import (
	"os"
	"path/filepath"
)

// 下載掃描用到的位置

// SupportDir 資料:白名單、設定、掃描紀錄、隔離區、每次掃描的暫存(%APPDATA%\DownloadGuard)
func SupportDir() string {
	if v := os.Getenv("LIRI_GUARD_HOME"); v != "" {
		return v
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = filepath.Join(HomeDir(), "AppData", "Roaming")
	}
	return filepath.Join(dir, "DownloadGuard")
}

func HomeDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return h
}

func WhitelistFile() string { return filepath.Join(SupportDir(), "whitelist.json") }
func HistoryFile() string   { return filepath.Join(SupportDir(), "history.jsonl") }
func SettingsFile() string  { return filepath.Join(SupportDir(), "settings.json") }

// QuarantineDir 判定為惡意(或你按了「隔離」)的檔案放這裡,可以從紀錄還原
func QuarantineDir() string { return filepath.Join(SupportDir(), "Quarantine") }
func ScansDir() string      { return filepath.Join(SupportDir(), "scans") }

// HoldingDir 小黑屋:下載先放這裡,掃描通過才送回原本的資料夾
func HoldingDir() string {
	if v := os.Getenv("LIRI_GUARD_HOLDING"); v != "" {
		return v
	}
	return filepath.Join(HomeDir(), "小黑屋")
}

// DownloadsDir「下載」資料夾(使用者可能搬到別的磁碟,Windows 上問系統)
func DownloadsDir() string { return downloadsDir() }
