package core

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
)

// 從檔案裡抽出可印字串,找已知的惡意程式手法(以 Windows 上的竊密程式、下載器、勒索軟體為主)。
// 這是給 Claude 的線索,也是 Claude 判斷之外的保險:Claude 說安全但這裡抓到嚴重警訊時,
// 最終判定至少是「可疑」(檔案內容可能企圖用文字影響 Claude 的判斷)。

type iocPattern struct {
	needle   string
	severity Severity
	meaning  string
}

// 不分大小寫比對
var iocPatterns = []iocPattern{
	{"Add-MpPreference -ExclusionPath", SevCritical, "把路徑加進 Defender 排除清單"},
	{"Add-MpPreference -ExclusionProcess", SevCritical, "把程式加進 Defender 排除清單"},
	{"Set-MpPreference -DisableRealtimeMonitoring", SevCritical, "關閉 Defender 即時保護"},
	{"DisableAntiSpyware", SevCritical, "用登錄檔關閉 Defender"},
	{"vssadmin delete shadows", SevCritical, "刪除陰影複製(勒索軟體手法)"},
	{"shadowcopy delete", SevCritical, "刪除陰影複製(勒索軟體手法)"},
	{"wbadmin delete catalog", SevCritical, "刪除備份目錄(勒索軟體手法)"},
	{"recoveryenabled no", SevCritical, "關閉開機修復(勒索軟體手法)"},
	{"certutil -urlcache", SevCritical, "用 certutil 下載檔案(常見的繞過手法)"},
	{"/i:http", SevCritical, "regsvr32 從網路載入腳本(Squiblydoo)"},
	{"login.keychain", SevCritical, "macOS 鑰匙圈檔案"},
	{"nkbihfbeogaeaoehlefnkodbefgpgknn", SevCritical, "MetaMask 錢包擴充功能 ID"},
	{"Exodus\\exodus.wallet", SevCritical, "Exodus 錢包資料"},
	{"Electrum\\wallets", SevCritical, "Electrum 錢包資料"},
	{"Telegram Desktop\\tdata", SevCritical, "Telegram 登入資料"},
	{"discord\\Local Storage\\leveldb", SevCritical, "Discord 登入權杖(竊密程式常見目標)"},
	{"needs your password to continue", SevCritical, "假的密碼視窗文字"},
	{"-EncodedCommand", SevWarning, "PowerShell 執行編碼過的指令(用來隱藏內容)"},
	{"powershell -enc", SevWarning, "PowerShell 執行編碼過的指令(用來隱藏內容)"},
	{"powershell.exe -enc", SevWarning, "PowerShell 執行編碼過的指令(用來隱藏內容)"},
	{"FromBase64String", SevWarning, "解碼隱藏的內容"},
	{"Invoke-Expression", SevWarning, "PowerShell 把字串當指令執行"},
	{"IEX(", SevWarning, "PowerShell 把字串當指令執行"},
	{"IEX (", SevWarning, "PowerShell 把字串當指令執行"},
	{"DownloadString(", SevWarning, "下載內容直接在記憶體裡執行"},
	{"Net.WebClient", SevWarning, "PowerShell 連網下載"},
	{"-WindowStyle Hidden", SevWarning, "隱藏視窗執行"},
	{"-w hidden", SevWarning, "隱藏視窗執行"},
	{"certutil -decode", SevWarning, "用 certutil 解碼隱藏的內容"},
	{"bitsadmin /transfer", SevWarning, "用 bitsadmin 下載檔案"},
	{"mshta ", SevWarning, "用 mshta 執行 HTML 應用程式"},
	{"schtasks /create", SevWarning, "建立排程工作(開機常駐)"},
	{"CurrentVersion\\Run", SevWarning, "寫入登錄檔的開機自動執行"},
	{"Start Menu\\Programs\\Startup", SevWarning, "放進「啟動」資料夾(開機常駐)"},
	{"Zone.Identifier", SevWarning, "動到下載標記(可能用來繞過 SmartScreen)"},
	{"Unblock-File", SevWarning, "移除下載標記以繞過 SmartScreen"},
	{"Login Data", SevWarning, "瀏覽器存的密碼資料庫"},
	{"\\User Data\\Local State", SevWarning, "Chrome / Edge 的密碼加密金鑰"},
	{"wallet.dat", SevWarning, "加密貨幣錢包檔"},
	{"api.telegram.org/bot", SevWarning, "把資料傳到 Telegram 機器人(竊密程式常用的外傳管道)"},
	{"discord.com/api/webhooks", SevWarning, "把資料傳到 Discord(竊密程式常用的外傳管道)"},
	{"Win + R", SevWarning, "叫你按 Win+R 貼上指令(ClickFix 假驗證手法)"},
	{"Win+R", SevWarning, "叫你按 Win+R 貼上指令(ClickFix 假驗證手法)"},
	{"rundll32", SevInfo, "用 rundll32 執行 DLL"},
	{"Invoke-WebRequest", SevInfo, "PowerShell 連網"},
	{"curl ", SevInfo, "用 curl 連網"},
	{"VirtualAllocEx", SevInfo, "在別的程式裡配置記憶體(注入手法會用到)"},
	{"WriteProcessMemory", SevInfo, "寫入別的程式的記憶體(注入手法會用到)"},
	{"CreateRemoteThread", SevInfo, "在別的程式裡開執行緒(注入手法會用到)"},
	{"%TEMP%", SevInfo, "使用暫存資料夾"},
}

type IOCReport struct {
	Hits         map[string]string `json:"hits"` // needle → 意義
	Signals      []Signal          `json:"signals"`
	URLs         []string          `json:"urls"`
	IPs          []string          `json:"ips"`
	BytesScanned int               `json:"bytesScanned"`
	Files        []string          `json:"files,omitempty"`
}

const iocMaxBytes = 16 << 20

func ScanData(data []byte) *IOCReport {
	strs := PrintableStrings(data)
	lower := strings.ToLower(strs)
	r := &IOCReport{Hits: map[string]string{}, Signals: []Signal{}, BytesScanned: len(data)}
	for _, p := range iocPatterns {
		if _, done := r.Hits[p.needle]; done {
			continue
		}
		if strings.Contains(lower, strings.ToLower(p.needle)) {
			r.Hits[p.needle] = p.meaning
			r.Signals = append(r.Signals, Signal{p.severity, fmt.Sprintf("%s(字串「%s」)", p.meaning, p.needle)})
		}
	}
	r.URLs = uniqueMatches(urlRegex, strs, 60)
	for _, ip := range uniqueMatches(ipRegex, strs, 40) {
		if isInterestingIP(ip) {
			r.IPs = append(r.IPs, ip)
		}
	}
	return r
}

// ScanPath 掃一個路徑:一般檔案直接讀;壓縮檔、映像檔、資料夾掃裡面的程式與腳本。
func ScanPath(p string, f *FileFacts) *IOCReport {
	var buf []byte
	var files []string
	appendFrom := func(name string, rd io.Reader) {
		chunk, _ := io.ReadAll(io.LimitReader(rd, int64(iocMaxBytes-len(buf))))
		buf = append(buf, chunk...)
		buf = append(buf, '\n')
		files = append(files, name)
	}
	switch f.Category {
	case CatFolder:
		for _, rel := range f.Contents {
			if len(files) >= 8 || len(buf) >= iocMaxBytes {
				break
			}
			if !scanWorthy(rel) {
				continue
			}
			if h, err := os.Open(filepath.Join(p, rel)); err == nil {
				appendFrom(rel, h)
				h.Close()
			}
		}
	case CatArchive, CatDiskImage:
		if c, err := OpenContainer(p, f.Ext); err == nil {
			for _, m := range c.Members() {
				if len(files) >= 8 || len(buf) >= iocMaxBytes {
					break
				}
				if m.Dir || !scanWorthy(m.Name) {
					continue
				}
				if rd, err := c.Open(m.Name); err == nil {
					appendFrom(m.Name, rd)
					rd.Close()
				}
			}
			c.Close()
		}
	}
	if len(files) == 0 || f.Category == CatArchive || f.Category == CatDiskImage {
		// 容器本身也掃一次(7z / rar 打不開裡面,至少看得到未壓縮的部分)
		if h, err := os.Open(p); err == nil && f.Category != CatFolder {
			appendFrom(f.Name, h)
			h.Close()
		}
	}
	r := ScanData(buf)
	r.Files = files
	return r
}

func scanWorthy(name string) bool {
	ext := extOf(name)
	return ScriptExts[ext] || ExecExts[ext] || nestedCritical[ext] || nestedWarning[ext] || ext == "" ||
		ext == "txt" || ext == "html" || ext == "htm" || ext == "svg"
}

// PrintableStrings 長度 ≥ 5 的可印字元片段(和 strings 工具同一個意思),另外保留 UTF-8 中文;
// Windows 程式的字串多半是 UTF-16LE,也一併抽出來
func PrintableStrings(data []byte) string {
	out := make([]byte, 0, min(len(data), 4<<20))
	var run []byte
	flush := func() {
		if len(run) >= 5 {
			out = append(out, run...)
			out = append(out, '\n')
		}
		run = run[:0]
	}
	for _, b := range data {
		if (b >= 0x20 && b < 0x7F) || b == 0x09 || b >= 0x80 {
			run = append(run, b)
		} else {
			flush()
		}
	}
	flush()

	// UTF-16LE:ASCII 字元後面接 0x00
	var wide []uint16
	flushWide := func() {
		if len(wide) >= 5 {
			out = append(out, string(utf16.Decode(wide))...)
			out = append(out, '\n')
		}
		wide = wide[:0]
	}
	for i := 0; i+1 < len(data); i += 2 {
		lo, hi := data[i], data[i+1]
		if hi == 0 && ((lo >= 0x20 && lo < 0x7F) || lo == 0x09) {
			wide = append(wide, uint16(lo))
		} else {
			flushWide()
		}
	}
	flushWide()
	return strings.ToValidUTF8(string(out), "")
}

var (
	urlRegex = regexp.MustCompile(`https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,200}`)
	ipRegex  = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
)

func uniqueMatches(re *regexp.Regexp, text string, limit int) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, m := range re.FindAllString(text, -1) {
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
			if len(out) >= limit {
				break
			}
		}
	}
	return out
}

// 排除本機位址與看起來像版本號的組合
func isInterestingIP(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	n := make([]int, 4)
	for i, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil {
			return false
		}
		n[i] = v
	}
	if n[0] == 0 || n[0] == 127 || n[0] == 10 || n[0] == 255 || (n[0] == 192 && n[1] == 168) {
		return false
	}
	if n[0] < 10 && n[1] < 10 && n[2] < 10 && n[3] < 10 { // 1.2.3.4 這類版本號
		return false
	}
	return true
}
