package core

import (
	"fmt"
	"path"
	"strings"
)

// 不靠 Claude 的固定規則。只會把判定拉高到「可疑」,永遠不會單獨判「惡意」
// (誤判成惡意會把正常檔案丟進隔離區,這個決定留給 Claude 加上證據)。

// 壓縮檔 / 映像檔 / 資料夾裡出現就很危險的類型(ISO、ZIP 夾帶捷徑或腳本是常見的投遞手法)
var nestedCritical = map[string]bool{"lnk": true, "hta": true, "vbs": true, "vbe": true, "js": true, "jse": true,
	"wsf": true, "wsh": true, "scr": true, "pif": true, "cpl": true, "chm": true, "url": true, "scf": true,
	"library-ms": true, "settingcontent-ms": true, "appref-ms": true}
var nestedWarning = map[string]bool{"bat": true, "cmd": true, "ps1": true, "psm1": true, "reg": true, "msc": true,
	"jar": true, "inf": true, "dll": true}

var macroDocExts = map[string]bool{"docm": true, "dotm": true, "xlsm": true, "xltm": true, "xlam": true,
	"pptm": true, "potm": true, "ppam": true, "sldm": true}

func LocalSignals(f *FileFacts, ioc *IOCReport) []Signal {
	var out []Signal
	add := func(sev Severity, msg string) { out = append(out, Signal{sev, msg}) }

	if f.Disguised {
		kind := "執行檔"
		if f.Category == CatScript {
			kind = "腳本"
		}
		add(SevCritical, fmt.Sprintf("副檔名是 .%s,內容卻是%s", f.Ext, kind))
	}
	if f.DeceptiveName != "" {
		add(SevCritical, f.DeceptiveName)
	}

	if s := f.Signature; s != nil && (f.Category == CatExecutable || f.Category == CatInstaller) {
		switch s.Status {
		case SigUnsigned:
			add(SevWarning, "程式沒有數位簽章")
		case SigUntrusted:
			add(SevWarning, "程式的簽章不受信任(自簽或憑證鏈有問題),無法追溯開發者")
		case SigInvalid:
			add(SevCritical, "程式簽章無效(檔案可能被竄改)")
		}
	}

	if macroDocExts[f.Ext] {
		add(SevWarning, "含巨集的 Office 檔案(打開並啟用內容就會執行程式碼)")
	}

	// 磁碟映像 / 資料夾 / 壓縮檔裡的內容
	if f.Category == CatDiskImage || f.Category == CatArchive || f.Category == CatFolder {
		var crit, warn []string
		for _, item := range f.Contents {
			ext := strings.ToLower(strings.TrimPrefix(path.Ext(strings.ReplaceAll(item, "\\", "/")), "."))
			if nestedCritical[ext] {
				crit = append(crit, item)
			} else if nestedWarning[ext] {
				warn = append(warn, item)
			}
		}
		if len(crit) > 0 {
			add(SevCritical, "裡面有捷徑或腳本,點兩下就會執行:"+strings.Join(first(crit, 3), "、"))
		}
		if len(warn) > 0 {
			add(SevWarning, "裡面有批次檔、PowerShell 或 DLL:"+strings.Join(first(warn, 3), "、"))
		}
	}

	if ioc != nil && (f.Category.CanRunCode() || f.Disguised || macroDocExts[f.Ext]) {
		out = append(out, ioc.Signals...)
	}
	return out
}

func first(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// LocalVerdict 本機規則的結論:有嚴重警訊,或累積兩個以上警告 → 可疑
func LocalVerdict(signals []Signal) Verdict {
	warnings := 0
	for _, s := range signals {
		if s.Severity == SevCritical {
			return Suspicious
		}
		if s.Severity == SevWarning {
			warnings++
		}
	}
	if warnings >= 2 {
		return Suspicious
	}
	return Safe
}
