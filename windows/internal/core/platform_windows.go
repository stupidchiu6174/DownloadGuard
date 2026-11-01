//go:build windows

package core

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

func downloadsDir() string {
	if p, err := windows.KnownFolderPath(windows.FOLDERID_Downloads, 0); err == nil && p != "" {
		return p
	}
	return HomeDir() + `\Downloads`
}

// MARK: - NTFS 替代資料流(Zone.Identifier 和我們自己的標記都放這裡,跟著檔案搬移)

func ReadStream(path, name string) ([]byte, error) { return os.ReadFile(path + ":" + name) }

func WriteStream(path, name string, data []byte) error {
	return os.WriteFile(path+":"+name, data, 0o644)
}

func RemoveStream(path, name string) {
	if p, err := windows.UTF16PtrFromString(path + ":" + name); err == nil {
		_ = windows.DeleteFile(p)
	}
}

func HasStream(path, name string) bool {
	_, err := os.Stat(path + ":" + name)
	return err == nil
}

// moveItem 同一顆磁碟直接改名;跨磁碟時由系統複製(連同替代資料流)再刪除原檔
func moveItem(from, to string) error {
	f, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	t, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(f, t, windows.MOVEFILE_COPY_ALLOWED|windows.MOVEFILE_WRITE_THROUGH)
}

func creationTime(path string) (time.Time, bool) {
	st, err := os.Stat(path)
	if err != nil {
		return time.Time{}, false
	}
	if d, ok := st.Sys().(*syscall.Win32FileAttributeData); ok {
		return time.Unix(0, d.CreationTime.Nanoseconds()), true
	}
	return st.ModTime(), true
}

// MARK: - 執行權限
//
// Windows 沒有「可執行」位元,改用存取控制:對 Everyone 拒絕「執行檔案」,
// 關在小黑屋裡的 .exe 點兩下也跑不起來。加了拒絕的檔案會留一個 DownloadGuard.Locked 標記,
// 放行時只移除我們自己加的那條。

const lockedStream = "DownloadGuard.Locked"

func lockExecution(path string) {
	st, err := os.Stat(path)
	if err != nil || st.IsDir() || HasStream(path, lockedStream) {
		return
	}
	if runHidden("icacls", path, "/deny", "*S-1-1-0:(X)") == nil {
		_ = WriteStream(path, lockedStream, []byte("1"))
	}
}

func unlockExecution(path string) {
	if !HasStream(path, lockedStream) {
		return
	}
	_ = runHidden("icacls", path, "/remove:d", "*S-1-1-0")
	RemoveStream(path, lockedStream)
}

func runHidden(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	HideWindow(cmd)
	return cmd.Run()
}

// HideWindow 從背景程式啟動子程序時不要閃出黑色主控台視窗
func HideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
}

// KillTree 連同子程序一起結束(claude 會再開 liri-scan)
func KillTree(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	if runHidden("taskkill", "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid)) != nil {
		_ = cmd.Process.Kill()
	}
}

// MARK: - Authenticode

const authenticodeScript = `
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$s = Get-AuthenticodeSignature -LiteralPath $env:DG_TARGET
$c = $s.SignerCertificate
[pscustomobject]@{
  status = "$($s.Status)"; message = $s.StatusMessage
  subject = if ($c) { $c.Subject } else { "" }
  issuer = if ($c) { $c.Issuer } else { "" }
  thumbprint = if ($c) { $c.Thumbprint } else { "" }
  timestamped = ($null -ne $s.TimeStamperCertificate)
  os = [bool]$s.IsOSBinary
} | ConvertTo-Json -Compress
`

func Authenticode(path string) *SignatureInfo {
	info := &SignatureInfo{Status: SigUnsigned}
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-EncodedCommand", encodePS(authenticodeScript))
	cmd.Env = append(os.Environ(), "DG_TARGET="+path)
	HideWindow(cmd)
	done := make(chan struct{})
	var out []byte
	var err error
	go func() { out, err = cmd.Output(); close(done) }()
	select {
	case <-done:
	case <-time.After(45 * time.Second):
		KillTree(cmd)
		<-done
		info.Message = "檢查簽章逾時"
		return info
	}
	if err != nil {
		info.Message = "無法檢查簽章:" + err.Error()
		return info
	}
	var r struct {
		Status, Message, Subject, Issuer, Thumbprint string
		Timestamped, OS                              bool
	}
	if json.Unmarshal([]byte(strings.TrimSpace(string(out))), &r) != nil {
		info.Message = "無法解讀簽章結果"
		return info
	}
	switch r.Status {
	case "Valid":
		info.Status = SigValid
	case "NotSigned", "NotSupportedFileFormat":
		info.Status = SigUnsigned
	case "HashMismatch", "Incompatible":
		info.Status = SigInvalid
	default: // NotTrusted、UnknownError:自簽或憑證鏈不受信任
		info.Status = SigUntrusted
	}
	if r.Subject != "" {
		info.Subject = r.Subject
		info.Publisher = PublisherFromSubject(r.Subject)
	}
	info.Issuer, info.Thumbprint, info.Timestamped, info.IsOSBinary = r.Issuer, r.Thumbprint, r.Timestamped, r.OS
	info.Message = r.Message
	return info
}

func encodePS(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, len(u)*2)
	for i, c := range u {
		b[i*2], b[i*2+1] = byte(c), byte(c>>8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// EncodePowerShell 給其他地方(例如通知)用的 -EncodedCommand 編碼
func EncodePowerShell(script string) string { return encodePS(script) }
