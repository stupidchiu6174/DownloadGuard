//go:build !windows

package core

// 非 Windows 平台只是為了能在開發機上跑測試:替代資料流用延伸屬性模擬,簽章一律當成沒簽。

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

func downloadsDir() string { return filepath.Join(HomeDir(), "Downloads") }

func ReadStream(path, name string) ([]byte, error) {
	buf := make([]byte, 64<<10)
	n, err := unix.Lgetxattr(path, "user."+name, buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func WriteStream(path, name string, data []byte) error {
	return unix.Lsetxattr(path, "user."+name, data, 0)
}

func RemoveStream(path, name string) { _ = unix.Lremovexattr(path, "user."+name) }

func HasStream(path, name string) bool {
	_, err := unix.Lgetxattr(path, "user."+name, nil)
	return err == nil
}

func moveItem(from, to string) error { return os.Rename(from, to) }

func creationTime(path string) (time.Time, bool) {
	st, err := os.Stat(path)
	if err != nil {
		return time.Time{}, false
	}
	return st.ModTime(), true
}

const lockedStream = "DownloadGuard.Locked"

func lockExecution(path string) {
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Mode()&0o111 == 0 || HasStream(path, lockedStream) {
		return
	}
	_ = WriteStream(path, lockedStream, []byte(strconv.FormatUint(uint64(st.Mode().Perm()), 8)))
	_ = os.Chmod(path, st.Mode().Perm()&^0o111)
}

func unlockExecution(path string) {
	data, err := ReadStream(path, lockedStream)
	if err != nil {
		return
	}
	if mode, err := strconv.ParseUint(string(data), 8, 32); err == nil {
		_ = os.Chmod(path, os.FileMode(mode))
	}
	RemoveStream(path, lockedStream)
}

func HideWindow(cmd *exec.Cmd) {}

func KillTree(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

func Authenticode(path string) *SignatureInfo {
	return &SignatureInfo{Status: SigUnsigned, Message: "這個平台不檢查 Authenticode"}
}
