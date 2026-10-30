package core

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// 小黑屋:下載完成就關進 %USERPROFILE%\小黑屋,掃描通過才送回原本要存的資料夾。
//
//   - 關進來時記下原本的資料夾(DownloadGuard.Origin 資料流),放行時送回去;記錄不見或資料夾已刪就送「下載」
//   - 關著的期間對 Everyone 拒絕執行,不小心在小黑屋裡點兩下也跑不起來;放行時還原
//   - 放行的項目加上 DownloadGuard.Released,之後在任何資料夾被碰到都不會再抓回來
//   - Windows 原本的下載標記(Zone.Identifier)保留,打開時 SmartScreen 和 Office 保護檢視照樣檢查

const (
	ReleasedStream = "DownloadGuard.Released"
	originStream   = "DownloadGuard.Origin"
)

func IsReleased(path string) bool { return HasStream(path, ReleasedStream) }

// Origin 關進小黑屋時記下的原本資料夾
func Origin(path string) string {
	data, err := ReadStream(path, originStream)
	if err != nil {
		return ""
	}
	return string(data)
}

// Admit 從原本的資料夾關進小黑屋
func Admit(path, holding string) (string, error) {
	origin := filepath.Dir(path)
	dest, err := moveInto(path, holding)
	if err != nil {
		return "", err
	}
	_ = WriteStream(dest, originStream, []byte(origin))
	lockExecution(dest)
	return dest, nil
}

// Release 放行:送回原本的資料夾(沒有記錄就送 fallback),還原權限並加上已放行標記
func Release(path, fallback string) (string, error) {
	target := fallback
	if o := Origin(path); o != "" {
		if st, err := os.Stat(o); err == nil && st.IsDir() {
			target = o
		}
	}
	unlockExecution(path)
	dest, err := moveInto(path, target)
	if err != nil {
		return "", err
	}
	RemoveStream(dest, originStream)
	_ = WriteStream(dest, ReleasedStream, []byte("1"))
	return dest, nil
}

// Quarantine 移到隔離區(App 資料夾裡,不在你平常會點開的地方)
func Quarantine(path, dir string) (string, error) {
	dest, err := moveInto(path, dir)
	if err != nil {
		return "", err
	}
	lockExecution(dest)
	return dest, nil
}

// Restore 從隔離區放回小黑屋(之後可以再放行;原本的資料夾記錄跟著檔案走)
func Restore(path, holding string) (string, error) { return moveInto(path, holding) }

func moveInto(path, dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	dest := UniqueDestination(dir, filepath.Base(path))
	if err := moveItem(path, dest); err != nil {
		return "", err
	}
	return dest, nil
}

// UniqueDestination 同名就加「 (2)」「 (3)」…,和檔案總管一樣
func UniqueDestination(dir, name string) string {
	dest := filepath.Join(dir, name)
	if _, err := os.Lstat(dest); err != nil {
		return dest
	}
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	for n := 2; ; n++ {
		dest = filepath.Join(dir, base+" ("+strconv.Itoa(n)+")"+ext)
		if _, err := os.Lstat(dest); err != nil {
			return dest
		}
	}
}

func SamePath(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if os.PathSeparator == '\\' {
		return strings.EqualFold(a, b)
	}
	return a == b
}

func IsInHolding(path string) bool { return SamePath(filepath.Dir(path), HoldingDir()) }
