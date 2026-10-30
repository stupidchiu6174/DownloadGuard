package core

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// 瀏覽器的暫存檔,改名成正式檔名時會再收到一次事件
var temporaryExts = set("crdownload", "download", "part", "partial", "opdownload", "tmp", "aria2", "!ut",
	"filepart", "crswap", "dtapart")

func ShouldIgnore(name string) bool {
	lower := strings.ToLower(name)
	if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "~$") || strings.HasPrefix(name, "Unconfirmed ") ||
		lower == "desktop.ini" || lower == "thumbs.db" {
		return true
	}
	return temporaryExts[extOf(name)]
}

// snapshot 大小 + 修改時間;資料夾用裡面最新的修改時間與項目數
func snapshot(path string) (string, bool) {
	st, err := os.Lstat(path)
	if err != nil {
		return "", false
	}
	if !st.IsDir() {
		return fmt.Sprintf("%d|%d", st.Size(), st.ModTime().UnixNano()), true
	}
	newest, count, bytes := st.ModTime().Unix(), 0, int64(0)
	_ = filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if count++; count > 20000 {
			return filepath.SkipAll
		}
		if info, err := d.Info(); err == nil {
			newest = max(newest, info.ModTime().Unix())
			if !d.IsDir() {
				bytes += info.Size()
			}
		}
		return nil
	})
	return fmt.Sprintf("d%d|%d|%d", count, bytes, newest), true
}

// settler 等項目「寫完」:大小和修改時間連續一段時間沒變才回報
type settler struct {
	delay    time.Duration
	attempts int
	mu       sync.Mutex
	pending  map[string]bool
	stopped  chan struct{}
}

func newSettler(delay time.Duration, attempts int) *settler {
	return &settler{delay: delay, attempts: attempts, pending: map[string]bool{}, stopped: make(chan struct{})}
}

func (s *settler) schedule(path string, done func(path, snap string)) {
	s.mu.Lock()
	if s.pending[path] {
		s.mu.Unlock()
		return
	}
	s.pending[path] = true
	s.mu.Unlock()
	go func() {
		defer func() { s.mu.Lock(); delete(s.pending, path); s.mu.Unlock() }()
		last, ok := snapshot(path)
		if !ok {
			return
		}
		for i := 0; ; i++ {
			select {
			case <-s.stopped:
				return
			case <-time.After(s.delay):
			}
			now, ok := snapshot(path)
			if !ok {
				return // 被搬走了
			}
			if now == last || i >= s.attempts {
				done(path, now)
				return
			}
			last = now
		}
	}()
}

func (s *settler) stop() {
	select {
	case <-s.stopped:
	default:
		close(s.stopped)
	}
}

// MARK: - DirWatcher

// DirWatcher 監看一個資料夾最上層的新項目,等它「下載完成」才通知(小黑屋用)。
// 同一個項目(路徑 + 大小 + 修改時間)只通知一次。
type DirWatcher struct {
	Dir     string
	OnReady func(path string)
	Delay   time.Duration

	mu     sync.Mutex
	seen   map[string]bool
	stopFn func()
	s      *settler
}

func NewDirWatcher(dir string, onReady func(string)) *DirWatcher {
	return &DirWatcher{Dir: dir, OnReady: onReady, Delay: 2500 * time.Millisecond, seen: map[string]bool{}}
}

// Start includeExisting:啟動時把資料夾裡現有的項目也當成新項目(App 沒開時進來的檔案)
func (w *DirWatcher) Start(includeExisting bool) error {
	w.s = newSettler(w.Delay, 240)
	stop, err := watchTree(w.Dir, false, w.received)
	if err != nil {
		return err
	}
	w.stopFn = stop
	if includeExisting {
		entries, _ := os.ReadDir(w.Dir)
		for _, e := range entries {
			w.received(filepath.Join(w.Dir, e.Name()))
		}
	}
	return nil
}

func (w *DirWatcher) Stop() {
	if w.stopFn != nil {
		w.stopFn()
		w.stopFn = nil
	}
	if w.s != nil {
		w.s.stop()
	}
}

// Forget 處理完的項目被搬走後又搬回來(例如從隔離區還原到小黑屋),要能再通知一次
func (w *DirWatcher) Forget(path string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for k := range w.seen {
		if strings.HasPrefix(k, path+"|") {
			delete(w.seen, k)
		}
	}
}

func (w *DirWatcher) received(path string) {
	rel, err := filepath.Rel(w.Dir, path)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return
	}
	// 只看最上層:資料夾裡的變動歸到那個資料夾
	top := strings.Split(rel, string(filepath.Separator))[0]
	if ShouldIgnore(top) {
		return
	}
	w.s.schedule(filepath.Join(w.Dir, top), func(p, snap string) {
		key := p + "|" + snap
		w.mu.Lock()
		if w.seen[key] {
			w.mu.Unlock()
			return
		}
		w.seen[key] = true
		w.mu.Unlock()
		w.OnReady(p)
	})
}

// MARK: - Interceptor

// Interceptor 監看整個使用者資料夾(含子資料夾),抓「剛下載完成」的檔案,不管它被存在哪個資料夾。
//
// 怎麼認出下載:瀏覽器、Outlook、Teams 存下來的檔案會帶 Zone.Identifier(Mark of the Web),
// 裡面有 ZoneId(3 = 網際網路)和下載網址。只有 ZoneId ≥ 3、有 http(s) 網址、建立時間是最近幾分鐘、
// 而且還沒被放行過的,才算新下載:
//   - 從帶標記的 ZIP 解壓縮出來的檔案也會被加上 ZoneId=3,但網址是 ZIP 的本機路徑,不會被抓
//   - 不看時間的話,你把舊的下載檔搬到別的資料夾也會被抓
type Interceptor struct {
	Root       string
	Excluded   []string
	Window     time.Duration
	OnDownload func(path string)

	stopFn func()
	s      *settler
}

// 這些名稱的資料夾整個略過(系統資料、套件管理器、建置輸出、版本控制)
var skippedFolderNames = set("appdata", "node_modules", ".git", ".build", "build", "venv", ".venv", "__pycache__",
	"site-packages", "$recycle.bin", "temp", "bin", "obj", "target")

func NewInterceptor(root string, excluded []string, onDownload func(string)) *Interceptor {
	return &Interceptor{Root: root, Excluded: excluded, Window: 15 * time.Minute, OnDownload: onDownload}
}

func DefaultExclusions(home string) []string {
	return []string{HoldingDir(), SupportDir(), filepath.Join(home, "AppData")}
}

func (w *Interceptor) Start() error {
	w.s = newSettler(800*time.Millisecond, 600)
	stop, err := watchTree(w.Root, true, w.received)
	if err != nil {
		return err
	}
	w.stopFn = stop
	return nil
}

func (w *Interceptor) Stop() {
	if w.stopFn != nil {
		w.stopFn()
		w.stopFn = nil
	}
	if w.s != nil {
		w.s.stop()
	}
}

func (w *Interceptor) received(path string) {
	if !w.Candidate(path) {
		return
	}
	w.s.schedule(path, func(p, _ string) {
		if IsFreshDownload(p, w.Window, time.Now()) {
			w.OnDownload(p)
		}
	})
}

// Candidate 事件路徑是不是要處理的檔案;略過的位置回傳 false
func (w *Interceptor) Candidate(path string) bool {
	rel, err := filepath.Rel(w.Root, path)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return false
	}
	for _, ex := range w.Excluded {
		if SamePath(path, ex) || isUnder(path, ex) {
			return false
		}
	}
	parts := strings.Split(rel, string(filepath.Separator))
	for i, part := range parts {
		if strings.HasPrefix(part, ".") {
			return false // 隱藏的檔案與資料夾
		}
		if i < len(parts)-1 && skippedFolderNames[strings.ToLower(part)] {
			return false
		}
	}
	if ShouldIgnore(parts[len(parts)-1]) {
		return false
	}
	st, err := os.Lstat(path)
	return err == nil && st.Mode().IsRegular()
}

func isUnder(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != "." && !strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel)
}

// IsFreshDownload 有下載標記、時間夠新、還沒放行過
func IsFreshDownload(path string, window time.Duration, now time.Time) bool {
	if IsReleased(path) {
		return false
	}
	data, err := ReadStream(path, ZoneStream)
	if err != nil {
		return false
	}
	zone, host, referrer := ParseZoneIdentifier(data)
	if zone < 3 || (hostOf(host) == "" && hostOf(referrer) == "") {
		return false
	}
	created, ok := creationTime(path)
	if !ok {
		return false
	}
	age := now.Sub(created)
	return age <= window && age > -5*time.Minute
}
