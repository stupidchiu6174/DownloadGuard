package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"downloadguard/internal/core"
)

// Controller 下載掃描(小黑屋)。
//
// 流程:任何資料夾裡出現新下載 → 關進 %USERPROFILE%\小黑屋(記下原本的資料夾)→ 白名單?直接放行
// → 否則背景 Claude Code 掃描 → 安全就送回原本的資料夾;可疑留在小黑屋等你決定;惡意移到隔離區。
type Controller struct {
	mu          sync.Mutex
	settings    Settings
	history     []core.ScanOutcome
	scanning    string
	queued      []string
	whitelist   core.Whitelist
	lastMessage string

	holding     *core.DirWatcher
	interceptor *core.Interceptor

	// 系統通知(Windows 用 toast);actions 是通知上的按鈕
	Notify func(title, body, id string, actions []NotifyAction)
	// 狀態變了(更新系統匣的提示文字)
	OnChange func()
}

type NotifyAction struct {
	Label string
	Op    string
}

type Settings struct {
	Enabled bool   `json:"enabled"`
	Model   string `json:"model"`
	// 安全放行時也通知(預設只在可疑 / 惡意時通知)
	NotifySafe bool `json:"notifySafe"`
	// 判定惡意時自動移到隔離區
	AutoQuarantine bool `json:"autoQuarantine"`
	// 使用者資料夾裡任何地方出現新下載時自動關進小黑屋(瀏覽器存到哪裡都有效)
	InterceptDownloads bool `json:"interceptDownloads"`
}

var models = []map[string]string{
	{"id": "claude-sonnet-5-5", "label": "Sonnet 5.5(建議)"},
	{"id": "claude-haiku-5-5", "label": "Haiku 5.5(較快、較省)"},
	{"id": "claude-opus-5-5", "label": "Opus 5.5(最仔細)"},
}

func NewController() *Controller {
	c := &Controller{settings: Settings{Enabled: true, Model: core.DefaultModel, AutoQuarantine: true,
		InterceptDownloads: true}}
	if data, err := os.ReadFile(core.SettingsFile()); err == nil {
		_ = json.Unmarshal(data, &c.settings)
	}
	c.whitelist = core.LoadWhitelist(core.WhitelistFile())
	c.history = loadHistory()
	return c
}

func (c *Controller) saveSettings() {
	data, _ := json.MarshalIndent(c.settings, "", "  ")
	_ = core.WriteFileAtomic(core.SettingsFile(), data)
}

func (c *Controller) changed() {
	if c.OnChange != nil {
		go c.OnChange()
	}
}

// Restore App 啟動時呼叫:上次開著就恢復
func (c *Controller) Restore() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.settings.Enabled {
		c.start()
	}
}

func (c *Controller) Enabled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.settings.Enabled
}

func (c *Controller) SetEnabled(on bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.settings.Enabled = on
	c.saveSettings()
	if on {
		c.start()
	} else {
		c.stop()
	}
	c.changed()
}

func (c *Controller) start() {
	if c.holding != nil {
		return
	}
	for _, dir := range []string{core.HoldingDir(), core.QuarantineDir(), core.ScansDir()} {
		_ = os.MkdirAll(dir, 0o755)
	}
	if _, err := os.Stat(core.WhitelistFile()); err != nil {
		_ = c.whitelist.Save(core.WhitelistFile())
	}
	holding := core.NewDirWatcher(core.HoldingDir(), c.enqueue)
	if err := holding.Start(true); err != nil { // App 沒開的時候進來的也要掃
		c.lastMessage = "無法監看小黑屋:" + err.Error()
		return
	}
	c.holding = holding
	home := core.HomeDir()
	ic := core.NewInterceptor(home, core.DefaultExclusions(home), c.intercept)
	if err := ic.Start(); err != nil {
		c.lastMessage = "無法監看使用者資料夾:" + err.Error()
	} else {
		c.interceptor = ic
	}
}

func (c *Controller) stop() {
	if c.holding != nil {
		c.holding.Stop()
		c.holding = nil
	}
	if c.interceptor != nil {
		c.interceptor.Stop()
		c.interceptor = nil
	}
	c.queued = nil
}

func (c *Controller) Shutdown() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stop()
}

// MARK: - 小黑屋

// intercept 剛下載完成的檔案(Interceptor 已確認有下載標記、還沒放行過)→ 關進小黑屋
func (c *Controller) intercept(path string) {
	c.mu.Lock()
	on := c.settings.InterceptDownloads
	c.mu.Unlock()
	if !on {
		return
	}
	if _, err := core.Admit(path, core.HoldingDir()); err != nil {
		c.mu.Lock()
		c.lastMessage = fmt.Sprintf("無法把 %s 移進小黑屋:%v", filepath.Base(path), err)
		c.mu.Unlock()
		c.changed()
	}
}

func (c *Controller) enqueue(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.enqueueLocked(path)
}

func (c *Controller) enqueueLocked(path string) {
	if !c.settings.Enabled {
		return
	}
	for _, q := range c.queued {
		if core.SamePath(q, path) {
			return
		}
	}
	c.queued = append(c.queued, path)
	c.processNext()
	c.changed()
}

func (c *Controller) processNext() {
	if c.scanning != "" || len(c.queued) == 0 {
		return
	}
	path := c.queued[0]
	c.queued = c.queued[1:]
	if _, err := os.Lstat(path); err != nil {
		c.processNext()
		return
	}
	claude, err := core.FindClaude()
	if err != nil {
		c.lastMessage = "找不到 claude 指令,請先安裝 Claude Code 並登入。檔案先留在小黑屋。"
		c.notify("下載掃描無法執行", c.lastMessage, "", nil)
		return
	}
	helper := helperPath()
	if helper == "" {
		c.lastMessage = "找不到 liri-scan.exe(要和 DownloadGuard.exe 放在同一個資料夾)"
		return
	}
	c.whitelist = core.LoadWhitelist(core.WhitelistFile()) // 可能被 Claude Code 對話改過
	runner := core.ScanRunner{Claude: claude, HelperPath: helper, Model: c.settings.Model, Whitelist: c.whitelist}
	c.scanning = filepath.Base(path)
	go func() {
		outcome := runner.Scan(path)
		c.mu.Lock()
		c.scanning = ""
		c.finish(outcome)
		c.processNext()
		c.mu.Unlock()
		c.changed()
	}()
}

func (c *Controller) finish(o core.ScanOutcome) {
	_, err := os.Lstat(o.Path)
	stillHere := err == nil
	switch {
	case o.Verdict == core.Safe && stillHere:
		if dest, err := core.Release(o.Path, core.DownloadsDir()); err == nil {
			o.Path = dest
		}
		if c.settings.NotifySafe {
			c.notify(fmt.Sprintf("已放行到「%s」:%s", filepath.Base(filepath.Dir(o.Path)), o.Name), o.Summary, o.ID, nil)
		}
	case o.Verdict == core.Malicious && stillHere && c.settings.AutoQuarantine:
		if dest, err := core.Quarantine(o.Path, core.QuarantineDir()); err == nil {
			o.QuarantinedPath = dest
		}
		c.notify("⚠️ 已隔離惡意檔案:"+o.Name, o.Summary, o.ID,
			[]NotifyAction{{"還原到原本的資料夾", "release"}, {"顯示紀錄", "show"}})
	default:
		prefix := ""
		if o.Verdict == core.Malicious {
			prefix = "⚠️ "
		}
		actions := []NotifyAction{{"放行", "release"}, {"隔離", "quarantine"}, {"顯示紀錄", "show"}}
		if o.Claude != nil && o.Claude.Suggestion != nil {
			actions = append([]NotifyAction{{"加入白名單並放行", "accept"}}, actions...)
		}
		c.notify(fmt.Sprintf("%s%s:%s 留在小黑屋", prefix, o.Verdict.Label(), o.Name), o.Summary, o.ID, actions)
	}
	c.record(o)
}

func (c *Controller) notify(title, body, id string, actions []NotifyAction) {
	if c.Notify != nil {
		go c.Notify(title, body, id, actions)
	}
}

// MARK: - 使用者動作

func (c *Controller) outcome(id string) (core.ScanOutcome, bool) {
	for _, o := range c.history {
		if o.ID == id {
			return o, true
		}
	}
	return core.ScanOutcome{}, false
}

// Act 執行一個使用者動作(網頁按鈕或通知按鈕)
func (c *Controller) Act(op, id, kind, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.changed()
	switch op {
	case "release":
		c.release(id)
	case "quarantine":
		c.quarantine(id)
	case "rescan":
		if o, ok := c.outcome(id); ok {
			p := o.Path
			if o.QuarantinedPath != "" {
				p = o.QuarantinedPath
			}
			c.enqueueLocked(p)
		}
	case "accept":
		// 接受掃描的 Claude 提出的白名單建議,並放行這個檔案
		if o, ok := c.outcome(id); ok && o.Claude != nil && o.Claude.Suggestion != nil {
			s := o.Claude.Suggestion
			c.updateWhitelist(func(w *core.Whitelist) { w.Add(s.Kind, s.Value) })
			if _, err := os.Lstat(o.Path); err == nil && core.IsInHolding(o.Path) {
				c.release(id)
			}
		}
	case "trust":
		if o, ok := c.outcome(id); ok {
			v := ""
			switch core.SuggestionKind(kind) {
			case core.KindDomain:
				if u, err := url.Parse(o.DownloadURL); err == nil {
					v = u.Hostname()
				}
			case core.KindPublisher:
				v = o.Publisher
			case core.KindSHA256:
				v = o.SHA256
			}
			if v != "" {
				c.updateWhitelist(func(w *core.Whitelist) { w.Add(core.SuggestionKind(kind), v) })
			}
		}
	case "wlAdd", "wlRemove":
		c.updateWhitelist(func(w *core.Whitelist) {
			switch {
			case kind == "extension" && op == "wlAdd":
				w.AddExtension(value)
			case kind == "extension":
				w.RemoveExtension(value)
			case op == "wlAdd":
				w.Add(core.SuggestionKind(kind), value)
			default:
				w.Remove(core.SuggestionKind(kind), value)
			}
		})
	case "reveal":
		if o, ok := c.outcome(id); ok {
			p := o.Path
			if o.QuarantinedPath != "" {
				p = o.QuarantinedPath
			}
			revealFile(p)
		}
	case "openHolding":
		_ = os.MkdirAll(core.HoldingDir(), 0o755)
		openFolder(core.HoldingDir())
	case "openQuarantine":
		_ = os.MkdirAll(core.QuarantineDir(), 0o755)
		openFolder(core.QuarantineDir())
	case "openSupport":
		_ = os.MkdirAll(core.SupportDir(), 0o755)
		openFolder(core.SupportDir())
	case "registerMCP":
		c.registerWhitelistMCP()
	case "dismiss":
		c.lastMessage = ""
	}
}

func (c *Controller) release(id string) {
	o, ok := c.outcome(id)
	if !ok {
		return
	}
	src := o.Path
	if o.QuarantinedPath != "" {
		src = o.QuarantinedPath
	}
	dest, err := core.Release(src, core.DownloadsDir())
	if err != nil {
		c.lastMessage = "放行失敗:" + err.Error()
		return
	}
	o.Path, o.QuarantinedPath = dest, ""
	o.Summary += "(你手動放行)"
	c.record(o)
}

func (c *Controller) quarantine(id string) {
	o, ok := c.outcome(id)
	if !ok {
		return
	}
	dest, err := core.Quarantine(o.Path, core.QuarantineDir())
	if err != nil {
		c.lastMessage = "隔離失敗:" + err.Error()
		return
	}
	o.QuarantinedPath = dest
	c.record(o)
}

func (c *Controller) updateWhitelist(change func(*core.Whitelist)) {
	list := core.LoadWhitelist(core.WhitelistFile())
	change(&list)
	if err := list.Save(core.WhitelistFile()); err != nil {
		c.lastMessage = "白名單存檔失敗:" + err.Error()
		return
	}
	c.whitelist = list
}

// UpdateSettings 網頁上改設定
func (c *Controller) UpdateSettings(patch map[string]any) {
	if v, ok := patch["enabled"].(bool); ok && v != c.Enabled() {
		c.SetEnabled(v)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := patch["model"].(string); ok && v != "" {
		c.settings.Model = v
	}
	if v, ok := patch["notifySafe"].(bool); ok {
		c.settings.NotifySafe = v
	}
	if v, ok := patch["autoQuarantine"].(bool); ok {
		c.settings.AutoQuarantine = v
	}
	if v, ok := patch["interceptDownloads"].(bool); ok {
		c.settings.InterceptDownloads = v
	}
	if v, ok := patch["autostart"].(bool); ok {
		if err := setAutostart(v); err != nil {
			c.lastMessage = "無法設定開機自動執行:" + err.Error()
		}
	}
	c.saveSettings()
	c.changed()
}

// registerWhitelistMCP 把白名單 MCP 註冊到你的 Claude Code(使用者範圍),之後在任何對話都能請 Claude 改白名單
func (c *Controller) registerWhitelistMCP() {
	claude, err := core.FindClaude()
	helper := helperPath()
	if err != nil || helper == "" {
		c.lastMessage = "找不到 claude 或 liri-scan.exe"
		return
	}
	go func() {
		cmd := claude.Command("mcp", "add", "--scope", "user", "liri-whitelist", "--", helper, "whitelist-mcp")
		core.HideWindow(cmd)
		out, err := cmd.CombinedOutput()
		msg := "完成。在 Claude Code 裡說「把 xxx 加進下載白名單」就可以了(新開的對話才會載入)。"
		if err != nil && !strings.Contains(string(out), "already exists") {
			msg = "註冊失敗:" + truncate(string(out), 200)
		}
		c.mu.Lock()
		c.lastMessage = msg
		c.mu.Unlock()
		c.changed()
	}()
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

func helperPath() string {
	self, err := os.Executable()
	if err != nil {
		return ""
	}
	name := "liri-scan"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	p := filepath.Join(filepath.Dir(self), name)
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	return p
}

// MARK: - 紀錄(JSON Lines;同一個 id 以最後一筆為準)

func (c *Controller) record(o core.ScanOutcome) {
	found := false
	for i := range c.history {
		if c.history[i].ID == o.ID {
			c.history[i] = o
			found = true
			break
		}
	}
	if !found {
		c.history = append([]core.ScanOutcome{o}, c.history...)
	}
	line, err := json.Marshal(o)
	if err != nil {
		return
	}
	_ = os.MkdirAll(core.SupportDir(), 0o755)
	f, err := os.OpenFile(core.HistoryFile(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(line, '\n'))
}

func loadHistory() []core.ScanOutcome {
	data, err := os.ReadFile(core.HistoryFile())
	if err != nil {
		return nil
	}
	byID := map[string]core.ScanOutcome{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var o core.ScanOutcome
		if json.Unmarshal(sc.Bytes(), &o) == nil && o.ID != "" {
			byID[o.ID] = o
		}
	}
	out := make([]core.ScanOutcome, 0, len(byID))
	for _, o := range byID {
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Date.After(out[j].Date) })
	if len(out) > 300 {
		out = out[:300]
	}
	return out
}

// MARK: - 給網頁的狀態

type outcomeView struct {
	core.ScanOutcome
	VerdictLabel string `json:"verdictLabel"`
	Location     string `json:"location"` // holding / quarantine / released / gone
	LocationText string `json:"locationText"`
	DomainHost   string `json:"domainHost,omitempty"`
	Ago          string `json:"ago"`
}

func (c *Controller) State() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	views := make([]outcomeView, 0, len(c.history))
	for _, o := range c.history {
		v := outcomeView{ScanOutcome: o, VerdictLabel: o.Verdict.Label(), Ago: ago(o.Date)}
		_, qErr := os.Lstat(o.QuarantinedPath)
		_, pErr := os.Lstat(o.Path)
		switch {
		case o.QuarantinedPath != "" && qErr == nil:
			v.Location, v.LocationText = "quarantine", "隔離區"
		case pErr != nil:
			v.Location, v.LocationText = "gone", "已移走"
		case core.IsInHolding(o.Path):
			v.Location, v.LocationText = "holding", "小黑屋"
		default:
			v.Location, v.LocationText = "released", "已放行到「"+filepath.Base(filepath.Dir(o.Path))+"」"
		}
		if u, err := url.Parse(o.DownloadURL); err == nil {
			v.DomainHost = u.Hostname()
		}
		views = append(views, v)
	}
	return map[string]any{
		"settings":    c.settings,
		"autostart":   autostartEnabled(),
		"models":      models,
		"history":     views,
		"scanning":    c.scanning,
		"queued":      len(c.queued),
		"whitelist":   c.whitelist,
		"lastMessage": c.lastMessage,
		"holding":     core.HoldingDir(),
		"platform":    runtime.GOOS,
	}
}

// Tooltip 系統匣圖示的提示文字
func (c *Controller) Tooltip() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case !c.settings.Enabled:
		return "下載掃描:已關閉"
	case c.scanning != "":
		return truncate("正在掃描 "+c.scanning, 100)
	}
	return "下載掃描:待命中"
}

func ago(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "剛剛"
	case d < time.Hour:
		return fmt.Sprintf("%d 分鐘前", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d 小時前", int(d.Hours()))
	case d < 30*24*time.Hour:
		return fmt.Sprintf("%d 天前", int(d.Hours()/24))
	}
	return t.Local().Format("2006-01-02")
}
