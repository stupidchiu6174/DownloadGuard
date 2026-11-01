package core

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Whitelist 白名單:命中就直接放行,不呼叫 Claude。
//
//   - 網域:下載網址或來源網頁的網域符合(含子網域)
//   - 發行者:Authenticode 簽章有效、憑證鏈受信任,而且發行者在清單裡
//   - SHA-256:完全相同的檔案
//   - 副檔名:只對「內容確實是文件或影音」的檔案生效;副檔名是 .jpg 但內容是程式的,不會放行
type Whitelist struct {
	Domains    []string `json:"domains"`
	Publishers []string `json:"publishers"`
	SHA256     []string `json:"sha256"`
	Extensions []string `json:"extensions"`
}

func DefaultWhitelist() Whitelist {
	return Whitelist{Domains: []string{}, Publishers: []string{}, SHA256: []string{},
		Extensions: []string{"jpg", "jpeg", "png", "gif", "heic", "webp", "mp4", "mov", "mp3", "m4a", "wav"}}
}

func trimDots(s string) string { return strings.Trim(strings.ToLower(s), ". ") }

// Match 命中的規則說明;沒命中回傳 ""
func (w Whitelist) Match(f *FileFacts) string {
	if f.SHA256 != "" {
		for _, h := range w.SHA256 {
			if strings.EqualFold(h, f.SHA256) {
				return "SHA-256 " + f.SHA256[:12] + "…"
			}
		}
	}
	if p := w.trustedPublisher(f); p != "" {
		return "發行者 " + p
	}
	for _, host := range []string{f.DownloadHost(), f.ReferrerHost()} {
		if host == "" {
			continue
		}
		for _, d := range w.Domains {
			if HostMatches(host, d) {
				return "網域 " + d + "(" + host + ")"
			}
		}
	}
	for _, e := range w.Extensions {
		if trimDots(e) == f.Ext && !f.Disguised && f.DeceptiveName == "" &&
			(f.Category == CatMedia || f.Category == CatDocument) {
			return "副檔名 ." + f.Ext
		}
	}
	return ""
}

func (w Whitelist) trustedPublisher(f *FileFacts) string {
	if len(w.Publishers) == 0 || f.Signature == nil || f.Signature.Status != SigValid || f.Signature.Publisher == "" {
		return ""
	}
	switch f.Category {
	case CatExecutable, CatInstaller, CatScript:
	default:
		return ""
	}
	if f.DeceptiveName != "" {
		return ""
	}
	for _, p := range w.Publishers {
		if strings.EqualFold(strings.TrimSpace(p), f.Signature.Publisher) {
			return f.Signature.Publisher
		}
	}
	return ""
}

func HostMatches(host, domain string) bool {
	d := trimDots(domain)
	if d == "" {
		return false
	}
	return host == d || strings.HasSuffix(host, "."+d)
}

// MARK: - 修改

func Normalize(kind SuggestionKind, raw string) string {
	v := strings.TrimSpace(raw)
	switch kind {
	case KindDomain:
		// 接受貼上整個網址
		if u, err := url.Parse(v); err == nil && u.Hostname() != "" {
			v = u.Hostname()
		}
		return trimDots(v)
	case KindSHA256:
		return strings.ToLower(v)
	default:
		return v
	}
}

func appendUnique(list []string, v string, fold bool) []string {
	for _, x := range list {
		if x == v || (fold && strings.EqualFold(x, v)) {
			return list
		}
	}
	return append(list, v)
}

func removeValue(list []string, v string, fold bool) []string {
	out := list[:0:0]
	for _, x := range list {
		if x == v || (fold && strings.EqualFold(x, v)) {
			continue
		}
		out = append(out, x)
	}
	return out
}

func (w *Whitelist) Add(kind SuggestionKind, raw string) {
	v := Normalize(kind, raw)
	if v == "" {
		return
	}
	switch kind {
	case KindDomain:
		w.Domains = appendUnique(w.Domains, v, false)
	case KindPublisher:
		w.Publishers = appendUnique(w.Publishers, v, true)
	case KindSHA256:
		w.SHA256 = appendUnique(w.SHA256, v, false)
	}
}

func (w *Whitelist) Remove(kind SuggestionKind, raw string) {
	v := Normalize(kind, raw)
	switch kind {
	case KindDomain:
		w.Domains = removeValue(w.Domains, v, false)
	case KindPublisher:
		w.Publishers = removeValue(w.Publishers, v, true)
	case KindSHA256:
		w.SHA256 = removeValue(w.SHA256, v, false)
	}
}

func (w *Whitelist) AddExtension(raw string) {
	if v := trimDots(raw); v != "" {
		w.Extensions = appendUnique(w.Extensions, v, false)
	}
}

func (w *Whitelist) RemoveExtension(raw string) {
	w.Extensions = removeValue(w.Extensions, trimDots(raw), false)
}

// IsConsistent 掃描的 Claude 給的建議,必須和檔案的真實資料對得上才採用,
// 不然就是被檔案內容誤導(例如建議一個跟這次下載無關的網域)
func IsConsistent(s WhitelistSuggestion, f *FileFacts) bool {
	v := Normalize(s.Kind, s.Value)
	switch s.Kind {
	case KindSHA256:
		return f.SHA256 != "" && strings.ToLower(f.SHA256) == v
	case KindDomain:
		// 必須是下載網域或來源網頁網域本身(或其上層網域);只有頂級網域(例如 "com")不算
		if !strings.Contains(v, ".") {
			return false
		}
		for _, h := range []string{f.DownloadHost(), f.ReferrerHost()} {
			if h != "" && HostMatches(h, v) {
				return true
			}
		}
		return false
	case KindPublisher:
		return f.Signature != nil && f.Signature.Status == SigValid && f.Signature.Publisher != "" &&
			strings.EqualFold(f.Signature.Publisher, v)
	}
	return false
}

// MARK: - 存檔

func LoadWhitelist(path string) Whitelist {
	data, err := os.ReadFile(path)
	if err != nil {
		return DefaultWhitelist()
	}
	var w Whitelist
	if json.Unmarshal(data, &w) != nil {
		return DefaultWhitelist()
	}
	for _, p := range []*[]string{&w.Domains, &w.Publishers, &w.SHA256, &w.Extensions} {
		if *p == nil {
			*p = []string{}
		}
	}
	return w
}

func (w Whitelist) Save(path string) error {
	data, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(path, data)
}

// WriteFileAtomic 先寫暫存檔再改名,讀的一方不會讀到寫一半的檔案
func WriteFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
