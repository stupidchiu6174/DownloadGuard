package core

import (
	"crypto/rand"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Verdict 掃描判定。順序有意義:越後面越嚴重(用來取兩個判定中比較嚴重的那個)。
type Verdict string

const (
	Safe       Verdict = "safe"
	Unknown    Verdict = "unknown"
	Suspicious Verdict = "suspicious"
	Malicious  Verdict = "malicious"
)

var verdictOrder = []Verdict{Safe, Unknown, Suspicious, Malicious}

func (v Verdict) rank() int {
	for i, x := range verdictOrder {
		if x == v {
			return i
		}
	}
	return 1
}

func (v Verdict) Label() string {
	switch v {
	case Safe:
		return "安全"
	case Suspicious:
		return "可疑"
	case Malicious:
		return "惡意"
	default:
		return "無法判定"
	}
}

// MaxVerdict 取比較嚴重的那個
func MaxVerdict(a, b Verdict) Verdict {
	if a.rank() >= b.rank() {
		return a
	}
	return b
}

func (v Verdict) Less(b Verdict) bool { return v.rank() < b.rank() }

// FileCategory 依「打開它會發生什麼事」分類,不是依副檔名:一個 .jpg 如果其實是 PE 執行檔,就歸在 executable。
type FileCategory string

const (
	CatExecutable FileCategory = "executable"
	CatDiskImage  FileCategory = "diskImage"
	CatInstaller  FileCategory = "installerPackage"
	CatArchive    FileCategory = "archive"
	CatScript     FileCategory = "script"
	CatDocument   FileCategory = "document"
	CatMedia      FileCategory = "media"
	CatFolder     FileCategory = "folder"
	CatOther      FileCategory = "other"
)

// CanRunCode 打開或執行後可能跑程式碼的類別
func (c FileCategory) CanRunCode() bool {
	switch c {
	case CatExecutable, CatDiskImage, CatInstaller, CatArchive, CatScript, CatFolder:
		return true
	}
	return false
}

type SigStatus string

const (
	SigUnsigned  SigStatus = "unsigned"
	SigUntrusted SigStatus = "untrusted" // 自簽或憑證鏈不受信任
	SigValid     SigStatus = "valid"
	SigInvalid   SigStatus = "invalid" // 內容和簽章對不上(可能被竄改)
)

// SignatureInfo Authenticode 簽章(Get-AuthenticodeSignature)
type SignatureInfo struct {
	Status SigStatus `json:"status"`
	// 發行者:憑證 Subject 的 O=(沒有就用 CN=),白名單比對用這個
	Publisher   string `json:"publisher,omitempty"`
	Subject     string `json:"subject,omitempty"`
	Issuer      string `json:"issuer,omitempty"`
	Thumbprint  string `json:"thumbprint,omitempty"`
	Timestamped bool   `json:"timestamped,omitempty"`
	IsOSBinary  bool   `json:"isOSBinary,omitempty"`
	Message     string `json:"message,omitempty"`
}

type FileFacts struct {
	Path     string       `json:"path"`
	Name     string       `json:"name"`
	Ext      string       `json:"ext"`
	Size     int64        `json:"size"`
	SHA256   string       `json:"sha256,omitempty"`
	FileType string       `json:"fileType"`
	Category FileCategory `json:"category"`
	// 副檔名看起來是文件/影音,實際內容卻是程式或腳本
	Disguised bool `json:"disguised"`
	// 檔名的偽裝手法(雙重副檔名、反向字元、一大串空白)
	DeceptiveName string `json:"deceptiveName,omitempty"`
	// Zone.Identifier(Windows 的「網際網路下載」標記)
	ZoneID      int            `json:"zoneId,omitempty"`
	HostURL     string         `json:"hostUrl,omitempty"`
	ReferrerURL string         `json:"referrerUrl,omitempty"`
	Signature   *SignatureInfo `json:"signature,omitempty"`
	// 壓縮檔 / 磁碟映像 / 資料夾內的檔案清單(有上限)
	Contents []string `json:"contents,omitempty"`
	// 檢查過程中失敗但不致命的步驟
	Notes []string `json:"notes,omitempty"`
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func (f *FileFacts) DownloadHost() string { return hostOf(f.HostURL) }
func (f *FileFacts) ReferrerHost() string { return hostOf(f.ReferrerURL) }

type Severity string

const (
	SevInfo     Severity = "info"
	SevWarning  Severity = "warning"
	SevCritical Severity = "critical"
)

// Signal 本機規則(不經過 Claude)找到的警訊
type Signal struct {
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
}

type SuggestionKind string

const (
	KindDomain    SuggestionKind = "domain"
	KindPublisher SuggestionKind = "publisher"
	KindSHA256    SuggestionKind = "sha256"
)

// WhitelistSuggestion 掃描的 Claude 建議加入白名單的規則(要使用者按一下才生效)
type WhitelistSuggestion struct {
	Kind   SuggestionKind `json:"kind"`
	Value  string         `json:"value"`
	Reason string         `json:"reason,omitempty"`
}

func (s WhitelistSuggestion) Label() string {
	switch s.Kind {
	case KindDomain:
		return "網域 " + s.Value
	case KindPublisher:
		return "發行者 " + s.Value
	default:
		v := s.Value
		if len(v) > 12 {
			v = v[:12]
		}
		return "這個檔案(SHA-256 " + v + "…)"
	}
}

// ClaudeVerdict Claude 透過 submit_verdict 回報的結果
type ClaudeVerdict struct {
	Verdict    Verdict              `json:"verdict"`
	Confidence *float64             `json:"confidence,omitempty"`
	Summary    string               `json:"summary"`
	Reasons    []string             `json:"reasons"`
	Suggestion *WhitelistSuggestion `json:"suggestion,omitempty"`
}

type OutcomeSource string

const (
	SourceWhitelist OutcomeSource = "whitelist"
	SourceClaude    OutcomeSource = "claude"
	SourceLocalOnly OutcomeSource = "localOnly"
)

type ScanOutcome struct {
	ID          string        `json:"id"`
	Date        time.Time     `json:"date"`
	Path        string        `json:"path"`
	Name        string        `json:"name"`
	SHA256      string        `json:"sha256,omitempty"`
	DownloadURL string        `json:"downloadURL,omitempty"`
	Publisher   string        `json:"publisher,omitempty"`
	Source      OutcomeSource `json:"source"`
	// 命中的白名單規則(Source == whitelist 時)
	WhitelistRule string         `json:"whitelistRule,omitempty"`
	Claude        *ClaudeVerdict `json:"claude,omitempty"`
	Signals       []Signal       `json:"signals"`
	// 最終判定:Claude 和本機規則取比較嚴重的那個(本機規則最多拉到「可疑」)
	Verdict         Verdict  `json:"verdict"`
	Summary         string   `json:"summary"`
	Error           string   `json:"error,omitempty"`
	CostUSD         *float64 `json:"costUSD,omitempty"`
	DurationSeconds float64  `json:"durationSeconds"`
	// 被移到隔離區之後的位置
	QuarantinedPath string `json:"quarantinedPath,omitempty"`
}

func NewID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
