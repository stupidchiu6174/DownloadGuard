package core

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf16"
)

// 收集一個下載檔的客觀資料。全程不執行、不打開檔案:
// 只讀位元組、讀 Zone.Identifier、用 PowerShell 的 Get-AuthenticodeSignature 驗簽章。

var (
	MediaExts = set("jpg", "jpeg", "png", "gif", "heic", "heif", "webp", "tif", "tiff", "bmp", "svg", "ico",
		"mp4", "mov", "m4v", "mkv", "avi", "webm", "wmv", "mp3", "m4a", "wav", "aac", "flac", "ogg", "opus", "wma")
	DocumentExts = set("pdf", "txt", "md", "rtf", "csv", "json", "yaml", "yml", "xml", "doc", "docx", "docm",
		"xls", "xlsx", "xlsm", "ppt", "pptx", "pptm", "odt", "ods", "odp", "epub", "srt", "ttf", "otf", "vrm",
		"fbx", "obj", "glb", "gltf", "blend", "psd", "kra", "unitypackage")
	ExecExts = set("exe", "scr", "com", "pif", "cpl", "dll", "sys", "ocx", "drv")
	// 點兩下就會執行程式碼的類型
	ScriptExts = set("bat", "cmd", "ps1", "psm1", "psd1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "lnk",
		"url", "scf", "reg", "jar", "py", "pyw", "chm", "msc", "inf", "settingcontent-ms", "appref-ms",
		"library-ms", "application", "gadget", "xll", "iqy", "slk")
	DiskImageExts = set("iso", "img", "vhd", "vhdx")
	InstallerExts = set("msi", "msp", "msix", "msixbundle", "appx", "appxbundle", "appinstaller")
	ArchiveExts   = set("zip", "tar", "gz", "tgz", "bz2", "tbz2", "xz", "7z", "rar", "zst", "cab", "arj", "lzh")
)

func set(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, s := range items {
		m[s] = true
	}
	return m
}

func extOf(name string) string {
	return strings.ToLower(strings.TrimPrefix(filepath.Ext(strings.ReplaceAll(name, "\\", "/")), "."))
}

const maxListing = 300

func Inspect(path string) *FileFacts {
	name := filepath.Base(path)
	f := &FileFacts{Path: path, Name: name, Ext: extOf(name), Category: CatOther}
	f.DeceptiveName = deceptiveName(name)
	readZone(f)

	st, err := os.Stat(path)
	if err != nil {
		f.Notes = append(f.Notes, "讀不到檔案:"+err.Error())
		return f
	}
	if st.IsDir() {
		f.FileType = "directory"
		f.Category = CatFolder
		f.Size, f.Contents = listDirectory(path)
		return f
	}

	f.Size = st.Size()
	f.SHA256 = fileSHA256(path)
	head := readHead(path, 0x8006)
	f.FileType, f.Category = classify(f.Ext, head, path)
	looksHarmless := MediaExts[f.Ext] || DocumentExts[f.Ext]
	f.Disguised = looksHarmless && (f.Category == CatExecutable || f.Category == CatScript) && !ScriptExts[f.Ext]

	switch f.Category {
	case CatExecutable, CatInstaller:
		f.Signature = Authenticode(path)
	case CatScript:
		if f.Ext == "ps1" || f.Ext == "psm1" || f.Ext == "vbs" || f.Ext == "js" || f.Ext == "wsf" {
			f.Signature = Authenticode(path)
		}
	}
	switch f.Category {
	case CatArchive, CatDiskImage, CatInstaller:
		if c, err := OpenContainer(path, f.Ext); err == nil {
			for _, m := range c.Members() {
				f.Contents = append(f.Contents, m.Name)
			}
			c.Close()
			if f.Category != CatInstaller {
				f.Notes = append(f.Notes, "沒有解壓縮,裡面的程式沒有檢查簽章")
			}
		} else if f.Category != CatInstaller {
			f.Notes = append(f.Notes, "看不到裡面的檔案:"+err.Error())
		}
	}
	return f
}

// MARK: - 分類(看開頭的位元組,不信副檔名)

func classify(ext string, head []byte, path string) (string, FileCategory) {
	has := func(p string) bool { return bytes.HasPrefix(head, []byte(p)) }
	at := func(off int, p string) bool { return len(head) >= off+len(p) && string(head[off:off+len(p)]) == p }

	switch {
	case has("MZ"):
		desc := peDescription(head, path)
		if InstallerExts[ext] {
			return desc, CatInstaller
		}
		return desc, CatExecutable
	case has("\x7fELF"):
		return "ELF executable", CatExecutable
	case has("\xcf\xfa\xed\xfe") || has("\xce\xfa\xed\xfe") || has("\xca\xfe\xba\xbe"):
		if ext == "class" || ext == "jar" {
			return "Java class", CatScript
		}
		return "Mach-O executable", CatExecutable
	case has("L\x00\x00\x00\x01\x14\x02\x00"):
		return "Windows shortcut (.lnk)", CatScript
	case has("ITSF"):
		return "Compiled HTML Help (.chm)", CatScript
	case has("#!"):
		return "script text (shebang)", CatScript
	case has("PK\x03\x04") || has("PK\x05\x06"):
		switch {
		case InstallerExts[ext]:
			return "Windows app package (ZIP)", CatInstaller
		case ext == "jar":
			return "Java archive (ZIP)", CatScript
		case DocumentExts[ext]:
			return "Office Open XML / ZIP document", CatDocument
		}
		return "Zip archive", CatArchive
	case has("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
		if ext == "msi" || ext == "msp" {
			return "Windows Installer (OLE)", CatInstaller
		}
		return "OLE2 compound document (舊版 Office,可能含巨集)", CatDocument
	case has("MSCF"):
		return "Microsoft Cabinet archive", CatArchive
	case has("7z\xbc\xaf\x27\x1c"):
		return "7-zip archive", CatArchive
	case has("Rar!\x1a\x07"):
		return "RAR archive", CatArchive
	case has("\x1f\x8b"):
		return "gzip compressed data", CatArchive
	case has("BZh"):
		return "bzip2 compressed data", CatArchive
	case has("\xfd7zXZ\x00"):
		return "XZ compressed data", CatArchive
	case has("\x28\xb5\x2f\xfd"):
		return "Zstandard compressed data", CatArchive
	case at(257, "ustar"):
		return "POSIX tar archive", CatArchive
	case at(0x8001, "CD001"):
		return "ISO 9660 CD-ROM filesystem", CatDiskImage
	case has("vhdxfile") || has("conectix"):
		return "Virtual hard disk", CatDiskImage
	case has("%PDF"):
		return "PDF document", CatDocument
	case has("{\\rtf"):
		return "Rich Text Format", CatDocument
	case has("\x89PNG"), has("\xff\xd8\xff"), has("GIF8"), has("BM") && MediaExts[ext],
		has("RIFF") && (at(8, "WEBP") || at(8, "WAVE") || at(8, "AVI ")),
		at(4, "ftyp"), has("ID3"), has("OggS"), has("fLaC"), has("\x1a\x45\xdf\xa3"),
		has("\x30\x26\xb2\x75\x8e\x66\xcf\x11"):
		return "media (" + strings.ToUpper(ext) + ")", CatMedia
	}

	// 副檔名決定 Windows 怎麼打開它:文字檔取名 .bat / .js / .hta 一樣會執行
	if ScriptExts[ext] {
		return "script text (." + ext + ")", CatScript
	}
	if ExecExts[ext] {
		return "data (副檔名是 ." + ext + ",但不是 PE 執行檔)", CatOther
	}
	switch {
	case DiskImageExts[ext]:
		return "disk image", CatDiskImage
	case InstallerExts[ext]:
		return "installer package", CatInstaller
	case ArchiveExts[ext]:
		return "archive", CatArchive
	case MediaExts[ext]:
		return "media (" + strings.ToUpper(ext) + ")", CatMedia
	case DocumentExts[ext]:
		return "document (" + strings.ToUpper(ext) + ")", CatDocument
	}
	if looksLikeText(head) {
		return "text", CatOther
	}
	return "data", CatOther
}

// "PE32+ executable (GUI) x86-64" 這類說明
func peDescription(head []byte, path string) string {
	if len(head) < 0x40 {
		return "MS-DOS executable"
	}
	off := int(binary.LittleEndian.Uint32(head[0x3c:]))
	buf := head
	if off+0x60 > len(buf) {
		buf = readHead(path, off+0x60)
	}
	if off <= 0 || off+0x60 > len(buf) || string(buf[off:off+4]) != "PE\x00\x00" {
		return "MS-DOS executable"
	}
	machine := binary.LittleEndian.Uint16(buf[off+4:])
	chars := binary.LittleEndian.Uint16(buf[off+22:])
	magic := binary.LittleEndian.Uint16(buf[off+24:])
	subsystem := binary.LittleEndian.Uint16(buf[off+24+68:])
	kind := "PE32"
	if magic == 0x20b {
		kind = "PE32+"
	}
	what := "executable"
	if chars&0x2000 != 0 {
		what = "DLL"
	}
	sub := map[uint16]string{2: " (GUI)", 3: " (console)", 1: " (native/driver)"}[subsystem]
	arch := map[uint16]string{0x14c: " Intel 80386", 0x8664: " x86-64", 0xaa64: " ARM64", 0x1c4: " ARM"}[machine]
	return kind + " " + what + sub + arch
}

func looksLikeText(head []byte) bool {
	if len(head) == 0 {
		return false
	}
	n := min(len(head), 4096)
	bad := 0
	for _, b := range head[:n] {
		if b < 0x09 || (b > 0x0d && b < 0x20) {
			bad++
		}
	}
	return bad*20 < n
}

// MARK: - 檔名偽裝

var harmlessLooking = set("pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png",
	"gif", "mp4", "mp3", "mov", "zip", "rar", "csv", "rtf", "html", "htm")

func deceptiveName(name string) string {
	if strings.ContainsAny(name, "‮‭‏‎⁦⁧⁨") {
		return "檔名裡有反向文字字元,實際副檔名和看到的不一樣"
	}
	ext := extOf(name)
	if !(ExecExts[ext] || ScriptExts[ext] || ext == "msi") {
		return ""
	}
	base := strings.TrimSuffix(name, filepath.Ext(name))
	if strings.HasSuffix(base, "     ") || strings.Contains(base, "      .") {
		return fmt.Sprintf("檔名用一大串空白把真正的副檔名 .%s 擠到看不到的地方", ext)
	}
	if inner := extOf(strings.TrimRight(base, " ")); harmlessLooking[inner] {
		return fmt.Sprintf("雙重副檔名:看起來是 .%s,其實是 .%s(Windows 預設會隱藏後面那個)", inner, ext)
	}
	return ""
}

// MARK: - Zone.Identifier

// ParseZoneIdentifier 解析 Zone.Identifier 資料流:
//
//	[ZoneTransfer]
//	ZoneId=3
//	ReferrerUrl=https://example.com/
//	HostUrl=https://example.com/file.zip
func ParseZoneIdentifier(data []byte) (zone int, host, referrer string) {
	if len(data) >= 2 && data[0] == 0xff && data[1] == 0xfe { // 少數程式寫成 UTF-16
		u := make([]uint16, (len(data)-2)/2)
		for i := range u {
			u[i] = binary.LittleEndian.Uint16(data[2+i*2:])
		}
		data = []byte(string(utf16.Decode(u)))
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		switch strings.ToLower(k) {
		case "zoneid":
			zone, _ = strconv.Atoi(strings.TrimSpace(v))
		case "hosturl":
			host = strings.TrimSpace(v)
		case "referrerurl":
			referrer = strings.TrimSpace(v)
		}
	}
	return
}

const ZoneStream = "Zone.Identifier"

func readZone(f *FileFacts) {
	data, err := ReadStream(f.Path, ZoneStream)
	if err != nil || len(data) == 0 {
		return
	}
	f.ZoneID, f.HostURL, f.ReferrerURL = ParseZoneIdentifier(data)
}

// MARK: - 雜湊與內容

func fileSHA256(path string) string {
	h, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer h.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, h); err != nil {
		return ""
	}
	return hex.EncodeToString(sum.Sum(nil))
}

// 資料夾清單:相對路徑,最多三層
func listDirectory(root string) (int64, []string) {
	var total int64
	var out []string
	n := 0
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == root {
			return nil
		}
		n++
		if n > 20000 {
			return filepath.SkipAll
		}
		rel, _ := filepath.Rel(root, p)
		if strings.Count(rel, string(filepath.Separator)) >= 3 {
			if d.IsDir() {
				return filepath.SkipDir
			}
		} else if len(out) < maxListing {
			out = append(out, rel)
		}
		if info, err := d.Info(); err == nil && !d.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total, out
}

// PublisherFromSubject 從憑證 Subject("CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, C=US")
// 取出發行者:有 O= 用 O=,沒有就用 CN=
func PublisherFromSubject(subject string) string {
	fields := map[string]string{}
	var cur strings.Builder
	inQuote := false
	flush := func() {
		k, v, ok := strings.Cut(strings.TrimSpace(cur.String()), "=")
		if ok {
			k = strings.ToUpper(strings.TrimSpace(k))
			if _, dup := fields[k]; !dup {
				fields[k] = strings.Trim(strings.TrimSpace(v), `"`)
			}
		}
		cur.Reset()
	}
	for _, r := range subject {
		switch {
		case r == '"':
			inQuote = !inQuote
			cur.WriteRune(r)
		case r == ',' && !inQuote:
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	if o := fields["O"]; o != "" {
		return o
	}
	return fields["CN"]
}
