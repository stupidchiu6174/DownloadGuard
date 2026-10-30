package core

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf16"
)

// 不解壓、不掛載,直接讀壓縮檔與光碟映像裡的清單和內容(Windows 沒有 zipinfo / hdiutil 可借用,
// 而且掛載 ISO 會讓檔案總管自動打開它,正好是攻擊者想要的)。

type Member struct {
	Name string
	Size int64
	Dir  bool
}

type Container interface {
	Members() []Member
	Open(name string) (io.ReadCloser, error)
	Close() error
}

var errUnsupported = errors.New("這個類型的檔案不支援讀取內部項目")

const maxMembers = 300

func OpenContainer(path, ext string) (Container, error) {
	head := readHead(path, 0x8006)
	switch {
	case bytes.HasPrefix(head, []byte("PK\x03\x04")) || bytes.HasPrefix(head, []byte("PK\x05\x06")):
		zr, err := zip.OpenReader(path)
		if err != nil {
			return nil, err
		}
		return &zipContainer{zr}, nil
	case len(head) >= 0x8006 && string(head[0x8001:0x8006]) == "CD001":
		return openISO(path)
	case ext == "tar" || ext == "tgz" || ext == "gz" || ext == "bz2" || ext == "tbz2":
		return &tarContainer{path: path, ext: ext}, nil
	}
	return nil, errUnsupported
}

// MARK: - ZIP(含 .docx / .jar / .msix 這類 ZIP 格式)

type zipContainer struct{ zr *zip.ReadCloser }

func (z *zipContainer) Members() []Member {
	var out []Member
	for _, f := range z.zr.File {
		if len(out) >= maxMembers {
			break
		}
		out = append(out, Member{Name: f.Name, Size: int64(f.UncompressedSize64), Dir: f.FileInfo().IsDir()})
	}
	return out
}

func (z *zipContainer) Open(name string) (io.ReadCloser, error) {
	for _, f := range z.zr.File {
		if f.Name == name {
			if f.Flags&1 != 0 {
				return nil, fmt.Errorf("%s 有密碼保護", name)
			}
			return f.Open()
		}
	}
	return nil, fmt.Errorf("壓縮檔裡沒有 %s", name)
}

func (z *zipContainer) Close() error { return z.zr.Close() }

// MARK: - tar / tar.gz / tar.bz2

type tarContainer struct {
	path string
	ext  string
}

func (t *tarContainer) reader() (*tar.Reader, io.Closer, error) {
	f, err := os.Open(t.path)
	if err != nil {
		return nil, nil, err
	}
	var r io.Reader = f
	switch t.ext {
	case "tgz", "gz":
		gz, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return nil, nil, err
		}
		r = gz
	case "bz2", "tbz2":
		r = bzip2.NewReader(f)
	}
	return tar.NewReader(r), f, nil
}

func (t *tarContainer) Members() []Member {
	tr, c, err := t.reader()
	if err != nil {
		return nil
	}
	defer c.Close()
	var out []Member
	for len(out) < maxMembers {
		h, err := tr.Next()
		if err != nil {
			break
		}
		out = append(out, Member{Name: h.Name, Size: h.Size, Dir: h.Typeflag == tar.TypeDir})
	}
	return out
}

func (t *tarContainer) Open(name string) (io.ReadCloser, error) {
	tr, c, err := t.reader()
	if err != nil {
		return nil, err
	}
	for {
		h, err := tr.Next()
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("壓縮檔裡沒有 %s", name)
		}
		if h.Name == name {
			data, err := io.ReadAll(io.LimitReader(tr, iocMaxBytes))
			c.Close()
			return io.NopCloser(bytes.NewReader(data)), err
		}
	}
}

func (t *tarContainer) Close() error { return nil }

// MARK: - ISO 9660(優先讀 Joliet 長檔名)

type isoContainer struct {
	f       *os.File
	members []Member
	extents map[string][2]int64 // 名稱 → 位置、大小
}

func openISO(path string) (Container, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	c := &isoContainer{f: f, extents: map[string][2]int64{}}
	var root []byte
	joliet := false
	for sector := int64(16); sector < 64; sector++ {
		vd := make([]byte, 2048)
		if _, err := f.ReadAt(vd, sector*2048); err != nil || string(vd[1:6]) != "CD001" {
			break
		}
		if vd[0] == 255 {
			break
		}
		if vd[0] == 1 && root == nil {
			root = append([]byte(nil), vd[156:190]...)
		}
		if vd[0] == 2 && vd[88] == '%' && vd[89] == '/' && (vd[90] == '@' || vd[90] == 'C' || vd[90] == 'E') {
			root = append([]byte(nil), vd[156:190]...)
			joliet = true
		}
	}
	if root == nil {
		f.Close()
		return nil, errors.New("讀不到 ISO 的目錄(可能是 UDF 格式)")
	}
	c.walk(int64(binary.LittleEndian.Uint32(root[2:])), int64(binary.LittleEndian.Uint32(root[10:])), "", joliet, 0)
	return c, nil
}

func (c *isoContainer) walk(lba, size int64, prefix string, joliet bool, depth int) {
	if depth > 3 || size <= 0 || size > 1<<20 {
		return
	}
	buf := make([]byte, size)
	if _, err := c.f.ReadAt(buf, lba*2048); err != nil && !errors.Is(err, io.EOF) {
		return
	}
	for off := 0; off < len(buf) && len(c.members) < maxMembers; {
		n := int(buf[off])
		if n == 0 { // 這個磁區剩下的是填充,跳到下一個磁區
			off = (off/2048 + 1) * 2048
			continue
		}
		if off+n > len(buf) || n < 34 {
			return
		}
		rec := buf[off : off+n]
		off += n
		nameLen := int(rec[32])
		if 33+nameLen > len(rec) {
			continue
		}
		raw := rec[33 : 33+nameLen]
		if nameLen == 1 && (raw[0] == 0 || raw[0] == 1) {
			continue // . 和 ..
		}
		var name string
		if joliet {
			u := make([]uint16, nameLen/2)
			for i := range u {
				u[i] = binary.BigEndian.Uint16(raw[i*2:])
			}
			name = string(utf16.Decode(u))
		} else {
			name = string(raw)
		}
		if i := strings.LastIndexByte(name, ';'); i >= 0 {
			name = name[:i]
		}
		name = strings.TrimSuffix(name, ".")
		full := prefix + name
		extent := int64(binary.LittleEndian.Uint32(rec[2:]))
		length := int64(binary.LittleEndian.Uint32(rec[10:]))
		isDir := rec[25]&2 != 0
		c.members = append(c.members, Member{Name: full, Size: length, Dir: isDir})
		c.extents[full] = [2]int64{extent, length}
		if isDir {
			c.walk(extent, length, full+"/", joliet, depth+1)
		}
	}
}

func (c *isoContainer) Members() []Member { return c.members }

func (c *isoContainer) Open(name string) (io.ReadCloser, error) {
	e, ok := c.extents[name]
	if !ok {
		return nil, fmt.Errorf("映像檔裡沒有 %s", name)
	}
	return io.NopCloser(io.NewSectionReader(c.f, e[0]*2048, e[1])), nil
}

func (c *isoContainer) Close() error { return c.f.Close() }

func readHead(path string, n int) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	buf := make([]byte, n)
	k, _ := io.ReadFull(f, buf)
	return buf[:k]
}
