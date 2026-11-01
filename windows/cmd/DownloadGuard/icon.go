package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"math"
)

// 系統匣圖示:綠色盾牌加白色勾,程式畫出來再包成 .ico(未壓縮 32 位元,LoadImage 一定讀得了)

func shield(size int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	s := float64(size)
	fill := color.RGBA{0x1f, 0x9d, 0x55, 0xff}
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			// 4x4 超取樣讓邊緣平滑
			hits, check := 0, 0
			for sy := 0; sy < 4; sy++ {
				for sx := 0; sx < 4; sx++ {
					px := (float64(x) + (float64(sx)+0.5)/4) / s
					py := (float64(y) + (float64(sy)+0.5)/4) / s
					if inShield(px, py) {
						hits++
						if onCheck(px, py) {
							check++
						}
					}
				}
			}
			if hits == 0 {
				continue
			}
			a := float64(hits) / 16
			t := float64(check) / float64(hits)
			r := float64(fill.R)*(1-t) + 255*t
			g := float64(fill.G)*(1-t) + 255*t
			b := float64(fill.B)*(1-t) + 255*t
			// .ico 要的是未預乘的 alpha
			img.SetRGBA(x, y, color.RGBA{uint8(r), uint8(g), uint8(b), uint8(255 * a)})
		}
	}
	return img
}

// 盾牌:上半是有圓角的矩形,下半收成尖角
func inShield(x, y float64) bool {
	if y < 0.08 || y > 0.94 || x < 0.12 || x > 0.88 {
		return false
	}
	if y < 0.5 {
		return true
	}
	half := 0.38 * math.Sqrt(1-math.Pow((y-0.5)/0.44, 2))
	return math.Abs(x-0.5) <= half
}

func onCheck(x, y float64) bool {
	dist := func(ax, ay, bx, by float64) float64 {
		dx, dy := bx-ax, by-ay
		t := math.Max(0, math.Min(1, ((x-ax)*dx+(y-ay)*dy)/(dx*dx+dy*dy)))
		return math.Hypot(x-(ax+t*dx), y-(ay+t*dy))
	}
	const w = 0.065
	return dist(0.31, 0.5, 0.45, 0.65) < w || dist(0.45, 0.65, 0.7, 0.34) < w
}

func trayIcon() []byte {
	sizes := []int{16, 24, 32, 48}
	var images [][]byte
	for _, sz := range sizes {
		images = append(images, bmpEntry(shield(sz)))
	}
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, [3]uint16{0, 1, uint16(len(sizes))})
	offset := 6 + 16*len(sizes)
	for i, sz := range sizes {
		binary.Write(&buf, binary.LittleEndian, struct {
			W, H, Colors, Reserved uint8
			Planes, BPP            uint16
			Size, Offset           uint32
		}{uint8(sz), uint8(sz), 0, 0, 1, 32, uint32(len(images[i])), uint32(offset)})
		offset += len(images[i])
	}
	for _, img := range images {
		buf.Write(img)
	}
	return buf.Bytes()
}

func bmpEntry(img *image.RGBA) []byte {
	size := img.Rect.Dx()
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, struct {
		Size          uint32
		Width, Height int32
		Planes, BPP   uint16
		Compression   uint32
		ImageSize     uint32
		XPPM, YPPM    int32
		Used, Imp     uint32
	}{40, int32(size), int32(size * 2), 1, 32, 0, 0, 0, 0, 0, 0})
	for y := size - 1; y >= 0; y-- { // 由下往上
		for x := 0; x < size; x++ {
			c := img.RGBAAt(x, y)
			buf.Write([]byte{c.B, c.G, c.R, c.A})
		}
	}
	maskRow := ((size + 31) / 32) * 4
	buf.Write(make([]byte, maskRow*size)) // AND 遮罩全 0,透明度看 alpha
	return buf.Bytes()
}
