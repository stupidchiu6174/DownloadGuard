#!/usr/bin/env bash
# 交叉編譯 Windows 版(x64 與 ARM64),輸出到 dist/DownloadGuard-windows-<架構>.zip
set -euo pipefail
cd "$(dirname "$0")"
version="${VERSION:-$(git describe --tags --always 2>/dev/null || echo dev)}"
rm -rf dist
for arch in amd64 arm64; do
  out="dist/DownloadGuard-windows-$arch"
  mkdir -p "$out"
  # 主程式不開主控台視窗;liri-scan 是 MCP 伺服器,要用主控台(stdin / stdout)
  GOOS=windows GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -H windowsgui" -o "$out/DownloadGuard.exe" ./cmd/DownloadGuard
  GOOS=windows GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$out/liri-scan.exe" ./cmd/liri-scan
  cp README.md "$out/README.md"
  echo "$version" > "$out/VERSION.txt"
  (cd dist && zip -qr "DownloadGuard-windows-$arch.zip" "DownloadGuard-windows-$arch")
done
ls -l dist/*.zip
