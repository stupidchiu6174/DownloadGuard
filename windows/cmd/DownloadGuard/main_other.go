//go:build !windows

package main

import (
	"fmt"
	"net/http"
	"os/exec"
)

// 非 Windows 平台只用來開發介面:不放系統匣,直接印出網址
func main() {
	ctrl := NewController()
	srv, ln, err := NewServer(ctrl)
	if err != nil {
		panic(err)
	}
	ctrl.Notify = func(title, body, id string, _ []NotifyAction) { fmt.Println("[通知]", title, "—", body) }
	ctrl.Restore()
	fmt.Println(srv.URL())
	_ = http.Serve(ln, srv.Handler())
}

func openFolder(dir string)      { _ = exec.Command("xdg-open", dir).Start() }
func revealFile(path string)     { _ = exec.Command("xdg-open", path).Start() }
func autostartEnabled() bool     { return false }
func setAutostart(on bool) error { return fmt.Errorf("只有 Windows 支援") }
