//go:build !windows

package core

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"time"
)

// watchTree 非 Windows 平台用輪詢(只給開發時跑測試)
func watchTree(root string, recursive bool, onPath func(string)) (func(), error) {
	stop := make(chan struct{})
	state := map[string]string{}
	scan := func(emit bool) {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || p == root {
				return nil
			}
			if d.IsDir() && !recursive && strings.Count(p[len(root):], string(filepath.Separator)) > 1 {
				return filepath.SkipDir
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			sig := fmt.Sprintf("%d|%d", info.ModTime().UnixNano(), info.Size())
			if state[p] != sig {
				state[p] = sig
				if emit {
					onPath(p)
				}
			}
			return nil
		})
	}
	scan(false)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(200 * time.Millisecond):
				scan(true)
			}
		}
	}()
	return func() { close(stop) }, nil
}
