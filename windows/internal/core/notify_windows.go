//go:build windows

package core

import (
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// watchTree 用 ReadDirectoryChangesW 監看資料夾,每個變動的路徑都呼叫 onPath(在背景 goroutine)。
func watchTree(root string, recursive bool, onPath func(string)) (func(), error) {
	p, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.FILE_LIST_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		return nil, err
	}
	ioEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	stopEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		windows.CloseHandle(ioEvent)
		windows.CloseHandle(h)
		return nil, err
	}
	finished := make(chan struct{})

	go func() {
		defer close(finished)
		defer windows.CloseHandle(h)
		defer windows.CloseHandle(ioEvent)
		buf := make([]uint32, 16<<10) // 64 KB,DWORD 對齊
		const filter = windows.FILE_NOTIFY_CHANGE_FILE_NAME | windows.FILE_NOTIFY_CHANGE_DIR_NAME |
			windows.FILE_NOTIFY_CHANGE_SIZE | windows.FILE_NOTIFY_CHANGE_LAST_WRITE | windows.FILE_NOTIFY_CHANGE_CREATION
		for {
			var ov windows.Overlapped
			ov.HEvent = ioEvent
			_ = windows.ResetEvent(ioEvent)
			err := windows.ReadDirectoryChanges(h, (*byte)(unsafe.Pointer(&buf[0])), uint32(len(buf)*4),
				recursive, filter, nil, &ov, 0)
			if err != nil {
				return
			}
			ev, _ := windows.WaitForMultipleObjects([]windows.Handle{ioEvent, stopEvent}, false, windows.INFINITE)
			if ev != windows.WAIT_OBJECT_0 {
				_ = windows.CancelIoEx(h, &ov)
				var n uint32
				_ = windows.GetOverlappedResult(h, &ov, &n, true)
				return
			}
			var n uint32
			if windows.GetOverlappedResult(h, &ov, &n, false) != nil {
				return
			}
			if n == 0 {
				continue // 緩衝區滿了,這一批事件遺失
			}
			raw := unsafe.Slice((*byte)(unsafe.Pointer(&buf[0])), n)
			for off := uint32(0); off+12 <= n; {
				info := (*windows.FileNotifyInformation)(unsafe.Pointer(&raw[off]))
				name := windows.UTF16ToString(unsafe.Slice(&info.FileName, info.FileNameLength/2))
				// 替代資料流的變動(例如瀏覽器寫入 Zone.Identifier)回報成「檔名:資料流」,歸到檔案本身
				if i := strings.IndexByte(name, ':'); i >= 0 {
					name = name[:i]
				}
				if info.Action != windows.FILE_ACTION_REMOVED && info.Action != windows.FILE_ACTION_RENAMED_OLD_NAME {
					onPath(filepath.Join(root, name))
				}
				if info.NextEntryOffset == 0 {
					break
				}
				off += info.NextEntryOffset
			}
		}
	}()

	return func() {
		_ = windows.SetEvent(stopEvent)
		<-finished
		windows.CloseHandle(stopEvent)
	}, nil
}
