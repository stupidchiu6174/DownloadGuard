//go:build windows

package main

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"fyne.io/systray"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"downloadguard/internal/core"
)

// DownloadGuard.exe:常駐在系統匣,介面是本機網頁。
//
//	DownloadGuard.exe              啟動並打開介面(已經在跑就只打開介面)
//	DownloadGuard.exe --background 啟動但不打開介面(開機自動執行用)
func main() {
	background := len(os.Args) > 1 && os.Args[1] == "--background"

	// 只跑一份:已經在跑就叫它打開介面
	name, _ := windows.UTF16PtrFromString(`Local\DownloadGuard.Instance`)
	if _, err := windows.CreateMutex(nil, false, name); err == windows.ERROR_ALREADY_EXISTS {
		if !background {
			if data, err := os.ReadFile(instanceFile()); err == nil {
				var info struct{ URL string }
				if json.Unmarshal(data, &info) == nil && info.URL != "" {
					openURL(info.URL)
				}
			}
		}
		return
	}

	ctrl := NewController()
	srv, ln, err := NewServer(ctrl)
	if err != nil {
		messageBox("DownloadGuard 無法啟動", err.Error())
		return
	}
	go func() { _ = http.Serve(ln, srv.Handler()) }()
	data, _ := json.Marshal(map[string]string{"URL": srv.URL()})
	_ = core.WriteFileAtomic(instanceFile(), data)

	ctrl.Notify = func(title, body, id string, actions []NotifyAction) { showToast(srv, title, body, id, actions) }
	ctrl.Restore()

	systray.Run(func() {
		systray.SetIcon(trayIcon())
		systray.SetTitle("DownloadGuard")
		systray.SetTooltip(ctrl.Tooltip())
		open := systray.AddMenuItem("打開下載掃描", "")
		enabled := systray.AddMenuItemCheckbox("啟用下載掃描", "", ctrl.Enabled())
		holding := systray.AddMenuItem("打開小黑屋", "")
		systray.AddSeparator()
		quit := systray.AddMenuItem("結束", "")
		ctrl.OnChange = func() {
			systray.SetTooltip(ctrl.Tooltip())
			if ctrl.Enabled() {
				enabled.Check()
			} else {
				enabled.Uncheck()
			}
		}
		if !background {
			openURL(srv.URL())
		}
		go func() {
			for {
				select {
				case <-open.ClickedCh:
					openURL(srv.URL())
				case <-enabled.ClickedCh:
					ctrl.SetEnabled(!ctrl.Enabled())
				case <-holding.ClickedCh:
					ctrl.Act("openHolding", "", "", "")
				case <-quit.ClickedCh:
					systray.Quit()
					return
				}
			}
		}()
	}, func() {
		ctrl.Shutdown()
		_ = os.Remove(instanceFile())
	})
}

func instanceFile() string { return filepath.Join(core.SupportDir(), "instance.json") }

func shellOpen(target, args string) {
	verb, _ := windows.UTF16PtrFromString("open")
	t, _ := windows.UTF16PtrFromString(target)
	var a *uint16
	if args != "" {
		a, _ = windows.UTF16PtrFromString(args)
	}
	_ = windows.ShellExecute(0, verb, t, a, nil, windows.SW_SHOWNORMAL)
}

func openURL(u string)       { shellOpen(u, "") }
func openFolder(dir string)  { shellOpen(dir, "") }
func revealFile(path string) { shellOpen("explorer.exe", `/select,"`+path+`"`) }

func messageBox(title, text string) {
	t, _ := windows.UTF16PtrFromString(title)
	m, _ := windows.UTF16PtrFromString(text)
	_, _ = windows.MessageBox(0, m, t, windows.MB_ICONERROR)
}

// MARK: - 開機自動執行(HKCU\...\Run)

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`

func autostartEnabled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue("DownloadGuard")
	return err == nil
}

func setAutostart(on bool) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if !on {
		if err := k.DeleteValue("DownloadGuard"); err != nil && err != registry.ErrNotExist {
			return err
		}
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return k.SetStringValue("DownloadGuard", `"`+exe+`" --background`)
}

// MARK: - 通知(Windows toast,透過 PowerShell 的 WinRT;按鈕打開本機網址執行動作)

// Windows PowerShell 的 AppUserModelID:不用安裝就能發 toast
const toastAppID = `{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe`

const toastScript = `
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$x = New-Object Windows.Data.Xml.Dom.XmlDocument
$x.LoadXml($env:DG_TOAST)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($env:DG_APPID).Show([Windows.UI.Notifications.ToastNotification]::new($x))
`

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;").Replace(s)
}

func showToast(srv *Server, title, body, id string, actions []NotifyAction) {
	var b strings.Builder
	b.WriteString(`<toast activationType="protocol" launch="` + xmlEscape(srv.URL()) + `"`)
	if len(actions) > 0 {
		b.WriteString(` scenario="reminder"`)
	}
	b.WriteString(`><visual><binding template="ToastGeneric"><text>` + xmlEscape(title) + `</text><text>` +
		xmlEscape(truncate(body, 300)) + `</text><text placement="attribution">DownloadGuard</text></binding></visual>`)
	if len(actions) > 0 {
		b.WriteString(`<actions>`)
		for i, a := range actions {
			if i >= 5 { // toast 最多五個按鈕
				break
			}
			b.WriteString(`<action activationType="protocol" content="` + xmlEscape(a.Label) + `" arguments="` +
				xmlEscape(srv.ActionURL(a.Op, id)) + `"/>`)
		}
		b.WriteString(`</actions>`)
	}
	b.WriteString(`</toast>`)

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-EncodedCommand", core.EncodePowerShell(toastScript))
	cmd.Env = append(os.Environ(), "DG_TOAST="+b.String(), "DG_APPID="+toastAppID)
	core.HideWindow(cmd)
	_ = cmd.Run()
}
