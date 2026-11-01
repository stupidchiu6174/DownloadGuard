package main

import (
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
)

// 介面是本機網頁(只聽 127.0.0.1)。安全:
//   - 每次啟動產生隨機權杖,API 一律要帶 X-Token 標頭(別的網站的頁面送不出自訂標頭,沒有 CORS 就擋掉了)
//   - 檢查 Host 標頭,防 DNS rebinding
//   - 通知按鈕用的 /act 是 GET,權杖放在網址裡

//go:embed ui.html
var uiHTML []byte

type Server struct {
	ctrl  *Controller
	Token string
	Port  int
}

func NewServer(ctrl *Controller) (*Server, net.Listener, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	var b [24]byte
	_, _ = rand.Read(b[:])
	s := &Server{ctrl: ctrl, Token: hex.EncodeToString(b[:]), Port: ln.Addr().(*net.TCPAddr).Port}
	return s, ln, nil
}

func (s *Server) Base() string { return "http://127.0.0.1:" + strconv.Itoa(s.Port) }

// URL 打開介面用的網址(權杖放在 # 後面,不會送到伺服器記錄或 Referer)
func (s *Server) URL() string { return s.Base() + "/#t=" + s.Token }

func (s *Server) ActionURL(op, id string) string {
	return s.Base() + "/act?t=" + s.Token + "&op=" + op + "&id=" + id
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'")
		_, _ = w.Write(uiHTML)
	})
	mux.HandleFunc("/api/state", s.api(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.ctrl.State())
	}))
	mux.HandleFunc("/api/settings", s.api(func(w http.ResponseWriter, r *http.Request) {
		var patch map[string]any
		if json.NewDecoder(r.Body).Decode(&patch) != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		s.ctrl.UpdateSettings(patch)
		writeJSON(w, s.ctrl.State())
	}))
	mux.HandleFunc("/api/action", s.api(func(w http.ResponseWriter, r *http.Request) {
		var a struct{ Op, ID, Kind, Value string }
		if json.NewDecoder(r.Body).Decode(&a) != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		s.ctrl.Act(a.Op, a.ID, a.Kind, a.Value)
		writeJSON(w, s.ctrl.State())
	}))
	// 通知按鈕
	mux.HandleFunc("/act", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if !s.hostOK(r) || q.Get("t") != s.Token {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if op := q.Get("op"); op != "show" {
			s.ctrl.Act(op, q.Get("id"), "", "")
		}
		http.Redirect(w, r, "/#t="+s.Token, http.StatusSeeOther)
	})
	return mux
}

func (s *Server) hostOK(r *http.Request) bool {
	p := strconv.Itoa(s.Port)
	return r.Host == "127.0.0.1:"+p || r.Host == "localhost:"+p
}

func (s *Server) api(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.hostOK(r) || r.Header.Get("X-Token") != s.Token {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "unsupported", http.StatusUnsupportedMediaType)
			return
		}
		h(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}
