// Package httpapi exposes the panel, the subscription endpoints and the
// control API.
package httpapi

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"warpsub/internal/account"
	"warpsub/internal/config"
	"warpsub/internal/model"
	"warpsub/internal/render"
	"warpsub/internal/scan"
	"warpsub/internal/store"
	"warpsub/internal/v2raya"
	"warpsub/internal/writeback"
)

//go:embed web/*.html
var webFS embed.FS

// Server wires everything together.
type Server struct {
	holder *config.Holder
	acct   *account.Account
	masque *account.MasqueAccount
	acctMu sync.RWMutex
	st     *store.Store
	acctStore *account.Store

	wb        *writeback.Syncer
	v2a       *v2raya.Syncer
	runMu     sync.Mutex
	running   bool
	runScan   func(ctx context.Context, opts scan.Options) (model.Report, error)
}

// New builds the HTTP server.
func New(holder *config.Holder, acct *account.Account, masque *account.MasqueAccount, st *store.Store,
	acctStore *account.Store, wb *writeback.Syncer, v2a *v2raya.Syncer,
	run func(ctx context.Context, opts scan.Options) (model.Report, error)) *Server {
	return &Server{holder: holder, acct: acct, masque: masque, st: st, acctStore: acctStore,
		wb: wb, v2a: v2a, runScan: run}
}

func (s *Server) authorized(r *http.Request) bool {
	cfg := s.holder.Get()
	if cfg.Token == "" {
		return true
	}
	if r.URL.Query().Get("token") == cfg.Token {
		return true
	}
	return r.Header.Get("X-Warp-Token") == cfg.Token
}

// Handler returns the root mux.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/simple", s.handleSimple)
	mux.HandleFunc("/sub", s.handleSub)
	mux.HandleFunc("/api/state", s.handleState)
	mux.HandleFunc("/api/report", s.handleReport)
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/license", s.handleLicense)
	mux.HandleFunc("/api/history", s.handleHistory)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/writeback", s.handleWriteback)
	mux.HandleFunc("/api/writeback/sync", s.handleWritebackSync)
	mux.HandleFunc("/api/v2raya", s.handleV2raya)
	mux.HandleFunc("/api/v2raya/test", s.handleV2rayaTest)
	mux.HandleFunc("/api/v2raya/sync", s.handleV2rayaSync)
	return mux
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	raw, err := webFS.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "panel missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(raw)
}

func (s *Server) handleSimple(w http.ResponseWriter, r *http.Request) {
	raw, err := webFS.ReadFile("web/simple.html")
	if err != nil {
		http.Error(w, "page missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(raw)
}

func (s *Server) handleSub(w http.ResponseWriter, r *http.Request) {
	cur := s.holder.Get()
	if cur.Token != "" && r.URL.Query().Get("token") != cur.Token {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	target := strings.ToLower(r.URL.Query().Get("target"))
	if target == "" {
		target = "clash"
	}
	only := strings.ToLower(r.URL.Query().Get("only"))

	rep := s.st.Report()
	nodes := rep.Nodes
	if only != "" {
		filtered := make([]model.Node, 0, len(nodes))
		for _, n := range nodes {
			if strings.Contains(n.Class, only) {
				filtered = append(filtered, n)
			}
		}
		nodes = filtered
	}

	s.acctMu.RLock()
	acct := s.acct
	s.acctMu.RUnlock()

	s.acctMu.RLock()
	mq := s.masque
	s.acctMu.RUnlock()
	opt := render.Options{Account: acct, Masque: mq, Config: cur}

	w.Header().Set("Profile-Update-Interval", itoa(maxInt(1, cur.Subtpl.UpdateHours)))
	w.Header().Set("Cache-Control", "no-store")

	switch target {
	case "v2ray", "v2rayn", "base64":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(render.V2Ray(nodes, opt)))
	default:
		w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		w.Write([]byte(render.Clash(nodes, opt)))
	}
}

type stateResp struct {
	GeneratedAt string       `json:"generated_at"`
	DurationSec float64      `json:"duration_sec"`
	Candidates  int          `json:"candidates"`
	Passed      int          `json:"passed"`
	Running     bool         `json:"running"`
	StartedAt   string       `json:"started_at"`
	Account     accountView  `json:"account"`
	Masque      masqueView   `json:"masque"`
	Nodes       []model.Node `json:"nodes"`
	Rejected    []model.Node `json:"rejected"`
	Counts      map[string]int `json:"counts"`
	DiagCounts  map[string]int `json:"diag_counts"`
}

type masqueView struct {
	Registered bool   `json:"registered"`
	AddressV4  string `json:"address_v4"`
	Endpoint   string `json:"endpoint"`
}

type accountView struct {
	Registered  bool   `json:"registered"`
	AccountType string `json:"account_type"`
	License     string `json:"license"`
	AddressV4   string `json:"address_v4"`
	ClientID    string `json:"client_id"`
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	rep := s.st.Report()
	running, started := s.st.State()

	s.acctMu.RLock()
	av := accountView{}
	if s.acct != nil {
		av = accountView{
			Registered:  true,
			AccountType: s.acct.AccountType,
			License:     s.acct.License,
			AddressV4:   s.acct.AddressV4,
			ClientID:    s.acct.ClientID,
		}
	}
	s.acctMu.RUnlock()

	mv := masqueView{}
	s.acctMu.RLock()
	if s.masque != nil {
		mv = masqueView{Registered: true, AddressV4: s.masque.AddressV4, Endpoint: s.masque.Endpoint}
	}
	s.acctMu.RUnlock()

	counts := map[string]int{}
	for _, n := range rep.Nodes {
		counts[n.Class]++
	}

	out := stateResp{
		DurationSec: rep.DurationSec,
		Candidates:  rep.Candidates,
		Passed:      rep.Passed,
		Running:     running,
		StartedAt:   started,
		Account:     av,
		Masque:      mv,
		Nodes:       rep.Nodes,
		Rejected:    rep.Rejected,
		Counts:      counts,
		DiagCounts:  rep.DiagCounts,
	}
	if !rep.GeneratedAt.IsZero() {
		out.GeneratedAt = rep.GeneratedAt.Format("2006-01-02 15:04:05")
	}
	writeJSON(w, out)
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	writeJSON(w, s.st.Report())
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.runMu.Lock()
	if s.running {
		s.runMu.Unlock()
		writeJSON(w, map[string]any{"ok": false, "error": "扫描已在运行"})
		return
	}
	s.running = true
	s.runMu.Unlock()

	full := r.URL.Query().Get("full") == "1" || r.URL.Query().Get("full") == "true"
	go func() {
		defer func() {
			s.runMu.Lock()
			s.running = false
			s.runMu.Unlock()
		}()
		timeout := 2 * time.Hour
		if full {
			timeout = 12 * time.Hour
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		if _, err := s.runScan(ctx, scan.Options{Full: full}); err != nil {
			log.Printf("api: scan failed: %v", err)
		}
	}()
	writeJSON(w, map[string]any{"ok": true, "full": full})
}

func (s *Server) handleLicense(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		License string `json:"license"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": "请求格式错误"})
		return
	}
	s.acctMu.Lock()
	defer s.acctMu.Unlock()
	if s.acct == nil {
		writeJSON(w, map[string]any{"ok": false, "error": "尚未注册 WARP 账号"})
		return
	}
	if err := s.acct.ApplyLicense(body.License); err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if err := s.acctStore.Save(s.acct); err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": "保存失败: " + err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "license": s.acct.License})
}

// handleConfig exposes and edits the effective configuration.
//
// GET returns the schema plus current values; POST accepts a flat map of
// dot-path -> value, validates the result, writes data/override.json and swaps
// the live config so the next scan uses it without a restart.
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	switch r.Method {
	case http.MethodGet:
		cur := s.holder.Get()
		writeJSON(w, map[string]any{
			"ok":       true,
			"groups":   config.Schema(),
			"sections": cur.Describe(),
			"values":   cur.Map(),
			"env":      config.ActiveEnv(),
		})
	case http.MethodPost:
		var body struct {
			Values map[string]any `json:"values"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, map[string]any{"ok": false, "error": "请求格式错误"})
			return
		}
		cur := s.holder.Get()
		base := cur.Map()
		for k, v := range body.Values {
			config.SetPath(base, k, v)
		}
		next, err := config.FromMap(base)
		if err != nil {
			writeJSON(w, map[string]any{"ok": false, "error": "配置解析失败: " + err.Error()})
			return
		}
		if errs := config.Validate(next); len(errs) > 0 {
			writeJSON(w, map[string]any{"ok": false, "errors": errs})
			return
		}
		if err := config.SaveOverlay(next.DataDir, base); err != nil {
			writeJSON(w, map[string]any{"ok": false, "error": "保存失败: " + err.Error()})
			return
		}
		s.holder.Set(next)

		// tell the UI which of the changed fields only apply after a restart
		var restart []string
		for _, g := range config.Schema() {
			for _, f := range g.Fields {
				if !f.Restart {
					continue
				}
				a, _ := config.GetPath(cur.Map(), f.Key)
				b, _ := config.GetPath(next.Map(), f.Key)
				if fmt.Sprint(a) != fmt.Sprint(b) {
					restart = append(restart, f.Label)
				}
			}
		}
		writeJSON(w, map[string]any{"ok": true, "restart": restart})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	writeJSON(w, s.st.History())
}

type writebackView struct {
	Enabled  bool   `json:"enabled"`
	BaseURL  string `json:"base_url"`
	Auto     bool   `json:"auto"`
	HasPass  bool   `json:"has_password"`
	Last     writeback.Result `json:"last"`
}

func (s *Server) handleWriteback(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if s.wb == nil {
		writeJSON(w, map[string]any{"ok": false, "error": "writeback 未初始化"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.writeWriteback(w)
	case http.MethodPost:
		var body struct {
			Enabled  bool   `json:"enabled"`
			BaseURL  string `json:"base_url"`
			Password string `json:"password"`
			Auto     bool   `json:"auto"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, map[string]any{"ok": false, "error": "请求格式错误"})
			return
		}
		cur := s.wb.Settings()
		next := writeback.Settings{
			Enabled:  body.Enabled,
			BaseURL:  body.BaseURL,
			Password: body.Password,
			Auto:     body.Auto,
		}
		// an empty password field means "keep the stored one"
		if strings.TrimSpace(next.Password) == "" {
			next.Password = cur.Password
		}
		if err := s.wb.Update(next); err != nil {
			writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		s.writeWriteback(w)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) writeWriteback(w http.ResponseWriter) {
	cur := s.wb.Settings()
	writeJSON(w, map[string]any{
		"ok": true,
		"writeback": writebackView{
			Enabled: cur.Enabled,
			BaseURL: cur.BaseURL,
			Auto:    cur.Auto,
			HasPass: cur.Password != "",
			Last:    s.wb.Last(),
		},
	})
}

func (s *Server) handleWritebackSync(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.wb == nil {
		writeJSON(w, map[string]any{"ok": false, "error": "writeback 未初始化"})
		return
	}
	rep := s.st.Report()
	res := s.wb.Sync(rep.Nodes)
	writeJSON(w, map[string]any{"ok": res.OK, "result": res})
}

func (s *Server) handleV2raya(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if s.v2a == nil {
		writeJSON(w, map[string]any{"ok": false, "error": "v2rayA 未初始化"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		cur := s.v2a.Settings()
		writeJSON(w, map[string]any{
			"ok": true,
			"v2raya": map[string]any{
				"enabled":        cur.Enabled,
				"base_url":       cur.BaseURL,
				"username":       cur.Username,
				"auto":           cur.Auto,
				"subscription_url": cur.SubURL,
				"has_password":   cur.Password != "",
				"last":           s.v2a.Last(),
			},
		})
	case http.MethodPost:
		var body struct {
			Enabled  bool   `json:"enabled"`
			BaseURL  string `json:"base_url"`
			Username string `json:"username"`
			Password string `json:"password"`
			Auto     bool   `json:"auto"`
			SubURL   string `json:"subscription_url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, map[string]any{"ok": false, "error": "请求格式错误"})
			return
		}
		cur := s.v2a.Settings()
		next := v2raya.Settings{
			Enabled:  body.Enabled,
			BaseURL:  body.BaseURL,
			Username: body.Username,
			Password: body.Password,
			Auto:     body.Auto,
			SubURL:   body.SubURL,
		}
		if strings.TrimSpace(next.Password) == "" {
			next.Password = cur.Password
		}
		if strings.TrimSpace(next.Username) == "" {
			next.Username = cur.Username
		}
		if err := s.v2a.Update(next); err != nil {
			writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleV2rayaTest(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost || s.v2a == nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	cur := s.v2a.Settings()
	subs, err := s.v2a.Test(cur.BaseURL, cur.Username, cur.Password)
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "subscriptions": subs})
}

func (s *Server) handleV2rayaSync(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.v2a == nil {
		writeJSON(w, map[string]any{"ok": false, "error": "v2rayA 未初始化"})
		return
	}
	res := s.v2a.Sync()
	writeJSON(w, map[string]any{"ok": res.OK, "result": res})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [8]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
