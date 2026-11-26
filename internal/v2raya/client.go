// Package v2raya syncs the generated subscription into a running v2rayA
// instance over its HTTP API.
package v2raya

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Settings is user controlled and persisted in data/v2raya.json.
type Settings struct {
	Enabled  bool   `json:"enabled"`
	BaseURL  string `json:"base_url"`         // http://192.168.1.2:2017
	Username string `json:"username"`
	Password string `json:"password"`
	Auto     bool   `json:"auto"`             // sync after every scan
	SubURL   string `json:"subscription_url"` // URL v2rayA should fetch, must be reachable from v2rayA
}

// Result records the outcome of the last sync.
type Result struct {
	At      string `json:"at"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	Action  string `json:"action"` // imported | refreshed
	SubID   int    `json:"sub_id"`
}

// Sub is one subscription as reported by v2rayA.
type Sub struct {
	ID      int    `json:"id"`
	Address string `json:"address"`
	Count   int    `json:"count"`
	Status  string `json:"status"`
}

// Syncer owns settings plus the last result.
type Syncer struct {
	mu       sync.Mutex
	path     string
	dataDir  string
	settings Settings
	last     Result
}

// New loads data/v2raya.json.
func New(dataDir string) *Syncer {
	s := &Syncer{path: filepath.Join(dataDir, "v2raya.json"), dataDir: dataDir}
	if raw, err := os.ReadFile(s.path); err == nil {
		_ = json.Unmarshal(raw, &s.settings)
	}
	return s
}

// Settings returns a copy.
func (s *Syncer) Settings() Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settings
}

// Last returns the last sync result.
func (s *Syncer) Last() Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

// Update persists new settings.
func (s *Syncer) Update(in Settings) error {
	in.BaseURL = normalizeBase(in.BaseURL)
	s.mu.Lock()
	s.settings = in
	raw, err := json.MarshalIndent(s.settings, "", "  ")
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.dataDir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(s.path, raw, 0o600)
}

// Enabled reports whether an automatic sync should run.
func (s *Syncer) Enabled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settings.Enabled && s.settings.Auto && s.settings.BaseURL != "" && s.settings.SubURL != ""
}

func normalizeBase(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		s = "http://" + s
	}
	return strings.TrimRight(s, "/")
}

// client talks to one v2rayA instance.
type client struct {
	base  string
	http  *http.Client
	token string
}

func newClient(base string) *client {
	return &client{base: normalizeBase(base), http: &http.Client{Timeout: 40 * time.Second}}
}

func (c *client) login(user, pass string) error {
	body, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	resp, err := c.http.Post(c.base+"/api/login", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	var out struct {
		Code string `json:"code"`
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return fmt.Errorf("响应解析失败: %s", truncate(string(raw), 120))
	}
	if out.Data.Token == "" {
		return fmt.Errorf("登录失败: %s", truncate(string(raw), 120))
	}
	c.token = out.Data.Token
	return nil
}

func (c *client) do(method, path string, payload any) ([]byte, error) {
	var rdr io.Reader
	if payload != nil {
		b, _ := json.Marshal(payload)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		return raw, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(raw), 160))
	}
	return raw, nil
}

// List returns the subscriptions v2rayA currently holds.
func (c *client) list() ([]Sub, error) {
	raw, err := c.do("GET", "/api/touch", nil)
	if err != nil {
		return nil, err
	}
	var out struct {
		Data struct {
			Touch struct {
				Subscriptions []struct {
					ID      int    `json:"id"`
					Address string `json:"address"`
					Status  string `json:"status"`
					Servers []any  `json:"servers"`
				} `json:"subscriptions"`
			} `json:"touch"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	subs := make([]Sub, 0, len(out.Data.Touch.Subscriptions))
	for _, s := range out.Data.Touch.Subscriptions {
		subs = append(subs, Sub{ID: s.ID, Address: s.Address, Count: len(s.Servers), Status: s.Status})
	}
	return subs, nil
}

func (c *client) importSub(subURL string) error {
	_, err := c.do("POST", "/api/import", map[string]any{
		"url":  subURL,
		"kind": "subscription",
	})
	return err
}

func (c *client) refresh(id int) error {
	_, err := c.do("PUT", "/api/subscription", map[string]any{
		"_type": "subscription",
		"id":    id,
	})
	return err
}

// Test checks connectivity and credentials without changing anything.
func (s *Syncer) Test(baseURL, user, pass string) ([]Sub, error) {
	c := newClient(baseURL)
	if err := c.login(user, pass); err != nil {
		return nil, err
	}
	return c.list()
}

// Sync makes sure v2rayA holds our subscription, then refreshes it.
func (s *Syncer) Sync() Result {
	s.mu.Lock()
	cfg := s.settings
	s.mu.Unlock()

	res := Result{At: time.Now().Format("2006-01-02 15:04:05")}
	finish := func(ok bool, msg string) Result {
		res.OK, res.Message = ok, msg
		s.mu.Lock()
		s.last = res
		s.mu.Unlock()
		return res
	}

	if cfg.BaseURL == "" {
		return finish(false, "未填写 v2rayA 地址")
	}
	if cfg.SubURL == "" {
		return finish(false, "未填写 v2rayA 可访问的订阅地址")
	}

	c := newClient(cfg.BaseURL)
	if err := c.login(cfg.Username, cfg.Password); err != nil {
		return finish(false, err.Error())
	}

	subs, err := c.list()
	if err != nil {
		return finish(false, "读取订阅列表失败: "+err.Error())
	}

	target := strings.TrimSpace(cfg.SubURL)
	for _, sub := range subs {
		if sameSubscription(sub.Address, target) {
			res.Action, res.SubID = "refreshed", sub.ID
			if err := c.refresh(sub.ID); err != nil {
				return finish(false, "刷新订阅失败: "+err.Error())
			}
			after, _ := c.list()
			for _, a := range after {
				if a.ID == sub.ID {
					res.Action = fmt.Sprintf("refreshed(%d节点)", a.Count)
				}
			}
			return finish(true, "已刷新已有订阅")
		}
	}

	res.Action = "imported"
	if err := c.importSub(target); err != nil {
		return finish(false, "导入订阅失败: "+err.Error())
	}
	after, _ := c.list()
	for _, a := range after {
		if sameSubscription(a.Address, target) {
			res.SubID = a.ID
			res.Action = fmt.Sprintf("imported(%d节点)", a.Count)
		}
	}
	return finish(true, "已导入新订阅")
}

// sameSubscription compares two subscription addresses ignoring formatting noise.
func sameSubscription(a, b string) bool {
	na, err1 := url.Parse(strings.TrimSpace(a))
	nb, err2 := url.Parse(strings.TrimSpace(b))
	if err1 != nil || err2 != nil {
		return strings.TrimSpace(a) == strings.TrimSpace(b)
	}
	return na.Host == nb.Host && na.Path == nb.Path && na.RawQuery == nb.RawQuery
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
