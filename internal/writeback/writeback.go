// Package writeback pushes the measured best VLESS addresses into an
// edgetunnel deployment's ADD.txt, so the worker's own subscription keeps
// working even when this host is offline.
package writeback

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"warpsub/internal/model"
)

const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

// Settings is user controlled and persisted separately from config.yaml so the
// panel can change it without a restart.
type Settings struct {
	Enabled  bool   `json:"enabled"`
	BaseURL  string `json:"base_url"`
	Password string `json:"password"`
	Auto     bool   `json:"auto"` // run after every scan
}

// Result records the outcome of the last sync.
type Result struct {
	At      string `json:"at"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	Count   int    `json:"count"`
	Backup  string `json:"backup,omitempty"`
}

// Syncer owns the settings and performs syncs.
type Syncer struct {
	mu       sync.Mutex
	path     string
	dataDir  string
	settings Settings
	last     Result
}

// New loads data/writeback.json, falling back to defaults.
func New(dataDir string) *Syncer {
	s := &Syncer{
		path:    filepath.Join(dataDir, "writeback.json"),
		dataDir: dataDir,
	}
	if raw, err := os.ReadFile(s.path); err == nil {
		_ = json.Unmarshal(raw, &s.settings)
	}
	return s
}

// Settings returns a copy of the current settings.
func (s *Syncer) Settings() Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settings
}

// Last returns the most recent sync result.
func (s *Syncer) Last() Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

// Update applies a partial settings change and persists it.
func (s *Syncer) Update(in Settings) error {
	s.mu.Lock()
	s.settings = in
	s.settings.BaseURL = normalizeBase(s.settings.BaseURL)
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

// Enabled reports whether auto sync should run.
func (s *Syncer) Enabled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settings.Enabled && s.settings.Auto && s.settings.BaseURL != ""
}

// Sync writes the given nodes into ADD.txt.
func (s *Syncer) Sync(nodes []model.Node) Result {
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
		return finish(false, "未填写 edgetunnel 地址")
	}
	if cfg.Password == "" {
		return finish(false, "未填写后台密码")
	}

	lines := buildLines(nodes)
	if len(lines) == 0 {
		return finish(false, "没有可回写的 VLESS 节点")
	}
	res.Count = len(lines)

	base := normalizeBase(cfg.BaseURL)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Timeout: 25 * time.Second, Jar: jar}

	// 1. login; edgetunnel binds the auth cookie to the User-Agent
	if err := login(client, base, cfg.Password); err != nil {
		return finish(false, "登录失败: "+err.Error())
	}

	// 2. back up the current list, so an accidental overwrite is recoverable
	old, err := fetchADD(client, base)
	if err != nil {
		return finish(false, "读取原列表失败: "+err.Error())
	}
	if old != "" {
		name := filepath.Join(s.dataDir, "add-backup-"+time.Now().Format("20060102-150405")+".txt")
		if err := os.WriteFile(name, []byte(old), 0o600); err == nil {
			res.Backup = filepath.Base(name)
		}
	}

	// 3. write
	body := strings.Join(lines, "\n")
	if err := postADD(client, base, body); err != nil {
		return finish(false, "写入失败: "+err.Error())
	}
	return finish(true, fmt.Sprintf("已同步 %d 条到 %s", len(lines), base))
}

func normalizeBase(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		s = "https://" + s
	}
	return strings.TrimRight(s, "/")
}

func login(client *http.Client, base, password string) error {
	form := url.Values{"password": {password}}
	req, err := http.NewRequest("POST", base+"/login", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Referer", base+"/login")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if !strings.Contains(string(raw), `"success":true`) && !strings.Contains(string(raw), "success") {
		return fmt.Errorf("密码被拒绝")
	}
	// verify the cookie actually arrived
	u, _ := url.Parse(base)
	if client.Jar != nil {
		if cs := client.Jar.Cookies(u); len(cs) == 0 {
			return fmt.Errorf("未拿到会话 cookie")
		}
	}
	return nil
}

func fetchADD(client *http.Client, base string) (string, error) {
	req, _ := http.NewRequest("GET", base+"/admin/ADD.txt", nil)
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return string(raw), nil
}

func postADD(client *http.Client, base, body string) error {
	req, err := http.NewRequest("POST", base+"/admin/ADD.txt", strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "text/plain;charset=utf-8")
	req.Header.Set("Referer", base+"/admin")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(raw), 160))
	}
	if !strings.Contains(string(raw), `"success":true`) {
		return fmt.Errorf("服务端未确认: %s", truncate(string(raw), 160))
	}
	return nil
}

// buildLines renders ADD.txt entries: host:port#remark with the measured stats.
func buildLines(nodes []model.Node) []string {
	var out []string
	for _, n := range nodes {
		if n.Class != model.ClassVless {
			continue
		}
		remark := fmt.Sprintf("VL %.0fms", n.LatencyMS)
		if n.JitterMS > 0 {
			remark += fmt.Sprintf(" 抖%.0fms", n.JitterMS)
		}
		if n.LossPct > 0 {
			remark += fmt.Sprintf(" 丢%.0f%%", n.LossPct)
		}
		host := n.Server
		if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
			host = "[" + host + "]"
		}
		out = append(out, host+":"+strconv.Itoa(n.Port)+"#"+
			strings.ReplaceAll(strings.ReplaceAll(remark, "\n", " "), "#", " "))
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
