package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Map renders the config as a generic map keyed by the same names config.yaml
// uses, so the panel can read and patch individual fields by dot path.
func (c Config) Map() map[string]any {
	raw, err := yaml.Marshal(c)
	if err != nil {
		return map[string]any{}
	}
	var out map[string]any
	if err := yaml.Unmarshal(raw, &out); err != nil {
		return map[string]any{}
	}
	return out
}

// FromMap builds a Config from a generic map.
func FromMap(m map[string]any) (Config, error) {
	c := Default()
	raw, err := yaml.Marshal(m)
	if err != nil {
		return c, err
	}
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return c, err
	}
	return c, nil
}

// GetPath reads m["a"]["b"]... by dot path.
func GetPath(m map[string]any, path string) (any, bool) {
	parts := strings.Split(path, ".")
	cur := any(m)
	for _, p := range parts {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = mm[p]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// SetPath writes a value at a dot path, creating intermediate maps.
func SetPath(m map[string]any, path string, v any) {
	parts := strings.Split(path, ".")
	cur := m
	for i, p := range parts {
		if i == len(parts)-1 {
			cur[p] = v
			return
		}
		next, ok := cur[p].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[p] = next
		}
		cur = next
	}
}

// OverlayPath is where panel edits are persisted.
func OverlayPath(dataDir string) string { return filepath.Join(dataDir, "override.json") }

// LoadOverlay merges data/override.json over a config.
func LoadOverlay(dataDir string) (map[string]any, error) {
	raw, err := os.ReadFile(OverlayPath(dataDir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// SaveOverlay persists the panel-edited map.
func SaveOverlay(dataDir string, m map[string]any) error {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(OverlayPath(dataDir), raw, 0o600)
}

// Validate checks the fields a bad edit could break badly.
func Validate(c Config) []string {
	var errs []string
	if c.Listen == "" {
		errs = append(errs, "监听地址不能为空")
	} else if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		errs = append(errs, "监听地址格式错误，应形如 :8080")
	}
	if _, err := parseCronLoose(c.Schedule); err != nil {
		errs = append(errs, "定时表达式错误: "+err.Error())
	}
	if c.Scan.Concurrency < 1 || c.Scan.Concurrency > 1000 {
		errs = append(errs, "并发数应在 1-1000")
	}
	if c.Scan.Rounds < 1 || c.Scan.Rounds > 20 {
		errs = append(errs, "探测轮次应在 1-20")
	}
	if c.Scan.SamplePerSubnet < 0 || c.Scan.SamplePerSubnet > 256 {
		errs = append(errs, "每网段抽样应在 0-256（0 表示全量）")
	}
	for _, s := range c.Scan.Subnets {
		if _, _, err := net.ParseCIDR(s); err != nil {
			errs = append(errs, "网段格式错误: "+s)
		}
	}
	for _, p := range c.Scan.Ports {
		if p < 1 || p > 65535 {
			errs = append(errs, fmt.Sprintf("端口越界: %d", p))
		}
	}
	if c.VLESS.Enabled {
		if c.VLESS.WorkerHost == "" {
			errs = append(errs, "开启 VLESS 时 Worker 域名必填")
		}
		if c.VLESS.UUID == "" {
			errs = append(errs, "开启 VLESS 时 UUID 必填")
		}
	}
	for _, u := range c.VLESS.Sources {
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			errs = append(errs, "优选源必须是 http(s) 地址: "+u)
		}
	}
	if c.Speed.Enabled && c.Speed.URL == "" {
		errs = append(errs, "开启测速时目标地址必填")
	}
	if c.Speed.DurationS < 1 || c.Speed.DurationS > 300 {
		errs = append(errs, "测速时长应在 1-300 秒")
	}
	if c.Speed.Shortlist < 1 || c.Speed.Shortlist > 100 {
		errs = append(errs, "短名单数量应在 1-100")
	}
	if c.Stable.MinHits < 1 || c.Stable.MinHits > 10 {
		errs = append(errs, "稳定性窗口应在 1-10")
	}
	if _, err := parseCronLoose(c.Schedule); err == nil && strings.Count(c.Schedule, " ") > 4 {
		errs = append(errs, "定时表达式只支持「分 时 * * *」")
	}
	return errs
}

func parseCronLoose(expr string) (string, error) {
	f := strings.Fields(expr)
	if expr == "@daily" || expr == "@midnight" {
		return expr, nil
	}
	if len(f) < 2 {
		return "", fmt.Errorf("至少需要「分 时」两个字段")
	}
	m, err := strconv.Atoi(f[0])
	if err != nil || m < 0 || m > 59 {
		return "", fmt.Errorf("分钟字段无效: %q", f[0])
	}
	h, err := strconv.Atoi(f[1])
	if err != nil || h < 0 || h > 23 {
		return "", fmt.Errorf("小时字段无效: %q", f[1])
	}
	return expr, nil
}

// Holder keeps the live config so a panel edit can take effect without a
// restart. Scanners are rebuilt from it on every run.
type Holder struct {
	mu  sync.RWMutex
	cfg Config
}

// NewHolder wraps a config.
func NewHolder(c Config) *Holder { return &Holder{cfg: c} }

// Get returns the current config.
func (h *Holder) Get() Config {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.cfg
}

// Set replaces the current config.
func (h *Holder) Set(c Config) {
	h.mu.Lock()
	h.cfg = c
	h.mu.Unlock()
}
