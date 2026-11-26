package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the whole application configuration, loaded from YAML.
type Config struct {
	Listen   string `yaml:"listen"`
	Token    string `yaml:"token"`
	DataDir  string `yaml:"data_dir"`
	Schedule string `yaml:"schedule"` // cron expression, 5 fields
	Timezone string `yaml:"timezone"`

	Warp     Warp     `yaml:"warp"`
	Scan     Scan     `yaml:"scan"`
	VLESS    VLESS    `yaml:"vless"`
	Thresh   Thresh   `yaml:"thresholds"`
	Top      Top      `yaml:"top"`
	Speed    Speed    `yaml:"speed_test"`
	Subtpl   Subtpl   `yaml:"subscription"`
	Writeback Writeback `yaml:"writeback"`
	V2raya    V2raya    `yaml:"v2raya"`
	Stable    Stability `yaml:"stability"`
	LogLevel string   `yaml:"log_level"`
}

// Warp holds account settings.
type Warp struct {
	AutoRegister bool   `yaml:"auto_register"`
	LicenseKey   string `yaml:"license_key"`
	MTU          int    `yaml:"mtu"`
	Reserved     string `yaml:"reserved"` // hex or base64 client_id; empty = derive from account
}

// Scan holds candidate generation and probing settings.
type Scan struct {
	Concurrency     int      `yaml:"concurrency"`
	Rounds          int      `yaml:"rounds"`
	TimeoutMS       int      `yaml:"timeout_ms"`
	SamplePerSubnet int      `yaml:"sample_per_subnet"` // 0 = full subnet
	Subnets         []string `yaml:"subnets"`
	Ports           []int    `yaml:"ports"`
	DomainTargets   []string `yaml:"domain_targets"`
	MasqueHosts     []string `yaml:"masque_hosts"`
	MasqueSNI       []string `yaml:"masque_sni"`
	MasquePort      int      `yaml:"masque_port"`
}

// VLESS holds the edgetunnel-style node source.
type VLESS struct {
	Enabled    bool     `yaml:"enabled"`
	WorkerHost string   `yaml:"worker_host"`
	UUID       string   `yaml:"uuid"`
	Path       string   `yaml:"path"`
	Fingerprint string  `yaml:"fingerprint"`
	Port       int      `yaml:"port"`
	SNIHosts   []string `yaml:"sni_hosts"` // Host/SNI values that the worker answers for
	Candidates []string `yaml:"candidates"` // preferred access addresses: domain or IP
	Sources    []string `yaml:"sources"`    // public lists to harvest candidates from
	MaxCandidates int   `yaml:"max_candidates"` // cap on collected candidates, 0 = unlimited
	ECH        ECH      `yaml:"ech"`
	// VerifyDomains are probed through every shortlisted node; nodes that fail
	// are excluded from the per-domain Clash groups.
	VerifyDomains []string `yaml:"verify_domains"`
	// EgressProbe is fetched through each node to learn its exit IP/region.
	EgressProbe string `yaml:"egress_probe"`
	// AllowedCountries keeps only nodes whose exit country is in this list
	// (empty = no filtering). This is what makes region-locked services work.
	AllowedCountries []string `yaml:"allowed_countries"`
}

// ECH mirrors edgetunnel's ECH option so our nodes are behaviourally identical.
type ECH struct {
	Enabled    bool   `yaml:"enabled"`
	PublicName string `yaml:"public_name"` // e.g. cloudflare-ech.com
	DoH        string `yaml:"doh"`         // e.g. https://dns.alidns.com/dns-query
	// ClashConfig is a base64 ECHConfigList. mihomo needs the concrete list;
	// without it we only emit ECH in the v2ray/base64 output.
	ClashConfig string `yaml:"clash_config"`
}

// Query builds the "public_name+doh" token used by the vless share link.
func (e ECH) Query() string {
	if !e.Enabled || e.PublicName == "" {
		return ""
	}
	if e.DoH == "" {
		return e.PublicName
	}
	return e.PublicName + "+" + e.DoH
}

// Stability requires a node to survive N consecutive scans.
type Stability struct {
	MinHits   int  `yaml:"min_hits"`   // 1 = off
	Bootstrap bool `yaml:"bootstrap"`  // keep the current set when nothing qualifies yet
}

// Thresh is the pass/fail gate applied to every candidate.
type Thresh struct {
	MaxLatencyMS float64 `yaml:"max_latency_ms"`
	MaxJitterMS  float64 `yaml:"max_jitter_ms"`
	MaxLossPct   float64 `yaml:"max_loss_pct"`
	MinSpeedMbps float64 `yaml:"min_speed_mbps"`
	MinStability float64 `yaml:"min_stability"` // 0..100, derived stability score
	// SpeedRefMbps is the throughput that counts as a full speed score.
	SpeedRefMbps float64 `yaml:"speed_ref_mbps"`
	// MasqueMaxLatencyMS is a separate liveness cap: a MASQUE tunnel costs a
	// QUIC handshake plus a CONNECT-IP exchange, so it is naturally slower than
	// a TCP handshake and must not be judged by the same limit.
	MasqueMaxLatencyMS float64 `yaml:"masque_max_latency_ms"`
}

// Top controls how many nodes of each class end up in the subscription.
type Top struct {
	WG       int `yaml:"wg"`
	WGDomain int `yaml:"wg_domain"`
	Masque   int `yaml:"masque"`
	Vless    int `yaml:"vless"`
}

// Speed configures the real tunnel throughput test.
type Speed struct {
	Enabled       bool   `yaml:"enabled"`
	URL           string `yaml:"url"`
	MaxEndpoints  int    `yaml:"max_endpoints"`
	Required      bool   `yaml:"required"`
	CooldownMS    int    `yaml:"cooldown_ms"`
	Shortlist     int    `yaml:"shortlist"`      // how many candidates get the real download test
	DurationS     int    `yaml:"duration_s"`     // seconds per throughput test
	MaxBytesMB    int    `yaml:"max_bytes_mb"`   // byte cap per throughput test
	IdleEnabled   bool   `yaml:"idle_enabled"`   // run the idle-survival probe
	IdleSeconds   int    `yaml:"idle_seconds"`
	TimeoutMS     int    `yaml:"timeout_ms"`
	Concurrency   int    `yaml:"concurrency"`
}

// Writeback configures pushing results into an edgetunnel deployment.
type Writeback struct {
	Enabled  bool   `yaml:"enabled"`
	BaseURL  string `yaml:"base_url"`
	Password string `yaml:"password"`
	Auto     bool   `yaml:"auto"`
}

// V2raya configures syncing the subscription into a running v2rayA.
type V2raya struct {
	Enabled  bool   `yaml:"enabled"`
	BaseURL  string `yaml:"base_url"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Auto     bool   `yaml:"auto"`
	SubURL   string `yaml:"subscription_url"`
}

// Subtpl configures subscription presentation.
type Subtpl struct {
	Name         string `yaml:"name"`
	UpdateHours  int    `yaml:"update_hours"`
	IncludeMasque bool  `yaml:"include_masque"`
	TestURL      string `yaml:"test_url"`
}

// Default returns a config with sane values so a missing file still works.
func Default() Config {
	return Config{
		Listen:   ":8080",
		DataDir:  "./data",
		Schedule: "0 4 * * *",
		Timezone: "Asia/Shanghai",
		Warp:     Warp{AutoRegister: true, MTU: 1280},
		Scan: Scan{
			Concurrency:     128,
			Rounds:          5,
			TimeoutMS:       1200,
			SamplePerSubnet: 16,
			Subnets: []string{
				"162.159.192.0/24", "162.159.193.0/24", "162.159.195.0/24",
				"162.159.204.0/24", "188.114.96.0/24", "188.114.97.0/24",
				"188.114.98.0/24", "188.114.99.0/24",
			},
			Ports:         []int{2408, 500, 1701, 4500, 1018, 854, 880, 890, 903, 934, 939, 942, 943, 946, 955, 968, 987, 1014, 1074, 1843},
			DomainTargets: []string{"engage.cloudflareclient.com:2408"},
			MasqueHosts:   []string{"162.159.198.1", "162.159.197.1", "162.159.199.1"},
			MasquePort:    443,
			MasqueSNI:     []string{"consumer-masque.cloudflareclient.com"},
		},
		VLESS: VLESS{Enabled: false, Path: "/", Fingerprint: "chrome", Port: 443,
			ECH: ECH{Enabled: true, PublicName: "cloudflare-ech.com", DoH: "https://dns.alidns.com/dns-query"}},
		Thresh: Thresh{
			MaxLatencyMS: 800, MaxJitterMS: 200, MaxLossPct: 20, MinSpeedMbps: 5, MinStability: 40, SpeedRefMbps: 50, MasqueMaxLatencyMS: 4000,
		},
		Top:   Top{WG: 8, WGDomain: 4, Masque: 4, Vless: 8},
		Speed: Speed{Enabled: true, URL: "https://proof.ovh.net/files/100Mb.dat", MaxEndpoints: 20, TimeoutMS: 8000, Concurrency: 2, Required: false, CooldownMS: 30000,
			Shortlist: 15, DurationS: 15, MaxBytesMB: 20, IdleEnabled: true, IdleSeconds: 60},
		Subtpl: Subtpl{Name: "warp-sub", UpdateHours: 24, IncludeMasque: true, TestURL: "http://cp.cloudflare.com/generate_204"},
		Stable: Stability{MinHits: 1, Bootstrap: true},
		LogLevel: "info",
	}
}

// Load reads a YAML config and fills unset fields with defaults.
func Load(path string) (Config, error) {
	c := Default()
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return c, err
	}
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return c, err
	}
	if c.Warp.MTU == 0 {
		c.Warp.MTU = 1280
	}
	if c.Speed.TimeoutMS == 0 {
		c.Speed.TimeoutMS = 8000
	}
	if c.Speed.Concurrency <= 0 {
		c.Speed.Concurrency = 2
	}
	return c, nil
}

// Location returns the configured timezone, falling back to UTC.
func (c Config) Location() *time.Location {
	loc, err := time.LoadLocation(c.Timezone)
	if err != nil {
		return time.UTC
	}
	return loc
}
