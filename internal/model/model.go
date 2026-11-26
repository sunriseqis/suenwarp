package model

import "time"

// Class identifies which pool a node came from.
const (
	ClassWG       = "wg"        // WireGuard endpoint, IP:port
	ClassWGDomain = "wg_domain" // WireGuard endpoint reached through a domain
	ClassMasque   = "masque"    // WARP over MASQUE/HTTP3
	ClassVless    = "vless"     // edgetunnel style VLESS over CDN
)

// Node is one measured candidate and, when OK, one subscription entry.
type Node struct {
	Class      string  `json:"class"`
	Name       string  `json:"name"`
	Server     string  `json:"server"`
	Port       int     `json:"port"`
	SNI        string  `json:"sni,omitempty"`
	ResolvedIP string  `json:"resolved_ip,omitempty"`
	LatencyMS  float64 `json:"latency_ms"`
	JitterMS   float64 `json:"jitter_ms"`
	LossPct    float64 `json:"loss_pct"`
	SpeedMbps  float64 `json:"speed_mbps"`       // average
	SpeedPeak  float64 `json:"speed_peak_mbps"`
	SpeedTail  float64 `json:"speed_tail_mbps"`
	SpeedCV    float64 `json:"speed_cv"`
	StallPct   float64 `json:"stall_pct"`
	MaxStallS  int     `json:"max_stall_s"`
	Stability  float64 `json:"stability"`        // 0..100 derived from the curve
	Measured   bool    `json:"measured"`         // true when a real download ran
	IdleOK     bool    `json:"idle_ok"`
	IdleDetail string  `json:"idle_detail,omitempty"`
	DomainOK   map[string]bool `json:"domain_ok,omitempty"`
	EgressIP      string `json:"egress_ip,omitempty"`
	EgressCountry string `json:"egress_country,omitempty"`
	EgressCity    string `json:"egress_city,omitempty"`
	EgressOrg     string `json:"egress_org,omitempty"`
	SpeedError    string `json:"speed_error,omitempty"`
	SpeedDiag     string `json:"speed_diag,omitempty"`      // ok|connect_failed|tls_blocked|no_data|failed
	SpeedDiagText string `json:"speed_diag_text,omitempty"`
	Score      float64 `json:"score"`
	Streak     int     `json:"streak,omitempty"` // consecutive scans this node survived
	OK         bool    `json:"ok"`
	Reason     string  `json:"reason,omitempty"`
}

// Label renders the human readable node name used in subscriptions.
func (n Node) Label() string {
	if n.Name != "" {
		return n.Name
	}
	tag := map[string]string{
		ClassWG: "WG", ClassWGDomain: "WGD", ClassMasque: "MQ", ClassVless: "VL",
	}[n.Class]
	if tag == "" {
		tag = "N"
	}
	s := tag + " " + n.Server + ":" + itoa(n.Port)
	s += " · " + ftoa(n.LatencyMS) + "ms"
	if n.LossPct > 0 {
		s += " · 丢" + ftoa(n.LossPct) + "%"
	}
	if n.JitterMS > 0 {
		s += " · 抖" + ftoa(n.JitterMS) + "ms"
	}
	if n.SpeedMbps > 0 {
		s += " · " + ftoa(n.SpeedMbps) + "Mbps"
	}
	if n.EgressCountry != "" {
		s += " · " + n.EgressCountry
	}
	return s
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

func ftoa(v float64) string {
	if v == 0 {
		return "0"
	}
	iv := int64(v)
	frac := int64((v - float64(iv)) * 10)
	if frac < 0 {
		frac = -frac
	}
	if frac == 0 {
		return itoa(int(iv))
	}
	return itoa(int(iv)) + "." + itoa(int(frac))
}

// Report is one complete scan result, persisted for the API to serve.
type Report struct {
	GeneratedAt time.Time `json:"generated_at"`
	DurationSec float64   `json:"duration_sec"`
	Candidates  int       `json:"candidates"`
	Passed      int       `json:"passed"`
	Nodes       []Node    `json:"nodes"`     // passing, sorted by score
	Rejected    []Node    `json:"rejected"`  // failed, capped for display
	Error       string         `json:"error,omitempty"`
	DiagCounts  map[string]int `json:"diag_counts,omitempty"`
}

// ByClass returns the passing nodes of one class.
func (r Report) ByClass(class string) []Node {
	out := make([]Node, 0, len(r.Nodes))
	for _, n := range r.Nodes {
		if n.Class == class {
			out = append(out, n)
		}
	}
	return out
}
