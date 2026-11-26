// Package scan builds candidates, measures them and produces a report.
package scan

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net/url"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"warpsub/internal/account"
	"warpsub/internal/config"
	"warpsub/internal/model"
	"warpsub/internal/probe"
	"warpsub/internal/scoring"
	"warpsub/internal/source"
	"warpsub/internal/stability"
	"warpsub/internal/store"
	"warpsub/internal/tunnel"
	"warpsub/internal/vless"
	"warpsub/internal/wgn"
	"warpsub/internal/v2raya"
	"warpsub/internal/writeback"
)

// Scanner runs the whole measurement pipeline.
type Scanner struct {
	cfg     config.Config
	acct    *account.Account
	masque  *account.MasqueAccount
	st      *store.Store
	wb      *writeback.Syncer
	v2a     *v2raya.Syncer
	stab    *stability.Store
}

// SetStability attaches the streak tracker.
func (s *Scanner) SetStability(v *stability.Store) { s.stab = v }

// SetV2raya attaches the optional v2rayA sync target.
func (s *Scanner) SetV2raya(v *v2raya.Syncer) { s.v2a = v }

// SetWriteback attaches the optional edgetunnel sync target.
func (s *Scanner) SetWriteback(w *writeback.Syncer) { s.wb = w }

// New builds a scanner.
func New(cfg config.Config, acct *account.Account, masque *account.MasqueAccount, st *store.Store) *Scanner {
	return &Scanner{cfg: cfg, acct: acct, masque: masque, st: st}
}

// candidate is one thing to measure.
type candidate struct {
	class  string
	server string // subscription server value (IP or domain)
	port   int
	dial   string // actual ip:port to probe
	sni    string
}

// Options tweaks one run.
type Options struct {
	Full bool // scan every address of every subnet instead of sampling
}

// Run executes a full scan and persists the report.
func (s *Scanner) Run(ctx context.Context, opts Options) (model.Report, error) {
	start := time.Now()

	if s.acct == nil {
		return model.Report{Error: "no WARP account"}, fmt.Errorf("scan: no account")
	}
	priv, err := s.acct.PrivateKeyBytes()
	if err != nil {
		return model.Report{Error: err.Error()}, err
	}
	peer, err := s.acct.PublicKeyBytes()
	if err != nil {
		return model.Report{Error: err.Error()}, err
	}
	reserved := s.acct.ReservedBytes(s.cfg.Warp.Reserved)
	client, err := wgn.NewClientFromPrivate(priv, peer)
	if err != nil {
		return model.Report{Error: err.Error()}, err
	}

	cands := s.buildCandidates(ctx, opts)
	log.Printf("scan: %d candidates (%d wg, %d masque, %d vless)",
		len(cands),
		countClass(cands, model.ClassWG), countClass(cands, model.ClassMasque),
		countClass(cands, model.ClassVless))

	timeout := time.Duration(s.cfg.Scan.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 1200 * time.Millisecond
	}
	rounds := s.cfg.Scan.Rounds
	if rounds <= 0 {
		rounds = 5
	}
	// TLS/QUIC based probes need a far more generous window than a UDP
	// handshake: a full TCP+TLS handshake can easily exceed a second.
	tlsTimeout := timeout
	if tlsTimeout < 5*time.Second {
		tlsTimeout = 5 * time.Second
	}

	results := make([]model.Node, 0, len(cands))
	var mu sync.Mutex
	sem := make(chan struct{}, max(1, s.cfg.Scan.Concurrency))
	var wg sync.WaitGroup

	for _, c := range cands {
		select {
		case <-ctx.Done():
			return model.Report{}, ctx.Err()
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(c candidate) {
			defer wg.Done()
			defer func() { <-sem }()

			node := model.Node{Class: c.class, Server: c.server, Port: c.port, SNI: c.sni}
			switch c.class {
			case model.ClassWG, model.ClassWGDomain:
				r := client.Probe(c.dial, peer, reserved, rounds, timeout)
				node.LatencyMS = float64(r.RTT.Microseconds()) / 1000
				smp := probe.Aggregate(r.RTTs, r.Sent)
				node.JitterMS = float64(smp.Jitter.Microseconds()) / 1000
				node.LossPct = smp.LossPct
				if !r.OK {
					node.Reason = "无响应"
				}
				if c.class == model.ClassWGDomain {
					if ip := resolveFirst(c.server); ip != "" {
						node.ResolvedIP = ip
					}
				}
			case model.ClassMasque:
				mr := probe.ProbeMasque(s.masque, c.dial, rounds, tlsTimeout)
				node.LatencyMS = float64(mr.Latency.Microseconds()) / 1000
				node.JitterMS = float64(mr.Jitter.Microseconds()) / 1000
				node.LossPct = mr.LossPct
				node.SNI = account.MasqueSNI
				if !mr.OK {
					node.Reason = "CONNECT-IP 失败: " + mr.Detail
				}
			case model.ClassVless:
				r := probe.ProbeVLESS(c.dial, s.cfg.VLESS.WorkerHost, s.cfg.VLESS.Path, rounds, tlsTimeout)
				node.LatencyMS = float64(r.Latency.Microseconds()) / 1000
				node.JitterMS = float64(r.Jitter.Microseconds()) / 1000
				node.LossPct = r.LossPct
				if !r.OK {
					if r.StatusCode != 0 {
						node.Reason = fmt.Sprintf("HTTP %d", r.StatusCode)
					} else {
						node.Reason = "握手失败: " + r.Detail
					}
				} else {
					if ip := resolveFirst(c.server); ip != "" {
						node.ResolvedIP = ip
					}
				}
			}

			mu.Lock()
			results = append(results, node)
			mu.Unlock()
		}(c)
	}
	wg.Wait()

	// Diagnose a total WireGuard blackout: that almost always means the local
	// account cannot complete a handshake with the edge (stale peer key or a
	// throttled device), not that every endpoint is down.
	wgTotal, wgOK := 0, 0
	for _, n := range results {
		if n.Class == model.ClassWG || n.Class == model.ClassWGDomain {
			wgTotal++
			if n.LatencyMS > 0 {
				wgOK++
			}
		}
	}
	if wgTotal > 20 && wgOK == 0 {
		log.Printf("scan: WARNING 0/%d WireGuard handshakes answered. The edge is reachable "+
			"but rejecting this device's handshake — check that the account is enabled and "+
			"that peer_public_key from the registration is still current.", wgTotal)
	}

	// gate + score
	passed := make([]model.Node, 0, len(results))
	rejected := make([]model.Node, 0)
	for i := range results {
		n := results[i]
		hasSpeed := false // throughput is measured later for finalists only
		score, ok, reason := scoring.Evaluate(&n, s.cfg.Thresh, hasSpeed)
		n.Score = score
		n.OK = ok
		if ok {
			passed = append(passed, n)
		} else {
			if n.Reason == "" {
				n.Reason = reason
			}
			rejected = append(rejected, n)
		}
	}

	// throughput on the best WireGuard candidates
	if s.cfg.Speed.Enabled {
		// The mass probe phase sends thousands of handshakes from one address;
		// Cloudflare throttles that, so pause before opening real tunnels.
		if cd := s.cfg.Speed.CooldownMS; cd > 0 {
			log.Printf("scan: cooling down %dms before throughput phase", cd)
			select {
			case <-ctx.Done():
				return model.Report{}, ctx.Err()
			case <-time.After(time.Duration(cd) * time.Millisecond):
			}
		}
		var speedDropped []model.Node
		passed, speedDropped = s.applySpeedTests(passed)
		rejected = append(rejected, speedDropped...)
	}

	// Enrich every surviving node with its exit region and per-site reachability.
	// These are cheap single requests, so unlike the throughput test they can run
	// for the whole set instead of only the shortlist.
	s.enrich(ctx, passed)

	sort.Slice(passed, func(i, j int) bool { return passed[i].Score > passed[j].Score })
	sort.Slice(rejected, func(i, j int) bool { return rejected[i].LatencyMS < rejected[j].LatencyMS })

	if s.stab != nil {
		before := len(passed)
		minHits := s.cfg.Stable.MinHits
		if minHits < 1 {
			minHits = 1
		}
		kept, streak, fellBack := s.stab.Apply(passed, minHits, s.cfg.Stable.Bootstrap)
		if !fellBack && minHits > 1 {
			passed = kept
		}
		// attach the streak to whatever set we are publishing
		for i := range passed {
			if v, ok := streak[stability.Key(passed[i])]; ok {
				passed[i].Streak = v
			}
		}
		if minHits > 1 {
			if fellBack {
				log.Printf("scan: stability %d hits filtered everything, bootstrapping with %d nodes",
					minHits, before)
			} else {
				log.Printf("scan: stability filter %d -> %d nodes (min hits %d)", before, len(passed), minHits)
			}
		}
	}

	passed = s.selectTop(passed)

	if len(rejected) > 300 {
		rejected = rejected[:300]
	}

	diagCounts := map[string]int{}
	for _, n := range passed {
		if n.SpeedDiag != "" {
			diagCounts[n.SpeedDiag]++
		}
	}

	report := model.Report{
		DiagCounts:  diagCounts,
		GeneratedAt: time.Now(),
		DurationSec: time.Since(start).Seconds(),
		Candidates:  len(results),
		Passed:      len(passed),
		Nodes:       passed,
		Rejected:    rejected,
	}
	if err := s.st.Save(report); err != nil {
		log.Printf("scan: save: %v", err)
	}

	// keep a compact trend record for the panel
	entry := store.HistoryEntry{
		At:          report.GeneratedAt.Format("2006-01-02 15:04"),
		Candidates:  report.Candidates,
		Passed:      report.Passed,
		Counts:      map[string]int{},
		DurationSec: report.DurationSec,
	}
	var latSum float64
	for _, n := range passed {
		entry.Counts[n.Class]++
		if entry.BestLatency == 0 || n.LatencyMS < entry.BestLatency {
			entry.BestLatency = n.LatencyMS
		}
		if n.SpeedMbps > entry.BestSpeed {
			entry.BestSpeed = n.SpeedMbps
		}
		latSum += n.LatencyMS
	}
	if len(passed) > 0 {
		entry.AvgLatency = round1(latSum / float64(len(passed)))
	}
	entry.BestLatency = round1(entry.BestLatency)
	if err := s.st.AppendHistory(entry); err != nil {
		log.Printf("scan: append history: %v", err)
	}
	log.Printf("scan: done in %.0fs, %d passed / %d measured", report.DurationSec, report.Passed, report.Candidates)

	if s.v2a != nil && s.v2a.Enabled() {
		go func() {
			res := s.v2a.Sync()
			log.Printf("v2raya: %s", res.Message)
		}()
	}

	if s.wb != nil && s.wb.Enabled() {
		go func(nodes []model.Node) {
			res := s.wb.Sync(nodes)
			if res.OK {
				log.Printf("writeback: %s", res.Message)
			} else {
				log.Printf("writeback: %s", res.Message)
			}
		}(passed)
	}
	return report, nil
}

// buildCandidates assembles every address to measure.
func (s *Scanner) buildCandidates(ctx context.Context, opts Options) []candidate {
	var out []candidate
	seen := map[string]struct{}{}
	add := func(c candidate) {
		key := c.class + "|" + c.server + "|" + strconv.Itoa(c.port) + "|" + c.sni
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, c)
	}

	// WireGuard ingress IP x port
	sample := s.cfg.Scan.SamplePerSubnet
	if opts.Full {
		sample = 0
	}
	for _, cidr := range s.cfg.Scan.Subnets {
		ips := sampleSubnet(cidr, sample)
		for _, ip := range ips {
			for _, port := range s.cfg.Scan.Ports {
				add(candidate{
					class:  model.ClassWG,
					server: ip,
					port:   port,
					dial:   net.JoinHostPort(ip, strconv.Itoa(port)),
				})
			}
		}
	}

	// WireGuard through domains
	for _, t := range s.cfg.Scan.DomainTargets {
		host, port, err := probe.SplitHostPort(t, 2408)
		if err != nil {
			continue
		}
		ip := resolveFirst(host)
		if ip == "" {
			continue
		}
		add(candidate{
			class:  model.ClassWGDomain,
			server: host,
			port:   port,
			dial:   net.JoinHostPort(ip, strconv.Itoa(port)),
		})
	}

	// MASQUE ingresses
	if s.cfg.Subtpl.IncludeMasque {
		port := s.cfg.Scan.MasquePort
		if port == 0 {
			port = 443
		}
		// Each (ingress, SNI) pair behaves differently: the SNI decides which
		// certificate is presented and how the connection is classified.
		snis := s.cfg.Scan.MasqueSNI
		if len(snis) == 0 {
			snis = []string{""}
		}
		for _, h := range s.cfg.Scan.MasqueHosts {
			for _, sni := range snis {
				add(candidate{
					class:  model.ClassMasque,
					server: h,
					port:   port,
					dial:   net.JoinHostPort(h, strconv.Itoa(port)),
					sni:    sni,
				})
			}
		}
	}

	// VLESS preferred access addresses
	if s.cfg.VLESS.Enabled && s.cfg.VLESS.WorkerHost != "" {
		port := s.cfg.VLESS.Port
		if port == 0 {
			port = 443
		}
		pool := append([]string{}, s.cfg.VLESS.Candidates...)
		if len(s.cfg.VLESS.Sources) > 0 {
			found := source.Collect(ctx, s.cfg.VLESS.Sources, port, s.cfg.VLESS.MaxCandidates, log.Printf)
			for _, e := range found {
				pool = append(pool, fmt.Sprintf("%s:%d", e.Host, e.Port))
			}
			log.Printf("scan: source pool added %d candidates (total %d)", len(found), len(pool))
		}
		for _, c := range pool {
			host, p, err := probe.SplitHostPort(c, port)
			if err != nil {
				continue
			}
			ip := host
			if net.ParseIP(host) == nil {
				if r := resolveFirst(host); r != "" {
					ip = r
				} else {
					continue
				}
			}
			add(candidate{
				class:  model.ClassVless,
				server: host,
				port:   p,
				dial:   net.JoinHostPort(ip, strconv.Itoa(p)),
			})
		}
	}
	return out
}

// applySpeedTests runs the real download test on a shortlist, then the idle
// survival probe, then re-scores with throughput and stability included.
func (s *Scanner) applySpeedTests(nodes []model.Node) (kept []model.Node, dropped []model.Node) {
	var order []int
	for i, n := range nodes {
		switch n.Class {
		case model.ClassWG, model.ClassWGDomain, model.ClassVless:
			order = append(order, i)
		}
	}
	if len(order) == 0 {
		return nodes, nil
	}
	sort.Slice(order, func(a, b int) bool { return nodes[order[a]].Score > nodes[order[b]].Score })
	limit := s.cfg.Speed.Shortlist
	if limit <= 0 {
		limit = 15
	}
	if len(order) > limit {
		order = order[:limit]
	}

	dur := time.Duration(s.cfg.Speed.DurationS) * time.Second
	if dur <= 0 {
		dur = 15 * time.Second
	}
	var maxBytes int64
	if s.cfg.Speed.MaxBytesMB > 0 {
		maxBytes = int64(s.cfg.Speed.MaxBytesMB) * 1_000_000
	}
	targetURL := s.cfg.Speed.URL

	log.Printf("scan: throughput phase on %d shortlisted nodes (%s, cap %dMB)",
		len(order), dur, s.cfg.Speed.MaxBytesMB)

	for _, i := range order {
		n := &nodes[i]
		var t tunnel.Throughput
		switch n.Class {
		case model.ClassWG, model.ClassWGDomain:
			t = tunnel.MeasureSpeed(s.acct, net.JoinHostPort(n.Server, strconv.Itoa(n.Port)),
				s.cfg.Warp.MTU, targetURL, dur, maxBytes)
		case model.ClassVless:
			conn, err := s.dialVLESS(n, targetURL)
			if err != nil {
				t.Error = err.Error()
			} else {
				t = tunnel.MeasureDownstream(conn, targetURL, dur, maxBytes)
				conn.Close()
			}
		}
		applyThroughput(n, t)
		if n.SpeedDiag == "tls_blocked" && s.plaintextWorks(n) {
			n.SpeedDiagText = "出口只放行明文：HTTPS 站点（ChatGPT/推特等）不可用"
		} else if n.SpeedDiag == "tls_blocked" {
			n.SpeedDiagText = "TLS 无法建立：该出口不支持 HTTPS 目标"
		}

		if s.cfg.Speed.IdleEnabled && n.Class == model.ClassVless {
			s.probeIdle(n)
		} else if s.cfg.Speed.IdleEnabled {
			n.IdleDetail = "未测（非 VLESS）"
		}

	}

	// final scoring with the real numbers
	var out []model.Node
	for _, n := range nodes {
		measured := n.SpeedMbps > 0
		n.Measured = measured
		score, ok, reason := scoring.Evaluate(&n, s.cfg.Thresh, measured)
		n.Score = score
		if ok && !measured && s.cfg.Speed.Required {
			ok = false
			reason = "测速失败（未取到数据）"
		}
		if !ok {
			n.OK = false
			if n.Reason == "" {
				n.Reason = reason
			}
			dropped = append(dropped, n)
			continue
		}
		out = append(out, n)
	}
	return out, dropped
}

// applyThroughput copies one measurement onto a node and derives stability.
func applyThroughput(n *model.Node, t tunnel.Throughput) {
	if t.Error != "" {
		n.SpeedError = t.Error
		n.SpeedDiag, n.SpeedDiagText = classifyError(t.Error)
		if n.Reason == "" {
			n.Reason = "测速失败: " + t.Error
		}
		return
	}
	n.SpeedDiag = "ok"
	n.SpeedDiagText = ""
	n.Measured = true
	n.SpeedMbps = round1(t.AvgMbps)
	n.SpeedPeak = round1(t.PeakMbps)
	n.SpeedTail = round1(t.TailMbps)
	n.SpeedCV = round2(t.CV)
	n.StallPct = round1(t.StallPct)
	n.MaxStallS = t.MaxStallS
	n.Stability = round1(tunnel.StabilityScore(t))
	if len(t.Windows) < 3 {
		// Fewer than three 500ms buckets means the transfer finished almost at
		// once — usually a genuinely fast node that pulled the whole test file
		// before the second tick. The rate is real; the stability verdict is not,
		// so keep the speed and mark stability as neutral.
		n.SpeedDiag = "short_sample"
		n.SpeedDiagText = fmt.Sprintf("采样不足（%d 个窗口 / %ds），稳定性按中性 50 计", len(t.Windows), t.Seconds)
	}
}

// classifyError maps a throughput failure onto a cause the user can act on.
//
// The distinction matters: "TLS blocked" means the node's egress only carries
// plaintext (so HTTPS sites are dead), while "connect_failed" means the tunnel
// itself never came up. Both look like "测速失败" without this.
func classifyError(msg string) (code, text string) {
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "tls"):
		return "tls_blocked", "TLS 握手失败：该出口无法承载 HTTPS 目标"
	case strings.Contains(low, "ws upgrade") || strings.Contains(low, "refused") ||
		strings.Contains(low, "dial") || strings.Contains(low, "connect:"):
		return "connect_failed", "隧道建立失败：连不上或 WS 握手被拒"
	case strings.Contains(low, "no data") || strings.Contains(low, "status:") || strings.Contains(low, "http "):
		return "no_data", "隧道通了但取不到数据"
	}
	return "failed", msg
}

// plaintextWorks checks whether the node can carry plain HTTP at all. It lets a
// TLS failure be reported as "this egress is plaintext only" instead of a
// generic timeout.
func (s *Scanner) plaintextWorks(n *model.Node) bool {
	if n.Class != model.ClassVless {
		return false
	}
	conn, err := s.dialVLESSHost(n, "cp.cloudflare.com", 80)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := conn.Write([]byte("GET /generate_204 HTTP/1.1\r\nHost: cp.cloudflare.com\r\nUser-Agent: warp-sub\r\nConnection: close\r\n\r\n")); err != nil {
		return false
	}
	buf := make([]byte, 64)
	nn, err := conn.Read(buf)
	if err != nil || nn == 0 {
		return false
	}
	return strings.HasPrefix(string(buf[:nn]), "HTTP/1.")
}

// dialVLESS opens a stream through a VLESS node towards the URL's host.
func (s *Scanner) dialVLESS(n *model.Node, rawURL string) (net.Conn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	port := 443
	if p := u.Port(); p != "" {
		fmt.Sscanf(p, "%d", &port)
	}
	return s.dialVLESSHost(n, u.Hostname(), port)
}

func (s *Scanner) dialVLESSHost(n *model.Node, host string, port int) (net.Conn, error) {
	v := s.cfg.VLESS
	conn, err := vless.Dial(vless.Config{
		Addr: net.JoinHostPort(n.Server, strconv.Itoa(n.Port)),
		SNI:  v.WorkerHost,
		Host: v.WorkerHost,
		Path: v.Path,
		UUID: v.UUID,
	}, host, port, 20*time.Second)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// enrich fills in exit region and per-site reachability for every node.
func (s *Scanner) enrich(ctx context.Context, nodes []model.Node) {
	wantEgress := s.cfg.VLESS.EgressProbe != "" || len(s.cfg.VLESS.AllowedCountries) > 0
	wantDomains := len(s.cfg.VLESS.VerifyDomains) > 0
	if !wantEgress && !wantDomains {
		return
	}
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i := range nodes {
		if nodes[i].Class != model.ClassVless {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(n *model.Node) {
			defer wg.Done()
			defer func() { <-sem }()
			if wantEgress {
				s.probeEgress(n)
			}
			if wantDomains {
				s.probeDomains(n)
			}
		}(&nodes[i])
	}
	wg.Wait()
	log.Printf("scan: enriched %d nodes with exit region / site reachability", len(nodes))
}

// probeEgress records which IP and country the internet sees when traffic goes
// through this node. Cloudflare routes the same worker to different colos
// depending on the access address, so two nodes of one deployment can exit in
// completely different countries — which is exactly why a region-locked service
// works on some nodes and not others.
func (s *Scanner) probeEgress(n *model.Node) {
	probeURL := s.cfg.VLESS.EgressProbe
	if probeURL == "" {
		probeURL = "https://ipinfo.io/json"
	}
	u, err := url.Parse(probeURL)
	if err != nil || u.Host == "" {
		return
	}
	port := 443
	if p := u.Port(); p != "" {
		fmt.Sscanf(p, "%d", &port)
	}
	conn, err := s.dialVLESSHost(n, u.Hostname(), port)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	stream := net.Conn(conn)
	if port == 443 {
		tc := tls.Client(conn, &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12})
		if err := tc.Handshake(); err != nil {
			return
		}
		stream = tc
	}
	fmt.Fprintf(stream, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl/8\r\nAccept: application/json\r\nConnection: close\r\n\r\n", u.RequestURI(), u.Host)
	raw, _ := io.ReadAll(io.LimitReader(stream, 8192))
	body := string(raw)
	if i := strings.Index(body, "\r\n\r\n"); i >= 0 {
		body = body[i+4:]
	}
	if i := strings.IndexByte(body, '{'); i > 0 {
		body = body[i:]
	}
	if j := strings.LastIndexByte(body, '}'); j > 0 {
		body = body[:j+1]
	}

	var info struct {
		IP      string `json:"ip"`
		City    string `json:"city"`
		Country string `json:"country"`
		Org     string `json:"org"`
	}
	if err := json.Unmarshal([]byte(body), &info); err != nil {
		return
	}
	n.EgressIP = info.IP
	n.EgressCountry = strings.ToUpper(info.Country)
	n.EgressCity = info.City
	n.EgressOrg = info.Org
}

// probeDomains checks, per node, whether a specific site is reachable through
// it. Some nodes work for general traffic but fail for a particular service
// (egress IP blocked, region locked, session broken by proxyip rotation), and
// that is impossible to see from latency or throughput alone.
func (s *Scanner) probeDomains(n *model.Node) {
	n.DomainOK = map[string]bool{}
	for _, domain := range s.cfg.VLESS.VerifyDomains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}
		host := domain
		port := 443
		if h, p, err := net.SplitHostPort(domain); err == nil {
			host = h
			fmt.Sscanf(p, "%d", &port)
		}
		n.DomainOK[host] = s.domainReachable(n, host, port)
	}
}

// domainReachable opens a TLS connection to the target through the node and
// requires a real HTTP response, not just a TCP handshake.
func (s *Scanner) domainReachable(n *model.Node, host string, port int) bool {
	conn, err := s.dialVLESSHost(n, host, port)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))

	tlsConn := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err := tlsConn.Handshake(); err != nil {
		return false
	}
	req := "HEAD / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		return false
	}
	buf := make([]byte, 64)
	nn, err := tlsConn.Read(buf)
	if err != nil || nn == 0 {
		return false
	}
	line := string(buf[:nn])
	return strings.HasPrefix(line, "HTTP/1.") || strings.HasPrefix(line, "HTTP/2")
}

// probeIdle checks whether the tunnel survives being quiet, which is what a
// chat session does between messages.
func (s *Scanner) probeIdle(n *model.Node) {
	idle := time.Duration(s.cfg.Speed.IdleSeconds) * time.Second
	if idle <= 0 {
		idle = 60 * time.Second
	}
	conn, err := s.dialVLESSHost(n, "cp.cloudflare.com", 80)
	if err != nil {
		n.IdleDetail = "建连失败: " + err.Error()
		return
	}
	defer conn.Close()
	ok, detail := tunnel.IdleProbe(conn, "cp.cloudflare.com", "/generate_204", idle, 10*time.Second)
	n.IdleOK = ok
	n.IdleDetail = detail
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }

// selectTop keeps the best N of every class.
func (s *Scanner) selectTop(nodes []model.Node) []model.Node {
	limits := map[string]int{
		model.ClassWG:       s.cfg.Top.WG,
		model.ClassWGDomain: s.cfg.Top.WGDomain,
		model.ClassMasque:   s.cfg.Top.Masque,
		model.ClassVless:    s.cfg.Top.Vless,
	}
	// nodes we actually measured come first: an unmeasured node should never
	// outrank one whose throughput and stability we know
	sorted := append([]model.Node(nil), nodes...)
	sort.SliceStable(sorted, func(i, j int) bool {
		mi := sorted[i].SpeedMbps > 0
		mj := sorted[j].SpeedMbps > 0
		if mi != mj {
			return mi
		}
		return sorted[i].Score > sorted[j].Score
	})

	counts := map[string]int{}
	out := make([]model.Node, 0, len(nodes))
	for _, n := range sorted {
		if lim, ok := limits[n.Class]; ok && lim > 0 {
			if counts[n.Class] >= lim {
				continue
			}
		}
		counts[n.Class]++
		out = append(out, n)
	}
	return out
}

func countClass(cs []candidate, class string) int {
	n := 0
	for _, c := range cs {
		if c.class == class {
			n++
		}
	}
	return n
}

// sampleSubnet returns up to n random usable addresses from a CIDR.
func sampleSubnet(cidr string, n int) []string {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 {
		return nil
	}
	total := 1 << (32 - ones)
	if n <= 0 || n >= total {
		out := make([]string, 0, total)
		base := ipnet.IP.To4()
		for i := 0; i < total; i++ {
			out = append(out, fmt.Sprintf("%d.%d.%d.%d", base[0], base[1], base[2], byte(i)))
		}
		return out
	}
	base := ipnet.IP.To4()
	out := make([]string, 0, n)
	used := map[int]struct{}{}
	for len(out) < n {
		i := rand.Intn(total)
		if _, dup := used[i]; dup {
			continue
		}
		used[i] = struct{}{}
		out = append(out, fmt.Sprintf("%d.%d.%d.%d", base[0], base[1], base[2], byte(i)))
	}
	return out
}

func resolveFirst(host string) string {
	if ip := net.ParseIP(host); ip != nil {
		return host
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return ""
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
	}
	return ""
}

func round1(v float64) float64 {
	return float64(int(v*10+0.5)) / 10
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
