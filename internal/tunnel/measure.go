package tunnel

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Throughput is a time-series view of one download, not just an average.
//
// Peak matters because it is what the user sees in the first seconds; Tail is
// what is left after the connection settles; the pair exposes the "10MB/s then
// 10KB/s" collapse that a single average hides.
type Throughput struct {
	PeakMbps  float64 `json:"peak_mbps"`
	AvgMbps   float64 `json:"avg_mbps"`
	TailMbps  float64 `json:"tail_mbps"`
	CV        float64 `json:"cv"`         // stdev/mean of the per-second rates
	StallPct  float64 `json:"stall_pct"`  // share of seconds that moved no bytes
	MaxStallS int     `json:"max_stall_s"` // longest run of dead seconds
	Bytes     int64   `json:"bytes"`
	Seconds   int     `json:"seconds"`
	Windows   []float64 `json:"-"`
	Error     string  `json:"error,omitempty"`
}

// MeasureDownstream downloads rawURL over conn and samples throughput once per
// second. It stops at maxDuration or maxBytes, whichever comes first.
func MeasureDownstream(conn net.Conn, rawURL string, maxDuration time.Duration, maxBytes int64) Throughput {
	var out Throughput
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		out.Error = "bad url"
		return out
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}

	// A deadline must be in place before the TLS handshake: a stalled handshake
	// would otherwise block the whole scan with no timeout.
	_ = conn.SetDeadline(time.Now().Add(maxDuration + 10*time.Second))

	stream := conn
	if port == "443" {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		if err := tlsConn.Handshake(); err != nil {
			out.Error = "tls: " + err.Error()
			return out
		}
		stream = tlsConn
	}

	_ = stream.SetDeadline(deadlineAt(maxDuration))
	req := "GET " + u.RequestURI() + " HTTP/1.1\r\nHost: " + u.Host +
		"\r\nUser-Agent: warp-sub\r\nAccept: */*\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(stream, req); err != nil {
		out.Error = "write: " + err.Error()
		return out
	}

	br := bufio.NewReaderSize(stream, 32*1024)
	status, err := br.ReadString('\n')
	if err != nil {
		out.Error = "status: " + err.Error()
		return out
	}
	parts := strings.Fields(strings.TrimSpace(status))
	if len(parts) < 2 || !strings.HasPrefix(parts[1], "2") {
		out.Error = "http " + strings.TrimSpace(status)
		return out
	}
	for { // drain headers
		line, err := br.ReadString('\n')
		if err != nil {
			out.Error = "headers: " + err.Error()
			return out
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	start := time.Now()
	deadline := start.Add(maxDuration)
	var total int64
	var windowBytes int64
	windows := []float64{}
	// 500ms buckets: short downloads (a few MB) would otherwise finish before the
	// first 1s tick and produce a meaningless average.
	interval := 500 * time.Millisecond
	last := start
	tick := time.NewTicker(interval)
	defer tick.Stop()

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, err := br.Read(buf)
			if n > 0 {
				total += int64(n)
				windowBytes += int64(n)
			}
			if err != nil {
				done <- err
				return
			}
			if maxBytes > 0 && total >= maxBytes {
				done <- nil
				return
			}
			if time.Now().After(deadline) {
				done <- nil
				return
			}
		}
	}()

loop:
	for {
		select {
		case <-tick.C:
			now := time.Now()
			if dt := now.Sub(last).Seconds(); dt > 0 {
				windows = append(windows, float64(windowBytes)*8/1e6/dt)
			}
			windowBytes = 0
			last = now
			if now.After(deadline) || (maxBytes > 0 && total >= maxBytes) {
				break loop
			}
		case <-done:
			now := time.Now()
			if dt := now.Sub(last).Seconds(); dt > 0 && windowBytes > 0 {
				windows = append(windows, float64(windowBytes)*8/1e6/dt)
			}
			windowBytes = 0
			break loop
		}
	}

	elapsed := time.Since(start).Seconds()
	out.Bytes = total
	out.Seconds = len(windows)
	out.Windows = windows
	if total == 0 || elapsed <= 0 {
		if out.Error == "" {
			out.Error = "no data"
		}
		return out
	}
	out.AvgMbps = float64(total) * 8 / elapsed / 1e6
	if len(windows) == 0 {
		out.PeakMbps, out.TailMbps = out.AvgMbps, out.AvgMbps
		return out
	}

	sorted := append([]float64(nil), windows...)
	sort.Float64s(sorted)
	out.PeakMbps = sorted[len(sorted)-1]

	tailN := len(windows) / 3
	if tailN < 1 {
		tailN = 1
	}
	tail := append([]float64(nil), windows[len(windows)-tailN:]...)
	sort.Float64s(tail)
	out.TailMbps = tail[len(tail)/2]

	var sum, zeros float64
	run, maxRun := 0, 0
	for _, w := range windows {
		sum += w
		if w <= 0.05 {
			zeros++
			run++
			if run > maxRun {
				maxRun = run
			}
		} else {
			run = 0
		}
	}
	mean := sum / float64(len(windows))
	if mean > 0 {
		var vr float64
		for _, w := range windows {
			d := w - mean
			vr += d * d
		}
		out.CV = sqrt(vr/float64(len(windows))) / mean
	}
	out.StallPct = zeros / float64(len(windows)) * 100
	out.MaxStallS = maxRun
	return out
}

// StabilityScore turns a download into a 0..100 stability figure.
//
// It is dominated by "does it keep going": a node that peaks high but decays to
// nothing scores worse than a slower node that holds its rate.
//
//	decay 45%  tail/peak  — 越接近 1 越好
//	flat  35%  1 - CV     — 每秒速率越平越好
//	cont  20%  1 - 卡顿   — 断流秒数越少越好
func StabilityScore(t Throughput) float64 {
	if t.Bytes == 0 {
		return 0
	}
	// Fewer than three buckets means the transfer ended almost immediately
	// (byte cap, or the exit closed the stream). Both "flat" and "collapsed"
	// look identical in that case, so stay neutral instead of pretending.
	if len(t.Windows) < 3 {
		return 50
	}
	decay := 1.0
	if t.PeakMbps > 0 {
		decay = clamp01(t.TailMbps / t.PeakMbps)
	}
	flat := 1 - clamp01(t.CV)
	cont := 1 - clamp01(t.StallPct/100)
	switch {
	case t.MaxStallS >= 5:
		cont *= 0.5
	case t.MaxStallS >= 3:
		cont *= 0.75
	}
	return (decay*0.45 + flat*0.35 + cont*0.20) * 100
}

func deadlineAt(d time.Duration) time.Time {
	return time.Now().Add(d + 10*time.Second)
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func sqrt(v float64) float64 {
	if v <= 0 {
		return 0
	}
	x := v / 2
	for i := 0; i < 40; i++ {
		x = (x + v/x) / 2
	}
	return x
}

// IdleProbe holds an established stream open for `idle`, then sends one small
// request. It answers the question a latency test cannot: does the tunnel
// survive being quiet, which is exactly what a chat session does.
func IdleProbe(conn net.Conn, hostHeader string, path string, idle time.Duration, timeout time.Duration) (ok bool, detail string) {
	if path == "" {
		path = "/generate_204"
	}
	req := func() string {
		return "GET " + path + " HTTP/1.1\r\nHost: " + hostHeader +
			"\r\nUser-Agent: warp-sub\r\nConnection: keep-alive\r\n\r\n"
	}

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := io.WriteString(conn, req()); err != nil {
		return false, "空闲前请求失败: " + err.Error()
	}
	br := bufio.NewReader(conn)
	first, err := br.ReadString('\n')
	if err != nil {
		return false, "空闲前无响应: " + err.Error()
	}
	if !strings.Contains(first, " 2") && !strings.Contains(first, " 3") {
		return false, "空闲前状态异常: " + strings.TrimSpace(first)
	}
	// drain the rest of the first response so the next read starts clean
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return false, "空闲前响应未读完: " + err.Error()
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	time.Sleep(idle)

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := io.WriteString(conn, req()); err != nil {
		return false, fmt.Sprintf("空闲 %s 后写入失败", idle)
	}
	second, err := br.ReadString('\n')
	if err != nil {
		return false, fmt.Sprintf("空闲 %s 后无响应", idle)
	}
	if !strings.Contains(second, " 2") && !strings.Contains(second, " 3") {
		return false, fmt.Sprintf("空闲 %s 后状态异常: %s", idle, strings.TrimSpace(second))
	}
	return true, fmt.Sprintf("空闲 %s 后仍可用", idle)
}
