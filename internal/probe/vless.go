// Package probe measures candidate endpoints for each node class.
package probe

import (
	"bufio"
	"math"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Sample is the aggregated outcome of probing one address several times.
type Sample struct {
	OK       bool
	RTTs     []time.Duration
	Latency  time.Duration
	Jitter   time.Duration
	LossPct  float64
	Detail   string
}

// Aggregate turns a list of round timings into latency/jitter/loss figures.
func Aggregate(rtts []time.Duration, rounds int) Sample {
	s := Sample{RTTs: rtts}
	if rounds <= 0 {
		rounds = 1
	}
	s.LossPct = float64(rounds-len(rtts)) / float64(rounds) * 100
	if len(rtts) == 0 {
		return s
	}
	var sum time.Duration
	for _, r := range rtts {
		sum += r
	}
	s.Latency = sum / time.Duration(len(rtts))
	var varSum float64
	mean := float64(s.Latency)
	for _, r := range rtts {
		d := float64(r) - mean
		varSum += d * d
	}
	s.Jitter = time.Duration(sqrt(varSum / float64(len(rtts))))
	s.OK = true
	return s
}

func sqrt(v float64) float64 { return math.Sqrt(v) }

// VLESSResult describes a VLESS access-address probe.
type VLESSResult struct {
	Sample
	StatusCode int
}

// ProbeVLESS validates that addr routes into the worker (WebSocket upgrade
// answers 101) and measures TCP handshake latency to that address.
//
// Latency is measured on the TCP handshake rather than the full TLS exchange:
// the TLS cost is dominated by the edge and would drown out the difference
// between two preferred addresses, which is the thing we are choosing between.
func ProbeVLESS(addr, workerHost, path string, rounds int, timeout time.Duration) VLESSResult {
	if path == "" {
		path = "/"
	}
	res := VLESSResult{}

	code, _, err := oneWS(addr, workerHost, path, timeout)
	res.StatusCode = code
	if err != nil {
		res.Detail = err.Error()
	} else if code != 101 {
		res.Detail = fmt.Sprintf("HTTP %d", code)
	}
	if err != nil || code != 101 {
		res.Sample = Aggregate(nil, rounds)
		return res
	}

	var rtts []time.Duration
	for i := 0; i < rounds; i++ {
		d, err := tcpConnect(addr, timeout)
		if err != nil {
			continue
		}
		rtts = append(rtts, d)
	}
	res.Sample = Aggregate(rtts, rounds)
	if !res.OK {
		res.Detail = "TCP 握手失败"
	}
	return res
}

func tcpConnect(addr string, timeout time.Duration) (time.Duration, error) {
	d := &net.Dialer{Timeout: timeout}
	start := time.Now()
	c, err := d.Dial("tcp", addr)
	if err != nil {
		return 0, err
	}
	elapsed := time.Since(start)
	c.Close()
	return elapsed, nil
}

func oneWS(addr, workerHost, path string, timeout time.Duration) (int, time.Duration, error) {
	dialer := &net.Dialer{Timeout: timeout}
	start := time.Now()
	rawConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return 0, 0, err
	}
	defer rawConn.Close()
	_ = rawConn.SetDeadline(time.Now().Add(timeout))

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         workerHost,
		NextProtos:         []string{"http/1.1"},
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		return 0, 0, err
	}

	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + workerHost + "\r\n" +
		"User-Agent: Mozilla/5.0\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: websocket\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		return 0, 0, err
	}
	br := bufio.NewReader(tlsConn)
	line, err := br.ReadString('\n')
	elapsed := time.Since(start)
	if err != nil {
		return 0, 0, err
	}
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "HTTP/") {
		return 0, 0, fmt.Errorf("bad status line: %q", strings.TrimSpace(line))
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, 0, fmt.Errorf("bad status code: %q", fields[1])
	}
	return code, elapsed, nil
}

// SplitHostPort keeps "host:port" intact and defaults the port.
func SplitHostPort(s string, defPort int) (string, int, error) {
	if strings.Contains(s, ":") {
		h, p, err := net.SplitHostPort(s)
		if err == nil {
			var port int
			fmt.Sscanf(p, "%d", &port)
			return h, port, nil
		}
	}
	return s, defPort, nil
}
