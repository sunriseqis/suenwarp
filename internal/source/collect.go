// Package source collects VLESS access-address candidates from public
// preferred-IP/domain lists and filters out anything that is not a Cloudflare
// address.
package source

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// CFv4 is a static fallback of Cloudflare's published IPv4 ranges. The list is
// refreshed from cloudflare.com when the network allows it.
var CFv4 = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
}

// Entry is one normalised candidate address.
type Entry struct {
	Host   string
	Port   int
	Remark string
	Source string
}

var (
	lineRe  = regexp.MustCompile(`^\s*([a-zA-Z0-9._-]+|\[[0-9a-fA-F:]+\])(?::(\d+))?\s*(?:#(.*))?$`)
	prefixes []*net.IPNet
)

func init() {
	RefreshCFRanges(context.Background(), nil)
}

// RefreshCFRanges loads Cloudflare's official list, keeping the static fallback
// when the request fails.
func RefreshCFRanges(ctx context.Context, client *http.Client) {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	var list []string
	req, err := http.NewRequestWithContext(ctx, "GET", "https://www.cloudflare.com/ips-v4", nil)
	if err == nil {
		req.Header.Set("User-Agent", "warp-sub")
		if resp, err := client.Do(req); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == 200 {
				raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
				list = strings.Fields(strings.ReplaceAll(string(raw), ",", " "))
			}
		}
	}
	if len(list) == 0 {
		list = CFv4
	}
	var out []*net.IPNet
	for _, c := range list {
		if _, n, err := net.ParseCIDR(strings.TrimSpace(c)); err == nil {
			out = append(out, n)
		}
	}
	if len(out) > 0 {
		prefixes = out
	}
}

// IsCloudflare reports whether ip falls inside a Cloudflare range.
func IsCloudflare(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	for _, n := range prefixes {
		if n.Contains(v4) {
			return true
		}
	}
	return false
}

// Collect fetches every source URL and returns de-duplicated candidates whose
// host resolves into a Cloudflare range.
//
// max caps how many candidates survive; 0 means unlimited.
func Collect(ctx context.Context, urls []string, defaultPort, max int, logf func(string, ...any)) []Entry {
	seen := map[string]struct{}{}
	var out []Entry
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		entries, err := fetchList(ctx, u, defaultPort)
		if err != nil {
			if logf != nil {
				logf("source: %s -> %v", u, err)
			}
			continue
		}
		kept := 0
		for _, e := range entries {
			key := fmt.Sprintf("%s:%d", e.Host, e.Port)
			if _, dup := seen[key]; dup {
				continue
			}
			if !resolvesToCloudflare(e.Host) {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, e)
			kept++
			if max > 0 && len(out) >= max {
				if logf != nil {
					logf("source: %s -> kept %d (hit max %d)", u, kept, max)
				}
				return out
			}
		}
		if logf != nil {
			logf("source: %s -> %d entries, %d kept", u, len(entries), kept)
		}
	}
	return out
}

func fetchList(ctx context.Context, rawURL string, defaultPort int) ([]Entry, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "warp-sub/1.0")
	resp, err := (&http.Client{Timeout: 25 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return Parse(resp.Body, defaultPort), nil
}

// Parse turns a list body into entries. Supported line shapes:
//
//	domain:443#remark
//	1.2.3.4:2053
//	domain
func Parse(r io.Reader, defaultPort int) []Entry {
	if defaultPort <= 0 {
		defaultPort = 443
	}
	var out []Entry
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// some lists are "host:port#remark" with spaces around the hash
		line = strings.ReplaceAll(line, " #", "#")
		m := lineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		host := strings.Trim(m[1], "[]")
		port := defaultPort
		if m[2] != "" {
			fmt.Sscanf(m[2], "%d", &port)
		}
		if port <= 0 || port > 65535 {
			continue
		}
		out = append(out, Entry{Host: host, Port: port, Remark: strings.TrimSpace(m[3])})
	}
	return out
}

var resolveCache = map[string]bool{}

func resolvesToCloudflare(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return IsCloudflare(ip)
	}
	if v, ok := resolveCache[host]; ok {
		return v
	}
	ips, err := net.LookupIP(host)
	ok := false
	if err == nil {
		for _, ip := range ips {
			if IsCloudflare(ip) {
				ok = true
				break
			}
		}
	}
	resolveCache[host] = ok
	return ok
}
