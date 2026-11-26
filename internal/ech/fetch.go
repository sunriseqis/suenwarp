// Package ech resolves the ECHConfigList for a host via DNS-over-HTTPS so that
// mihomo's `ech-opts.config` can be filled automatically.
package ech

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// candidates are JSON-capable DoH endpoints, tried in order. The `doh` value
// configured for the node URI is not necessarily JSON capable (alidns wants
// /resolve, not /dns-query), so we fall back to known-good resolvers.
func candidates(preferred string) []string {
	out := []string{}
	if preferred != "" {
		out = append(out, preferred)
		// alidns serves JSON on /resolve instead of /dns-query
		if strings.Contains(preferred, "alidns.com/dns-query") {
			out = append(out, strings.Replace(preferred, "/dns-query", "/resolve", 1))
		}
	}
	out = append(out,
		"https://cloudflare-dns.com/dns-query",
		"https://dns.alidns.com/resolve",
		"https://doh.pub/dns-query",
	)
	return out
}

// FetchConfigList queries the HTTPS (type 65) record for serverName and returns
// the base64 ECHConfigList, ready to paste into mihomo's ech-opts.config.
func FetchConfigList(ctx context.Context, preferred, serverName string) (string, error) {
	var lastErr error
	for _, dohURL := range candidates(preferred) {
		v, err := fetchOne(ctx, dohURL, serverName)
		if err == nil && v != "" {
			return v, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no ech record")
	}
	return "", lastErr
}

func fetchOne(ctx context.Context, dohURL, serverName string) (string, error) {
	u, err := url.Parse(dohURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("name", serverName)
	q.Set("type", "HTTPS")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/dns-json")

	cli := &http.Client{Timeout: 12 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("doh HTTP %d", resp.StatusCode)
	}

	var out struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("doh decode: %w", err)
	}
	for _, a := range out.Answer {
		if a.Type != 65 {
			continue
		}
		if v := extractECH(a.Data); v != "" {
			return v, nil
		}
	}
	return "", fmt.Errorf("no ech in HTTPS record for %s", serverName)
}

// extractECH pulls ech="..." out of an SVCB/HTTPS RDATA string.
func extractECH(data string) string {
	for _, field := range strings.Fields(data) {
		if !strings.HasPrefix(field, "ech=") {
			continue
		}
		v := strings.TrimPrefix(field, "ech=")
		v = strings.Trim(v, `"`)
		// the value may be base64 standard or raw base64; mihomo wants std
		return v
	}
	return ""
}
