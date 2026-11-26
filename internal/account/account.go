// Package account manages the Cloudflare WARP device registration: keys,
// addresses and the WARP+ license.
package account

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

const (
	apiBase        = "https://api.cloudflareclient.com/v0i1909051800"
	clientVersion  = "a-6.30-2158"
	userAgent      = "okhttp/3.12.1"
	warpDefaultMTU = 1280
)

// Account is the persisted registration state.
type Account struct {
	ID         string `json:"id"`
	Token      string `json:"token"`
	PrivateKey string `json:"private_key"` // base64
	PublicKey  string `json:"public_key"`  // peer public key, base64
	ClientID   string `json:"client_id"`
	Reserved   []byte `json:"reserved"`
	AddressV4  string `json:"address_v4"`
	AddressV6  string `json:"address_v6"`
	License    string `json:"license,omitempty"`
	AccountType string `json:"account_type,omitempty"`
	WarpEnabled bool  `json:"warp_enabled"`
	CreatedAt  time.Time `json:"created_at"`
}

// Address returns the v4 address in CIDR form.
func (a *Account) Address() string {
	if a.AddressV4 == "" {
		return "172.16.0.2/32"
	}
	if strings.Contains(a.AddressV4, "/") {
		return a.AddressV4
	}
	return a.AddressV4 + "/32"
}

// Address6 returns the v6 address in CIDR form.
func (a *Account) Address6() string {
	if a.AddressV6 == "" {
		return ""
	}
	if strings.Contains(a.AddressV6, "/") {
		return a.AddressV6
	}
	return a.AddressV6 + "/128"
}

// PrivateKeyBytes decodes the private key.
func (a *Account) PrivateKeyBytes() ([32]byte, error) {
	var out [32]byte
	b, err := base64.StdEncoding.DecodeString(a.PrivateKey)
	if err != nil || len(b) != 32 {
		return out, errors.New("account: invalid private key")
	}
	copy(out[:], b)
	return out, nil
}

// PublicKeyBytes decodes the peer public key.
func (a *Account) PublicKeyBytes() ([32]byte, error) {
	var out [32]byte
	b, err := base64.StdEncoding.DecodeString(a.PublicKey)
	if err != nil || len(b) != 32 {
		return out, errors.New("account: invalid public key")
	}
	copy(out[:], b)
	return out, nil
}

// ReservedBytes returns the three reserved bytes, preferring an explicit value.
func (a *Account) ReservedBytes(override string) [3]byte {
	var out [3]byte
	if override != "" {
		if b, err := base64.StdEncoding.DecodeString(override); err == nil && len(b) >= 3 {
			copy(out[:], b[:3])
			return out
		}
		if b, err := hexDecode(override); err == nil && len(b) >= 3 {
			copy(out[:], b[:3])
			return out
		}
	}
	if len(a.Reserved) >= 3 {
		copy(out[:], a.Reserved[:3])
		return out
	}
	if a.ClientID != "" {
		if b, err := base64.StdEncoding.DecodeString(a.ClientID); err == nil && len(b) >= 3 {
			copy(out[:], b[:3])
		}
	}
	return out
}

func hexDecode(s string) ([]byte, error) {
	s = strings.ReplaceAll(strings.TrimPrefix(s, "0x"), ":", "")
	if len(s)%2 != 0 {
		return nil, errors.New("odd hex length")
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		v, err := strconv.ParseUint(s[i*2:i*2+2], 16, 8)
		if err != nil {
			return nil, err
		}
		out[i] = byte(v)
	}
	return out, nil
}

// Store persists the account on disk.
type Store struct {
	Path string
}

// NewStore points at data/account.json under dir.
func NewStore(dir string) *Store {
	return &Store{Path: filepath.Join(dir, "account.json")}
}

// Load reads the account, returning nil when absent.
func (s *Store) Load() (*Account, error) {
	raw, err := os.ReadFile(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var a Account
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, err
	}
	return &a, nil
}

// Save writes the account with tight permissions.
func (s *Store) Save(a *Account) error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.Path, raw, 0o600)
}

// client returns an HTTP client honouring the environment proxy.
func client() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

func newKeypair() (priv, pub [32]byte, err error) {
	if _, err = rand.Read(priv[:]); err != nil {
		return
	}
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64
	p, e := curve25519.X25519(priv[:], curve25519.Basepoint)
	if e != nil {
		err = e
		return
	}
	copy(pub[:], p)
	return
}

type regResult struct {
	Result struct {
		ID     string `json:"id"`
		Token  string `json:"token"`
		Config struct {
			ClientID string `json:"client_id"`
			Peers    []struct {
				PublicKey string `json:"public_key"`
			} `json:"peers"`
			Interface struct {
				Addresses struct {
					V4 string `json:"v4"`
					V6 string `json:"v6"`
				} `json:"addresses"`
			} `json:"interface"`
		} `json:"config"`
		Account struct {
			License     string `json:"license"`
			AccountType string `json:"account_type"`
		} `json:"account"`
		WarpEnabled bool `json:"warp_enabled"`
	} `json:"result"`
	Success bool     `json:"success"`
	Errors  []string `json:"errors"`
}

// Register creates a new WARP device and enables WARP for it.
func Register() (*Account, error) {
	priv, pub, err := newKeypair()
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]string{
		"key":    base64.StdEncoding.EncodeToString(pub[:]),
		"tos":    time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"type":   "Android",
		"locale": "en_US",
		"model":  "PC",
	})
	req, _ := http.NewRequest("POST", apiBase+"/reg", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("CF-Client-Version", clientVersion)
	req.Header.Set("User-Agent", userAgent)

	resp, err := client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("register: HTTP %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	var rr regResult
	if err := json.Unmarshal(raw, &rr); err != nil {
		return nil, fmt.Errorf("register: decode: %w", err)
	}
	if !rr.Success || len(rr.Result.Config.Peers) == 0 {
		return nil, fmt.Errorf("register: rejected: %v", rr.Errors)
	}

	a := &Account{
		ID:          rr.Result.ID,
		Token:       rr.Result.Token,
		PrivateKey:  base64.StdEncoding.EncodeToString(priv[:]),
		PublicKey:   rr.Result.Config.Peers[0].PublicKey,
		ClientID:    rr.Result.Config.ClientID,
		AddressV4:   rr.Result.Config.Interface.Addresses.V4,
		AddressV6:   rr.Result.Config.Interface.Addresses.V6,
		License:     rr.Result.Account.License,
		AccountType: rr.Result.Account.AccountType,
		CreatedAt:   time.Now(),
	}
	if cid, err := base64.StdEncoding.DecodeString(a.ClientID); err == nil && len(cid) >= 3 {
		a.Reserved = cid[:3]
	}
	if err := a.Enable(); err != nil {
		// not fatal: the device usually still works
		fmt.Fprintf(os.Stderr, "warn: enable warp: %v\n", err)
	}
	return a, nil
}

// Enable flips warp_enabled on the device.
func (a *Account) Enable() error {
	return a.patch("/reg/"+a.ID, map[string]any{"warp_enabled": true})
}

// ApplyLicense attaches a WARP+ license key to the account.
func (a *Account) ApplyLicense(license string) error {
	license = strings.TrimSpace(license)
	if license == "" {
		return errors.New("account: empty license")
	}
	if err := a.patch("/reg/"+a.ID+"/account", map[string]any{"license": license}); err != nil {
		return err
	}
	a.License = license
	a.AccountType = "warp_plus"
	return nil
}

func (a *Account) patch(path string, payload any) error {
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("PATCH", apiBase+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("CF-Client-Version", clientVersion)
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Authorization", "Bearer "+a.Token)

	resp, err := client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
