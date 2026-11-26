package account

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// MASQUE registration differs from WireGuard in three ways: the key type is
// secp256r1 (ECDSA P-256) instead of curve25519, the tunnel type is "masque",
// and the client authenticates the TLS session with a self signed certificate
// built from that key.
const (
	masqueAPIVersion = "v0a4471"
	masqueUserAgent  = "WARP for Android"
	masqueClientVer  = "a-6.35-4471"

	// MasqueSNI is the SNI Cloudflare's MASQUE ingress expects.
	MasqueSNI = "consumer-masque.cloudflareclient.com"
	// MasqueConnectURI is the URI template used for the CONNECT-IP request.
	MasqueConnectURI = "https://cloudflareaccess.com"
)

// MasqueAccount is the persisted MASQUE device.
type MasqueAccount struct {
	ID          string `json:"id"`
	Token       string `json:"token"`
	PrivateKey  string `json:"private_key"` // base64 SEC1 DER, ECDSA P-256
	PublicKey   string `json:"public_key"`  // base64 PKIX DER, endpoint key
	AddressV4   string `json:"address_v4"`
	AddressV6   string `json:"address_v6"`
	Endpoint    string `json:"endpoint"`
	EndpointH2  string `json:"endpoint_h2"`
	CreatedAt   time.Time `json:"created_at"`
}

// Address returns the v4 address in CIDR form.
func (m *MasqueAccount) Address() string {
	if m.AddressV4 == "" {
		return "172.16.0.2/32"
	}
	return withPrefix(m.AddressV4, "/32")
}

// Address6 returns the v6 address in CIDR form.
func (m *MasqueAccount) Address6() string {
	if m.AddressV6 == "" {
		return ""
	}
	return withPrefix(m.AddressV6, "/128")
}

func withPrefix(s, def string) string {
	if len(s) > 0 && s[len(s)-1] >= '0' && s[len(s)-1] <= '9' && !containsSlash(s) {
		return s + def
	}
	return s
}

func containsSlash(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			return true
		}
	}
	return false
}

// PrivateKeyDER decodes the stored ECDSA private key.
func (m *MasqueAccount) PrivateKeyDER() ([]byte, error) {
	return base64.StdEncoding.DecodeString(m.PrivateKey)
}

// ECDSAKey parses the ECDSA private key.
func (m *MasqueAccount) ECDSAKey() (*ecdsa.PrivateKey, error) {
	der, err := m.PrivateKeyDER()
	if err != nil {
		return nil, err
	}
	return x509.ParseECPrivateKey(der)
}

// PeerPublicKey parses the pinned endpoint key.
func (m *MasqueAccount) PeerPublicKey() (*ecdsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(m.PublicKey)
	if err != nil {
		return nil, err
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("account: peer key is not ECDSA")
	}
	return ec, nil
}

// ClientCert builds the self signed certificate used for TLS client auth.
func (m *MasqueAccount) ClientCert() ([]byte, error) {
	key, err := m.ECDSAKey()
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "warp-sub"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * 365 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// MasqueStore persists data/masque.json.
type MasqueStore struct{ Path string }

// NewMasqueStore points at the masque account file.
func NewMasqueStore(dir string) *MasqueStore {
	return &MasqueStore{Path: filepath.Join(dir, "masque.json")}
}

// Load reads the MASQUE account, nil when absent.
func (s *MasqueStore) Load() (*MasqueAccount, error) {
	raw, err := os.ReadFile(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var m MasqueAccount
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// Save writes the MASQUE account.
func (s *MasqueStore) Save(m *MasqueAccount) error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.Path, raw, 0o600)
}

// masqueRegResult mirrors the flat (non "result"-wrapped) response of the
// newer v0a4471 endpoint.
type masqueRegResult struct {
	ID     string `json:"id"`
	Token  string `json:"token"`
	Key    string `json:"key"`
	Config struct {
		Peers []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				V4   string `json:"v4"`
				V6   string `json:"v6"`
				Host string `json:"host"`
			} `json:"endpoint"`
		} `json:"peers"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
	} `json:"config"`
	Success bool            `json:"success"`
	Errors  json.RawMessage `json:"errors"`
}

// RegisterMasque creates a MASQUE device with an ECDSA key.
func RegisterMasque() (*MasqueAccount, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}

	body, _ := json.Marshal(map[string]string{
		"key":           base64.StdEncoding.EncodeToString(pubDER),
		"install_id":    "",
		"fcm_token":     "",
		"tos":           time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"model":         "PC",
		"serial_number": "",
		"os_version":    "14",
		"key_type":      "secp256r1",
		"tunnel_type":   "masque",
		"locale":        "en_US",
	})

	req, _ := http.NewRequest("POST", "https://api.cloudflareclient.com/"+masqueAPIVersion+"/reg", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("CF-Client-Version", masqueClientVer)
	req.Header.Set("User-Agent", masqueUserAgent)

	resp, err := client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("masque register: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("masque register: HTTP %d: %s", resp.StatusCode, truncate(string(raw), 240))
	}

	var rr masqueRegResult
	if err := json.Unmarshal(raw, &rr); err != nil {
		return nil, fmt.Errorf("masque register: decode: %w", err)
	}
	if rr.ID == "" || len(rr.Config.Peers) == 0 {
		return nil, fmt.Errorf("masque register rejected: %s", truncate(string(raw), 240))
	}

	pubKey := normalizePEMKey(rr.Config.Peers[0].PublicKey)

	m := &MasqueAccount{
		ID:         rr.ID,
		Token:      rr.Token,
		PrivateKey: base64.StdEncoding.EncodeToString(privDER),
		PublicKey:  pubKey,
		AddressV4:  rr.Config.Interface.Addresses.V4,
		AddressV6:  rr.Config.Interface.Addresses.V6,
		Endpoint:   rr.Config.Peers[0].Endpoint.V4,
		EndpointH2: "162.159.198.2",
		CreatedAt:  time.Now(),
	}
	if err := m.Enable(); err != nil {
		fmt.Fprintf(os.Stderr, "warn: enable masque warp: %v\n", err)
	}
	return m, nil
}

// normalizePEMKey converts the endpoint key from PEM to the base64 PKIX DER
// form that mihomo expects, leaving it untouched when it already is base64.
func normalizePEMKey(k string) string {
	if !strings.Contains(k, "-----BEGIN") {
		return strings.TrimSpace(k)
	}
	block, _ := pem.Decode([]byte(k))
	if block == nil {
		return strings.TrimSpace(k)
	}
	return base64.StdEncoding.EncodeToString(block.Bytes)
}

// Enable flips warp_enabled for the MASQUE device.
func (m *MasqueAccount) Enable() error {
	body, _ := json.Marshal(map[string]any{"warp_enabled": true})
	req, _ := http.NewRequest("PATCH", "https://api.cloudflareclient.com/"+masqueAPIVersion+"/reg/"+m.ID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("CF-Client-Version", masqueClientVer)
	req.Header.Set("User-Agent", masqueUserAgent)
	req.Header.Set("Authorization", "Bearer "+m.Token)

	resp, err := client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	return nil
}
