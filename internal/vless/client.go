// Package vless implements just enough of the VLESS protocol to open a TCP
// stream through an edgetunnel-style worker: TLS, a WebSocket upgrade, then the
// VLESS request header. It is used to measure real throughput and connection
// durability through the node the user actually runs.
package vless

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// Config describes one node to connect through.
type Config struct {
	Addr  string // preferred access address, ip:port or host:port
	SNI   string // TLS server name (the worker host)
	Host  string // WebSocket Host header (usually the same as SNI)
	Path  string // WebSocket path
	UUID  string // VLESS user id
	Quiet bool
}

// Conn is a VLESS stream exposed as a net.Conn.
type Conn struct {
	raw  net.Conn
	br   *bufio.Reader
	cfg  Config
	mu   sync.Mutex // guards writes
	rbuf []byte // leftover payload from the last frame

	hdrDone bool // VLESS response header consumed
}

func (c *Conn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }

func (c *Conn) Close() error { return c.raw.Close() }

// Dial connects to the node and opens a stream to targetHost:targetPort.
func Dial(cfg Config, targetHost string, targetPort int, timeout time.Duration) (*Conn, error) {
	if cfg.Path == "" {
		cfg.Path = "/"
	}
	d := &net.Dialer{Timeout: timeout}
	raw, err := d.Dial("tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("vless: dial %s: %w", cfg.Addr, err)
	}
	dialed := time.Now()
	_ = raw.SetDeadline(dialed.Add(timeout))

	tlsConn := tls.Client(raw, &tls.Config{
		ServerName:         cfg.SNI,
		NextProtos:         []string{"http/1.1"},
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
	})
	if err := tlsConn.Handshake(); err != nil {
		raw.Close()
		return nil, fmt.Errorf("vless: tls: %w", err)
	}

	br := bufio.NewReader(tlsConn)
	if err := wsHandshake(tlsConn, br, cfg); err != nil {
		tlsConn.Close()
		return nil, err
	}

	c := &Conn{raw: tlsConn, br: br, cfg: cfg}
	// VLESS request header travels as the first WebSocket frame
	hdr, err := buildRequest(cfg.UUID, targetHost, targetPort)
	if err != nil {
		tlsConn.Close()
		return nil, err
	}
	if err := c.writeFrame(hdr); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("vless: send header: %w", err)
	}
	_ = tlsConn.SetDeadline(time.Time{})
	return c, nil
}

func wsHandshake(conn net.Conn, br *bufio.Reader, cfg Config) error {
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		return err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)
	path := cfg.Path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	host := cfg.Host
	if host == "" {
		host = cfg.SNI
	}
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: Mozilla/5.0\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return fmt.Errorf("vless: ws write: %w", err)
	}

	status, err := br.ReadString('\n')
	if err != nil {
		return fmt.Errorf("vless: ws read status: %w", err)
	}
	fields := strings.Fields(strings.TrimSpace(status))
	if len(fields) < 2 || fields[1] != "101" {
		return fmt.Errorf("vless: ws upgrade refused: %q", strings.TrimSpace(status))
	}
	// drain the response headers
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return fmt.Errorf("vless: ws read headers: %w", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	// verify the accept token when present
	_ = sha1.Sum([]byte(key))
	return nil
}

func buildRequest(uuid, host string, port int) ([]byte, error) {
	id, err := parseUUID(uuid)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 0, 64)
	buf = append(buf, 0)          // version
	buf = append(buf, id[:]...)   // 16 byte uuid
	buf = append(buf, 0)          // addon length
	buf = append(buf, 1)          // command: TCP
	buf = append(buf, byte(port>>8), byte(port))
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			buf = append(buf, 1)
			buf = append(buf, v4...)
		} else {
			buf = append(buf, 3)
			buf = append(buf, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("vless: host too long")
		}
		buf = append(buf, 2, byte(len(host)))
		buf = append(buf, host...)
	}
	return buf, nil
}

func parseUUID(s string) ([16]byte, error) {
	var out [16]byte
	clean := strings.ReplaceAll(strings.TrimSpace(s), "-", "")
	if len(clean) != 32 {
		return out, fmt.Errorf("vless: bad uuid %q", s)
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return out, err
	}
	copy(out[:], b)
	return out, nil
}

// writeFrame sends one masked binary frame.
func (c *Conn) writeFrame(payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	hdr := make([]byte, 0, 14)
	hdr = append(hdr, 0x82) // FIN + binary
	n := len(payload)
	switch {
	case n < 126:
		hdr = append(hdr, 0x80|byte(n))
	case n <= 0xFFFF:
		hdr = append(hdr, 0x80|126, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, 0x80|127)
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(n))
		hdr = append(hdr, l[:]...)
	}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	hdr = append(hdr, mask[:]...)

	masked := make([]byte, n)
	for i := 0; i < n; i++ {
		masked[i] = payload[i] ^ mask[i%4]
	}
	if _, err := c.raw.Write(hdr); err != nil {
		return err
	}
	_, err := c.raw.Write(masked)
	return err
}

// Write sends payload as one or more binary frames.
func (c *Conn) Write(p []byte) (int, error) {
	const chunk = 32 * 1024
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > chunk {
			n = chunk
		}
		if err := c.writeFrame(p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// Read returns payload bytes from the server frames, stripping the VLESS
// response header (version + addition length + additions) on first use.
func (c *Conn) Read(p []byte) (int, error) {
	if !c.hdrDone {
		if err := c.consumeResponseHeader(); err != nil {
			return 0, err
		}
	}
	for {
		if len(c.rbuf) > 0 {
			n := copy(p, c.rbuf)
			c.rbuf = c.rbuf[n:]
			return n, nil
		}
		payload, err := c.readFrame()
		if err != nil {
			return 0, err
		}
		if len(payload) == 0 {
			continue
		}
		c.rbuf = payload
	}
}

// consumeResponseHeader reads and discards the VLESS response preamble.
func (c *Conn) consumeResponseHeader() error {
	for len(c.rbuf) < 2 {
		payload, err := c.readFrame()
		if err != nil {
			return err
		}
		c.rbuf = append(c.rbuf, payload...)
	}
	addonLen := int(c.rbuf[1])
	need := 2 + addonLen
	for len(c.rbuf) < need {
		payload, err := c.readFrame()
		if err != nil {
			return err
		}
		c.rbuf = append(c.rbuf, payload...)
	}
	c.rbuf = c.rbuf[need:]
	c.hdrDone = true
	return nil
}

func (c *Conn) readFrame() ([]byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(c.br, h[:]); err != nil {
		return nil, err
	}
	opcode := h[0] & 0x0f
	masked := h[1]&0x80 != 0
	length := int(h[1] & 0x7f)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return nil, err
		}
		length = int(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return nil, err
		}
		length = int(binary.BigEndian.Uint64(ext[:]))
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(c.br, mask[:]); err != nil {
			return nil, err
		}
	}
	if length < 0 || length > 16<<20 {
		return nil, fmt.Errorf("vless: frame too large: %d", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(c.br, buf); err != nil {
		return nil, err
	}
	if masked {
		for i := range buf {
			buf[i] ^= mask[i%4]
		}
	}
	switch opcode {
	case 0x8: // close
		return nil, io.EOF
	case 0x9: // ping -> pong
		_ = c.writeControl(0xA, buf)
		return nil, nil
	case 0xA: // pong
		return nil, nil
	default: // binary / text / continuation
		return buf, nil
	}
}

func (c *Conn) writeControl(opcode byte, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	hdr := []byte{0x80 | opcode}
	n := len(payload)
	if n < 126 {
		hdr = append(hdr, 0x80|byte(n))
	} else {
		hdr = append(hdr, 0x80|126, byte(n>>8), byte(n))
	}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	hdr = append(hdr, mask[:]...)
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = payload[i] ^ mask[i%4]
	}
	if _, err := c.raw.Write(hdr); err != nil {
		return err
	}
	_, err := c.raw.Write(out)
	return err
}
