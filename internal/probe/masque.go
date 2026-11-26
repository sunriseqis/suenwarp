package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"warpsub/internal/account"
)

// MasqueResult is the outcome of a CONNECT-IP tunnel attempt.
type MasqueResult struct {
	Sample
	StatusCode int
	Verified   bool // HTTP CONNECT-IP answered 2xx
	DataPath   bool // an ICMP echo actually came back through the tunnel
}

// session holds one live MASQUE tunnel.
type session struct {
	ipConn  *connectip.Conn
	tr      *http3.Transport
	conn    *quic.Conn
	udp     *net.UDPConn
	closers []func()
}

func (s *session) Close() {
	for _, f := range s.closers {
		f()
	}
}

// ProbeMasque establishes a real MASQUE CONNECT-IP tunnel, verifies the handshake
// response, then pushes ICMP echo requests through the tunnel so latency, jitter
// and loss describe the data path instead of just the setup cost.
func ProbeMasque(acct *account.MasqueAccount, addr string, rounds int, timeout time.Duration) MasqueResult {
	res := MasqueResult{}
	if acct == nil {
		res.Detail = "未注册 MASQUE 设备"
		return res
	}
	certPEM, err := acct.ClientCert()
	if err != nil {
		res.Detail = "证书生成失败: " + err.Error()
		return res
	}
	key, err := acct.ECDSAKey()
	if err != nil {
		res.Detail = "私钥解析失败: " + err.Error()
		return res
	}
	cert, err := ecKeyPair(certPEM, key)
	if err != nil {
		res.Detail = "密钥对失败: " + err.Error()
		return res
	}

	local, err := netip.ParsePrefix(acct.Address())
	if err != nil {
		local = netip.MustParsePrefix("172.16.0.2/32")
	}

	sess, code, setupTime, err := dialMasque(addr, cert, timeout)
	if err != nil {
		res.StatusCode = code
		res.Detail = err.Error()
		return res
	}
	defer sess.Close()

	res.StatusCode = code
	if code/100 != 2 {
		res.Detail = fmt.Sprintf("CONNECT-IP HTTP %d", code)
		return res
	}
	res.Verified = true

	// ask for our tunnel address; best effort, the server may assign it anyway
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	_ = sess.ipConn.AssignAddresses(ctx, []netip.Prefix{local})
	cancel()

	pg := newPinger(sess.ipConn)
	defer pg.Close()

	// One throwaway echo wakes the tunnel up (route setup, first capsule cost);
	// counting it would make the first sample dominate the average.
	pg.ping(1, 3*timeout)
	rtts, replied := pg.ping(rounds, timeout)
	res.DataPath = replied > 0
	if replied == 0 {
		// tunnel came up but no data path: fall back to setup time so the node
		// can still be ranked, and say so
		res.Sample = Aggregate([]time.Duration{setupTime}, 1)
		res.Detail = "隧道已建立但无回包"
		return res
	}
	res.Sample = Aggregate(rtts, rounds)
	return res
}

// dialMasque performs the QUIC + extended CONNECT handshake.
func dialMasque(addr string, cert tls.Certificate, timeout time.Duration) (*session, int, time.Duration, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, 0, 0, err
	}
	tlsConf := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		ServerName:         account.MasqueSNI,
		NextProtos:         []string{http3.NextProtoH3},
		InsecureSkipVerify: true, // WARP pins the endpoint key, not the hostname
		MinVersion:         tls.VersionTLS13,
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, 0, 0, err
	}
	qtr := &quic.Transport{Conn: udpConn, ConnectionIDLength: 20}
	sess := &session{udp: udpConn}
	sess.closers = append(sess.closers, func() { qtr.Close() }, func() { udpConn.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()
	conn, err := qtr.Dial(ctx, udpAddr, tlsConf, &quic.Config{
		HandshakeIdleTimeout: timeout,
		MaxIdleTimeout:       3 * timeout,
	})
	if err != nil {
		sess.Close()
		return nil, 0, 0, err
	}
	sess.conn = conn

	tr := &http3.Transport{
		EnableDatagrams: true,
		AdditionalSettings: map[uint64]uint64{
			// deprecated SETTINGS_H3_DATAGRAM_00, still sent by the official client
			0x276: 1,
		},
		DisableCompression: true,
	}
	sess.tr = tr

	hconn := tr.NewClientConn(conn)
	tmpl := uritemplate.MustNew(account.MasqueConnectURI)
	ipConn, rsp, err := connectip.Dial(ctx, hconn, tmpl, "cf-connect-ip", http.Header{"User-Agent": []string{""}}, true)
	elapsed := time.Since(start)
	if err != nil {
		sess.Close()
		return nil, 0, 0, err
	}
	sess.ipConn = ipConn
	sess.closers = append([]func(){func() { _ = ipConn.Close() }, func() { tr.Close() }}, sess.closers...)

	code := 0
	if rsp != nil {
		code = rsp.StatusCode
	}
	return sess, code, elapsed, nil
}

// pinger owns the single reader goroutine for one tunnel session. Two readers
// on the same connection would steal each other's replies.
type pinger struct {
	c       *connectip.Conn
	replies chan int
	stop    chan struct{}
	once    sync.Once
}

func newPinger(c *connectip.Conn) *pinger {
	p := &pinger{c: c, replies: make(chan int, 64), stop: make(chan struct{})}
	go p.readLoop()
	return p
}

func (p *pinger) readLoop() {
	buf := make([]byte, 4096)
	for {
		select {
		case <-p.stop:
			return
		default:
		}
		n, err := p.c.ReadPacket(buf, true)
		if err != nil || n <= 20 {
			time.Sleep(2 * time.Millisecond)
			continue
		}
		msg, err := icmp.ParseMessage(1, buf[20:n])
		if err != nil || msg.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		if body, ok := msg.Body.(*icmp.Echo); ok {
			select {
			case p.replies <- body.Seq:
			case <-p.stop:
				return
			}
		}
	}
}

func (p *pinger) Close() {
	p.once.Do(func() { close(p.stop) })
}

// ping sends `rounds` echo requests and returns the round trip times that came back.
func (p *pinger) ping(rounds int, timeout time.Duration) ([]time.Duration, int) {
	if rounds <= 0 {
		rounds = 1
	}
	id := uint16(os.Getpid() & 0xffff)
	var rtts []time.Duration
	for seq := 0; seq < rounds; seq++ {
		pkt, err := echoRequest(id, seq)
		if err != nil {
			continue
		}
		start := time.Now()
		if _, err := p.c.WritePacket(pkt); err != nil {
			continue
		}
		deadline := time.After(timeout)
	wait:
		for {
			select {
			case got := <-p.replies:
				if got == seq {
					rtts = append(rtts, time.Since(start))
					break wait
				}
				// stale reply from an earlier round: ignore
			case <-deadline:
				break wait
			}
		}
	}
	return rtts, len(rtts)
}

func echoRequest(id uint16, seq int) ([]byte, error) {
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{ID: int(id), Seq: seq, Data: []byte("warp-sub")},
	}
	payload, err := msg.Marshal(nil)
	if err != nil {
		return nil, err
	}
	hdr := ipv4.Header{
		Version:  4,
		Len:      20,
		TotalLen: 20 + len(payload),
		TTL:      64,
		Protocol: 1,
		Dst:      net.IPv4(1, 1, 1, 1),
	}
	hdrBytes, err := hdr.Marshal()
	if err != nil {
		return nil, err
	}
	pkt := append(hdrBytes, payload...)
	pkt[10], pkt[11] = 0, 0
	sum := ipChecksum(pkt[:20])
	pkt[10] = byte(sum >> 8)
	pkt[11] = byte(sum)
	return pkt, nil
}

func ipChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(hdr[i])<<8 | uint32(hdr[i+1])
	}
	if len(hdr)%2 == 1 {
		sum += uint32(hdr[len(hdr)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func ecKeyPair(certPEM []byte, key *ecdsa.PrivateKey) (tls.Certificate, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	return tls.X509KeyPair(certPEM, keyPEM)
}
