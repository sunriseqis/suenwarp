// Package wgn implements a userspace WireGuard handshake prober.
//
// It builds a valid Noise IK handshake initiation for a given peer public key
// and measures the round-trip time of the 92-byte handshake response. No TUN
// device, no root and no kernel module are required, which makes it suitable
// for running inside a container.
package wgn

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"hash"
	"net"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	noiseConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	wgIdentifier      = "WireGuard v1 zx2c4 Jason@zx2c4.com"
	wgLabelMAC1       = "mac1----"

	// MessageInitiationSize is the on-wire size of a handshake initiation.
	MessageInitiationSize = 148
	// MessageResponseSize is the on-wire size of a handshake response.
	MessageResponseSize = 92
	// messageResponseType is the WireGuard message type of a handshake response.
	messageResponseType = 2

	// offsetMAC1 is where the first MAC starts; it covers msg[:offsetMAC1].
	offsetMAC1 = 116
)

var (
	initialChainKey [blake2s.Size]byte
	initialHash     [blake2s.Size]byte
	zeroNonce       [chacha20poly1305.NonceSize]byte
)

func init() {
	initialChainKey = blake2s.Sum256([]byte(noiseConstruction))
	// mixHash(&initialHash, &initialChainKey, []byte(wgIdentifier))
	mixHash(&initialHash, &initialChainKey, []byte(wgIdentifier))
}

func blake2sCtor() hash.Hash {
	h, err := blake2s.New256(nil)
	if err != nil {
		panic(err)
	}
	return h
}

func hmacInto(sum *[blake2s.Size]byte, key, in0 []byte) {
	mac := hmac.New(blake2sCtor, key)
	mac.Write(in0)
	mac.Sum(sum[:0])
}

func hmac2Into(sum *[blake2s.Size]byte, key, in0, in1 []byte) {
	mac := hmac.New(blake2sCtor, key)
	mac.Write(in0)
	mac.Write(in1)
	mac.Sum(sum[:0])
}

// kdf1 is the single-output HKDF step used by mixKey.
func kdf1(t0 *[blake2s.Size]byte, key, input []byte) {
	hmacInto(t0, key, input)
	hmacInto(t0, t0[:], []byte{0x1})
}

// kdf2 is the two-output HKDF step used to derive AEAD keys.
func kdf2(t0, t1 *[blake2s.Size]byte, key, input []byte) {
	var prk [blake2s.Size]byte
	hmacInto(&prk, key, input)
	hmacInto(t0, prk[:], []byte{0x1})
	hmac2Into(t1, prk[:], t0[:], []byte{0x2})
}

func mixHash(dst, h *[blake2s.Size]byte, data []byte) {
	hh, _ := blake2s.New256(nil)
	hh.Write(h[:])
	hh.Write(data)
	hh.Sum(dst[:0])
}

// newPrivateKey returns a clamped X25519 private key.
func newPrivateKey() ([32]byte, error) {
	var sk [32]byte
	if _, err := rand.Read(sk[:]); err != nil {
		return sk, err
	}
	sk[0] &= 248
	sk[31] = (sk[31] & 127) | 64
	return sk, nil
}

func publicKey(sk [32]byte) ([32]byte, error) {
	var pk [32]byte
	out, err := curve25519.X25519(sk[:], curve25519.Basepoint)
	if err != nil {
		return pk, err
	}
	copy(pk[:], out)
	return pk, nil
}

// Tai64nNow returns the 12-byte TAI64N timestamp WireGuard puts in handshakes.
func Tai64nNow() [12]byte {
	var b [12]byte
	now := time.Now()
	nano := now.UnixNano()
	secs := uint64(nano/1e9) + 0x400000000000000a
	binary.BigEndian.PutUint64(b[0:8], secs)
	binary.BigEndian.PutUint32(b[8:12], uint32(nano%1e9))
	return b
}

// Client holds a static keypair reused across probes.
type Client struct {
	priv    [32]byte
	pub     [32]byte
	mac1Key [32]byte
}

// NewClient creates a prober bound to the given peer (responder) public key.
func NewClient(peerPub [32]byte) (*Client, error) {
	c := &Client{}
	priv, err := newPrivateKey()
	if err != nil {
		return nil, err
	}
	c.priv = priv
	pub, err := publicKey(priv)
	if err != nil {
		return nil, err
	}
	c.pub = pub

	hh, _ := blake2s.New256(nil)
	hh.Write([]byte(wgLabelMAC1))
	hh.Write(peerPub[:])
	hh.Sum(c.mac1Key[:0])
	return c, nil
}

// NewClientFromPrivate builds a prober with a caller supplied static private key.
func NewClientFromPrivate(privB64 [32]byte, peerPub [32]byte) (*Client, error) {
	c := &Client{priv: privB64}
	pub, err := publicKey(privB64)
	if err != nil {
		return nil, err
	}
	c.pub = pub
	hh, _ := blake2s.New256(nil)
	hh.Write([]byte(wgLabelMAC1))
	hh.Write(peerPub[:])
	hh.Sum(c.mac1Key[:0])
	return c, nil
}

// Initiation builds one handshake initiation packet for the given peer.
func (c *Client) Initiation(peerPub [32]byte, reserved [3]byte, sender uint32) ([]byte, error) {
	ephPriv, err := newPrivateKey()
	if err != nil {
		return nil, err
	}
	ephPub, err := publicKey(ephPriv)
	if err != nil {
		return nil, err
	}

	chainKey := initialChainKey
	h := initialHash
	mixHash(&h, &h, peerPub[:])

	msg := make([]byte, MessageInitiationSize)
	msg[0] = 1 // MessageInitiationType
	copy(msg[1:4], reserved[:])
	binary.LittleEndian.PutUint32(msg[4:8], sender)
	copy(msg[8:40], ephPub[:])

	// mixKey(ephemeral) then mixHash(ephemeral)
	kdf1(&chainKey, chainKey[:], ephPub[:])
	mixHash(&h, &h, ephPub[:])

	// encrypted static
	ss, err := curve25519.X25519(ephPriv[:], peerPub[:])
	if err != nil {
		return nil, err
	}
	var key [chacha20poly1305.KeySize]byte
	kdf2(&chainKey, &key, chainKey[:], ss)
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	sealed := aead.Seal(nil, zeroNonce[:], c.pub[:], h[:])
	if len(sealed) != 48 {
		return nil, errors.New("wgn: unexpected sealed static length")
	}
	copy(msg[40:88], sealed)
	mixHash(&h, &h, msg[40:88])

	// encrypted timestamp, keyed with the precomputed static-static secret
	ss2, err := curve25519.X25519(c.priv[:], peerPub[:])
	if err != nil {
		return nil, err
	}
	kdf2(&chainKey, &key, chainKey[:], ss2)
	aead2, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	ts := Tai64nNow()
	sealedTS := aead2.Seal(nil, zeroNonce[:], ts[:], h[:])
	if len(sealedTS) != 28 {
		return nil, errors.New("wgn: unexpected sealed timestamp length")
	}
	copy(msg[88:116], sealedTS)

	// MAC1 over everything up to it; MAC2 stays zero for initiators
	mac, err := blake2s.New128(c.mac1Key[:])
	if err != nil {
		return nil, err
	}
	mac.Write(msg[:offsetMAC1])
	mac.Sum(msg[offsetMAC1:offsetMAC1])
	return msg, nil
}

// Result is the outcome of probing one endpoint.
type Result struct {
	OK      bool
	RTT     time.Duration
	Samples int
	Sent    int
	RTTs    []time.Duration
}

// Probe sends `rounds` handshakes to addr and reports reachability statistics.
func (c *Client) Probe(addr string, peerPub [32]byte, reserved [3]byte, rounds int, timeout time.Duration) Result {
	res := Result{Sent: rounds}
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return res
	}
	defer conn.Close()

	buf := make([]byte, 256)
	var total time.Duration
	var sender uint32 = 1
	for i := 0; i < rounds; i++ {
		pkt, err := c.Initiation(peerPub, reserved, sender)
		if err != nil {
			continue
		}
		sender++

		start := time.Now()
		if _, err := conn.Write(pkt); err != nil {
			continue
		}
		if err := conn.SetReadDeadline(start.Add(timeout)); err != nil {
			continue
		}
		n, err := conn.Read(buf)
		if err != nil {
			continue
		}
		if n != MessageResponseSize || buf[0] != messageResponseType {
			continue
		}
		res.Samples++
		d := time.Since(start)
		res.RTTs = append(res.RTTs, d)
		total += d
	}
	if res.Samples > 0 {
		res.OK = true
		res.RTT = total / time.Duration(res.Samples)
	}
	return res
}

// PublicKey returns the prober's static public key.
func (c *Client) PublicKey() [32]byte { return c.pub }
