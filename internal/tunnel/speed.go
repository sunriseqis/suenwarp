// Package tunnel builds a real userspace WireGuard tunnel (gVisor netstack)
// so throughput can be measured end to end without root or /dev/net/tun.
package tunnel

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"warpsub/internal/account"
)

// MeasureSpeed brings up a WireGuard tunnel to endpoint, opens a TCP connection
// to the speed target and delegates the actual sampling to MeasureDownstream.
func MeasureSpeed(acct *account.Account, endpoint string, mtu int, rawURL string, timeout time.Duration, maxBytes int64) Throughput {
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

	priv, err := acct.PrivateKeyBytes()
	if err != nil {
		out.Error = err.Error()
		return out
	}
	peer, err := acct.PublicKeyBytes()
	if err != nil {
		out.Error = err.Error()
		return out
	}
	local, err := netip.ParsePrefix(acct.Address())
	if err != nil {
		local = netip.MustParsePrefix("172.16.0.2/32")
	}

	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{local.Addr()},
		[]netip.Addr{netip.MustParseAddr("1.1.1.1")}, mtu)
	if err != nil {
		out.Error = "netstack: " + err.Error()
		return out
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "tunnel: "))
	defer dev.Close()

	cfg := fmt.Sprintf(
		"private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\npersistent_keepalive_interval=25\n",
		hex.EncodeToString(priv[:]), hex.EncodeToString(peer[:]), endpoint,
	)
	if err := dev.IpcSet(cfg); err != nil {
		out.Error = "ipc: " + err.Error()
		return out
	}
	if err := dev.Up(); err != nil {
		out.Error = "up: " + err.Error()
		return out
	}

	dialHost := host
	if addrs, err := net.LookupHost(host); err == nil {
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
				dialHost = a
				break
			}
		}
	}

	var rawConn net.Conn
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		time.Sleep(300 * time.Millisecond)
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		rawConn, lastErr = tnet.DialContext(ctx, "tcp", net.JoinHostPort(dialHost, port))
		cancel()
		if lastErr == nil {
			break
		}
	}
	if lastErr != nil {
		out.Error = "dial: " + lastErr.Error()
		return out
	}
	defer rawConn.Close()

	return MeasureDownstream(rawConn, rawURL, timeout, maxBytes)
}
