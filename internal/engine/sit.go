package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
)

// A private 6in4 (SIT, IP protocol 41) IPv6-over-IPv4 link between two servers.
//
// Many networks heavily filter or freeze IPv4 TCP/UDP and GRE (IP protocol 47),
// yet allow IPv6 or IP protocol 41 (SIT / 6in4 encapsulation) through untouched.
// A tunnel with "sit = on" creates a point-to-point IPv6 link encapsulated
// directly inside IPv4 packets between the two servers' public IPv4 addresses,
// giving both servers a private IPv6 path even if neither provider offers native
// IPv6.
//
// As with GRE, the interface name (pbs<hash>) and the two private ULA IPv6
// addresses (fd99:xxxx:xxxx::1 and fd99:xxxx:xxxx::2) are derived deterministically
// from the two public IPv4 addresses alone so Go and portbridge-firewall always
// arrive at the exact same answer.

const (
	sitMTU    = 1400
	sitPrefix = "fd99"
)

// sitLink computes the deterministic SIT interface name and private IPv6 pair
// for two public IPv4 addresses. The server with the numerically smaller IPv4
// address receives ::1 (low) and the other receives ::2 (high).
func sitLink(a, b string) (iface, low, high string, err error) {
	na, err := greIPv4(a)
	if err != nil {
		return "", "", "", err
	}
	nb, err := greIPv4(b)
	if err != nil {
		return "", "", "", err
	}
	if na == nb {
		return "", "", "", fmt.Errorf("both ends of a 6in4 (SIT) link cannot be the same address (%s)", a)
	}
	lo, hi := a, b
	if nb < na {
		lo, hi = b, a
	}
	sum := sha256.Sum256([]byte(lo + "-sit-" + hi))
	digest := hex.EncodeToString(sum[:4])
	h1 := digest[0:4]
	h2 := digest[4:8]
	iface = "pbs" + digest
	low = fmt.Sprintf("%s:%s:%s::1", sitPrefix, h1, h2)
	high = fmt.Sprintf("%s:%s:%s::2", sitPrefix, h1, h2)
	return iface, low, high, nil
}

// SITAddrs returns this server's private IPv6 address (own) and the peer's
// private IPv6 address (peer) on the 6in4 (SIT) link between local and remote.
func SITAddrs(local, remote string) (own, peer string, err error) {
	_, low, high, err := sitLink(local, remote)
	if err != nil {
		return "", "", err
	}
	nl, _ := greIPv4(local)
	nr, _ := greIPv4(remote)
	if nl < nr {
		return low, high, nil
	}
	return high, low, nil
}

func sitTunnelHost(c *Config) (string, error) {
	own, peer, err := SITAddrs(c.SITLocal, c.SITRemote)
	if err != nil {
		return "", err
	}
	if c.Dials() {
		return peer, nil
	}
	return own, nil
}

func (c *Config) validateSIT() error {
	if !c.SIT {
		return nil
	}
	if c.GRE {
		return fmt.Errorf("gre = on and sit = on cannot both be enabled on the same tunnel")
	}
	if c.SITLocal == "" || c.SITRemote == "" {
		return fmt.Errorf("sit = on needs sit_local (this server's public IPv4 address) and sit_remote (the other server's)")
	}
	if c.CDN || c.AltTarget != "" {
		return fmt.Errorf("sit = on cannot be combined with a CDN: the link between the servers does not cross one")
	}
	want, err := sitTunnelHost(c)
	if err != nil {
		return fmt.Errorf("sit_local and sit_remote: %w", err)
	}
	host, _, err := net.SplitHostPort(c.TunnelAddr)
	if err != nil {
		return fmt.Errorf("tunnel_addr must be [host]:port: %w", err)
	}
	if host != want {
		return fmt.Errorf("with sit = on, tunnel_addr must use the private 6in4 address %s, not %q", want, host)
	}
	return nil
}
