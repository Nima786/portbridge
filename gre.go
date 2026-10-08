package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
)

// A private GRE link between two servers.
//
// Some networks cut ordinary connections that leave the country after a few
// packets, yet let GRE (IP protocol 47) through. A tunnel run over a GRE link
// talks to the other server's private address on that link, so the only thing
// that crosses the border between the two public addresses is GRE.
//
// The link itself is made by the helper script (portbridge-firewall), which
// reads the settings below from the tunnel's config. This file holds the one rule
// both sides must agree on without talking to each other: which private address
// each server gets. It is worked out from the two public addresses alone, so
// the Iran server, the foreign server and the menu all arrive at the same answer,
// and every tunnel between the same two servers shares one link.
//
// The same rule is written in shell in the helper script, and
// TestGREHelperAgreesWithEngine holds the two together.

const (
	// greMTU is the size of packets inside the link. Small enough that GRE's
	// own header never pushes a packet over the path's limit.
	greMTU = 1300

	// grePrefix is the private network the links are taken from: 10.99.0.0/16,
	// split into 16384 blocks of four addresses, one block per pair of servers.
	grePrefix = "10.99"
	greBlocks = 16384
)

// greIPv4 reads a dotted IPv4 address exactly as written: no leading zeros, no
// IPv6, no shorthand. Anything looser would be read differently by the shell.
func greIPv4(s string) (uint32, error) {
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil || ip.To4().String() != s {
		return 0, fmt.Errorf("%q is not a plain IPv4 address", s)
	}
	return binary.BigEndian.Uint32(ip.To4()), nil
}

// greLink works out, for a pair of public addresses, the name of the link and
// the two private addresses on it. low goes to the server with the smaller public
// address and high to the other, so the answer does not depend on which side asks.
func greLink(a, b string) (iface, low, high string, err error) {
	na, err := greIPv4(a)
	if err != nil {
		return "", "", "", err
	}
	nb, err := greIPv4(b)
	if err != nil {
		return "", "", "", err
	}
	if na == nb {
		return "", "", "", fmt.Errorf("both ends of a GRE link cannot be the same address (%s)", a)
	}
	lo, hi := a, b
	if nb < na {
		lo, hi = b, a
	}
	sum := sha256.Sum256([]byte(lo + "-" + hi))
	digest := hex.EncodeToString(sum[:4])
	block := binary.BigEndian.Uint32(sum[:4]) % greBlocks
	offset := block * 4
	third, fourth := offset/256, offset%256
	iface = "pbg" + digest
	low = fmt.Sprintf("%s.%d.%d", grePrefix, third, fourth+1)
	high = fmt.Sprintf("%s.%d.%d", grePrefix, third, fourth+2)
	return iface, low, high, nil
}

// greAddrs gives this server's private address on its link to the other server,
// and the other server's, from the two public addresses.
func greAddrs(local, remote string) (own, peer string, err error) {
	_, low, high, err := greLink(local, remote)
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

// greTunnelHost is the private address a tunnel's tunnel_addr must name: the one
// this side listens on if it accepts the link, the other side's if it dials.
func greTunnelHost(c *Config) (string, error) {
	own, peer, err := greAddrs(c.GRELocal, c.GRERemote)
	if err != nil {
		return "", err
	}
	if c.Dials() {
		return peer, nil
	}
	return own, nil
}

// validateGRE checks the settings of a tunnel that runs over a GRE link.
func (c *Config) validateGRE() error {
	if !c.GRE {
		return nil
	}
	if c.GRELocal == "" || c.GRERemote == "" {
		return fmt.Errorf("gre = on needs gre_local (this server's public address) and gre_remote (the other server's)")
	}
	if c.Transport != TransportPlain {
		return fmt.Errorf("gre = on carries the plain link; the %s link is for reaching the other server over the open internet or a CDN", c.Transport)
	}
	if c.CDN || c.AltTarget != "" {
		return fmt.Errorf("gre = on cannot be combined with a CDN: the link between the servers does not cross one")
	}
	want, err := greTunnelHost(c)
	if err != nil {
		return fmt.Errorf("gre_local and gre_remote: %w", err)
	}
	host, _, err := net.SplitHostPort(c.TunnelAddr)
	if err != nil {
		return fmt.Errorf("tunnel_addr must be host:port: %w", err)
	}
	if host != want {
		return fmt.Errorf("with gre = on, tunnel_addr must use the private link address %s, not %q", want, host)
	}
	return nil
}
