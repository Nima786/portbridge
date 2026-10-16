package main

// Passing each user's real address on to the service.
//
// Without this, everything the service sees arrives from the tunnel on its own
// server, so every user looks like one: its logs, per-user limits and login
// protection all treat them as the same person. With proxy_protocol on, the edge
// sends each user's address across with the "a user has arrived" signal, and the
// origin hands it to the service in the standard PROXY protocol header, which
// Xray, nginx, HAProxy, LiteSpeed and most other servers already read.
//
// Only the edge writes the address, from the connection the user actually made,
// so a user cannot claim to be someone else. It crosses inside the tunnel, after
// the other server has proved it holds the password, so nobody else can either.
//
// Both servers need it on. If only the origin has it, the service is told the
// address is unknown and goes on using the connection's own; if only the edge
// has it, the origin leaves the service alone. Either way the tunnel keeps
// working, and the log says which server to change.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// The two versions of the header. Version 1 is a line of text that every server
// supporting the protocol reads, so it is what the menu turns on; version 2 is
// the binary form, for a service that asks for it.
const (
	proxyProtocolOff = 0
	proxyProtocolV1  = 1
	proxyProtocolV2  = 2
)

// userAddrs is the address a user connected from and the one they reached on
// the edge. A nil *userAddrs, or one with no source, means not known.
type userAddrs struct {
	src, dst *net.TCPAddr
}

// addrsOf reads both ends of a user's connection, or returns an empty value when
// the connection is not TCP (nothing in PortBridge listens for users any other
// way, so this is only a safeguard).
func addrsOf(c net.Conn) *userAddrs {
	src, ok1 := c.RemoteAddr().(*net.TCPAddr)
	dst, ok2 := c.LocalAddr().(*net.TCPAddr)
	if !ok1 || !ok2 || src == nil || dst == nil {
		return &userAddrs{}
	}
	return &userAddrs{src: src, dst: dst}
}

// family is 4 or 6 when both addresses are known, 0 otherwise. An IPv4 user on a
// listener that also takes IPv6 has both addresses in IPv4 form, so the two
// always share a family once To4 has been tried on both.
func (a *userAddrs) family() byte {
	if a == nil || a.src == nil || a.dst == nil {
		return 0
	}
	if a.src.IP.To4() != nil && a.dst.IP.To4() != nil {
		return 4
	}
	if a.src.IP.To16() != nil && a.dst.IP.To16() != nil {
		return 6
	}
	return 0
}

func (a *userAddrs) ips() (net.IP, net.IP) {
	if a.family() == 4 {
		return a.src.IP.To4(), a.dst.IP.To4()
	}
	return a.src.IP.To16(), a.dst.IP.To16()
}

// appendTo writes the addresses as they cross the tunnel:
//
//	1B family (0, 4 or 6), then for 4 or 6: source IP, destination IP,
//	2B source port, 2B destination port (big-endian), the same order as the
//	binary PROXY header.
func (a *userAddrs) appendTo(b []byte) []byte {
	fam := a.family()
	b = append(b, fam)
	if fam == 0 {
		return b
	}
	src, dst := a.ips()
	b = append(b, src...)
	b = append(b, dst...)
	b = binary.BigEndian.AppendUint16(b, uint16(a.src.Port))
	b = binary.BigEndian.AppendUint16(b, uint16(a.dst.Port))
	return b
}

var errBadUserAddrs = errors.New("the other server sent a user's address in a form this one does not understand")

// readUserAddrs reads what appendTo wrote.
func readUserAddrs(r io.Reader) (*userAddrs, error) {
	var fam [1]byte
	if _, err := io.ReadFull(r, fam[:]); err != nil {
		return nil, err
	}
	var n int
	switch fam[0] {
	case 0:
		return &userAddrs{}, nil
	case 4:
		n = net.IPv4len
	case 6:
		n = net.IPv6len
	default:
		return nil, errBadUserAddrs
	}
	buf := make([]byte, 2*n+4)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return &userAddrs{
		src: &net.TCPAddr{IP: net.IP(buf[:n]), Port: int(binary.BigEndian.Uint16(buf[2*n:]))},
		dst: &net.TCPAddr{IP: net.IP(buf[n : 2*n]), Port: int(binary.BigEndian.Uint16(buf[2*n+2:]))},
	}, nil
}

// proxyV2Signature opens every version 2 header.
var proxyV2Signature = []byte("\r\n\r\n\x00\r\nQUIT\n")

// proxyHeader is what the origin writes to the service before anything else.
// With the addresses not known it says so in the form each version has for it
// (UNKNOWN, or LOCAL), and the service uses the connection's own address.
func proxyHeader(version int, a *userAddrs) []byte {
	fam := a.family()
	if version == proxyProtocolV2 {
		h := append([]byte{}, proxyV2Signature...)
		if fam == 0 {
			// LOCAL command, no address family, no addresses.
			return append(h, 0x20, 0x00, 0x00, 0x00)
		}
		src, dst := a.ips()
		famByte, size := byte(0x11), 12 // TCP over IPv4
		if fam == 6 {
			famByte, size = 0x21, 36 // TCP over IPv6
		}
		h = append(h, 0x21, famByte) // version 2, PROXY command
		h = binary.BigEndian.AppendUint16(h, uint16(size))
		h = append(h, src...)
		h = append(h, dst...)
		h = binary.BigEndian.AppendUint16(h, uint16(a.src.Port))
		h = binary.BigEndian.AppendUint16(h, uint16(a.dst.Port))
		return h
	}
	if fam == 0 {
		return []byte("PROXY UNKNOWN\r\n")
	}
	src, dst := a.ips()
	proto := "TCP4"
	if fam == 6 {
		proto = "TCP6"
	}
	return []byte(fmt.Sprintf("PROXY %s %s %s %d %d\r\n", proto, src, dst, a.src.Port, a.dst.Port))
}

// parseProxyProtocol reads the setting: off, v1 or v2.
func parseProxyProtocol(val string) (int, error) {
	switch val {
	case "off", "no", "false", "0", "":
		return proxyProtocolOff, nil
	case "v1", "1":
		return proxyProtocolV1, nil
	case "v2", "2":
		return proxyProtocolV2, nil
	}
	return 0, fmt.Errorf("proxy_protocol must be off, v1 or v2, got %q", val)
}

// proxyProtocolName is the setting's value as written in a settings file.
func proxyProtocolName(v int) string {
	if v == proxyProtocolOff {
		return "off"
	}
	return "v" + strconv.Itoa(v)
}
