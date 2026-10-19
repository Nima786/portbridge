//go:build linux

package engine

import (
	"errors"
	"net"
	"syscall"
	"time"
)

const (
	linuxTCPRepair      = 19
	linuxTCPRepairQueue = 20
	linuxTCPQueueSeq    = 21
	linuxTCPSendQueue   = 1
	linuxTCPRecvQueue   = 2
)

func openRawSpoofSocket() (int, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return -1, err
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		_ = syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}

func closeRawSpoofSocket(fd int) {
	if fd >= 0 {
		_ = syscall.Close(fd)
	}
}

func setIPConnSocketMark(ipConn *net.IPConn, mark int) error {
	if ipConn == nil || mark == 0 {
		return nil
	}
	rc, err := ipConn.SyscallConn()
	if err != nil {
		return err
	}
	var sockErr error
	if err := rc.Control(func(fd uintptr) {
		sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark)
	}); err != nil {
		return err
	}
	return sockErr
}

func sendRawSpoofedUDP(fd int, srcIP, dstIP net.IP, srcPort, dstPort int, ttl int, payload []byte) error {
	if fd < 0 {
		return errors.New("raw socket not open")
	}
	dst4 := dstIP.To4()
	if dst4 == nil {
		return errors.New("destination IPv4 required")
	}
	pkt, err := buildIPv4UDPPacket(srcIP, dstIP, srcPort, dstPort, ttl, payload)
	if err != nil {
		return err
	}
	var sa syscall.SockaddrInet4
	sa.Port = dstPort
	copy(sa.Addr[:], dst4)
	return syscall.Sendto(fd, pkt, 0, &sa)
}

func sendRawTCPPacket(fd int, srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, flags byte, ttl int, payload []byte, corruptChecksum bool) error {
	if fd < 0 {
		return errors.New("raw socket not open")
	}
	dst4 := dstIP.To4()
	if dst4 == nil {
		return errors.New("destination IPv4 required")
	}
	pkt, err := buildIPv4TCPPacket(srcIP, dstIP, int(srcPort), int(dstPort), seq, ack, ttl, corruptChecksum, payload)
	if err != nil {
		return err
	}
	if flags != 0 && len(pkt) >= 40 {
		pkt[33] = flags
		pkt[36] = 0
		pkt[37] = 0
		csum := tcpUDPChecksum(srcIP.To4(), dst4, 6, pkt[20:])
		if corruptChecksum {
			csum ^= 0xffff
		}
		pkt[36] = byte(csum >> 8)
		pkt[37] = byte(csum)
	}
	var sa syscall.SockaddrInet4
	sa.Port = int(dstPort)
	copy(sa.Addr[:], dst4)
	return syscall.Sendto(fd, pkt, 0, &sa)
}

func readLinuxTCPSeqs(tcpConn *net.TCPConn) (sndNxt uint32, rcvNxt uint32, ok bool) {
	rc, err := tcpConn.SyscallConn()
	if err != nil {
		return 0, 0, false
	}
	_ = rc.Control(func(fd uintptr) {
		s := int(fd)
		if err := syscall.SetsockoptInt(s, syscall.IPPROTO_TCP, linuxTCPRepair, 1); err != nil {
			return
		}
		defer func() {
			_ = syscall.SetsockoptInt(s, syscall.IPPROTO_TCP, linuxTCPRepair, 0)
		}()
		if err := syscall.SetsockoptInt(s, syscall.IPPROTO_TCP, linuxTCPRepairQueue, linuxTCPSendQueue); err != nil {
			return
		}
		sndVal, err := syscall.GetsockoptInt(s, syscall.IPPROTO_TCP, linuxTCPQueueSeq)
		if err != nil {
			return
		}
		if err := syscall.SetsockoptInt(s, syscall.IPPROTO_TCP, linuxTCPRepairQueue, linuxTCPRecvQueue); err != nil {
			return
		}
		rcvVal, err := syscall.GetsockoptInt(s, syscall.IPPROTO_TCP, linuxTCPQueueSeq)
		if err != nil {
			return
		}
		sndNxt = uint32(sndVal)
		rcvNxt = uint32(rcvVal)
		ok = true
	})
	return sndNxt, rcvNxt, ok
}

// injectDecoyClientHello sends a decoy TLS 1.3 ClientHello carrying the whitelisted SNI
// on the exact TCP 4-tuple right after the TCP 3-way handshake completes, constructed so
// middlebox DPI classifies the connection under the whitelisted SNI while the destination
// server's TCP stack discards the decoy segment.
func injectDecoyClientHello(conn net.Conn, sni string, ttl int) error {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok || tcpConn == nil {
		return nil
	}
	lAddr, lOk := tcpConn.LocalAddr().(*net.TCPAddr)
	rAddr, rOk := tcpConn.RemoteAddr().(*net.TCPAddr)
	if !lOk || !rOk || lAddr == nil || rAddr == nil {
		return nil
	}
	src4 := lAddr.IP.To4()
	dst4 := rAddr.IP.To4()
	if src4 == nil || dst4 == nil {
		return nil
	}

	rawFD, err := openRawSpoofSocket()
	if err != nil {
		return err
	}
	defer closeRawSpoofSocket(rawFD)

	decoy := BuildDecoyClientHello(sni)
	sndNxt, rcvNxt, haveSeq := readLinuxTCPSeqs(tcpConn)
	if !haveSeq {
		sndNxt = 0x10203040
		rcvNxt = 0x50607080
	}

	var sa syscall.SockaddrInet4
	sa.Port = rAddr.Port
	copy(sa.Addr[:], dst4)

	// Low-TTL exact-sequence decoy with inverted TCP checksum:
	// Passes local ISP DPI hops and expires before reaching the remote server,
	// preventing cloud hypervisors with TX checksum offload from delivering an
	// in-window decoy segment to the destination socket.
	hopTTL := ttl
	if hopTTL <= 0 || hopTTL > 32 {
		hopTTL = 3
	}
	if pkt, err := buildIPv4TCPPacket(src4, dst4, lAddr.Port, rAddr.Port, sndNxt, rcvNxt, hopTTL, true, decoy); err == nil {
		_ = syscall.Sendto(rawFD, pkt, 0, &sa)
	}

	time.Sleep(5 * time.Millisecond)
	return nil
}
