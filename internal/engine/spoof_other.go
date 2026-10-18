//go:build !linux

package engine

import (
	"errors"
	"net"
)

func openRawSpoofSocket() (int, error) {
	return -1, errors.New("raw socket IP spoofing is only supported on Linux")
}

func closeRawSpoofSocket(_ int) {}

func sendRawSpoofedUDP(_ int, _, _ net.IP, _, _ int, _ int, _ []byte) error {
	return errors.New("raw socket IP spoofing is only supported on Linux")
}

func injectDecoyClientHello(_ net.Conn, _ string, _ int) error {
	return nil
}
