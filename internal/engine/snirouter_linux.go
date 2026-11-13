//go:build linux

package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

const syscallSO_REUSEPORT = 0x0f

func listenSharedTCP(addr string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var sockErr error
			if err := c.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscallSO_REUSEPORT, 1)
			}); err != nil {
				return err
			}
			return sockErr
		},
	}
	return lc.Listen(context.Background(), "tcp", addr)
}

func openHandoffListener(dir, tunnelName, shortID string) (net.Listener, string, string, func(), error) {
	if err := os.MkdirAll(dir, 0o755); err == nil {
		sockPath := filepath.Join(dir, fmt.Sprintf("sni-h-%s-%s.sock", tunnelName, shortID))
		if len(sockPath) <= 96 {
			_ = os.Remove(sockPath)
			ln, err := net.Listen("unix", sockPath)
			if err == nil {
				_ = os.Chmod(sockPath, 0o600)
				cleanup := func() {
					_ = ln.Close()
					_ = os.Remove(sockPath)
				}
				return ln, "unix", sockPath, cleanup, nil
			}
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", "", nil, err
	}
	cleanup := func() {
		_ = ln.Close()
	}
	return ln, "tcp", ln.Addr().String(), cleanup, nil
}

func prepareConnFDRights(hc net.Conn, user net.Conn) (*net.UnixConn, []byte, bool) {
	uc, ok := hc.(*net.UnixConn)
	if !ok || uc == nil {
		return nil, nil, false
	}
	tc, ok := underlyingTCPConn(user)
	if !ok || tc == nil {
		return nil, nil, false
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return nil, nil, false
	}
	var rights []byte
	if err := raw.Control(func(fd uintptr) {
		rights = syscall.UnixRights(int(fd))
	}); err != nil || len(rights) == 0 {
		return nil, nil, false
	}
	return uc, rights, true
}

func sendPreparedConnFD(uc *net.UnixConn, rights []byte) error {
	marker := [1]byte{'F'}
	n, oobn, err := uc.WriteMsgUnix(marker[:], rights, nil)
	if err != nil {
		return err
	}
	if n != 1 || oobn != len(rights) {
		return errors.New("short unix fd handoff write")
	}
	return nil
}

func recvConnFD(hc net.Conn) (net.Conn, error) {
	uc, ok := hc.(*net.UnixConn)
	if !ok || uc == nil {
		return nil, errors.New("fd handoff requires unix socket")
	}
	var marker [1]byte
	oob := make([]byte, syscall.CmsgSpace(4))
	n, oobn, _, _, err := uc.ReadMsgUnix(marker[:], oob)
	if err != nil {
		return nil, err
	}
	if n != 1 || marker[0] != 'F' || oobn == 0 {
		return nil, errors.New("missing unix fd handoff payload")
	}
	scms, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(scms) == 0 {
		return nil, errors.New("invalid socket control message")
	}
	var fds []int
	for i := range scms {
		parsed, err := syscall.ParseUnixRights(&scms[i])
		if err == nil {
			fds = append(fds, parsed...)
		}
	}
	if len(fds) == 0 {
		return nil, errors.New("no file descriptor in handoff message")
	}
	for _, fd := range fds {
		syscall.CloseOnExec(fd)
	}
	for _, extra := range fds[1:] {
		_ = syscall.Close(extra)
	}
	f := os.NewFile(uintptr(fds[0]), "sni-handoff")
	if f == nil {
		_ = syscall.Close(fds[0])
		return nil, errors.New("failed to wrap received fd")
	}
	fc, err := net.FileConn(f)
	_ = f.Close()
	if err != nil {
		return nil, err
	}
	tuneSocket(fc)
	return fc, nil
}
