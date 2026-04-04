//go:build !windows

package dns

import (
	"net"

	"golang.org/x/sys/unix"
)

// tuneUDPConnBuffers enlarges kernel UDP RX/TX buffers to reduce drops under burst traffic.
func tuneUDPConnBuffers(c *net.UDPConn) {
	if c == nil {
		return
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		const buf = 4 << 20 // 4 MiB; see 高并发系统优化说明.md for sysctl alignment
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, buf)
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, buf)
	})
}
