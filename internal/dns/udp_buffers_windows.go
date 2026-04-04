//go:build windows

package dns

import "net"

func tuneUDPConnBuffers(_ *net.UDPConn) {}
