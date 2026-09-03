package engine

import "math/bits"

// tcpTableConnectionKey converts the network-byte-order values returned by
// GetExtendedTcpTable into the same key used for inbound packets.
func tcpTableConnectionKey(remoteAddr, remotePortRaw, localPortRaw uint32) uint64 {
	remoteIP := bits.ReverseBytes32(remoteAddr)
	remotePort := uint16(((remotePortRaw & 0xFF) << 8) | ((remotePortRaw >> 8) & 0xFF))
	localPort := uint16(((localPortRaw & 0xFF) << 8) | ((localPortRaw >> 8) & 0xFF))
	return uint64(remoteIP)<<32 | uint64(remotePort)<<16 | uint64(localPort)
}
