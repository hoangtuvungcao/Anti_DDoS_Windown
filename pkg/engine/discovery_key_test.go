package engine

import (
	"testing"

	"waf-game/pkg/packet"
)

func TestTCPTableConnectionKeyMatchesPacketKey(t *testing.T) {
	pkt := packet.Packet{
		SrcIP:   [4]byte{203, 0, 113, 25},
		SrcPort: 53000,
		DstPort: 45678,
	}
	// DWORD values as read on little-endian Windows from network-order fields.
	const remoteAddrRaw uint32 = 0x197100cb
	const remotePortRaw uint32 = 0x000008cf
	const localPortRaw uint32 = 0x00006eb2
	if got := tcpTableConnectionKey(remoteAddrRaw, remotePortRaw, localPortRaw); got != pkt.ConnKey() {
		t.Fatalf("Windows table key %x does not match packet key %x", got, pkt.ConnKey())
	}
}
