package engine

import (
	"testing"

	"waf-game/pkg/packet"
)

func TestLayer1Filter_Check(t *testing.T) {
	filter := NewLayer1Filter()

	// Base valid packet
	validPkt := &packet.Packet{
		Version:       4,
		IHL:           5,
		TotalLen:      40,
		TTL:           64,
		Protocol:      packet.ProtoTCP,
		SrcIP:         [4]byte{8, 8, 8, 8},
		DstIP:         [4]byte{1, 1, 1, 1},
		SrcPort:       12345,
		DstPort:       80,
		TCPFlags:      packet.TCPFlagSYN,
		IPHeaderLen:   20,
		PayloadOffset: 40,
		PayloadLen:    0,
	}

	// 1. Check valid packet
	res, rule := filter.Check(validPkt)
	if res != FilterPass || rule != 0 {
		t.Errorf("Expected valid packet to pass, got res=%v, rule=%d", res, rule)
	}

	// Rule 1: Fragment
	fragPkt := *validPkt
	fragPkt.FragOffset = 100
	res, rule = filter.Check(&fragPkt)
	if res != FilterDrop || rule != 1 {
		t.Errorf("Expected drop Rule 1 for fragment, got res=%v, rule=%d", res, rule)
	}

	// Rule 2: Invalid IHL
	ihlPkt := *validPkt
	ihlPkt.IHL = 4
	res, rule = filter.Check(&ihlPkt)
	if res != FilterDrop || rule != 2 {
		t.Errorf("Expected drop Rule 2 for invalid IHL, got res=%v, rule=%d", res, rule)
	}

	// Rule 11: TTL = 0
	ttlPkt := *validPkt
	ttlPkt.TTL = 0
	res, rule = filter.Check(&ttlPkt)
	if res != FilterDrop || rule != 11 {
		t.Errorf("Expected drop Rule 11 for TTL=0, got res=%v, rule=%d", res, rule)
	}

	// Rule 3: TCP Null Scan
	nullPkt := *validPkt
	nullPkt.TCPFlags = 0
	res, rule = filter.Check(&nullPkt)
	if res != FilterDrop || rule != 3 {
		t.Errorf("Expected drop Rule 3 for TCP Null Scan, got res=%v, rule=%d", res, rule)
	}

	// Rule 4: TCP XMAS Scan (SYN+FIN)
	xmasPkt := *validPkt
	xmasPkt.TCPFlags = packet.TCPFlagSYN | packet.TCPFlagFIN
	res, rule = filter.Check(&xmasPkt)
	if res != FilterDrop || rule != 4 {
		t.Errorf("Expected drop Rule 4 for TCP XMAS, got res=%v, rule=%d", res, rule)
	}

	// Rule 5: TCP SYN+RST
	synRstPkt := *validPkt
	synRstPkt.TCPFlags = packet.TCPFlagSYN | packet.TCPFlagRST
	res, rule = filter.Check(&synRstPkt)
	if res != FilterDrop || rule != 5 {
		t.Errorf("Expected drop Rule 5 for TCP SYN+RST, got res=%v, rule=%d", res, rule)
	}

	// Rule 6: TCP FIN without ACK
	finNoAckPkt := *validPkt
	finNoAckPkt.TCPFlags = packet.TCPFlagFIN
	res, rule = filter.Check(&finNoAckPkt)
	if res != FilterDrop || rule != 6 {
		t.Errorf("Expected drop Rule 6 for TCP FIN without ACK, got res=%v, rule=%d", res, rule)
	}

	// Rule 7: Bogon IP (Invalid source IP: Multicast)
	bogonPkt := *validPkt
	bogonPkt.SrcIP = [4]byte{224, 0, 0, 1}
	res, rule = filter.Check(&bogonPkt)
	if res != FilterDrop || rule != 7 {
		t.Errorf("Expected drop Rule 7 for Bogon IP, got res=%v, rule=%d", res, rule)
	}

	// Rule 8: Land Attack
	landPkt := *validPkt
	landPkt.SrcIP = landPkt.DstIP
	res, rule = filter.Check(&landPkt)
	if res != FilterDrop || rule != 8 {
		t.Errorf("Expected drop Rule 8 for Land Attack, got res=%v, rule=%d", res, rule)
	}

	// Rule 9: UDP length < 8
	udpPkt := *validPkt
	udpPkt.Protocol = packet.ProtoUDP
	udpPkt.UDPLength = 7
	res, rule = filter.Check(&udpPkt)
	if res != FilterDrop || rule != 9 {
		t.Errorf("Expected drop Rule 9 for short UDP length, got res=%v, rule=%d", res, rule)
	}

	// Rule 10: TCP src port = 0
	portZeroPkt := *validPkt
	portZeroPkt.SrcPort = 0
	res, rule = filter.Check(&portZeroPkt)
	if res != FilterDrop || rule != 10 {
		t.Errorf("Expected drop Rule 10 for TCP port 0, got res=%v, rule=%d", res, rule)
	}
}
