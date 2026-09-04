package packet

import (
	"encoding/binary"
	"testing"
)

func buildIPv4Header(protocol uint8, totalLen uint16, flags uint8, fragOff uint16) []byte {
	header := make([]byte, 20)
	header[0] = 0x45 // Version 4, IHL 5 (20 bytes)
	header[1] = 0x00 // TOS
	binary.BigEndian.PutUint16(header[2:4], totalLen)
	binary.BigEndian.PutUint16(header[4:6], 0x1234) // ID
	flagsFrag := (uint16(flags) << 13) | (fragOff & 0x1FFF)
	binary.BigEndian.PutUint16(header[6:8], flagsFrag)
	header[8] = 64 // TTL
	header[9] = protocol
	// Bytes 10-11: Checksum (ignored by parser)
	copy(header[12:16], []byte{1, 2, 3, 4}) // Src IP
	copy(header[16:20], []byte{5, 6, 7, 8}) // Dst IP
	return header
}

func TestParseTCP(t *testing.T) {
	ipHeader := buildIPv4Header(ProtoTCP, 40, 0x02, 0) // DF set, total len 40 (20 IP + 20 TCP)
	tcpHeader := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHeader[0:2], 12345)   // Src port
	binary.BigEndian.PutUint16(tcpHeader[2:4], 80)      // Dst port
	binary.BigEndian.PutUint32(tcpHeader[4:8], 1000)    // Seq
	binary.BigEndian.PutUint32(tcpHeader[8:12], 2000)   // Ack
	tcpHeader[12] = 0x50                                // Data offset 5 (20 bytes)
	tcpHeader[13] = TCPFlagSYN                          // SYN flag
	binary.BigEndian.PutUint16(tcpHeader[14:16], 65535) // Window

	buf := append(ipHeader, tcpHeader...)

	var pkt Packet
	err := Parse(buf, &pkt)
	if err != nil {
		t.Fatalf("Failed to parse TCP packet: %v", err)
	}

	if pkt.Version != 4 || pkt.IHL != 5 {
		t.Errorf("Invalid IP header. Version: %d, IHL: %d", pkt.Version, pkt.IHL)
	}
	if pkt.SrcIP != [4]byte{1, 2, 3, 4} || pkt.DstIP != [4]byte{5, 6, 7, 8} {
		t.Errorf("IP address mismatch. Src: %v, Dst: %v", pkt.SrcIP, pkt.DstIP)
	}
	if pkt.Protocol != ProtoTCP {
		t.Errorf("Expected TCP protocol, got %d", pkt.Protocol)
	}
	if pkt.SrcPort != 12345 || pkt.DstPort != 80 {
		t.Errorf("TCP port mismatch. Src: %d, Dst: %d", pkt.SrcPort, pkt.DstPort)
	}
	if pkt.TCPFlags != TCPFlagSYN {
		t.Errorf("Expected TCP SYN flag, got 0x%02x", pkt.TCPFlags)
	}
	if !pkt.IsSYN() || pkt.IsSYNACK() || pkt.IsACK() {
		t.Errorf("IsSYN/IsSYNACK/IsACK flags helper mismatch")
	}
	if pkt.SeqNum != 1000 || pkt.AckNum != 2000 {
		t.Errorf("TCP Seq/Ack mismatch. Seq: %d, Ack: %d", pkt.SeqNum, pkt.AckNum)
	}
	if pkt.PayloadLen != 0 {
		t.Errorf("Expected 0 payload len, got %d", pkt.PayloadLen)
	}
}

func TestParseUDP(t *testing.T) {
	payload := []byte("hello world")
	ipHeader := buildIPv4Header(ProtoUDP, uint16(20+8+len(payload)), 0, 0)
	udpHeader := make([]byte, 8)
	binary.BigEndian.PutUint16(udpHeader[0:2], 54321) // Src port
	binary.BigEndian.PutUint16(udpHeader[2:4], 53)    // Dst port
	binary.BigEndian.PutUint16(udpHeader[4:6], uint16(8+len(payload)))

	buf := append(ipHeader, udpHeader...)
	buf = append(buf, payload...)

	var pkt Packet
	err := Parse(buf, &pkt)
	if err != nil {
		t.Fatalf("Failed to parse UDP packet: %v", err)
	}

	if pkt.Protocol != ProtoUDP {
		t.Errorf("Expected UDP protocol, got %d", pkt.Protocol)
	}
	if pkt.SrcPort != 54321 || pkt.DstPort != 53 {
		t.Errorf("UDP port mismatch. Src: %d, Dst: %d", pkt.SrcPort, pkt.DstPort)
	}
	if pkt.PayloadLen != len(payload) {
		t.Errorf("Expected payload len %d, got %d", len(payload), pkt.PayloadLen)
	}
	if string(buf[pkt.PayloadOffset:pkt.PayloadOffset+pkt.PayloadLen]) != "hello world" {
		t.Errorf("Payload content mismatch")
	}
}

func TestMalformedPackets(t *testing.T) {
	var pkt Packet

	// Too short
	if err := Parse(make([]byte, 10), &pkt); err != ErrTooShort {
		t.Errorf("Expected ErrTooShort, got %v", err)
	}

	// Not IPv4
	buf := make([]byte, 20)
	buf[0] = 0x55 // Version 5
	if err := Parse(buf, &pkt); err != ErrNotIPv4 {
		t.Errorf("Expected ErrNotIPv4, got %v", err)
	}

	// Bad IHL
	buf[0] = 0x44 // Version 4, IHL 4 (invalid, must be >= 5)
	if err := Parse(buf, &pkt); err != ErrBadIHL {
		t.Errorf("Expected ErrBadIHL, got %v", err)
	}

	// Declared total length larger than captured bytes must not be normalized.
	buf = buildIPv4Header(ProtoTCP, 60, 0, 0)
	buf = append(buf, make([]byte, 20)...)
	if err := Parse(buf, &pkt); err != ErrTruncated {
		t.Errorf("Expected ErrTruncated, got %v", err)
	}
}

func TestParseUDPFragmentsWithoutTreatingPayloadAsHeaders(t *testing.T) {
	// First fragment contains the UDP header, but its UDP length describes the
	// complete datagram and is therefore larger than this IP fragment.
	first := buildIPv4Header(ProtoUDP, 36, 0x01, 0)
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 40000)
	binary.BigEndian.PutUint16(udp[2:4], 27015)
	binary.BigEndian.PutUint16(udp[4:6], 108)
	first = append(first, udp...)
	first = append(first, make([]byte, 8)...)
	var pkt Packet
	if err := Parse(first, &pkt); err != nil {
		t.Fatalf("first UDP fragment rejected: %v", err)
	}
	if !pkt.IsFragment() || pkt.SrcPort != 40000 || pkt.DstPort != 27015 || pkt.PayloadLen != 8 {
		t.Fatalf("first fragment parsed incorrectly: %+v", pkt)
	}

	// A later fragment starts with arbitrary payload bytes that must never be
	// interpreted as source/destination ports. Reuse pkt to verify stale fields
	// from the first parse are cleared as well.
	later := buildIPv4Header(ProtoUDP, 36, 0, 2)
	later = append(later, []byte{0x9c, 0x40, 0x69, 0x87, 0, 108, 0, 0}...)
	later = append(later, make([]byte, 8)...)
	if err := Parse(later, &pkt); err != nil {
		t.Fatalf("later UDP fragment rejected: %v", err)
	}
	if pkt.SrcPort != 0 || pkt.DstPort != 0 || pkt.UDPLength != 0 || pkt.PayloadLen != 16 {
		t.Fatalf("later fragment inherited/decoded transport fields: %+v", pkt)
	}
}

func FuzzParseNeverPanics(f *testing.F) {
	f.Add([]byte{})
	f.Add(buildIPv4Header(ProtoUDP, 20, 0, 0))
	valid := buildIPv4Header(ProtoTCP, 40, 0, 0)
	tcp := make([]byte, 20)
	tcp[12] = 0x50
	f.Add(append(valid, tcp...))

	f.Fuzz(func(t *testing.T, data []byte) {
		var pkt Packet
		_ = Parse(data, &pkt)
		// Exercise object reuse as done by long-running packet workers.
		_ = Parse(data, &pkt)
	})
}
