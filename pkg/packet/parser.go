// Package packet provides zero-allocation IPv4/TCP/UDP packet parsing.
// Uses encoding/binary.BigEndian directly on byte slices — no reflection,
// no heap allocation, no gopacket dependency.
package packet

import (
	"encoding/binary"
	"errors"
)

// Protocol constants
const (
	ProtoICMP uint8 = 1
	ProtoTCP  uint8 = 6
	ProtoUDP  uint8 = 17
)

// TCP flag constants
const (
	TCPFlagFIN uint8 = 0x01
	TCPFlagSYN uint8 = 0x02
	TCPFlagRST uint8 = 0x04
	TCPFlagPSH uint8 = 0x08
	TCPFlagACK uint8 = 0x10
	TCPFlagURG uint8 = 0x20
)

// Errors
var (
	ErrTooShort     = errors.New("packet too short for IPv4 header")
	ErrNotIPv4      = errors.New("not an IPv4 packet")
	ErrBadIHL       = errors.New("invalid IP header length")
	ErrTCPTooShort  = errors.New("packet too short for TCP header")
	ErrUDPTooShort  = errors.New("packet too short for UDP header")
	ErrTruncated    = errors.New("packet truncated: total length exceeds buffer")
	ErrBadTCPOffset = errors.New("invalid TCP data offset")
	ErrBadUDPLength = errors.New("invalid UDP length")
)

// Packet holds parsed packet fields on the stack.
// Pass by pointer and reuse via sync.Pool to achieve zero-allocation.
type Packet struct {
	// IPv4 fields
	Version    uint8
	IHL        uint8 // Header length in 32-bit words (min 5)
	TotalLen   uint16
	ID         uint16
	Flags      uint8  // 3 bits: Reserved, DF, MF
	FragOffset uint16 // 13 bits fragment offset
	TTL        uint8
	Protocol   uint8 // 1=ICMP, 6=TCP, 17=UDP
	SrcIP      [4]byte
	DstIP      [4]byte

	// ICMP fields (valid when Protocol == ProtoICMP)
	ICMPType uint8
	ICMPCode uint8

	// TCP fields (valid when Protocol == ProtoTCP)
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8 // TCP header length in 32-bit words
	TCPFlags   uint8 // SYN, ACK, FIN, RST, PSH, URG
	Window     uint16

	// UDP fields (valid when Protocol == ProtoUDP)
	UDPLength uint16

	// Payload info
	IPHeaderLen    int // Actual IP header byte length
	TransHeaderLen int // TCP/UDP header byte length
	PayloadOffset  int // Offset into original buffer where payload starts
	PayloadLen     int // Length of payload data
}

// Parse parses a raw IP packet from buf into pkt.
// Zero-allocation: pkt must be pre-allocated (use sync.Pool).
func Parse(buf []byte, pkt *Packet) error {
	// Minimum IPv4 header: 20 bytes
	if len(buf) < 20 {
		return ErrTooShort
	}

	// Version and IHL from first byte
	pkt.Version = buf[0] >> 4
	if pkt.Version != 4 {
		return ErrNotIPv4
	}
	pkt.IHL = buf[0] & 0x0F
	if pkt.IHL < 5 {
		return ErrBadIHL
	}

	pkt.IPHeaderLen = int(pkt.IHL) * 4
	if len(buf) < pkt.IPHeaderLen {
		return ErrTooShort
	}

	// Parse IPv4 fields using BigEndian directly on slice
	pkt.TotalLen = binary.BigEndian.Uint16(buf[2:4])
	pkt.ID = binary.BigEndian.Uint16(buf[4:6])

	// Flags (3 bits) + Fragment Offset (13 bits) from bytes 6-7
	flagsFrag := binary.BigEndian.Uint16(buf[6:8])
	pkt.Flags = uint8(flagsFrag >> 13)
	pkt.FragOffset = flagsFrag & 0x1FFF

	pkt.TTL = buf[8]
	pkt.Protocol = buf[9]

	// Source and destination IP — direct copy, no allocation
	copy(pkt.SrcIP[:], buf[12:16])
	copy(pkt.DstIP[:], buf[16:20])

	// Check for truncation
	if int(pkt.TotalLen) > len(buf) {
		// Allow processing with available data, just note truncation
		pkt.TotalLen = uint16(len(buf))
	}

	// Parse transport layer header based on protocol
	transportStart := pkt.IPHeaderLen

	switch pkt.Protocol {
	case ProtoTCP:
		return parseTCP(buf, transportStart, pkt)
	case ProtoUDP:
		return parseUDP(buf, transportStart, pkt)
	case ProtoICMP:
		return parseICMP(buf, transportStart, pkt)
	default:
		// Unknown protocol — set payload to everything after IP header
		pkt.TransHeaderLen = 0
		pkt.PayloadOffset = transportStart
		pkt.PayloadLen = int(pkt.TotalLen) - transportStart
		if pkt.PayloadLen < 0 {
			pkt.PayloadLen = 0
		}
	}

	return nil
}

func parseICMP(buf []byte, offset int, pkt *Packet) error {
	if len(buf) < offset+4 {
		return ErrTooShort
	}
	pkt.ICMPType = buf[offset]
	pkt.ICMPCode = buf[offset+1]
	pkt.TransHeaderLen = 4
	pkt.PayloadOffset = offset + 4
	pkt.PayloadLen = int(pkt.TotalLen) - pkt.PayloadOffset
	if pkt.PayloadLen < 0 {
		pkt.PayloadLen = 0
	}
	return nil
}

func parseTCP(buf []byte, offset int, pkt *Packet) error {
	// Minimum TCP header: 20 bytes
	if len(buf) < offset+20 {
		return ErrTCPTooShort
	}

	pkt.SrcPort = binary.BigEndian.Uint16(buf[offset : offset+2])
	pkt.DstPort = binary.BigEndian.Uint16(buf[offset+2 : offset+4])
	pkt.SeqNum = binary.BigEndian.Uint32(buf[offset+4 : offset+8])
	pkt.AckNum = binary.BigEndian.Uint32(buf[offset+8 : offset+12])

	// Data offset (4 bits) from high nibble of byte 12
	pkt.DataOffset = buf[offset+12] >> 4
	if pkt.DataOffset < 5 {
		return ErrBadTCPOffset
	}
	pkt.TransHeaderLen = int(pkt.DataOffset) * 4
	if offset+pkt.TransHeaderLen > len(buf) || offset+pkt.TransHeaderLen > int(pkt.TotalLen) {
		return ErrBadTCPOffset
	}

	// TCP flags from byte 13
	pkt.TCPFlags = buf[offset+13]

	// Window size
	pkt.Window = binary.BigEndian.Uint16(buf[offset+14 : offset+16])

	// Payload
	pkt.PayloadOffset = offset + pkt.TransHeaderLen
	pkt.PayloadLen = int(pkt.TotalLen) - pkt.PayloadOffset
	if pkt.PayloadLen < 0 {
		pkt.PayloadLen = 0
	}

	return nil
}

func parseUDP(buf []byte, offset int, pkt *Packet) error {
	// UDP header: exactly 8 bytes
	if len(buf) < offset+8 {
		return ErrUDPTooShort
	}

	pkt.SrcPort = binary.BigEndian.Uint16(buf[offset : offset+2])
	pkt.DstPort = binary.BigEndian.Uint16(buf[offset+2 : offset+4])
	pkt.UDPLength = binary.BigEndian.Uint16(buf[offset+4 : offset+6])
	if pkt.UDPLength < 8 || offset+int(pkt.UDPLength) > int(pkt.TotalLen) {
		return ErrBadUDPLength
	}

	pkt.TransHeaderLen = 8
	pkt.PayloadOffset = offset + 8
	pkt.PayloadLen = int(pkt.UDPLength) - 8
	if pkt.PayloadLen < 0 {
		pkt.PayloadLen = 0
	}

	return nil
}

// Helper methods

// IsSYN returns true if SYN flag is set (and ACK is not)
func (p *Packet) IsSYN() bool {
	return p.TCPFlags&TCPFlagSYN != 0 && p.TCPFlags&TCPFlagACK == 0
}

// IsSYNACK returns true if both SYN and ACK flags are set
func (p *Packet) IsSYNACK() bool {
	return p.TCPFlags&TCPFlagSYN != 0 && p.TCPFlags&TCPFlagACK != 0
}

// IsACK returns true if ACK flag is set (and SYN is not)
func (p *Packet) IsACK() bool {
	return p.TCPFlags&TCPFlagACK != 0 && p.TCPFlags&TCPFlagSYN == 0
}

// IsRST returns true if RST flag is set
func (p *Packet) IsRST() bool {
	return p.TCPFlags&TCPFlagRST != 0
}

// IsFIN returns true if FIN flag is set
func (p *Packet) IsFIN() bool {
	return p.TCPFlags&TCPFlagFIN != 0
}

// HasPayload returns true if the packet has payload data
func (p *Packet) HasPayload() bool {
	return p.PayloadLen > 0
}

// IsFragment returns true if the packet is an IP fragment
func (p *Packet) IsFragment() bool {
	return p.FragOffset > 0 || (p.Flags&0x01) != 0 // MF flag
}

// MF returns true if More Fragments flag is set
func (p *Packet) MF() bool {
	return (p.Flags & 0x01) != 0
}

// DF returns true if Don't Fragment flag is set
func (p *Packet) DF() bool {
	return (p.Flags & 0x02) != 0
}

// SrcIPUint32 returns source IP as uint32 for fast map lookups
func (p *Packet) SrcIPUint32() uint32 {
	return binary.BigEndian.Uint32(p.SrcIP[:])
}

// DstIPUint32 returns destination IP as uint32
func (p *Packet) DstIPUint32() uint32 {
	return binary.BigEndian.Uint32(p.DstIP[:])
}

// FlowKey returns a uint64 key combining SrcIP + SrcPort for per-flow tracking
func (p *Packet) FlowKey() uint64 {
	return uint64(p.SrcIPUint32())<<16 | uint64(p.SrcPort)
}

// IPFlowKey returns a uint64 key for per-IP tracking (just SrcIP)
func (p *Packet) IPFlowKey() uint64 {
	return uint64(p.SrcIPUint32())
}

// ConnKey returns a uint64 key combining SrcIP+SrcPort+DstPort for connection tracking
func (p *Packet) ConnKey() uint64 {
	return uint64(p.SrcIPUint32())<<32 | uint64(p.SrcPort)<<16 | uint64(p.DstPort)
}
