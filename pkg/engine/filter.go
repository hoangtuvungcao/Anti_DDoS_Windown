// Package engine implements the core firewall packet processing pipeline.
package engine

import (
	"waf-game/pkg/packet"
)

// FilterResult indicates the action to take on a packet
type FilterResult int

const (
	FilterPass FilterResult = iota
	FilterDrop
)

// Layer1Filter performs Global Garbage Filtering — drops RFC violations.
// 11 rules that drop provably invalid packets regardless of application.
type Layer1Filter struct{}

// NewLayer1Filter creates a new garbage filter.
func NewLayer1Filter() *Layer1Filter {
	return &Layer1Filter{}
}

// Check examines a packet and returns FilterDrop if it violates any rule.
// Returns the rule number (1-11) that triggered the drop, or 0 if passed.
func (f *Layer1Filter) Check(pkt *packet.Packet) (FilterResult, int) {
	// Rule 1: Drop IP Fragments
	// Fragmented packets are commonly used in fragmentation floods and Teardrop attacks
	if pkt.IsFragment() {
		return FilterDrop, 1
	}

	// Rule 2: Invalid IP Header Length
	if pkt.IHL < 5 || int(pkt.TotalLen) < pkt.IPHeaderLen {
		return FilterDrop, 2
	}

	// Rule 3: TTL = 0 (invalid, should never reach us)
	if pkt.TTL == 0 {
		return FilterDrop, 11
	}

	// Rules 4-8: TCP-specific checks
	if pkt.Protocol == packet.ProtoTCP {
		return f.checkTCP(pkt)
	}

	// Rule 9: UDP Length = 0 (zero-length flood)
	if pkt.Protocol == packet.ProtoUDP {
		if pkt.UDPLength < 8 { // UDP header is 8 bytes minimum
			return FilterDrop, 9
		}
	}

	// Rules 10-11: IP source validation
	return f.checkIPSource(pkt)
}

func (f *Layer1Filter) checkTCP(pkt *packet.Packet) (FilterResult, int) {
	flags := pkt.TCPFlags

	// Rule 3: TCP Null Scan — no flags set
	if flags == 0 {
		return FilterDrop, 3
	}

	// Rule 4: TCP XMAS — SYN + FIN both set
	if flags&packet.TCPFlagSYN != 0 && flags&packet.TCPFlagFIN != 0 {
		return FilterDrop, 4
	}

	// Rule 5: TCP SYN + RST both set
	if flags&packet.TCPFlagSYN != 0 && flags&packet.TCPFlagRST != 0 {
		return FilterDrop, 5
	}

	// Rule 6: TCP FIN without ACK
	if flags&packet.TCPFlagFIN != 0 && flags&packet.TCPFlagACK == 0 {
		return FilterDrop, 6
	}

	// Rule 10: TCP source port = 0
	if pkt.SrcPort == 0 {
		return FilterDrop, 10
	}

	// IP source checks
	return f.checkIPSource(pkt)
}

func (f *Layer1Filter) checkIPSource(pkt *packet.Packet) (FilterResult, int) {
	src := pkt.SrcIP

	// Rule 7: Bogon source IP (RFC1918 + special ranges)
	// These should never arrive from the public internet as source addresses

	// Rule 7: Bogon source IP (invalid ranges that can never be source addresses on public internet)

	// 0.0.0.0/8 ("this" network)
	if src[0] == 0 {
		return FilterDrop, 7
	}

	// 224.0.0.0/4 (multicast as source — invalid)
	if src[0] >= 224 && src[0] <= 239 {
		return FilterDrop, 7
	}

	// 240.0.0.0/4 (reserved)
	if src[0] >= 240 {
		return FilterDrop, 7
	}

	// Rule 8: Land Attack — source IP equals destination IP
	if pkt.SrcIP == pkt.DstIP {
		return FilterDrop, 8
	}

	return FilterPass, 0
}
