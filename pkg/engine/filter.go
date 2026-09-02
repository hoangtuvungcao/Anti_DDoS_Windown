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

// DropReason preserves the mitigation decision for metrics and attack diagnosis.
type DropReason uint8

const (
	DropNone DropReason = iota
	DropBlacklisted
	DropUnverified
	DropGameQuery
	DropDPI
	DropEntropy
	DropFlowRate
	DropIPRate
	DropSubnetRate
	DropOutOfState
)

// Known UDP reflection / amplification source ports commonly abused in DDoS attacks
var knownReflectionPorts = map[uint16]string{
	17:    "QOTD",
	19:    "Chargen",
	53:    "DNS",
	69:    "TFTP",
	123:   "NTP",
	137:   "NetBIOS",
	161:   "SNMP",
	389:   "CLDAP",
	520:   "RIPv1",
	1900:  "SSDP",
	3702:  "WS-Discovery",
	5683:  "CoAP",
	11211: "Memcached",
}

// Layer1Filter performs Global Garbage Filtering & Reflection Filtering.
type Layer1Filter struct {
	enableAmplificationFilter bool
}

// NewLayer1Filter creates a new garbage filter.
func NewLayer1Filter() *Layer1Filter {
	return &Layer1Filter{
		enableAmplificationFilter: true,
	}
}

// SetAmplificationFilter enables or disables amplification port blocking.
func (f *Layer1Filter) SetAmplificationFilter(enabled bool) {
	f.enableAmplificationFilter = enabled
}

// IsReflectionPort checks if a UDP source port is a known DDoS reflection vector.
func (f *Layer1Filter) IsReflectionPort(port uint16) bool {
	_, ok := knownReflectionPorts[port]
	return ok
}

// Check examines a packet and returns FilterDrop if it violates any rule.
// Returns the rule number that triggered the drop, or 0 if passed.
func (f *Layer1Filter) Check(pkt *packet.Packet) (FilterResult, int) {
	// Rule 1: Drop IP Fragments (Teardrop / Fragment flood attacks)
	if pkt.IsFragment() {
		return FilterDrop, 1
	}

	// Rule 2: Invalid IP Header Length
	if pkt.IHL < 5 || int(pkt.TotalLen) < pkt.IPHeaderLen {
		return FilterDrop, 2
	}

	// Rule 3: TTL = 0 (invalid, should never reach us)
	if pkt.TTL == 0 {
		return FilterDrop, 3
	}

	// Rule 4: Port 0 check (both source and destination)
	if pkt.Protocol == packet.ProtoTCP || pkt.Protocol == packet.ProtoUDP {
		if pkt.SrcPort == 0 || pkt.DstPort == 0 {
			return FilterDrop, 4
		}
	}

	// Rule 5: TCP-specific protocol checks
	if pkt.Protocol == packet.ProtoTCP {
		return f.checkTCP(pkt)
	}

	// Rule 6: UDP Length checks
	if pkt.Protocol == packet.ProtoUDP {
		if pkt.UDPLength < 8 { // UDP header is 8 bytes minimum
			return FilterDrop, 6
		}
	}

	// Rule 7: ICMP Flood & Oversize Check
	if pkt.Protocol == packet.ProtoICMP {
		if pkt.TotalLen > 1024 { // Oversized ICMP / Ping of Death
			return FilterDrop, 7
		}
		// Block dangerous spoofed ICMP types (Router Discovery / Redirect / Bad Types)
		if pkt.ICMPType == 5 || pkt.ICMPType == 9 || pkt.ICMPType == 10 {
			return FilterDrop, 7
		}
	}

	// Rule 8: Block uncommon/malicious IP protocols not needed by typical servers
	// Allow: ICMP(1), IGMP(2), TCP(6), UDP(17)
	// Block: GRE(47), ESP(50), AH(51), EIGRP(88), OSPF(89), SCTP(132), etc.
	if pkt.Protocol != packet.ProtoTCP &&
		pkt.Protocol != packet.ProtoUDP &&
		pkt.Protocol != packet.ProtoICMP &&
		pkt.Protocol != 2 { // IGMP
		return FilterDrop, 8
	}

	// Rule 9-10: IP source validation
	return f.checkIPSource(pkt)
}

func (f *Layer1Filter) checkTCP(pkt *packet.Packet) (FilterResult, int) {
	flags := pkt.TCPFlags

	// TCP Null Scan — no flags set
	if flags == 0 {
		return FilterDrop, 10
	}

	// TCP SYN + FIN both set
	if flags&packet.TCPFlagSYN != 0 && flags&packet.TCPFlagFIN != 0 {
		return FilterDrop, 11
	}

	// TCP SYN + RST both set
	if flags&packet.TCPFlagSYN != 0 && flags&packet.TCPFlagRST != 0 {
		return FilterDrop, 12
	}

	// TCP FIN without ACK
	if flags&packet.TCPFlagFIN != 0 && flags&packet.TCPFlagACK == 0 {
		return FilterDrop, 13
	}

	// TCP XMAS (FIN + PSH + URG)
	if flags&(packet.TCPFlagFIN|packet.TCPFlagPSH|packet.TCPFlagURG) == (packet.TCPFlagFIN | packet.TCPFlagPSH | packet.TCPFlagURG) {
		return FilterDrop, 14
	}

	// TCP All flags set (0x3F or more)
	if flags&0x3F == 0x3F {
		return FilterDrop, 15
	}

	// IP source checks
	return f.checkIPSource(pkt)
}

func (f *Layer1Filter) checkIPSource(pkt *packet.Packet) (FilterResult, int) {
	src := pkt.SrcIP

	// Bogon source IP (0.0.0.0/8)
	if src[0] == 0 {
		return FilterDrop, 20
	}

	// Multicast as source IP (224.0.0.0/4)
	if src[0] >= 224 && src[0] <= 239 {
		return FilterDrop, 21
	}

	// Reserved / experimental range (240.0.0.0/4)
	if src[0] >= 240 {
		return FilterDrop, 22
	}

	// Land Attack — source IP equals destination IP
	if pkt.SrcIP == pkt.DstIP {
		return FilterDrop, 23
	}

	return FilterPass, 0
}
