//go:build windows

package engine

import (
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// PortSet is a read-only snapshot of listening ports on the system.
type PortSet struct {
	TCP map[uint16]bool
	UDP map[uint16]bool
}

// PortDiscovery periodically scans the OS for listening TCP/UDP ports.
// Uses Windows API GetExtendedTcpTable / GetExtendedUdpTable via iphlpapi.dll.
type PortDiscovery struct {
	current  atomic.Pointer[PortSet]
	interval time.Duration
	stopCh   chan struct{}
	exclude  map[uint16]bool
}

// Windows API constants
const (
	tcpTableOwnerPIDListener = 3 // TCP_TABLE_OWNER_PID_LISTENER
	udpTableOwnerPID         = 1 // UDP_TABLE_OWNER_PID
	afINET                   = 2 // AF_INET (IPv4)
)

// MIB_TCPROW_OWNER_PID structure
type tcpRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

// MIB_UDPROW_OWNER_PID structure
type udpRowOwnerPID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPid uint32
}

var (
	iphlpapi              = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTcpTab = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTab = iphlpapi.NewProc("GetExtendedUdpTable")
)

// NewPortDiscovery creates a new port discovery scanner.
func NewPortDiscovery(interval time.Duration, excludePorts []uint16) *PortDiscovery {
	pd := &PortDiscovery{
		interval: interval,
		stopCh:   make(chan struct{}),
		exclude:  make(map[uint16]bool),
	}
	for _, p := range excludePorts {
		pd.exclude[p] = true
	}

	// Initial scan
	ports := pd.scan()
	pd.current.Store(ports)

	return pd
}

// GetPorts returns the current snapshot of listening ports.
// Lock-free read via atomic.Pointer — safe from any goroutine.
func (pd *PortDiscovery) GetPorts() *PortSet {
	return pd.current.Load()
}

// IsListening checks if a port is being listened on for the given protocol.
func (pd *PortDiscovery) IsListening(port uint16, isTCP bool) bool {
	if pd.IsExcluded(port) {
		return true
	}
	ports := pd.current.Load()
	if ports == nil {
		return true // Fail-open if no scan yet
	}
	if isTCP {
		return ports.TCP[port]
	}
	return ports.UDP[port]
}

// IsExcluded reports whether a port bypasses closed-port filtering.
func (pd *PortDiscovery) IsExcluded(port uint16) bool {
	return pd.exclude[port]
}

// Start begins periodic scanning in a goroutine.
func (pd *PortDiscovery) Start() {
	go pd.loop()
}

// Stop halts the scanning goroutine.
func (pd *PortDiscovery) Stop() {
	close(pd.stopCh)
}

func (pd *PortDiscovery) loop() {
	ticker := time.NewTicker(pd.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ports := pd.scan()
			pd.current.Store(ports)
		case <-pd.stopCh:
			return
		}
	}
}

func (pd *PortDiscovery) scan() *PortSet {
	ps := &PortSet{
		TCP: make(map[uint16]bool),
		UDP: make(map[uint16]bool),
	}

	pd.scanTCP(ps)
	pd.scanUDP(ps)

	return ps
}

func (pd *PortDiscovery) scanTCP(ps *PortSet) {
	var size uint32

	// First call: get required buffer size
	procGetExtendedTcpTab.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		1, // bOrder = TRUE
		afINET,
		tcpTableOwnerPIDListener,
		0,
	)

	if size == 0 {
		return
	}

	buf := make([]byte, size)
	ret, _, _ := procGetExtendedTcpTab.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1,
		afINET,
		tcpTableOwnerPIDListener,
		0,
	)

	if ret != 0 {
		return
	}

	// Parse table: first 4 bytes = dwNumEntries
	if len(buf) < 4 {
		return
	}
	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(tcpRowOwnerPID{})

	for i := uint32(0); i < numEntries; i++ {
		offset := 4 + uintptr(i)*rowSize
		if offset+rowSize > uintptr(len(buf)) {
			break
		}
		row := (*tcpRowOwnerPID)(unsafe.Pointer(&buf[offset]))
		// Port is in network byte order (big-endian), need to swap
		port := uint16(row.LocalPort>>8 | row.LocalPort<<8)
		if !pd.exclude[port] {
			ps.TCP[port] = true
		}
	}
}

func (pd *PortDiscovery) scanUDP(ps *PortSet) {
	var size uint32

	procGetExtendedUdpTab.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		1,
		afINET,
		udpTableOwnerPID,
		0,
	)

	if size == 0 {
		return
	}

	buf := make([]byte, size)
	ret, _, _ := procGetExtendedUdpTab.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1,
		afINET,
		udpTableOwnerPID,
		0,
	)

	if ret != 0 {
		return
	}

	if len(buf) < 4 {
		return
	}
	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(udpRowOwnerPID{})

	for i := uint32(0); i < numEntries; i++ {
		offset := 4 + uintptr(i)*rowSize
		if offset+rowSize > uintptr(len(buf)) {
			break
		}
		row := (*udpRowOwnerPID)(unsafe.Pointer(&buf[offset]))
		port := uint16(row.LocalPort>>8 | row.LocalPort<<8)
		if !pd.exclude[port] {
			ps.UDP[port] = true
		}
	}
}
