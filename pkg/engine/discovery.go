//go:build windows

package engine

import (
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// PortSet is a read-only snapshot of listening ports on the system.
type PortSet struct {
	TCP            map[uint16]bool
	UDP            map[uint16]bool
	EstablishedTCP map[uint64]bool
}

// PortDiscovery periodically scans the OS for listening TCP/UDP ports.
// Uses Windows API GetExtendedTcpTable / GetExtendedUdpTable via iphlpapi.dll.
type PortDiscovery struct {
	current   atomic.Pointer[PortSet]
	interval  time.Duration
	stopCh    chan struct{}
	exclude   map[uint16]bool
	excludeMu sync.RWMutex // protects exclude; workers read, web-server writes
}

// Windows API constants
const (
	tcpTableOwnerPIDListener = 3 // TCP_TABLE_OWNER_PID_LISTENER (IPv6 scan)
	tcpTableOwnerPIDAll      = 5 // TCP_TABLE_OWNER_PID_ALL
	udpTableOwnerPID         = 1 // UDP_TABLE_OWNER_PID
	mibTCPStateListen        = 2
	mibTCPStateEstablished   = 5
	afINET                   = 2  // AF_INET (IPv4)
	afINET6                  = 23 // AF_INET6 (IPv6 / Dual-Stack sockets like [::]:8080)
)

// MIB_TCPROW_OWNER_PID structure (IPv4)
type tcpRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

// MIB_TCP6ROW_OWNER_PID structure (IPv6 / Dual-Stack)
type tcp6RowOwnerPID struct {
	LocalAddr     [16]byte
	LocalScopeId  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeId uint32
	RemotePort    uint32
	State         uint32
	OwningPid     uint32
}

// MIB_UDPROW_OWNER_PID structure (IPv4)
type udpRowOwnerPID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPid uint32
}

// MIB_UDP6ROW_OWNER_PID structure (IPv6 / Dual-Stack)
type udp6RowOwnerPID struct {
	LocalAddr    [16]byte
	LocalScopeId uint32
	LocalPort    uint32
	OwningPid    uint32
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

// IsEstablishedTCP verifies a complete remote-IP/remote-port/local-port tuple
// against Windows' live TCP connection table. It does not trust port numbers.
func (pd *PortDiscovery) IsEstablishedTCP(connKey uint64) bool {
	ports := pd.current.Load()
	return ports != nil && ports.EstablishedTCP[connKey]
}

// IsExcluded reports whether a port bypasses closed-port filtering.
func (pd *PortDiscovery) IsExcluded(port uint16) bool {
	pd.excludeMu.RLock()
	v := pd.exclude[port]
	pd.excludeMu.RUnlock()
	return v
}

// AddExcludePort registers a port that should be treated as listening even when
// OS discovery cannot see it. Other firewall layers still protect the port.
func (pd *PortDiscovery) AddExcludePort(port uint16) {
	pd.excludeMu.Lock()
	pd.exclude[port] = true
	pd.excludeMu.Unlock()
}

// Refresh immediately publishes a fresh snapshot after a local service starts.
// This avoids broad port exemptions while ensuring a newly opened listener is
// recognized before the next periodic scan.
func (pd *PortDiscovery) Refresh() {
	pd.current.Store(pd.scan())
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
		TCP:            make(map[uint16]bool),
		UDP:            make(map[uint16]bool),
		EstablishedTCP: make(map[uint64]bool),
	}

	// Scan both IPv4 and IPv6 / Dual-stack listeners
	pd.scanTCP4(ps)
	pd.scanTCP6(ps)
	pd.scanUDP4(ps)
	pd.scanUDP6(ps)

	return ps
}

func decodePort(raw uint32) uint16 {
	// dwLocalPort is stored in network byte order in first 16 bits
	return uint16(((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF))
}

func (pd *PortDiscovery) scanTCP4(ps *PortSet) {
	var size uint32
	procGetExtendedTcpTab.Call(0, uintptr(unsafe.Pointer(&size)), 1, afINET, tcpTableOwnerPIDAll, 0)
	if size == 0 {
		return
	}

	buf := make([]byte, size)
	ret, _, _ := procGetExtendedTcpTab.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1, afINET, tcpTableOwnerPIDAll, 0)
	if ret != 0 || len(buf) < 4 {
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
		localPort := decodePort(row.LocalPort)
		if row.State == mibTCPStateListen && localPort > 0 && !pd.IsExcluded(localPort) {
			ps.TCP[localPort] = true
		}
		if row.State == mibTCPStateEstablished && localPort > 0 {
			key := tcpTableConnectionKey(row.RemoteAddr, row.RemotePort, row.LocalPort)
			ps.EstablishedTCP[key] = true
		}
	}
}

func (pd *PortDiscovery) scanTCP6(ps *PortSet) {
	var size uint32
	procGetExtendedTcpTab.Call(0, uintptr(unsafe.Pointer(&size)), 1, afINET6, tcpTableOwnerPIDListener, 0)
	if size == 0 {
		return
	}

	buf := make([]byte, size)
	ret, _, _ := procGetExtendedTcpTab.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1, afINET6, tcpTableOwnerPIDListener, 0)
	if ret != 0 || len(buf) < 4 {
		return
	}

	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(tcp6RowOwnerPID{})

	for i := uint32(0); i < numEntries; i++ {
		offset := 4 + uintptr(i)*rowSize
		if offset+rowSize > uintptr(len(buf)) {
			break
		}
		row := (*tcp6RowOwnerPID)(unsafe.Pointer(&buf[offset]))
		port := decodePort(row.LocalPort)
		if port > 0 && !pd.IsExcluded(port) {
			ps.TCP[port] = true
		}
	}
}

func (pd *PortDiscovery) scanUDP4(ps *PortSet) {
	var size uint32
	procGetExtendedUdpTab.Call(0, uintptr(unsafe.Pointer(&size)), 1, afINET, udpTableOwnerPID, 0)
	if size == 0 {
		return
	}

	buf := make([]byte, size)
	ret, _, _ := procGetExtendedUdpTab.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1, afINET, udpTableOwnerPID, 0)
	if ret != 0 || len(buf) < 4 {
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
		port := decodePort(row.LocalPort)
		if port > 0 && !pd.IsExcluded(port) {
			ps.UDP[port] = true
		}
	}
}

func (pd *PortDiscovery) scanUDP6(ps *PortSet) {
	var size uint32
	procGetExtendedUdpTab.Call(0, uintptr(unsafe.Pointer(&size)), 1, afINET6, udpTableOwnerPID, 0)
	if size == 0 {
		return
	}

	buf := make([]byte, size)
	ret, _, _ := procGetExtendedUdpTab.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1, afINET6, udpTableOwnerPID, 0)
	if ret != 0 || len(buf) < 4 {
		return
	}

	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(udp6RowOwnerPID{})

	for i := uint32(0); i < numEntries; i++ {
		offset := 4 + uintptr(i)*rowSize
		if offset+rowSize > uintptr(len(buf)) {
			break
		}
		row := (*udp6RowOwnerPID)(unsafe.Pointer(&buf[offset]))
		port := decodePort(row.LocalPort)
		if port > 0 && !pd.IsExcluded(port) {
			ps.UDP[port] = true
		}
	}
}
