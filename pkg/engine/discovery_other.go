//go:build !windows

package engine

import (
	"sync/atomic"
	"time"
)

// PortSet is a read-only snapshot of listening ports on the system.
type PortSet struct {
	TCP            map[uint16]bool
	UDP            map[uint16]bool
	EstablishedTCP map[uint64]bool
}

// PortDiscovery is a fail-open development implementation outside Windows.
type PortDiscovery struct {
	current atomic.Pointer[PortSet]
	exclude map[uint16]bool
}

func NewPortDiscovery(_ time.Duration, excludePorts []uint16) *PortDiscovery {
	p := &PortDiscovery{exclude: make(map[uint16]bool)}
	for _, port := range excludePorts {
		p.exclude[port] = true
	}
	p.current.Store(&PortSet{TCP: map[uint16]bool{}, UDP: map[uint16]bool{}, EstablishedTCP: map[uint64]bool{}})
	return p
}

func (p *PortDiscovery) GetPorts() *PortSet                   { return p.current.Load() }
func (p *PortDiscovery) IsExcluded(port uint16) bool          { return p.exclude[port] }
func (p *PortDiscovery) IsListening(port uint16, _ bool) bool { return p.exclude[port] }
func (p *PortDiscovery) IsEstablishedTCP(connKey uint64) bool {
	return p.current.Load().EstablishedTCP[connKey]
}
func (p *PortDiscovery) AddExcludePort(port uint16) { p.exclude[port] = true }
func (p *PortDiscovery) Start()                     {}
func (p *PortDiscovery) Stop()                      {}
