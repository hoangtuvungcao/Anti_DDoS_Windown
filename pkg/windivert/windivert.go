//go:build windows

// Package windivert provides pure-Go bindings for WinDivert 2.2 via syscall.
// No CGO required — calls WinDivert.dll directly through Windows syscall interface.
package windivert

import (
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

// Layer constants
const (
	LayerNetwork        = 0
	LayerNetworkForward = 1
	LayerFlow           = 2
	LayerSocket         = 3
	LayerReflect        = 4
)

// Flag constants
const (
	FlagDefault  uint64 = 0
	FlagSniff    uint64 = 1
	FlagDrop     uint64 = 2
	FlagRecvOnly uint64 = 4
	FlagSendOnly uint64 = 8
	FlagNoInstall uint64 = 16
	FlagFragments uint64 = 32
)

// Param constants
const (
	ParamQueueLen  = 0
	ParamQueueTime = 1
	ParamQueueSize = 2
)

// Address represents WinDivert address structure (WINDIVERT_ADDRESS).
// Size: 80 bytes for WinDivert 2.x
type Address struct {
	Timestamp int64
	Layer     uint32
	Event     uint32
	// Flags packed into bitfield
	Flags     uint32
	_         uint32
	// Network layer data
	IfIdx     uint32
	SubIfIdx  uint32
	_         [48]byte // padding for union
}

// IsOutbound checks if the packet is outbound
func (a *Address) IsOutbound() bool {
	return a.Flags&1 != 0
}

// SetOutbound sets the outbound flag
func (a *Address) SetOutbound(outbound bool) {
	if outbound {
		a.Flags |= 1
	} else {
		a.Flags &^= 1
	}
}

// Handle wraps a WinDivert handle
type Handle struct {
	handle   uintptr
	mu       sync.Mutex
	closed   bool
}

var (
	windivertDLL *syscall.LazyDLL
	procOpen     *syscall.LazyProc
	procRecv     *syscall.LazyProc
	procRecvEx   *syscall.LazyProc
	procSend     *syscall.LazyProc
	procSendEx   *syscall.LazyProc
	procClose    *syscall.LazyProc
	procSetParam *syscall.LazyProc
	procGetParam *syscall.LazyProc
	procCalcChecksum *syscall.LazyProc

	initOnce sync.Once
	initErr  error
)

func initDLL() {
	initOnce.Do(func() {
		windivertDLL = syscall.NewLazyDLL("resources/bin/WinDivert.dll")
		initErr = windivertDLL.Load()
		if initErr != nil {
			return
		}
		procOpen = windivertDLL.NewProc("WinDivertOpen")
		procRecv = windivertDLL.NewProc("WinDivertRecv")
		procRecvEx = windivertDLL.NewProc("WinDivertRecvEx")
		procSend = windivertDLL.NewProc("WinDivertSend")
		procSendEx = windivertDLL.NewProc("WinDivertSendEx")
		procClose = windivertDLL.NewProc("WinDivertClose")
		procSetParam = windivertDLL.NewProc("WinDivertSetParam")
		procGetParam = windivertDLL.NewProc("WinDivertGetParam")
		procCalcChecksum = windivertDLL.NewProc("WinDivertHelperCalcChecksums")
	})
}

// Open opens a WinDivert handle with the given filter string.
func Open(filter string, layer uint32, priority int16, flags uint64) (*Handle, error) {
	initDLL()
	if initErr != nil {
		return nil, fmt.Errorf("failed to load WinDivert.dll: %w", initErr)
	}

	filterPtr, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return nil, fmt.Errorf("invalid filter string: %w", err)
	}

	r1, _, e1 := procOpen.Call(
		uintptr(unsafe.Pointer(filterPtr)),
		uintptr(layer),
		uintptr(priority),
		uintptr(flags),
	)

	handle := r1
	if handle == uintptr(syscall.InvalidHandle) {
		if e1 != nil && e1 != syscall.Errno(0) {
			return nil, fmt.Errorf("WinDivertOpen failed: %w", e1)
		}
		return nil, fmt.Errorf("WinDivertOpen failed with unknown error")
	}

	h := &Handle{handle: handle}
	runtime.SetFinalizer(h, (*Handle).Close)
	return h, nil
}

// Recv receives a single captured packet.
func (h *Handle) Recv(buf []byte, addr *Address) (uint, error) {
	if h.closed {
		return 0, fmt.Errorf("handle is closed")
	}

	var recvLen uint32
	r1, _, e1 := procRecv.Call(
		h.handle,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&recvLen)),
		uintptr(unsafe.Pointer(addr)),
	)

	if r1 == 0 {
		return 0, fmt.Errorf("WinDivertRecv failed: %w", e1)
	}
	return uint(recvLen), nil
}

// Send injects a packet back into the network stack.
func (h *Handle) Send(buf []byte, addr *Address) (uint, error) {
	if h.closed {
		return 0, fmt.Errorf("handle is closed")
	}

	var sendLen uint32
	r1, _, e1 := procSend.Call(
		h.handle,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&sendLen)),
		uintptr(unsafe.Pointer(addr)),
	)

	if r1 == 0 {
		return 0, fmt.Errorf("WinDivertSend failed: %w", e1)
	}
	return uint(sendLen), nil
}

// CalcChecksums recalculates checksums for a modified packet.
func (h *Handle) CalcChecksums(buf []byte, addr *Address, flags uint64) error {
	r1, _, e1 := procCalcChecksum.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(addr)),
		uintptr(flags),
	)
	if r1 == 0 {
		return fmt.Errorf("WinDivertHelperCalcChecksums failed: %w", e1)
	}
	return nil
}

// SetParam sets a WinDivert parameter.
func (h *Handle) SetParam(param int, value uint64) error {
	r1, _, e1 := procSetParam.Call(
		h.handle,
		uintptr(param),
		uintptr(value),
	)
	if r1 == 0 {
		return fmt.Errorf("WinDivertSetParam failed: %w", e1)
	}
	return nil
}

// Close closes the WinDivert handle and releases the driver.
func (h *Handle) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed {
		return nil
	}
	h.closed = true

	r1, _, e1 := procClose.Call(h.handle)
	runtime.SetFinalizer(h, nil)
	if r1 == 0 {
		return fmt.Errorf("WinDivertClose failed: %w", e1)
	}
	return nil
}
