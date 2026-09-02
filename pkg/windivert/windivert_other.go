//go:build !windows

// Package windivert exposes a development stub on non-Windows systems.
package windivert

import "errors"

const (
	LayerNetwork        = 0
	LayerNetworkForward = 1
	LayerFlow           = 2
	LayerSocket         = 3
	LayerReflect        = 4

	FlagDefault   uint64 = 0
	FlagSniff     uint64 = 1
	FlagDrop      uint64 = 2
	FlagRecvOnly  uint64 = 4
	FlagSendOnly  uint64 = 8
	FlagNoInstall uint64 = 16
	FlagFragments uint64 = 32

	ParamQueueLen  = 0
	ParamQueueTime = 1
	ParamQueueSize = 2
)

var ErrUnsupported = errors.New("WinDivert is only available on Windows")

type Address struct {
	Timestamp int64
	Layer     uint32
	Event     uint32
	Flags     uint32
	_         uint32
	IfIdx     uint32
	SubIfIdx  uint32
	_         [48]byte
}

func (a *Address) IsOutbound() bool { return a.Flags&1 != 0 }
func (a *Address) SetOutbound(outbound bool) {
	if outbound {
		a.Flags |= 1
	} else {
		a.Flags &^= 1
	}
}

type Handle struct{}

func Open(string, uint32, int16, uint64) (*Handle, error)      { return nil, ErrUnsupported }
func (h *Handle) Recv([]byte, *Address) (uint, error)          { return 0, ErrUnsupported }
func (h *Handle) Send([]byte, *Address) (uint, error)          { return 0, ErrUnsupported }
func (h *Handle) CalcChecksums([]byte, *Address, uint64) error { return ErrUnsupported }
func (h *Handle) SetParam(int, uint64) error                   { return ErrUnsupported }
func (h *Handle) Close() error                                 { return nil }
