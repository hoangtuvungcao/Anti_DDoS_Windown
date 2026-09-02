//go:build !windows

package engine

type WindowsHardening struct{}

var nonWindowsHardening = &WindowsHardening{}

func GetWindowsHardening() *WindowsHardening { return nonWindowsHardening }
func (*WindowsHardening) Apply() error       { return nil }
func (*WindowsHardening) Restore()           {}
