//go:build !windows
// +build !windows

package service

import (
	"fmt"
)


func RunService(runFunc func(), stopFunc func()) error {
	return fmt.Errorf("Windows Service is only supported on Windows")
}


func Install() error {
	return fmt.Errorf("Windows Service is only supported on Windows")
}

func Uninstall() error {
	return fmt.Errorf("Windows Service is only supported on Windows")
}

func Start() error {
	return fmt.Errorf("Windows Service is only supported on Windows")
}

func Stop() error {
	return fmt.Errorf("Windows Service is only supported on Windows")
}
