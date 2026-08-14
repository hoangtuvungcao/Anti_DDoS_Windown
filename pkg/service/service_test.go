package service

import (
	"runtime"
	"testing"
)

func TestService_Constants(t *testing.T) {
	if ServiceName != "WAFShieldService" {
		t.Errorf("Unexpected ServiceName: %s", ServiceName)
	}
	if ServiceDisplayName == "" {
		t.Errorf("Empty ServiceDisplayName")
	}
}

func TestService_NonWindowsGuard(t *testing.T) {
	if runtime.GOOS != "windows" {
		if err := Install(); err == nil {
			t.Errorf("Expected error on non-Windows OS")
		}
		if err := Uninstall(); err == nil {
			t.Errorf("Expected error on non-Windows OS")
		}
		if err := Start(); err == nil {
			t.Errorf("Expected error on non-Windows OS")
		}
		if err := Stop(); err == nil {
			t.Errorf("Expected error on non-Windows OS")
		}
	}
}
