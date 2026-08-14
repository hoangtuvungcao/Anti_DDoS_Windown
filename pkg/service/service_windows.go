//go:build windows
// +build windows

package service

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type wafService struct {
	runFunc  func()
	stopFunc func()
}

func (m *wafService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	if m.runFunc != nil {
		go m.runFunc()
	}

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				if m.stopFunc != nil {
					m.stopFunc()
				}
				changes <- svc.Status{State: svc.Stopped}
				return
			}
		}
	}
}

// RunService runs WAF-Shield under Windows Service Control Manager.
func RunService(runFunc func(), stopFunc func()) error {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return fmt.Errorf("not running in a service context")
	}

	return svc.Run(ServiceName, &wafService{runFunc: runFunc, stopFunc: stopFunc})
}


// Install installs WAF as a Windows background service set to auto-start on boot.
func Install() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot find executable path: %w", err)
	}
	exePath, _ = filepath.Abs(exePath)

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("cannot connect to Windows Service Manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err == nil {
		s.Close()
		fmt.Printf("[INFO] Service '%s' is already installed.\n", ServiceName)
		return nil
	}

	cfg := mgr.Config{
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:    mgr.StartAutomatic,
		DisplayName:  ServiceDisplayName,
		Description:  ServiceDescription,
		Dependencies: []string{"Tcpip"},
	}

	s, err = m.CreateService(ServiceName, exePath, cfg, "-service")
	if err != nil {
		return fmt.Errorf("failed to create service: %w", err)
	}
	defer s.Close()

	// Configure recovery options (restart service on crash)
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}, 86400)

	fmt.Println("[OK] Successfully installed WAF-Shield as Windows Service!")
	fmt.Printf("Service Name: %s (Auto-start on Boot)\n", ServiceName)
	return nil
}

// Uninstall removes the Windows Service.
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("cannot connect to Windows Service Manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("service '%s' is not installed: %w", ServiceName, err)
	}
	defer s.Close()

	// Stop service if running
	_, _ = s.Control(svc.Stop)
	time.Sleep(500 * time.Millisecond)

	err = s.Delete()
	if err != nil {
		return fmt.Errorf("failed to delete service: %w", err)
	}

	fmt.Println("[OK] Successfully removed WAF-Shield Windows Service!")
	return nil
}

// Start starts the background Windows Service.
func Start() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("cannot connect to Windows Service Manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		// Service not installed -> auto install it first!
		if errInstall := Install(); errInstall != nil {
			return errInstall
		}
		s, err = m.OpenService(ServiceName)
		if err != nil {
			return fmt.Errorf("failed to open service after installation: %w", err)
		}
	}
	defer s.Close()

	status, err := s.Query()
	if err == nil && status.State == svc.Running {
		fmt.Println("[INFO] WAF-Shield Windows Service is ALREADY running.")
		return nil
	}

	err = s.Start("-service")
	if err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	fmt.Println("[OK] WAF-Shield Windows Service started in background successfully!")
	return nil
}

// Stop stops the background Windows Service.
func Stop() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("cannot connect to Windows Service Manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("service '%s' is not installed: %w", ServiceName, err)
	}
	defer s.Close()

	status, err := s.Control(svc.Stop)
	if err != nil {
		return fmt.Errorf("failed to stop service: %w", err)
	}

	_ = status
	fmt.Println("[OK] WAF-Shield Windows Service stopped successfully!")
	return nil
}
