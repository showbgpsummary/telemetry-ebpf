package main

import (
	"log"
	"os"

	"github.com/showbgpsummary/telemetry-ebpf/core"
)

func main() {
	// To avoid getting more than one syscalls.
	stopChan := make(chan struct{}, 1)
	go func() {
		err := core.SysCallNotify(stopChan)
		if err != nil {
			log.Printf("warning: error at handling syscalls : %v", err)
			return
		}
		log.Println("info: syscalls will be notified")
	}()
	go func() {
		<-stopChan
		// Gracefulshutdown will be added by another issue.
		core.GraceFulShutdown()
	}()
	hostname, err := os.Hostname()
	if err != nil {
		log.Printf("warning: unable to get hostname : %v", err)
	}
	interfaces, err := core.FindInterfaces()
	if err != nil {
		log.Printf("warning: unable to get interfaces : %v", err)
	}
	log.Printf("info: interfaces scanned from appliance %s,interfaces : %s", hostname, interfaces)
}
