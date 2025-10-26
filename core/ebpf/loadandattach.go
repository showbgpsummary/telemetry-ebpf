package ebpf

import (
	"log"
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/showbgpsummary/telemetry-ebpf/core"
)

func LoadAndAttach() ([]link.Link, error) {
	var objs counterObjects
	if err := loadCounterObjects(&objs, nil); err != nil {
		log.Printf("Loading eBPF objects: %v", err)
		return nil, err
	}
	// OBJS MUST BE CLOSED VIA CALLER.
	IfaceList, err := core.FindInterfaces()
	if err != nil {
		log.Printf("warning: cannot load interfaces :%v", err)
		return nil, err
	}
	var XDPLinks []link.Link
	for _, ifaceName := range IfaceList {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			log.Printf("warning: cannot get interfacename for %s: %v", ifaceName, err)
			continue
		}
		XDPlink, err := link.AttachXDP(link.XDPOptions{
			Program:   objs.Firewall,
			Interface: iface.Index,
		})
		if err != nil {
			log.Printf("warning: cannot attach XDP : %v", err)
			continue
		}
		XDPLinks = append(XDPLinks, XDPlink)
		log.Printf("info: attached XDP to %s", ifaceName)

	}
	objs.Close()
	return XDPLinks, nil
}
