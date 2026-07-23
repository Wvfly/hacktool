//go:build windows

package main

import (
	"fmt"
	"net"
	"strings"

	"github.com/google/gopacket/pcap"
)

type pcapSender struct {
	handle *pcap.Handle
}

func newPacketSender(ifaceName string) (packetSender, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("FindAllDevs failed: %v", err)
	}

	// 通过接口名或 IP 匹配 pcap 设备
	// Windows 上 ifaceName 是 "VMware Network Adapter VMnet8"
	// pcap 设备名是 "\Device\NPF_{GUID}"
	// 需要通过 Description 或 Addresses 匹配
	var pcapDevName string

	// 方法1：通过 Description 匹配（pcap dev.Description 包含 Windows 网卡显示名）
	for _, dev := range devices {
		if strings.Contains(dev.Description, ifaceName) || dev.Name == ifaceName {
			pcapDevName = dev.Name
			break
		}
	}

	// 方法2：通过 IP 地址匹配
	if pcapDevName == "" {
		ifaces, _ := net.Interfaces()
		for _, iface := range ifaces {
			if iface.Name == ifaceName {
				addrs, _ := iface.Addrs()
				for _, addr := range addrs {
					ipNet, ok := addr.(*net.IPNet)
					if !ok || ipNet.IP.To4() == nil {
						continue
					}
					ip := ipNet.IP.To4()
					for _, dev := range devices {
						for _, devAddr := range dev.Addresses {
							if devAddr.IP.To4() != nil && ip.Equal(devAddr.IP.To4()) {
								pcapDevName = dev.Name
								break
							}
						}
						if pcapDevName != "" {
							break
						}
					}
					if pcapDevName != "" {
						break
					}
				}
			}
		}
	}

	if pcapDevName == "" {
		return nil, fmt.Errorf("no matching pcap device found for interface %q", ifaceName)
	}

	handle, err := pcap.OpenLive(pcapDevName, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("OpenLive(%s) failed: %v", pcapDevName, err)
	}
	return &pcapSender{handle: handle}, nil
}

func (ps *pcapSender) Send(data []byte) error {
	return ps.handle.WritePacketData(data)
}

func (ps *pcapSender) Close() error {
	ps.handle.Close()
	return nil
}
