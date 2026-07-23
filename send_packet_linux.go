//go:build linux

package main

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

const (
	ethPAll  = 0x0003
	ethPLoop = 1
)

type rawSender struct {
	fd    int
	ifIdx int
	addr  syscall.SockaddrLinklayer
}

func newPacketSender(deviceName string) (packetSender, error) {
	// 创建 AF_PACKET 原始套接字（需要 root）
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, ethPAll)
	if err != nil {
		return nil, fmt.Errorf("socket(AF_PACKET) failed: %v (需要 root 权限)", err)
	}

	// 查找网卡索引
	iface, err := net.InterfaceByName(deviceName)
	if err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("InterfaceByName(%s) failed: %v", deviceName, err)
	}

	// 绑定到指定网卡
	addr := syscall.SockaddrLinklayer{
		Protocol: ethPAll,
		Ifindex:  iface.Index,
	}
	if err := syscall.Bind(fd, &addr); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind failed: %v", err)
	}

	return &rawSender{fd: fd, ifIdx: iface.Index}, nil
}

func (rs *rawSender) Send(data []byte) error {
	rs.addr = syscall.SockaddrLinklayer{
		Protocol: ethPAll,
		Ifindex:  rs.ifIdx,
	}
	return syscall.Sendto(rs.fd, data, 0, &rs.addr)
}

func (rs *rawSender) Close() error {
	return syscall.Close(rs.fd)
}

// 确保 unsafe 被引用（某些架构需要）
var _ = unsafe.Sizeof(0)
