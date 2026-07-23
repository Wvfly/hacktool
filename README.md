# SYN Flood 压力测试工具

基于 Go 实现的 SYN Flood 网络压力测试工具，通过构造伪造源 IP 的 TCP SYN 包对目标发起连接请求洪泛，用于合法授权的网络压力测试与安全演练。

## 功能特性

- **交互式参数输入** — 运行时依次提示输入目标 IP、端口、并发 Worker 数
- **交互式网卡选择** — 自动列出所有可用网卡，支持手动指定或回车跳过使用自动选择
- **智能网卡匹配** — 自动选择与目标同子网的网卡，非同子网时自动回退
- **自动 MAC 解析** — 同子网目标通过 ARP 解析目的 MAC；跨子网自动获取默认网关并解析网关 MAC
- **多并发 Worker** — 每个 Worker 独立 goroutine + 独立随机源，无锁竞争，充分利用多核
- **实时统计面板** — 每秒刷新：总发包数、实时速率 (pps)、带宽 (Mbps)、错误计数
- **优雅退出** — 监听 `Ctrl+C` (SIGINT/SIGTERM)，等待所有 Worker 完成后输出汇总统计
- **跨平台支持** — Windows（基于 gopacket/pcap）和 Linux（基于 AF_PACKET 原始套接字）

## 项目结构

```
hacktool/
├── main.go                  # 主程序：交互逻辑、网卡选择、包构造与发包调度
├── send_packet_windows.go   # Windows 平台发包实现（gopacket/pcap）
├── send_packet_linux.go     # Linux 平台发包实现（AF_PACKET 原始套接字）
├── go.mod
└── go.sum
```

## 环境要求

| 平台 | 要求 |
|------|------|
| **Windows** | [Npcap](https://npcap.com/)（安装时勾选 "Install Npcap in WinPcap API-compatible Mode"） |
| **Linux** | 需要 root 权限运行 |
| **Go** | 1.22+ |

## 编译

### Windows

```powershell
go build -o synflood.exe .
```

### Linux

```bash
go build -o synflood .
```

### 交叉编译（在 Windows 上生成 Linux 可执行文件）

```powershell
$env:GOOS="linux"; $env:GOARCH="amd64"; go build -o synflood .
```

## 使用方法

直接运行程序，按提示输入参数：

```
请输入目标 IP: 192.168.1.100
请输入目标端口: 80
请输入并发 worker 数量 (建议 1-32): 4

可用网卡列表:
--------------------------------------------------------------
  序号 网卡名                    IPv4             MAC
--------------------------------------------------------------
  1    Ethernet                  192.168.1.5      aa:bb:cc:dd:ee:ff
  2    VMware Network Adapter    192.168.100.1    00:50:56:xx:yy:zz
--------------------------------------------------------------
请选择网卡序号 (直接回车使用自动选择): 1

[信息] 已选择网卡: Ethernet (192.168.1.5)
[信息] 使用指定网卡: Ethernet
[信息] 网卡:   Ethernet
[信息] 本机 IP:  192.168.1.5
[信息] 本机 MAC: aa:bb:cc:dd:ee:ff
[信息] 子网掩码: ffffff00
[信息] 目标 192.168.1.100 在同一子网，ARP 解析目标 MAC...
[信息] 目的 MAC: 11:22:33:44:55:66

启动 4 个并发 worker，无延迟发包，按 Ctrl+C 停止...

[统计] 总计: 1523847 包 | 速率: 385421 pps | 带宽: 166.437 Mbps | 错误: 0
```

按 `Ctrl+C` 停止后输出汇总：

```
已停止，共发送 1523847 个 SYN 包，错误 0 次
```

## 工作原理

1. **网卡选择**：优先选择与目标 IP 同子网的网卡，否则使用第一个可用网卡（或用户手动指定）
2. **MAC 地址解析**：
   - 同子网 → ping 目标后从 ARP 表获取目的 MAC
   - 跨子网 → 获取默认网关 IP，解析网关 MAC 作为目的 MAC
3. **包构造**：使用 `gopacket/layers` 构造完整的 Ethernet + IPv4 + TCP(SYN) 帧
   - 源 IP 随机伪造（`x.x.x.x`）
   - 源端口随机
   - 自动计算 IP/TCP 校验和
4. **发包**：
   - **Windows**：通过 `gopacket/pcap` 调用 Npcap 打开网卡句柄写入原始帧
   - **Linux**：通过 `AF_PACKET` 原始套接字直接发送
5. **多 Worker 并发**：每个 Worker 独立持有发包句柄和随机数生成器，无锁竞争

## 注意事项

- 本工具仅供**合法授权**的安全测试与压力演练使用，未经授权对他人的网络发起攻击属于违法行为
- Windows 上必须安装 Npcap 并启用 WinPcap 兼容模式
- Linux 上需要 `root` 权限（`sudo`）运行
- 并发 Worker 数建议 1-32，过大可能导致系统资源耗尽
