# DmaDetector
PCIe DMA 设备扫描器：用于检测传统的 DMA 欺骗硬件（例如 PCILeech / Squirrel 类 FPGA 卡，这类设备通过第二台 PC 读取游戏内存）。

该工具可在本机运行，无需访问或修改 Windows 设备树：不使用 SetupAPI、WMI 或注册表。一个精简的内核驱动程序通过传统的 `CF8` / `CFC` 端口对直接读取 PCI 配置空间。这与系统固件在操作系统启动前使用的机制相同。因此，即使设备没有绑定驱动程序，只要它能够在总线上响应，就仍然可以被检测到。

## 检测结果判定原理

| 判定结果 | 含义 |
| --- | --- |
| **已知 DMA（Known DMA）** | 供应商 ID 与设备 ID 精确匹配一小份已记录的作弊固件标识列表（例如 PCILeech 出厂默认值 `10ee:0666`） |
| **可疑（Suspicious）** | 消费级主板上的 FPGA 系列供应商设备、尚未分类的设备，或位于 0 号插槽之外且供应商未知的主桥设备 |
| **正常（Clean）** | 其他所有设备 |

上述检测结果本身都不能构成确凿证据：DMA 固件可以自定义供应商 ID、设备 ID、类别代码、BAR（基址寄存器）和序列号（PCILeech 的构建指南本身也对此有所说明）。

请将 `Suspicious` 理解为“需要进一步检查”，将 `Known DMA` 理解为“检测到未经过修改的出厂默认固件”。

供应商编号会根据公开的 PCI-SIG 供应商列表进行核验。配置空间的读取机制则遵循微软的 [PCI 配置空间文档](<https://learn.microsoft.com/en-us/windows-hardware/drivers/pci/accessing-pci-device-configuration-space>)。

## 构建

```
cmake -S . -B build -A x64
cmake --build build --config Release
```

安装 Windows Driver Kit（WDK）后，构建产物将输出到以下位置：

- 命令行工具（CLI）：`build/DmaDetector/Release/DmaDetector.exe`
- 内核驱动程序：`build/DmaDetectorDriver/<Config>/DmaDetectorDriver.sys`

## 运行

1. 安装并启动驱动程序服务（需要提升权限）：

```
   sc create DmaDetector binPath= "<path>\DmaDetectorDriver.sys" type= kernel
   sc start DmaDetector
```

2. 运行命令行工具：

```
   DmaDetector.exe          :: 普通表格输出
   DmaDetector.exe raw      :: 以制表符分隔的详细输出，供脚本处理
```

退出代码说明：

- `0`：未发现异常（正常）
- `1`：驱动程序或总线故障
- `2`：发现可疑设备
- `3`：发现已知 DMA 硬件

因此，CI 流水线或计划任务可以通过非零退出代码触发告警。

## 局限性（使用前请仔细阅读）

- 传统的 CF8/CFC 读取方式仅覆盖 8 条 PCI 总线，并且每个设备功能最多读取前 256 字节的配置空间。不支持多 PCI 段服务器以及仅支持 ECAM 的平台。
- 原始端口访问本身存在竞争条件。因此，本工具将读取操作控制在较短范围内，确保读取地址对齐，并且仅通过 IOCTL 路径执行读取。
- 无响应或存在故障的扩展卡不会响应配置空间读取请求。因此，未检测到设备条目并不能证明该设备不存在。
- 伪造或修改过的固件可以绕过基于 ID 的匹配。下一步自然的改进方向是进行配置空间指纹识别（例如 BAR 布局、设备能力结构和 MSI 结构），但当前版本尚未实现此功能。
