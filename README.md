# 太川 TC-3000MH-X1 门禁桥接器

逆向工程太川 TC-3000MH-X1 门禁系统协议，实现 UDP 信令控制 + Home Assistant 集成。

## 功能

- **远程开门** — 通过 UDP 端口 7800 信令模拟室内机发送开门指令
- **事件嗅探** — 监听信令端口，检测来电、开门、挂断等事件
- **MQTT 集成** — 将门禁事件发布到 Home Assistant，接收 HA 命令远程操作
- **视频转发** — 转发门禁视频流（端口 8800）到 HA/go2rtc

## 项目结构

```
├── open_door.py          # 独立开门脚本
├── requirements.txt      # Python 依赖
├── intercom/             # 守护进程模块
│   ├── daemon.py         # 主守护进程（整合所有模块）
│   ├── protocol.py       # 协议定义与包构造
│   ├── sniffer.py        # 信令嗅探器
│   ├── injector.py       # 信令注入器
│   ├── mqtt_client.py    # MQTT 客户端
│   ├── video_relay.py    # 视频流转发
│   └── video_analyzer.py # 视频流分析
└── *.pcapng              # 逆向工程抓包文件
```

## 快速开始

### 环境要求

- Python 3.9+
- 与门禁机在同一局域网

### 安装

```bash
pip install -r requirements.txt
```

### 独立开门

```bash
# 默认门禁机 IP: 192.168.120.96
python open_door.py

# 指定 IP
python open_door.py --door-ip 192.168.1.100
```

### 运行守护进程

```bash
# 启动完整守护进程（信令监听 + MQTT + 视频转发）
python -m intercom
```

## 协议概要

基于 UDP 端口 7800 的 76 字节固定长度信令包：

| 偏移 | 长度 | 说明 |
|------|------|------|
| 0x00 | 4 | 序列号 (uint32 LE) |
| 0x04 | 4 | 包长度 (0x4C) |
| 0x0C | 4 | 命令码 (uint32 LE) |
| 0x10 | 16 | 设备名 |
| 0x20 | 20 | 地址数据 |
| 0x34 | 12 | 地址填充 |
| 0x40 | 4 | 设备类型 |
| 0x44 | 4 | 分辨率 |

主要命令码：

- `0x04` — 开门 (OPEN)
- `0x03` — 挂断 (HANGUP)

## 许可

本项目仅供学习和研究用途。
