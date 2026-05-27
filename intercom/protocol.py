"""
太川 TC-3000MH-X1 门禁协议定义

协议基于 UDP:
- 端口 7800: 信令通道 (76 字节命令包 / 4 字节 ACK)
- 端口 8800: 音视频通道 (76 字节音频保活 / 1444 字节视频帧)
"""

from __future__ import annotations
import struct
from enum import IntEnum

# --------------- 端口 ---------------
SIGNAL_PORT = 7800
AUDIO_PORT = 8800

# --------------- 包长 ---------------
PKT_LEN = 0x4C  # 76 字节信令包
ACK_LEN = 4
DOOR_OPEN_BROADCAST_LEN = 23
HEARTBEAT_LEN = 52

# --------------- 命令码 (little-endian uint32 @ offset 12) ---------------
class Cmd(IntEnum):
    ANSWER = 0x00000000  # 接听
    HANGUP = 0x00000003  # 挂断
    OPEN = 0x00000004    # 开门
    CALL = 0x00000080    # 呼叫
    READY = 0x00000100   # 门禁就绪 (来自门禁机)
    RING = 0x00000300    # 门禁响铃 (来自门禁机)
    DOOR_OPEN = 0x00000550  # 门已开广播 (23 字节短包)
    DOOR_OPEN_CMD = 0x00000207  # 开门确认 (23 字节, cmd 在 offset 8)

# --------------- 设备标识 ---------------
DEVICE_NAME_MSTAR = b'MSTAR\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # 16 bytes
DEVICE_NAME_DOOR = b'DOOR\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # 16 bytes

# 室内机地址数据 (从抓包提取, GBK 编码: 02栋18幢2单元12层2房)
ADDR_DATA = bytes.fromhex('30c7f83138b6b032b5a5d4aa31322032b7bf0000')  # 20 bytes

# 地址填充 (12 bytes)
ADDR_PAD_NORMAL = b'\x00' * 12           # CALL / OPEN 使用
ADDR_PAD_ANSWER = b'\x00' * 11 + b'\xbe'  # ANSWER / HANGUP 使用

# 包尾固定字段
DEVICE_TYPE_MSTAR = struct.pack('<I', 3)   # 设备类型 3
RESERVED_TAIL = b'\x00\x00\x00\x00'
RESOLUTION = bytes.fromhex('0005d002')    # 1280x720

# 音频保活包 (端口 8800, 全零静音)
AUDIO_KEEPALIVE = bytes.fromhex(
    '01000000780500000000000000000000000000004c000000000000000000000000000000'
    '00000000000000000000000000000000000000000000000000000000000000000000000000000000'
)


# --------------- 包解析 ---------------

def parse_signal_packet(data: bytes) -> dict | None:
    """解析 76 字节信令包, 返回 dict 或 None (非信令包)"""
    if len(data) != PKT_LEN:
        return None
    seq = struct.unpack('<I', data[0:4])[0]
    pkt_len = struct.unpack('<I', data[4:8])[0]
    cmd = struct.unpack('<I', data[12:16])[0]
    device_name = data[16:32]
    return {
        'seq': seq,
        'pkt_len': pkt_len,
        'cmd': cmd,
        'device_name': device_name,
        'raw': data,
    }


def parse_ack(data: bytes) -> int | None:
    """解析 4 字节 ACK 包, 返回序列号"""
    if len(data) != ACK_LEN:
        return None
    return struct.unpack('<I', data)[0]


def classify_packet(data: bytes, src_ip: str, dst_ip: str) -> str:
    """
    分类数据包, 返回类型字符串:
    - 'signal': 76 字节信令包
    - 'ack': 4 字节 ACK
    - 'door_open': 23 字节开门广播
    - 'heartbeat': 52 字节心跳 (来自管理设备)
    - 'audio_keepalive': 76 字节音频保活 (端口 8800)
    - 'video': 1444 字节视频帧 (端口 8800)
    - 'audio': 其他音频数据
    - 'unknown': 未知
    """
    if len(data) == ACK_LEN:
        return 'ack'
    if len(data) == PKT_LEN:
        # 区分信令包和音频保活: 信令包的 cmd 在 offset 12
        # 音频保活包的前 4 字节是 0x00000001
        first_word = struct.unpack('<I', data[0:4])[0]
        if first_word == 1:
            return 'audio_keepalive'
        return 'signal'
    if len(data) == DOOR_OPEN_BROADCAST_LEN:
        return 'door_open'
    if len(data) == HEARTBEAT_LEN:
        return 'heartbeat'
    if len(data) >= 1000:
        return 'video'
    if len(data) > ACK_LEN:
        return 'audio'
    return 'unknown'


# --------------- 包构造 ---------------

def build_signal_packet(seq: int, cmd: int) -> bytes:
    """构造 76 字节信令包"""
    if cmd in (Cmd.ANSWER, Cmd.HANGUP):
        addr_pad = ADDR_PAD_ANSWER
    else:
        addr_pad = ADDR_PAD_NORMAL

    pkt = struct.pack('<I', seq)          # 序列号
    pkt += struct.pack('<I', PKT_LEN)     # 包长度
    pkt += b'\x00\x00\x00\x00'           # 保留
    pkt += struct.pack('<I', cmd)         # 命令码
    pkt += DEVICE_NAME_MSTAR             # 设备名 (16 bytes)
    pkt += ADDR_DATA                      # 地址数据 (20 bytes)
    pkt += addr_pad                       # 地址填充 (12 bytes)
    pkt += DEVICE_TYPE_MSTAR             # 设备类型 (4 bytes)
    pkt += RESERVED_TAIL                 # 保留 (4 bytes)
    pkt += RESOLUTION                    # 分辨率 (4 bytes)

    assert len(pkt) == PKT_LEN
    return pkt


def build_ack(seq_bytes: bytes) -> bytes:
    """构造 4 字节 ACK (直接回显序列号)"""
    return seq_bytes[:4]
