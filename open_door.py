#!/usr/bin/env python3
"""
太川 TC-3000MH-X1 门禁开门脚本
通过模拟室内机协议，向门禁机发送开门指令。

协议基于 UDP 端口 7800 信令。
基于真实抓包简化: 直接 OPEN → ACK → HANGUP。
"""

import socket
import struct
import time
import argparse
import sys

# --------------- 协议常量 ---------------

SIGNAL_PORT = 7800  # 信令端口
PKT_LEN = 0x4C      # 76 字节固定包长

# 命令码 (little-endian uint32 @ offset 12)
CMD_OPEN    = 0x00000004  # 开门
CMD_HANGUP  = 0x00000003  # 挂断

# 室内机设备名
DEVICE_NAME_MSTAR = b'MSTAR\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # 16 bytes

# 室内机地址数据（从 just_open.pcapng 抓包提取）
ADDR_DATA = bytes.fromhex('30c7f83138b6b032b5a5d4aa31322032b7bf0000')  # 20 bytes

# 地址填充 (12 bytes)
ADDR_PAD_NORMAL = b'\x00' * 12        # OPEN 使用
ADDR_PAD_HANGUP = b'\x00' * 11 + b'\xbe'  # HANGUP 使用

# 包尾固定字段
DEVICE_TYPE_MSTAR = struct.pack('<I', 3)   # 设备类型 3
RESERVED_TAIL     = b'\x00\x00\x00\x00'
RESOLUTION        = bytes.fromhex('0005d002')  # 1280x720


# --------------- 数据包构造 ---------------

def build_signal_packet(seq: int, cmd: int) -> bytes:
    """构造 76 字节信令包"""
    if cmd == CMD_HANGUP:
        addr_pad = ADDR_PAD_HANGUP
    else:
        addr_pad = ADDR_PAD_NORMAL

    pkt = struct.pack('<I', seq)        # 序列号
    pkt += struct.pack('<I', PKT_LEN)   # 包长度
    pkt += b'\x00\x00\x00\x00'         # 保留
    pkt += struct.pack('<I', cmd)       # 命令码
    pkt += DEVICE_NAME_MSTAR            # 设备名 (16 bytes)
    pkt += ADDR_DATA                    # 地址数据 (20 bytes)
    pkt += addr_pad                     # 地址填充 (12 bytes)
    pkt += DEVICE_TYPE_MSTAR            # 设备类型 (4 bytes)
    pkt += RESERVED_TAIL                # 保留 (4 bytes)
    pkt += RESOLUTION                   # 分辨率 (4 bytes)

    assert len(pkt) == PKT_LEN, f"包长度错误: {len(pkt)} != {PKT_LEN}"
    return pkt


def build_ack(seq_bytes: bytes) -> bytes:
    """构造 4 字节 ACK 包（直接回显序列号）"""
    return seq_bytes[:4]


# --------------- 门禁开门主逻辑 ---------------

class DoorOpener:
    def __init__(self, door_ip: str, door_port: int = SIGNAL_PORT,
                 timeout: float = 5.0):
        self.door_ip = door_ip
        self.door_port = door_port
        self.timeout = timeout
        self.seq = 0  # 真实设备序列号从 0 开始

        # 信令 socket (随机源端口, 不绑定 7800)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.settimeout(self.timeout)
        self.sock.bind(('0.0.0.0', 0))

    def _next_seq(self) -> int:
        s = self.seq
        self.seq += 1
        return s

    def _send_signal(self, cmd: int) -> int:
        seq = self._next_seq()
        pkt = build_signal_packet(seq, cmd)
        self.sock.sendto(pkt, (self.door_ip, self.door_port))
        return seq

    def _send_ack(self, seq_bytes: bytes):
        ack = build_ack(seq_bytes)
        self.sock.sendto(ack, (self.door_ip, self.door_port))

    def _recv(self, expected_len: int = None) -> tuple:
        deadline = time.time() + self.timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise TimeoutError("接收超时")
            self.sock.settimeout(remaining)
            try:
                data, addr = self.sock.recvfrom(4096)
                if expected_len is None or len(data) == expected_len:
                    return data, addr
            except socket.timeout:
                raise TimeoutError("接收超时")

    def _wait_ack(self, expected_seq: int):
        data, _ = self._recv(expected_len=4)
        recv_seq = struct.unpack('<I', data)[0]
        if recv_seq != expected_seq:
            print(f"  [警告] ACK 序列号不匹配: 期望 0x{expected_seq:08x}, 收到 0x{recv_seq:08x}")
        else:
            print(f"  [确认] 收到 ACK (seq=0x{recv_seq:08x})")

    def open(self):
        """执行开门流程: OPEN → ACK → HANGUP"""
        try:
            # 步骤1: 发送开门指令
            print("[1/3] 发送开门指令...")
            seq = self._send_signal(CMD_OPEN)
            self._wait_ack(seq)
            print("  [成功] 开门指令已发送并确认!")

            # 步骤2: 处理门禁返回的 23 字节确认包
            print("[2/3] 等待开门确认...")
            try:
                self.sock.settimeout(2.0)
                data, addr = self.sock.recvfrom(4096)
                if len(data) == 23:
                    print(f"  [确认] 收到开门确认包 (来自 {addr})")
                    self._send_ack(data[:4])
            except socket.timeout:
                print("  [信息] 未收到开门确认包")

            # 步骤3: 挂断
            print("[3/3] 发送挂断...")
            seq = self._send_signal(CMD_HANGUP)
            try:
                self._wait_ack(seq)
            except TimeoutError:
                print("  [信息] 未收到挂断确认（不影响开门）")

            print("\n===== 开门流程完成 =====")

        except TimeoutError as e:
            print(f"\n[错误] {e}")
            print("请检查:")
            print("  1. 门禁机 IP 是否正确")
            print("  2. 本机与门禁机是否在同一网络")
            print("  3. 端口 7800 是否被占用")
            sys.exit(1)
        except Exception as e:
            print(f"\n[错误] {e}")
            sys.exit(1)
        finally:
            self.sock.close()


# --------------- 入口 ---------------

def main():
    parser = argparse.ArgumentParser(
        description='太川 TC-3000MH-X1 门禁开门工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='示例:\n  python open_door.py\n  python open_door.py --door-ip 192.168.120.96'
    )
    parser.add_argument('--door-ip', default='192.168.120.96',
                        help='门禁机 IP 地址 (默认: 192.168.120.96)')
    parser.add_argument('--port', type=int, default=SIGNAL_PORT,
                        help=f'信令端口 (默认: {SIGNAL_PORT})')
    parser.add_argument('--timeout', type=float, default=5.0,
                        help='响应超时时间/秒 (默认: 5.0)')

    args = parser.parse_args()

    print(f"门禁机地址: {args.door_ip}:{args.port}")
    print(f"超时时间: {args.timeout}s")
    print("=" * 40)

    opener = DoorOpener(
        door_ip=args.door_ip,
        door_port=args.port,
        timeout=args.timeout,
    )
    opener.open()


if __name__ == '__main__':
    main()
