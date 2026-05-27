"""
信令嗅探器 - 监听 UDP 7800 流量, 识别状态变化

使用原始套接字嗅探, 不影响正常流量转发。
Mac 上用 BPF (Berkeley Packet Filter), Linux 上用 AF_PACKET。
"""

from __future__ import annotations
import socket
import struct
import threading
import time
from collections.abc import Callable

from .protocol import (
    SIGNAL_PORT, AUDIO_PORT, Cmd, PKT_LEN, ACK_LEN,
    parse_signal_packet, parse_ack, classify_packet,
)


class IntercomState:
    """门禁通话状态机"""
    IDLE = 'idle'
    CALLING = 'calling'       # 室内机呼叫门禁
    RINGING = 'ringing'       # 门禁呼叫室内机 (来电)
    ANSWERED = 'answered'     # 已接听
    TALKING = 'talking'       # 通话中 (收到 READY)
    DOOR_OPEN = 'door_open'   # 门已开
    HUNG_UP = 'hung_up'       # 已挂断


class Sniffer:
    """
    信令嗅探器

    监听指定网络接口上的 UDP 7800 流量, 解析信令包,
    通过回调函数通知状态变化。
    """

    def __init__(self, interface: str = None, door_ip: str = '192.168.120.96',
                 indoor_ip: str = '192.168.122.102'):
        self.interface = interface
        self.door_ip = door_ip
        self.indoor_ip = indoor_ip
        self.state = IntercomState.IDLE
        self._running = False
        self._thread = None
        self._sock = None
        self._callbacks: list[Callable] = []
        self._last_seq = 0

    def on_state_change(self, callback: Callable):
        """注册状态变化回调: callback(old_state, new_state, info_dict)"""
        self._callbacks.append(callback)

    def _notify(self, old_state: str, new_state: str, info: dict):
        self.state = new_state
        for cb in self._callbacks:
            try:
                cb(old_state, new_state, info)
            except Exception as e:
                print(f"[sniffer] 回调异常: {e}")

    def start(self):
        """启动嗅探线程"""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()
        print(f"[sniffer] 嗅探已启动 (门禁={self.door_ip}, 室内机={self.indoor_ip})")

    def stop(self):
        """停止嗅探"""
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=2)

    def _create_socket(self) -> socket.socket:
        """
        创建嗅探套接字。

        Mac (BPF): 用 UDP 套接字绑定端口 7800。
        注意: 这会捕获发往本机的包, 但不会捕获其他设备之间的流量。
        在透明网桥模式下 (OpenWRT), 需要用 AF_PACKET。
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind(('0.0.0.0', SIGNAL_PORT))
        sock.settimeout(1.0)
        return sock

    def _sniff_loop(self):
        """嗅探主循环"""
        try:
            self._sock = self._create_socket()
        except OSError as e:
            print(f"[sniffer] 创建套接字失败: {e}")
            print("[sniffer] 提示: 端口 7800 可能被占用, 或需要 sudo 权限")
            self._running = False
            return

        while self._running:
            try:
                data, addr = self._sock.recvfrom(4096)
                src_ip = addr[0]
                self._process_packet(data, src_ip)
            except socket.timeout:
                continue
            except OSError:
                if self._running:
                    time.sleep(0.1)
                continue

    def _process_packet(self, data: bytes, src_ip: str):
        """处理单个数据包"""
        pkt_type = classify_packet(data, src_ip, '')

        if pkt_type == 'ack':
            seq = parse_ack(data)
            if seq:
                self._last_seq = seq
            return

        if pkt_type == 'signal':
            pkt = parse_signal_packet(data)
            if not pkt:
                return
            cmd = pkt['cmd']
            self._handle_signal(cmd, src_ip, pkt)
            return

        if pkt_type == 'door_open':
            self._handle_door_open(data, src_ip)
            return

    def _handle_signal(self, cmd: int, src_ip: str, pkt: dict):
        """处理信令命令包"""
        old_state = self.state
        info = {'cmd': cmd, 'src_ip': src_ip, 'seq': pkt['seq']}

        if cmd == Cmd.CALL:
            if src_ip == self.indoor_ip:
                # 室内机呼叫门禁
                self._notify(old_state, IntercomState.CALLING, info)
            else:
                # 门禁呼叫室内机 (来电)
                self._notify(old_state, IntercomState.RINGING, info)

        elif cmd == Cmd.RING:
            # 门禁响铃 (响应呼叫)
            if old_state == IntercomState.CALLING:
                pass  # 保持 CALLING 状态, 等待后续
            else:
                self._notify(old_state, IntercomState.RINGING, info)

        elif cmd == Cmd.ANSWER:
            self._notify(old_state, IntercomState.ANSWERED, info)

        elif cmd == Cmd.READY:
            self._notify(old_state, IntercomState.TALKING, info)

        elif cmd == Cmd.OPEN:
            info['action'] = 'open'
            # 不改变状态, 等待开门确认广播

        elif cmd == Cmd.HANGUP:
            self._notify(old_state, IntercomState.HUNG_UP, info)
            # 延迟重置为 IDLE
            threading.Timer(1.0, lambda: self._reset_to_idle()).start()

    def _handle_door_open(self, data: bytes, src_ip: str):
        """处理 23 字节开门确认广播"""
        old_state = self.state
        info = {'action': 'door_confirmed_open', 'src_ip': src_ip}
        self._notify(old_state, IntercomState.DOOR_OPEN, info)

    def _reset_to_idle(self):
        """重置状态为 IDLE"""
        if self.state != IntercomState.IDLE:
            old = self.state
            self.state = IntercomState.IDLE
            self._notify(old, IntercomState.IDLE, {})


class BpfSniffer(Sniffer):
    """
    BPF 原始套接字嗅探器 (Mac/Linux 透明网桥模式)

    使用 AF_PACKET + BPF 过滤, 可以嗅探网桥上所有流量,
    不仅仅是发往本机的包。
    """

    def _create_socket(self) -> socket.socket:
        try:
            # Linux: AF_PACKET
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            sock.settimeout(1.0)
            if self.interface:
                sock.bind((self.interface, 0))
            return sock
        except (AttributeError, OSError):
            pass

        try:
            # Mac: 使用 BPF (需要安装 py-bpf 或 scapy)
            # 回退到普通 UDP 套接字
            print("[sniffer] AF_PACKET 不可用, 回退到 UDP 嗅探 (仅捕获发往本机的包)")
            return super()._create_socket()
        except OSError as e:
            raise RuntimeError(f"无法创建嗅探套接字: {e}")
