"""
命令注入器 - 向门禁机发送信令命令

基于真实抓包简化: 直接 OPEN → ACK → HANGUP, 无需完整握手。
"""

from __future__ import annotations
import socket
import struct
import time

from .protocol import (
    SIGNAL_PORT, Cmd,
    build_signal_packet, build_ack,
)


class Injector:
    """
    信令命令注入器

    向门禁机发送 UDP 信令包, 实现开门、接听、挂断等操作。
    """

    def __init__(self, door_ip: str = '192.168.120.96',
                 door_port: int = SIGNAL_PORT,
                 timeout: float = 5.0):
        self.door_ip = door_ip
        self.door_port = door_port
        self.timeout = timeout
        self.seq = 0
        self._sock = None

    def _ensure_socket(self):
        if self._sock is None:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.settimeout(self.timeout)
            self._sock.bind(('0.0.0.0', 0))

    def _next_seq(self) -> int:
        s = self.seq
        self.seq += 1
        return s

    def _send_signal(self, cmd: int) -> int:
        self._ensure_socket()
        seq = self._next_seq()
        pkt = build_signal_packet(seq, cmd)
        self._sock.sendto(pkt, (self.door_ip, self.door_port))
        return seq

    def _send_ack(self, seq_bytes: bytes):
        self._ensure_socket()
        ack = build_ack(seq_bytes)
        self._sock.sendto(ack, (self.door_ip, self.door_port))

    def _recv(self, expected_len: int = None) -> tuple:
        deadline = time.time() + self.timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise TimeoutError("接收超时")
            self._sock.settimeout(remaining)
            try:
                data, addr = self._sock.recvfrom(4096)
                if expected_len is None or len(data) == expected_len:
                    return data, addr
            except socket.timeout:
                raise TimeoutError("接收超时")

    def _wait_ack(self, expected_seq: int):
        data, _ = self._recv(expected_len=4)
        recv_seq = struct.unpack('<I', data)[0]
        if recv_seq != expected_seq:
            print(f"  [警告] ACK 序列号不匹配: 期望 0x{expected_seq:08x}, 收到 0x{recv_seq:08x}")

    def open_door(self) -> bool:
        """
        开门。

        基于真实抓包: 直接发送 OPEN → 收 ACK → 发 HANGUP。
        无需 CALL/RING/ANSWER/READY 握手, 无需音频保活。
        """
        try:
            self._ensure_socket()
            print("[injector] 开门...")

            # 发送 OPEN
            seq = self._send_signal(Cmd.OPEN)
            self._wait_ack(seq)
            print("[injector] OPEN 已确认")

            # 处理门禁返回的 23 字节确认包
            try:
                self._sock.settimeout(2.0)
                data, _ = self._sock.recvfrom(4096)
                if len(data) == 23:
                    print("[injector] 收到开门确认包")
                    self._send_ack(data[:4])
            except socket.timeout:
                pass

            # 发送 HANGUP
            seq = self._send_signal(Cmd.HANGUP)
            try:
                self._wait_ack(seq)
            except TimeoutError:
                pass
            print("[injector] 开门完成")
            return True
        except TimeoutError as e:
            print(f"[injector] 开门失败: {e}")
            return False
        except Exception as e:
            print(f"[injector] 开门异常: {e}")
            return False
        finally:
            self.close()

    def answer(self) -> bool:
        """接听来电"""
        try:
            self._ensure_socket()
            print("[injector] 发送接听...")
            seq = self._send_signal(Cmd.ANSWER)
            self._wait_ack(seq)
            print("[injector] 接听成功")
            return True
        except TimeoutError:
            print("[injector] 接听超时")
            return False
        except Exception as e:
            print(f"[injector] 接听异常: {e}")
            return False
        finally:
            self.close()

    def hangup(self) -> bool:
        """挂断"""
        try:
            self._ensure_socket()
            print("[injector] 发送挂断...")
            seq = self._send_signal(Cmd.HANGUP)
            try:
                self._wait_ack(seq)
            except TimeoutError:
                pass  # 挂断不需要确认
            print("[injector] 已挂断")
            return True
        except Exception as e:
            print(f"[injector] 挂断异常: {e}")
            return False
        finally:
            self.close()

    def close(self):
        """释放资源"""
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
