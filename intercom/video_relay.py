"""
视频转发器 - 将门禁视频流转发到 Home Assistant

视频格式: 44字节私有header + 原始H.264 Annex B流
每帧 1444 字节: header(44) + payload(1400)

转发方式:
  1. named_pipe: 写入命名管道, 配合 ffmpeg 转发到 go2rtc (推荐)
  2. udp: 直接通过 UDP 转发原始 H.264 数据
  3. file: 写入文件 (调试用)
"""

import os
import socket
import struct
import threading
import time

from .protocol import AUDIO_PORT

VIDEO_HEADER_LEN = 44
VIDEO_FRAME_LEN = 1444
VIDEO_PAYLOAD_LEN = VIDEO_FRAME_LEN - VIDEO_HEADER_LEN  # 1400


class VideoRelay:
    """
    视频转发器

    检测到通话开始时, 开始捕获 port 8800 的视频帧,
    去除 44 字节私有 header, 提取 H.264 流并转发。
    """

    def __init__(self, door_ip: str = '192.168.120.96',
                 relay_host: str = '127.0.0.1',
                 relay_port: int = 8554,
                 mode: str = 'named_pipe',
                 pipe_path: str = '/tmp/intercom_video.h264'):
        """
        Args:
            door_ip: 门禁机 IP
            relay_host: UDP 转发目标地址
            relay_port: UDP 转发目标端口
            mode: 'named_pipe' | 'udp' | 'file'
            pipe_path: named_pipe 模式的管道路径
        """
        self.door_ip = door_ip
        self.relay_host = relay_host
        self.relay_port = relay_port
        self.mode = mode
        self.pipe_path = pipe_path
        self._running = False
        self._thread = None
        self._sock = None
        self._relay_sock = None
        self._pipe_fd = None
        self._frame_count = 0
        self._h264_bytes = 0
        self._active = False

    def start(self):
        """启动视频嗅探 (不转发, 等待 activate)"""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()
        print(f"[video] 视频嗅探已启动 (mode={self.mode})")

    def stop(self):
        """停止"""
        self._running = False
        self._active = False
        self._close_outputs()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=2)

    def activate(self):
        """通话开始, 开始转发视频"""
        self._active = True
        self._frame_count = 0
        self._h264_bytes = 0
        self._open_outputs()
        print("[video] 视频转发已激活")

    def deactivate(self):
        """通话结束, 停止转发"""
        self._active = False
        self._close_outputs()
        print(f"[video] 视频转发已停止 (共 {self._frame_count} 帧, {self._h264_bytes} bytes H.264)")

    def _open_outputs(self):
        """打开输出目标"""
        if self.mode == 'named_pipe':
            self._open_pipe()
        elif self.mode == 'udp':
            self._relay_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        elif self.mode == 'file':
            self._pipe_fd = open(self.pipe_path, 'wb')

    def _close_outputs(self):
        """关闭输出目标"""
        if self._pipe_fd:
            try:
                self._pipe_fd.close()
            except OSError:
                pass
            self._pipe_fd = None
        if self._relay_sock:
            try:
                self._relay_sock.close()
            except OSError:
                pass
            self._relay_sock = None

    def _open_pipe(self):
        """创建命名管道 (如果不存在)"""
        if os.path.exists(self.pipe_path):
            if not os.path.exists(self.pipe_path) or not os.stat(self.pipe_path).st_mode & 0o010000:
                os.unlink(self.pipe_path)
                os.mkfifo(self.pipe_path)
        else:
            os.mkfifo(self.pipe_path)
        print(f"[video] 命名管道已创建: {self.pipe_path}")
        print(f"[video] 请运行 ffmpeg 读取管道:")
        print(f"  ffmpeg -f h264 -i {self.pipe_path} -c copy -f rtp rtp://{self.relay_host}:{self.relay_port}")

    def _sniff_loop(self):
        """嗅探 port 8800 的视频帧"""
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError):
                pass
            self._sock.bind(('0.0.0.0', AUDIO_PORT))
            self._sock.settimeout(1.0)
        except OSError as e:
            print(f"[video] 创建套接字失败: {e}")
            self._running = False
            return

        while self._running:
            try:
                data, addr = self._sock.recvfrom(4096)
                if addr[0] == self.door_ip and len(data) >= VIDEO_FRAME_LEN:
                    self._handle_video_frame(data)
            except socket.timeout:
                continue
            except OSError:
                if self._running:
                    time.sleep(0.1)
                continue

    def _handle_video_frame(self, data: bytes):
        """处理视频帧: 去除 44 字节 header, 提取 H.264 payload"""
        # 验证 header: 首字节应为 0x0e (视频标记)
        if data[0] != 0x0e:
            return

        self._frame_count += 1
        h264_payload = data[VIDEO_HEADER_LEN:]
        self._h264_bytes += len(h264_payload)

        if not self._active:
            return

        if self.mode == 'named_pipe' and self._pipe_fd:
            try:
                self._pipe_fd.write(h264_payload)
                self._pipe_fd.flush()
            except (BrokenPipeError, OSError):
                # ffmpeg 未连接管道, 忽略
                pass
        elif self.mode == 'udp' and self._relay_sock:
            try:
                self._relay_sock.sendto(h264_payload, (self.relay_host, self.relay_port))
            except OSError:
                pass
        elif self.mode == 'file' and self._pipe_fd:
            try:
                self._pipe_fd.write(h264_payload)
            except OSError:
                pass
