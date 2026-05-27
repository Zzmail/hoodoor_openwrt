"""
主守护进程 - 整合所有模块

功能:
1. 嗅探信令 (port 7800), 检测来电/开门/挂断等事件
2. 通过 MQTT 发布事件到 Home Assistant
3. 接收 HA 命令, 注入信令实现远程开门/接听/挂断
4. 转发视频流 (port 8800) 到 HA/go2rtc
"""

from __future__ import annotations
import os
import signal
import sys
import time
import argparse
import threading

# 支持直接运行 daemon.py (python3 intercom/daemon.py)
if __name__ == '__main__' and __package__ is None:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from .sniffer import Sniffer, IntercomState
    from .injector import Injector
    from .mqtt_client import MqttClient, state_to_mqtt
    from .video_relay import VideoRelay
except ImportError:
    from intercom.sniffer import Sniffer, IntercomState
    from intercom.injector import Injector
    from intercom.mqtt_client import MqttClient, state_to_mqtt
    from intercom.video_relay import VideoRelay


class IntercomDaemon:
    """门禁桥接守护进程"""

    def __init__(self, config: dict):
        self.config = config
        self._sniffer = None
        self._injector = None
        self._mqtt = None
        self._video = None
        self._running = False

    def start(self):
        """启动守护进程"""
        print("=" * 50)
        print("太川 TC-3000MH-X1 门禁桥接守护进程")
        print("=" * 50)
        print(f"门禁机: {self.config['door_ip']}")
        print(f"室内机: {self.config['indoor_ip']}")
        print(f"MQTT:   {self.config['mqtt_broker']}:{self.config['mqtt_port']}")
        if self.config.get('mqtt_username'):
            print(f"MQTT用户: {self.config['mqtt_username']}")
        print(f"视频转发: {self.config.get('video_mode', 'udp')} → {self.config['relay_host']}:{self.config['relay_port']}")
        print("=" * 50)

        self._running = True

        # 初始化模块
        self._init_sniffer()
        self._init_mqtt()
        self._init_video()
        self._injector = Injector(
            door_ip=self.config['door_ip'],
            timeout=self.config.get('timeout', 5.0),
        )

        # 注册信号处理
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        # 启动模块
        self._sniffer.start()
        self._mqtt.start()
        self._video.start()

        print("\n[daemon] 守护进程已启动, 按 Ctrl+C 停止\n")

        # 主循环
        try:
            while self._running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self):
        """停止守护进程"""
        print("\n[daemon] 正在停止...")
        self._running = False
        if self._sniffer:
            self._sniffer.stop()
        if self._video:
            self._video.stop()
        if self._mqtt:
            self._mqtt.stop()
        if self._injector:
            self._injector.close()
        print("[daemon] 已停止")

    def _signal_handler(self, signum, frame):
        self._running = False

    # --- 初始化模块 ---

    def _init_sniffer(self):
        self._sniffer = Sniffer(
            door_ip=self.config['door_ip'],
            indoor_ip=self.config['indoor_ip'],
        )
        self._sniffer.on_state_change(self._on_state_change)

    def _init_mqtt(self):
        try:
            self._mqtt = MqttClient(
                broker=self.config['mqtt_broker'],
                port=self.config['mqtt_port'],
                username=self.config.get('mqtt_username'),
                password=self.config.get('mqtt_password'),
                client_id=self.config.get('mqtt_client_id', 'intercom-bridge'),
            )
            # 注册 HA 命令回调
            self._mqtt.on_command('open', self._cmd_open_door)
            self._mqtt.on_command('answer', self._cmd_answer)
            self._mqtt.on_command('hangup', self._cmd_hangup)
            self._mqtt.on_command('call_elevator', self._cmd_call_elevator)
        except ImportError as e:
            print(f"[daemon] MQTT 不可用: {e}")
            self._mqtt = _DummyMqtt()

    def _init_video(self):
        self._video = VideoRelay(
            door_ip=self.config['door_ip'],
            relay_host=self.config['relay_host'],
            relay_port=self.config['relay_port'],
            mode=self.config.get('video_mode', 'named_pipe'),
            pipe_path=self.config.get('video_pipe', '/tmp/intercom_video.h264'),
        )

    # --- 状态变化处理 ---

    def _on_state_change(self, old_state: str, new_state: str, info: dict):
        """嗅探器状态变化回调"""
        print(f"[state] {old_state} → {new_state} (cmd=0x{info.get('cmd', 0):08x}, src={info.get('src_ip', '?')})")

        # 发布到 MQTT
        mqtt_state = state_to_mqtt(new_state)
        self._mqtt.publish_state(mqtt_state, {
            'old_state': old_state,
            'cmd': f"0x{info.get('cmd', 0):08x}",
            'src_ip': info.get('src_ip', ''),
        })

        # 视频转发控制
        if new_state == IntercomState.TALKING:
            self._video.activate()
        elif new_state in (IntercomState.HUNG_UP, IntercomState.IDLE, IntercomState.DOOR_OPEN):
            self._video.deactivate()

        # 门锁状态
        if new_state == IntercomState.DOOR_OPEN:
            self._mqtt.publish_door_state(False)  # unlocked

    # --- HA 命令处理 ---

    def _cmd_open_door(self):
        """HA 命令: 开门"""
        print("[cmd] 收到 HA 开门命令")
        injector = Injector(
            door_ip=self.config['door_ip'],
            timeout=self.config.get('timeout', 5.0),
        )
        success = injector.open_door()
        if success:
            self._mqtt.publish_state('door_open', {'source': 'ha'})
            self._mqtt.publish_door_state(False)

    def _cmd_answer(self):
        """HA 命令: 接听"""
        print("[cmd] 收到 HA 接听命令")
        injector = Injector(door_ip=self.config['door_ip'])
        injector.answer()

    def _cmd_hangup(self):
        """HA 命令: 挂断"""
        print("[cmd] 收到 HA 挂断命令")
        injector = Injector(door_ip=self.config['door_ip'])
        injector.hangup()
        self._video.deactivate()

    def _cmd_call_elevator(self):
        """HA 命令: 呼叫电梯 (待实现)"""
        print("[cmd] 收到 HA 呼叫电梯命令 (功能待实现, 需抓包确认协议)")


class _DummyMqtt:
    """MQTT 不可用时的空实现"""
    def start(self): pass
    def stop(self): pass
    def publish_state(self, *a, **kw): pass
    def publish_door_state(self, *a, **kw): pass
    def publish_video_url(self, *a, **kw): pass
    def on_command(self, *a, **kw): pass


def main():
    """CLI 入口"""
    parser = argparse.ArgumentParser(
        description='太川 TC-3000MH-X1 门禁桥接守护进程',
    )
    parser.add_argument('--door-ip', default='192.168.120.96',
                        help='门禁机 IP (默认: 192.168.120.96)')
    parser.add_argument('--indoor-ip', default='192.168.122.102',
                        help='室内机 IP (默认: 192.168.122.102)')
    parser.add_argument('--mqtt-broker', default='192.168.1.24',
                        help='MQTT broker 地址 (默认: 192.168.1.24)')
    parser.add_argument('--mqtt-port', type=int, default=1883,
                        help='MQTT broker 端口 (默认: 1883)')
    parser.add_argument('--mqtt-username', default='mq',
                        help='MQTT 用户名')
    parser.add_argument('--mqtt-password', default='mq123',
                        help='MQTT 密码')
    parser.add_argument('--relay-host', default='192.168.1.12',
                        help='视频转发目标地址 (默认: 192.168.1.12, go2rtc地址)')
    parser.add_argument('--relay-port', type=int, default=8554,
                        help='视频转发目标端口 (默认: 8554)')
    parser.add_argument('--video-mode', default='udp',
                        choices=['named_pipe', 'udp', 'file'],
                        help='视频转发模式 (默认: udp)')
    parser.add_argument('--video-pipe', default='/tmp/intercom_video.h264',
                        help='H.264 命名管道路径 (默认: /tmp/intercom_video.h264)')
    parser.add_argument('--timeout', type=float, default=5.0,
                        help='命令超时时间 (默认: 5.0s)')

    args = parser.parse_args()

    config = {
        'door_ip': args.door_ip,
        'indoor_ip': args.indoor_ip,
        'mqtt_broker': args.mqtt_broker,
        'mqtt_port': args.mqtt_port,
        'mqtt_username': args.mqtt_username,
        'mqtt_password': args.mqtt_password,
        'relay_host': args.relay_host,
        'relay_port': args.relay_port,
        'video_mode': args.video_mode,
        'video_pipe': args.video_pipe,
        'timeout': args.timeout,
    }

    daemon = IntercomDaemon(config)
    daemon.start()


if __name__ == '__main__':
    main()
