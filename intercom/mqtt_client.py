"""
MQTT 客户端 - 连接 Home Assistant

负责:
- 发布门禁状态事件 (来电、开门、挂断等)
- 订阅 HA 命令 (开门、接听、挂断、呼叫电梯)
- LWT (Last Will and Testament) 在线状态
- HA MQTT 自动发现 (Auto Discovery)
"""

from __future__ import annotations
import json
import threading
import time

try:
    import paho.mqtt.client as mqtt
except ImportError:
    mqtt = None

from .sniffer import IntercomState


# MQTT Topic 定义
TOPIC_STATE = 'intercom/state'
TOPIC_DOOR_STATE = 'intercom/door/state'
TOPIC_DOOR_CMD = 'intercom/door/command'
TOPIC_CALL_CMD = 'intercom/call/command'
TOPIC_ELEVATOR_CMD = 'intercom/elevator/cmd'
TOPIC_VIDEO_URL = 'intercom/video/url'
TOPIC_ONLINE = 'intercom/online'

# HA 自动发现
DISCOVERY_PREFIX = 'homeassistant'
DEVICE_ID = 'intercom_bridge'
DEVICE_NAME = '门禁桥接器'

DEVICE_INFO = {
    'identifiers': [DEVICE_ID],
    'name': DEVICE_NAME,
    'manufacturer': '太川',
    'model': 'TC-3000MH-X1',
}


class MqttClient:
    """
    MQTT 客户端

    连接 MQTT broker, 发布门禁事件, 订阅 HA 命令,
    支持 HA MQTT 自动发现。
    """

    def __init__(self, broker: str = 'localhost', port: int = 1883,
                 username: str = None, password: str = None,
                 client_id: str = 'intercom-bridge',
                 topic_prefix: str = 'intercom',
                 discovery: bool = True):
        if mqtt is None:
            raise ImportError("paho-mqtt 未安装, 请运行: pip install paho-mqtt")

        self.broker = broker
        self.port = port
        self.client_id = client_id
        self.topic_prefix = topic_prefix
        self.discovery = discovery

        self._client = mqtt.Client(client_id=client_id, protocol=mqtt.MQTTv311)
        if username:
            self._client.username_pw_set(username, password)

        # LWT: 离线时自动发布 "offline"
        self._client.will_set(TOPIC_ONLINE, 'offline', qos=1, retain=True)

        # 回调
        self._client.on_connect = self._on_connect
        self._client.on_disconnect = self._on_disconnect
        self._client.on_message = self._on_message

        # 命令回调
        self._command_callbacks: dict[str, list] = {
            'open': [],
            'answer': [],
            'hangup': [],
            'call_elevator': [],
        }

        self._connected = False
        self._thread = None

    def on_command(self, command: str, callback):
        """注册命令回调: 'open' | 'answer' | 'hangup' | 'call_elevator'"""
        if command in self._command_callbacks:
            self._command_callbacks[command].append(callback)

    def start(self):
        """连接 broker 并启动后台线程"""
        if self._thread:
            return
        self._thread = threading.Thread(target=self._connect_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """断开连接"""
        self._client.publish(TOPIC_ONLINE, 'offline', qos=1, retain=True)
        self._client.disconnect()
        self._connected = False

    @property
    def connected(self) -> bool:
        return self._connected

    # --- 发布方法 ---

    def publish_state(self, state: str, extra: dict = None):
        """发布门禁状态"""
        payload = {'state': state}
        if extra:
            payload.update(extra)
        self._publish(TOPIC_STATE, json.dumps(payload))

    def publish_door_state(self, locked: bool):
        """发布门锁状态"""
        self._publish(TOPIC_DOOR_STATE, 'locked' if locked else 'unlocked')

    def publish_video_url(self, url: str):
        """发布视频流 URL"""
        self._publish(TOPIC_VIDEO_URL, url)

    # --- 内部方法 ---

    def _publish(self, topic: str, payload: str, qos: int = 1, retain: bool = False):
        if self._connected:
            self._client.publish(topic, payload, qos=qos, retain=retain)

    def _connect_loop(self):
        """连接循环 (断线自动重连)"""
        while True:
            try:
                self._client.connect(self.broker, self.port, keepalive=60)
                self._client.loop_forever()
            except Exception as e:
                print(f"[mqtt] 连接失败: {e}, 5 秒后重试...")
                time.sleep(5)

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            print(f"[mqtt] 已连接 {self.broker}:{self.port}")
            self._connected = True
            # 发布上线状态
            self._publish(TOPIC_ONLINE, 'online', retain=True)
            # 订阅命令 topic
            client.subscribe(TOPIC_DOOR_CMD, qos=1)
            client.subscribe(TOPIC_CALL_CMD, qos=1)
            client.subscribe(TOPIC_ELEVATOR_CMD, qos=1)
            # 发送 HA 自动发现
            if self.discovery:
                self._publish_discovery()
        else:
            print(f"[mqtt] 连接失败, rc={rc}")

    def _on_disconnect(self, client, userdata, rc):
        self._connected = False
        if rc != 0:
            print(f"[mqtt] 意外断开 (rc={rc}), 将自动重连...")

    def _on_message(self, client, userdata, msg):
        """处理收到的 MQTT 消息"""
        topic = msg.topic
        payload = msg.payload.decode('utf-8').strip()

        if topic == TOPIC_DOOR_CMD and payload == 'open':
            self._fire_command('open')
        elif topic == TOPIC_CALL_CMD:
            if payload == 'answer':
                self._fire_command('answer')
            elif payload == 'hangup':
                self._fire_command('hangup')
        elif topic == TOPIC_ELEVATOR_CMD and payload == 'call':
            self._fire_command('call_elevator')

    def _fire_command(self, command: str):
        """触发命令回调 (在新线程中执行)"""
        for cb in self._command_callbacks.get(command, []):
            threading.Thread(target=cb, daemon=True).start()

    # --- HA 自动发现 ---

    def _publish_discovery(self):
        """发布 HA MQTT 自动发现配置"""
        print("[mqtt] 发送 HA 自动发现配置...")

        # 1. 门禁呼叫 (binary_sensor)
        self._discovery('binary_sensor', 'ring', {
            'name': '门禁呼叫',
            'state_topic': TOPIC_STATE,
            'value_template': "{{ 'ON' if value_json.state == 'ringing' else 'OFF' }}",
            'device_class': 'occupancy',
            'unique_id': f'{DEVICE_ID}_ring',
            'device': DEVICE_INFO,
        })

        # 2. 门禁状态 (sensor)
        self._discovery('sensor', 'state', {
            'name': '门禁状态',
            'state_topic': TOPIC_STATE,
            'value_template': '{{ value_json.state }}',
            'unique_id': f'{DEVICE_ID}_state',
            'device': DEVICE_INFO,
        })

        # 3. 门锁状态 (binary_sensor)
        self._discovery('binary_sensor', 'door', {
            'name': '门锁状态',
            'state_topic': TOPIC_DOOR_STATE,
            'payload_on': 'unlocked',
            'payload_off': 'locked',
            'device_class': 'lock',
            'unique_id': f'{DEVICE_ID}_door',
            'device': DEVICE_INFO,
        })

        # 4. 远程开门 (button)
        self._discovery('button', 'open_door', {
            'name': '远程开门',
            'command_topic': TOPIC_DOOR_CMD,
            'payload_press': 'open',
            'unique_id': f'{DEVICE_ID}_open_door',
            'device': DEVICE_INFO,
        })

        # 5. 接听 (button)
        self._discovery('button', 'answer', {
            'name': '接听门禁',
            'command_topic': TOPIC_CALL_CMD,
            'payload_press': 'answer',
            'unique_id': f'{DEVICE_ID}_answer',
            'device': DEVICE_INFO,
        })

        # 6. 挂断 (button)
        self._discovery('button', 'hangup', {
            'name': '挂断门禁',
            'command_topic': TOPIC_CALL_CMD,
            'payload_press': 'hangup',
            'unique_id': f'{DEVICE_ID}_hangup',
            'device': DEVICE_INFO,
        })

        # 7. 呼叫电梯 (button)
        self._discovery('button', 'elevator', {
            'name': '呼叫电梯',
            'command_topic': TOPIC_ELEVATOR_CMD,
            'payload_press': 'call',
            'unique_id': f'{DEVICE_ID}_elevator',
            'device': DEVICE_INFO,
        })

        # 8. 设备在线状态 (binary_sensor)
        self._discovery('binary_sensor', 'online', {
            'name': '桥接在线',
            'state_topic': TOPIC_ONLINE,
            'payload_on': 'online',
            'payload_off': 'offline',
            'device_class': 'connectivity',
            'unique_id': f'{DEVICE_ID}_online',
            'device': DEVICE_INFO,
        })

        print(f"[mqtt] 已注册 8 个实体到 HA, 设备名: {DEVICE_NAME}")

    def _discovery(self, component: str, object_id: str, config: dict):
        """发布单个发现配置"""
        topic = f'{DISCOVERY_PREFIX}/{component}/{DEVICE_ID}/{object_id}/config'
        self._publish(topic, json.dumps(config), retain=True)


def state_to_mqtt(state: str) -> str:
    """将 IntercomState 映射到 MQTT 状态字符串"""
    mapping = {
        IntercomState.IDLE: 'idle',
        IntercomState.CALLING: 'calling',
        IntercomState.RINGING: 'ringing',
        IntercomState.ANSWERED: 'answered',
        IntercomState.TALKING: 'talking',
        IntercomState.DOOR_OPEN: 'door_open',
        IntercomState.HUNG_UP: 'hung_up',
    }
    return mapping.get(state, 'unknown')
