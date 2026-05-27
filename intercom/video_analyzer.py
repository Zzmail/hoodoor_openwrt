"""
视频格式分析工具

嗅探 port 8800 的视频帧, 分析封装格式, 帮助确定如何对接 go2rtc。

用法:
  python3 -m intercom.video_analyzer [--pcap good_open_door.pcapng]
  python3 -m intercom.video_analyzer --live  # 实时嗅探
"""

from __future__ import annotations
import argparse
import struct
import sys


def analyze_pcap(pcap_path: str):
    """从 pcap 文件中提取 port 8800 视频帧并分析格式"""
    try:
        import dpkt
    except ImportError:
        print("需要安装 dpkt: pip install dpkt")
        print("或用 tshark 命令行分析:")
        print(f'  tshark -r {pcap_path} -Y "udp.port==8800 && data.len>=1000" -T fields -e data.data | head -10')
        return

    with open(pcap_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)

        video_frames = []
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                if not isinstance(ip.data, dpkt.udp.UDP):
                    continue
                udp = ip.data
                if udp.dport != 8800 and udp.sport != 8800:
                    continue
                payload = udp.data
                if len(payload) >= 1000:
                    video_frames.append({
                        'ts': ts,
                        'src': f"{ip.src[0]}.{ip.src[1]}.{ip.src[2]}.{ip.src[3]}",
                        'dst': f"{ip.dst[0]}.{ip.dst[1]}.{ip.dst[2]}.{ip.dst[3]}",
                        'len': len(payload),
                        'data': payload,
                    })
            except Exception:
                continue

    if not video_frames:
        print("未找到视频帧 (>= 1000 bytes on port 8800)")
        return

    print(f"找到 {len(video_frames)} 个视频帧")
    print(f"帧大小: {video_frames[0]['len']} bytes")
    print()

    # 分析前几个帧的 header
    for i, frame in enumerate(video_frames[:5]):
        data = frame['data']
        print(f"--- 帧 #{i+1} (来自 {frame['src']}, {frame['len']} bytes) ---")
        print(f"  前 32 字节 hex: {data[:32].hex()}")
        print(f"  前 32 字节 raw: {data[:32]}")

        # 检查是否是标准 RTP
        if len(data) >= 12:
            version = (data[0] >> 6) & 0x03
            padding = (data[0] >> 5) & 0x01
            extension = (data[0] >> 4) & 0x01
            cc = data[0] & 0x0F
            marker = (data[1] >> 7) & 0x01
            pt = data[1] & 0x7F
            seq = struct.unpack('!H', data[2:4])[0]
            timestamp = struct.unpack('!I', data[4:8])[0]
            ssrc = struct.unpack('!I', data[8:12])[0]

            if version == 2:
                print(f"  [RTP] version={version}, pt={pt}, seq={seq}, ts={timestamp}, ssrc=0x{ssrc:08x}")
                print(f"  [RTP] marker={marker}, padding={padding}, ext={extension}, cc={cc}")
                if pt == 96:
                    print(f"  [RTP] 动态 payload type 96, 可能是 H.264")
                elif pt == 34:
                    print(f"  [RTP] payload type 34 = H.263")
            else:
                print(f"  [非RTP] version={version}, 不是标准 RTP 封装")

        # 检查 H.264 NAL 单元标记
        h264_found = False
        for offset in range(min(32, len(data) - 4)):
            # H.264 NAL start code: 00 00 00 01 或 00 00 01
            if data[offset:offset+4] == b'\x00\x00\x00\x01':
                nal_type = data[offset+4] & 0x1F
                nal_names = {
                    1: 'P-frame', 5: 'IDR (keyframe)', 6: 'SEI',
                    7: 'SPS', 8: 'PPS', 9: 'AUD'
                }
                name = nal_names.get(nal_type, f'type={nal_type}')
                print(f"  [H.264] NAL start code @ offset {offset}, {name}")
                h264_found = True
                break
            elif data[offset:offset+3] == b'\x00\x00\x01':
                nal_type = data[offset+3] & 0x1F
                print(f"  [H.264] 3-byte NAL start code @ offset {offset}, type={nal_type}")
                h264_found = True
                break

        if not h264_found:
            # 检查是否有常见视频 marker
            print(f"  未检测到 H.264 NAL start code")

        print()

    # 总结
    print("=" * 50)
    print("分析总结:")
    print(f"  视频帧数: {len(video_frames)}")
    print(f"  帧大小: {video_frames[0]['len']} bytes (固定)")

    # 检查第一字节是否有规律
    first_bytes = [f['data'][0] for f in video_frames[:20]]
    unique_first = set(first_bytes)
    print(f"  首字节分布: { {hex(b): first_bytes.count(b) for b in unique_first} }")

    # 检查是否有 RTP header
    sample = video_frames[0]['data']
    if len(sample) >= 12 and (sample[0] >> 6) == 2:
        print("  格式判断: 可能是 RTP 封装, go2rtc 可能直接支持")
        print("  go2rtc 配置示例:")
        print("    streams:")
        print("      intercom: rtp://0.0.0.0:8801")
    else:
        print("  格式判断: 非标准 RTP, 需要自定义解封装")
        print("  方案: daemon 提取 payload 后转发, 或写 go2rtc 插件")


def analyze_live(interface: str = None, duration: int = 10):
    """实时嗅探 port 8800 视频帧"""
    import socket
    import time

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except (AttributeError, OSError):
        pass
    sock.bind(('0.0.0.0', 8800))
    sock.settimeout(1.0)

    print(f"实时嗅探 port 8800, 持续 {duration} 秒...")
    print("请触发门禁通话 (呼叫或来电) 以产生视频流\n")

    start = time.time()
    frames = []

    while time.time() - start < duration:
        try:
            data, addr = sock.recvfrom(4096)
            if len(data) >= 1000:
                frames.append({'data': data, 'src': addr[0], 'len': len(data)})
                if len(frames) <= 5:
                    print(f"  收到 {len(data)} 字节 from {addr[0]} | 前16字节: {data[:16].hex()}")
        except socket.timeout:
            continue

    sock.close()

    if frames:
        print(f"\n共收到 {len(frames)} 个视频帧")
        # 复用 pcap 分析逻辑
        analyze_frames_data(frames)
    else:
        print("\n未收到视频帧, 请确保门禁通话正在进行中")


def analyze_frames_data(frames: list):
    """分析帧数据"""
    sample = frames[0]['data']
    print(f"\n帧大小: {len(sample)} bytes")

    # 私有 header 检测: 首字节 0x0e = 视频, 0x01 = 音频保活
    if sample[0] == 0x0e and len(sample) >= 44:
        header = sample[:44]
        payload_len_le = struct.unpack('<I', header[4:8])[0]
        seq = struct.unpack('<I', header[8:12])[0]
        print(f"[私有 header] 首字节=0x{sample[0]:02x} (视频)")
        print(f"  payload_len field = 0x{payload_len_le:08x} ({payload_len_le})")
        print(f"  序列号 = {seq}")
        print(f"  header 44字节: {header.hex()}")

        # 检查 payload 中的 H.264
        payload = sample[44:]
        h264_check = check_h264(payload)
        if h264_check:
            print(f"  [H.264] payload 中检测到: {h264_check}")
            print(f"\n结论: 44字节私有header + 原始H.264 Annex B流")
            print(f"提取方法: 跳过前44字节, 剩余即为H.264数据")
            print(f"\ngo2rtc 配置方案:")
            print(f"  1. daemon 提取H.264 → 写入 named pipe → ffmpeg → RTP → go2rtc")
            print(f"  2. 或 daemon 直接通过RTP转发H.264到go2rtc")
        else:
            print(f"  payload 前32字节: {payload[:32].hex()}")
        return

    # RTP 检测
    if len(sample) >= 12:
        version = (sample[0] >> 6) & 0x03
        if version == 2:
            pt = sample[1] & 0x7F
            seq = struct.unpack('!H', sample[2:4])[0]
            print(f"[RTP] 检测到标准 RTP 封装, pt={pt}, seq={seq}")
            print("go2rtc 配置: rtp://0.0.0.0:<port>")
            return

    # 直接 H.264 检测
    h264_check = check_h264(sample)
    if h264_check:
        print(f"[H.264] {h264_check}")
        return

    print("[未知格式] 前 32 字节:", sample[:32].hex())
    print("需要进一步逆向分析")


def check_h264(data: bytes) -> str:
    """检查数据中是否包含 H.264 NAL start code, 返回描述或 None"""
    for offset in range(min(64, len(data) - 4)):
        if data[offset:offset+4] == b'\x00\x00\x00\x01':
            nal_type = data[offset+4] & 0x1F
            nal_names = {
                1: 'P-frame', 5: 'IDR (keyframe)', 6: 'SEI',
                7: 'SPS', 8: 'PPS', 9: 'AUD'
            }
            name = nal_names.get(nal_type, f'type={nal_type}')
            return f"NAL start code @ offset {offset}, {name}"
    return None


def main():
    parser = argparse.ArgumentParser(description='门禁视频格式分析工具')
    parser.add_argument('--pcap', help='pcap 文件路径')
    parser.add_argument('--live', action='store_true', help='实时嗅探')
    parser.add_argument('--duration', type=int, default=10, help='实时嗅探时长 (秒)')
    args = parser.parse_args()

    if args.pcap:
        analyze_pcap(args.pcap)
    elif args.live:
        analyze_live(duration=args.duration)
    else:
        print("请指定 --pcap <文件> 或 --live")
        print("示例:")
        print("  python3 -m intercom.video_analyzer --pcap good_open_door.pcapng")
        print("  python3 -m intercom.video_analyzer --live --duration 30")


if __name__ == '__main__':
    main()
