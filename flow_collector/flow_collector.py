import subprocess
from scapy.all import sniff
from flow import Flow
from utils import get_ip_and_ports, get_tcp_flags
import json
import os
import time

flows = {}

def list_interfaces_windows():
    # 调用 powershell 命令列出网卡名称和描述
    result = subprocess.run(
        ['powershell', '-Command',
         "Get-NetAdapter | Select-Object -Property ifIndex,Name,InterfaceDescription | ConvertTo-Json"],
        capture_output=True, text=True)
    adapters = result.stdout
    import json
    adapters = json.loads(adapters)
    # 处理单个或多个接口情况
    if isinstance(adapters, dict):
        adapters = [adapters]
    print(" 可用网卡列表：")
    for i, adapter in enumerate(adapters):
        print(f"{i}: {adapter['Name']} - {adapter['InterfaceDescription']}")
    return adapters

def choose_interface(adapters):
    while True:
        try:
            idx = int(input("请输入要监听的网卡编号："))
            if 0 <= idx < len(adapters):
                return adapters[idx]['Name']
            else:
                print("编号超出范围")
        except ValueError:
            print("无效输入，请输入数字编号")

def packet_handler(pkt):
    info = get_ip_and_ports(pkt)
    if info is None:
        return
    src_ip, dst_ip, src_port, dst_port, protocol = info
    key = (src_ip, dst_ip, src_port, dst_port, protocol)
    if key not in flows:
        flows[key] = Flow(*key)
    pkt_len = len(pkt)
    flags = get_tcp_flags(pkt)
    flows[key].update(pkt_len, flags)

def export_flows():
    os.makedirs("flow_collector/output", exist_ok=True)
    filename = f"flow_collector/output/flows_{int(time.time())}.json"
    with open(filename, "w") as f:
        result = [flow.get_features() for flow in flows.values()]
        json.dump(result, f, indent=2)
    print(f"\n导出 {len(result)} 个流到 {filename}")

if __name__ == "__main__":
    adapters = list_interfaces_windows()
    iface_name = choose_interface(adapters)
    print(f"使用接口: {iface_name}\n开始抓包 60 秒...")

    try:
        sniff(iface=iface_name, prn=packet_handler, store=0, filter="ip", timeout=60)
    except PermissionError:
        print("请以管理员权限运行本程序")
    except Exception as e:
        print(f"抓包失败: {e}")

    export_flows()
