# 流量捕获模块

---

## 文件说明

1. `output`：用于存放捕获的流量包文件；
2. `flow_collector.py`：主程序；
3. `flow.py`：定义Flow流对象类，维护其状态和特征统计；
4. `utils.py`：定义辅助函数，从Scapy报文中提取关键特征。
   
---

## 使用说明

执行`python flow_collector.py`,将在终端处输出可用的网卡列表，输入需要监听的网卡编号，程序对相应的接口进行60秒抓包，将流量导入至`output/flows_xxxxxxxxxx.json`文件中。

导出流格式：
```
{
    "flow_key": [
      "10.180.108.23",
      "183.240.211.68",
      8667,
      1812,
      "TCP"
    ],
    "duration": 49.099,
    "packet_count": 11,
    "byte_count": 833,
    "avg_packet_size": 75.73,
    "avg_inter_arrival": 4.91,
    "flags": {
      "SYN": 0,
      "ACK": 11,
      "FIN": 7
    }
}
