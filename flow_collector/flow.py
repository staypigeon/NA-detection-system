# flow.py

import time

class Flow:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.key = (src_ip, dst_ip, src_port, dst_port, protocol)
        self.start_time = time.time()
        self.last_time = self.start_time
        self.packet_count = 0
        self.byte_count = 0
        self.packet_sizes = []
        self.timestamps = []
        self.flags = {"SYN": 0, "ACK": 0, "FIN": 0}

    def update(self, pkt_len, flags):
        now = time.time()
        self.last_time = now
        self.packet_count += 1
        self.byte_count += pkt_len
        self.packet_sizes.append(pkt_len)
        self.timestamps.append(now)

        # 统计 TCP flags
        for flag in self.flags:
            if flag in flags:
                self.flags[flag] += 1

    def get_features(self):
        duration = self.last_time - self.start_time
        avg_pkt_size = sum(self.packet_sizes) / len(self.packet_sizes) if self.packet_sizes else 0
        inter_arrival = [
            t2 - t1 for t1, t2 in zip(self.timestamps[:-1], self.timestamps[1:])
        ]
        avg_interval = sum(inter_arrival) / len(inter_arrival) if inter_arrival else 0

        return {
            "flow_key": self.key,
            "duration": round(duration, 3),
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "avg_packet_size": round(avg_pkt_size, 2),
            "avg_inter_arrival": round(avg_interval, 3),
            "flags": self.flags,
        }
