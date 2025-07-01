# utils.py

def get_ip_and_ports(pkt):
    try:
        ip_layer = pkt['IP']
        proto = pkt.proto
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # TCP or UDP
        if proto == 6 and pkt.haslayer('TCP'):
            src_port = pkt['TCP'].sport
            dst_port = pkt['TCP'].dport
            protocol = 'TCP'
        elif proto == 17 and pkt.haslayer('UDP'):
            src_port = pkt['UDP'].sport
            dst_port = pkt['UDP'].dport
            protocol = 'UDP'
        else:
            return None
        return src_ip, dst_ip, src_port, dst_port, protocol
    except:
        return None

def get_tcp_flags(pkt):
    flags = []
    if pkt.haslayer('TCP'):
        tcp_flags = pkt['TCP'].flags
        if tcp_flags & 0x02: flags.append('SYN')
        if tcp_flags & 0x10: flags.append('ACK')
        if tcp_flags & 0x01: flags.append('FIN')
    return flags
