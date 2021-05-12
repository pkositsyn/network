import dpkt

from connection import ConnectionProcessor


class Processor:
    def __init__(self, bandwidth):
        self.bandwidth = bandwidth
        self.connections = {}

    def process(self, file):
        with open(file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            for packet_id, data in enumerate(pcap):
                ts, buf = data
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                if not isinstance(ip, dpkt.ip.IP):
                    continue
                self.process_packet(packet_id, ip, ts)

        self.save_files()

    def process_packet(self, packet_id, ip, ts):
        tcp = ip.data
        if not isinstance(tcp, dpkt.tcp.TCP):
            return
        print(tcp)
        four_tuple = (ip.src, tcp.sport, ip.dst, tcp.dport)
        if four_tuple in self.connections:
            connection = self.connections[four_tuple]
        else:
            # TODO: check SYN
            connection = self.connections[four_tuple] = ConnectionProcessor(ts, self.bandwidth)
        connection.process(packet_id, tcp, ts)

    def save_files(self):
        for four_tuple, connection in self.connections.items():
            # TODO: save png
            pass
