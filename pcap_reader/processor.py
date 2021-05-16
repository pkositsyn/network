from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.inet import TCP
from scapy.layers.ppp import PPP

from connection import ConnectionProcessor
import plot_builder


class Processor:
    def __init__(self, bandwidth):
        self.bandwidth = bandwidth
        self.connections = {}

    def process(self, file):
        sniff(offline=file, prn=self.process_packet, store=0)
        self.save_files()

    def process_packet(self, pack: PPP):
        if not pack.haslayer(TCP):
            return
        four_tuple = (pack[IP].src, str(pack[TCP].sport), pack[IP].dst, str(pack[TCP].dport))
        if four_tuple in self.connections:
            connection = self.connections[four_tuple]
        else:
            if not pack[TCP].flags.S:
                return
            connection = self.connections[four_tuple] = ConnectionProcessor(pack, self.bandwidth)
        connection.process(pack)

    def save_files(self):
        for four_tuple, connection in self.connections.items():
            # do last gather
            connection.gather_last_second_stats()
            file_suffix = "_".join(four_tuple)
            from_addr = f"{four_tuple[0]}:{four_tuple[1]}"
            to_addr = f"{four_tuple[2]}:{four_tuple[3]}"
            with open(f"retransmits_{file_suffix}.txt", "w") as out:
                out.write(",".join(connection.retransmits_ids))
            plot_builder.build_and_save_plot(f"retransmits_{file_suffix}.png", connection.retransmits_ratio,
                                             "Retransmits ratio", from_addr, to_addr)
            plot_builder.build_and_save_plot(f"utilization_{file_suffix}.png", connection.utilization,
                                             "Utilization", from_addr, to_addr)
