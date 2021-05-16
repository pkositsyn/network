from scapy.layers.inet import IP, TCP
from scapy.layers.ppp import PPP


class SequenceNumber:
    modulo = 2 ** 32

    def __init__(self, num: int):
        self.num = num % self.modulo

    def __add__(self, other: int):
        return (self.num + other) % self.modulo

    def __sub__(self, other: int):
        return (self.num - other) % self.modulo

    def __int__(self) -> int:
        return self.num


class ConnectionProcessor:
    def __init__(self, syn_packet: PPP, bandwidth):
        self.retransmits_ratio = [0.0]
        self.retransmits_ids = []
        self.utilization = [0.0]

        self.bandwidth = bandwidth

        self.last_ts = syn_packet.time
        self.last_sent_bytes = 0
        self.last_retransmits = 0
        self.last_transmits = 0

        self.next_seq = SequenceNumber(syn_packet[TCP].seq)

    def process(self, packet: PPP):
        while packet.time >= self.last_ts + 1:
            self.last_ts += 1
            self.gather_last_second_stats()

        if self.is_retransmit(packet):
            self.retransmits_ids.append(str(packet[IP].id))
            self.last_retransmits += 1
        else:
            self.last_sent_bytes += len(packet.payload)
            self.last_transmits += 1
            self.next_seq = SequenceNumber(packet[TCP].seq + len(packet[TCP].payload))
            if packet[TCP].flags.S:
                self.next_seq += 1

    def gather_last_second_stats(self):
        if all_packets := self.last_retransmits + self.last_transmits:
            self.retransmits_ratio.append(self.last_retransmits / all_packets)
        else:
            self.retransmits_ratio.append(0.0)

        self.utilization.append(self.last_sent_bytes / (self.bandwidth * 2 ** 17))

        self.last_retransmits = 0
        self.last_transmits = 0
        self.last_sent_bytes = 0

    def is_retransmit(self, packet_tcp_layer: TCP):
        return int(self.next_seq) != packet_tcp_layer.seq

