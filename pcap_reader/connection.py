class ConnectionProcessor:
    def __init__(self, ts, bandwidth):
        self.retransmits_ratio = [0.0]
        self.retransmits_ids = []
        self.utilization = [0.0]

        self.bandwidth = bandwidth

        self.last_ts = ts
        self.last_sent_bytes = 0
        self.last_retransmits = 0
        self.last_transmits = 0

    def process(self, packet_id, packet, ts):
        while ts >= self.last_ts + 1:
            self.last_ts += 1
            self.gather_last_second_stats()

        if self.is_retransmit(packet):
            self.retransmits_ids.append(packet_id)
            self.last_retransmits += 1
        else:
            self.last_sent_bytes += len(packet.data)
            self.last_transmits += 1


    def gather_last_second_stats(self):
        if (all_packets := self.last_retransmits + self.last_transmits):
            self.retransmits_ratio.append(self.last_retransmits / all_packets)
        else:
            self.retransmits_ratio.append(0.0)

        self.utilization = self.last_sent_bytes / (self.bandwidth * 2 ** 20)

        self.last_retransmits = 0
        self.last_transmits = 0
        self.last_sent_bytes = 0


    def is_retransmit(self, packet):
        print(packet)
        return False
