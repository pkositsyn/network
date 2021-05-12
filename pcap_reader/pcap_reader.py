import argparse

import dpkt

from processor import Processor


def main():
    parser = argparse.ArgumentParser(description="Reads .pcap files and produces utilization, "
                                                 "retransmits percentage pictures and retransmits packet ids")
    parser.add_argument("-f", type=str, required=True, help="pcap file to read")
    parser.add_argument("-b", type=int, required=True, help="bandwidth in Mb")

    args = parser.parse_args()

    process_packets(args.f, args.b)


def process_packets(file, bandwidth):
    processor = Processor(bandwidth)
    processor.process(file)


if __name__ == "__main__":
    main()
