from scapy.all import *


class Packet_Capture:
    def __init__(self, interface, pcap_file):
        self.interface = interface
        self.pcap_file = pcap_file

    def capturePackets(self, count=0):
        try:
            packets = sniff(iface=self.interface, count=count)
            wrpcap(self.pcap_file, packets)
            print("Packets captured successfully")
        except Exception as e:
            print("Error:", e)