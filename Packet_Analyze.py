from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.dns import DNSQR
from scapy.layers.tls.all import TLS
from scapy.layers.http import HTTP, Raw
from scapy.layers.l2 import Ether
from collections import Counter
from scapy.layers.inet import TCP
from scapy.layers.inet import UDP
from scapy.layers.inet import ICMP
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNSRR
from scapy.layers.dns import DNS
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
import cryptography


class Packet_Analyze:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = rdpcap(pcap_file)

    def load_packets(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = rdpcap(pcap_file)

    def get_packet_count(self):
        return len(self.packets)

    def get_packet_summary(self):
        summary = self.packets.summary()
        human_readable_summary = "\n".join([f"Packet {i+1}: {packet}" for i, packet in enumerate(summary.split("\n"))])
        return human_readable_summary

    def protocol_distribution(self):
        protocols = []
        for packet in self.packets:
            if packet.haslayer(IP):
                protocol_num = packet[IP].proto
                protocol_name = self.get_protocol_name(protocol_num)
                protocols.append(protocol_name)
        counter = Counter(protocols)
        return counter

    def get_protocol_name(self, protocol_num):
        protocols = {1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP' , 89: 'OSPF', 132: 'SCTP', 50: 'ESP', 51: 'AH', 58: 'ICMPv6', 115: 'L2TP', 136: 'UDPLite', 137: 'MPLS-in-IP', 138: 'manet', 139: 'HIP', 140: 'Shim6', 141: 'WESP', 142: 'ROHC', 255: 'Reserved'}
        return protocols.get(protocol_num, 'OTHER')

    def packet_sizes(self):
        sizes = []
        for packet in self.packets:
            sizes.append(len(packet))
        return sizes

    def topTalkers(self):
        talkers = []
        for packet in self.packets:
            if packet.haslayer(IP):
                talkers.append(f"Source: {packet[IP].src}")
                talkers.append(f"Destination: {packet[IP].dst}")
        counter = Counter(talkers)
        top_talkers = counter.most_common(10)
        human_readable_top_talkers = "\n".join([f"{talker[0]} - Count: {talker[1]}" for talker in top_talkers])
        return human_readable_top_talkers

    def traffic_patterns(self):
        patterns = []
        for packet in self.packets:
            if packet.haslayer(IP):
                patterns.append(f"Source: {packet[IP].src}, Destination: {packet[IP].dst}")
        counter = Counter(patterns)
        top_patterns = counter.most_common(10)
        human_readable_patterns = "\n".join([f"Traffic Pattern: {pattern[0]} - Count: {pattern[1]}" for pattern in top_patterns])
        return human_readable_patterns

    def dns_requests(self):
        dns = []
        for packet in self.packets:
            if packet.haslayer(DNSQR):
                dns.append(packet[DNSQR].qname.decode('utf-8'))
        human_readable_dns = "\n".join([f"DNS Request: {request}" for request in dns])
        return human_readable_dns

    def http_requests(self):
        http = []
        for packet in self.packets:
            if packet.haslayer(Raw):
                load = packet[Raw].load
                if "GET" in str(load):
                    http.append(load.decode('utf-8'))
        human_readable_http_requests = "\n".join([f"HTTP Request: {request}" for request in http])
        return human_readable_http_requests

    def http_responses(self):
        http = []
        for packet in self.packets:
            if packet.haslayer(Raw):
                load = packet[Raw].load
                if "HTTP" in str(load):
                    http.append(load.decode('utf-8'))
        human_readable_http_responses = "\n".join([f"HTTP Response: {response}" for response in http])
        return human_readable_http_responses

    def ssl_handshakes(self):
        handshakes = []
        for packet in self.packets:
            if packet.haslayer(TLS):
                handshakes.append(packet[TLS].msg)
        human_readable_handshakes = "\n".join([f"SSL Handshake: {handshake}" for handshake in handshakes])
        return human_readable_handshakes

    def payload(self, protocol):
        payloads = []
        for packet in self.packets:
            if protocol in packet and hasattr(packet[protocol], 'load'):
                payloads.append(packet[protocol].load)
        return payloads

    def traffic_volume_analysis(self, interval):
        traffic = []
        for packet in self.packets:
            traffic.append((packet.time, len(packet)))
        human_readable_traffic = "\n".join([f"Time: {data[0]}, Packet Length: {data[1]}" for data in traffic])
        return human_readable_traffic

    def tcp_connection_analysis(self):
        connections = []
        for packet in self.packets:
            if packet.haslayer(TCP):
                connections.append((packet[TCP].sport, packet[TCP].dport))
        counter = Counter(connections)
        top_connections = counter.most_common(10)
        human_readable_connections = "\n".join([f"Source Port: {connection[0][0]}, Destination Port: {connection[0][1]} - Count: {connection[1]}" for connection in top_connections])
        return human_readable_connections

    def generate_report(self,output_file):
    # Open the output file in write mode
        with open(output_file, 'w') as f:
            f.write("Packet Analysis Report\n")
            f.write("=====================================\n")
            f.write(f"Packet count: {self.get_packet_count()}\n")
            f.write("=====================================\n")
            f.write(f"Protocol distribution: {self.protocol_distribution()}\n")
            f.write("=====================================\n")
            f.write(f"Packet sizes: {self.packet_sizes()}\n")
            f.write("=====================================\n")
            f.write(f"Top talkers: {self.topTalkers()}\n")
            f.write("=====================================\n")
            f.write(f"Traffic patterns: {self.traffic_patterns()}\n")
            f.write("=====================================\n")
            f.write(f"DNS requests: {self.dns_requests()}\n")
            f.write("=====================================\n")
            f.write(f"HTTP requests: {self.http_requests()}\n")
            f.write("=====================================\n")
            f.write(f"HTTP responses: {self.http_responses()}\n")
            f.write("=====================================\n")
            f.write(f"SSL handshakes: {self.ssl_handshakes()}\n")
            f.write("=====================================\n")
            f.write(f"TCP connections: {self.tcp_connection_analysis()}\n")
            f.write("=====================================\n")
            f.write(f"Traffic volume analysis: {self.traffic_volume_analysis(60)}\n")
            f.write("=====================================\n")
            f.write(f"Payload: {self.payload(Raw)}\n")
            f.write("=====================================\n")
            f.write(f"Payload: {self.payload(TCP)}\n")
            f.write("=====================================\n")
            f.write(f"Payload: {self.payload(UDP)}\n")
            f.write("=====================================\n")
            f.write(f"Payload: {self.payload(ICMP)}\n")
            f.write("=====================================\n")
            f.write(f"Payload: {self.payload(ARP)}\n")
            f.write("=====================================\n")
            f.write(f"Payload: {self.payload(DNS)}\n")
            f.write("=====================================\n")
            f.write(f"Payload: {self.payload(TLS)}\n")
            f.write("=====================================\n")
            f.write(f"Payload: {self.payload(HTTP)}\n")
            f.write("=====================================\n")
            f.write(f"Payload: {self.payload(Ether)}\n")
            f.write("=====================================\n")
            f.write(f"Payload: {self.payload(IP)}\n")
            f.write("=====================================\n")
            f.write(f"Payload: {self.payload(DNSQR)}\n")
            f.write("=====================================\n")
            f.write(f"Payload: {self.payload(DNSRR)}\n")
            f.write("=====================================\n")
            
        print(f"Report generated successfully: {output_file}")