import cmd
from Packet_Capture import Packet_Capture
from Packet_Analyze import Packet_Analyze
from cmd import Cmd
import cryptography


class Cli(cmd.Cmd):
    intro = "Welcome to my Network Analyzer. Type help or ? to list commands.\n"
    prompt = "NetworkSniffer> "

    def __init__(self):
        super().__init__()
        self.packet_capture = None
        self.packet_analyzer = None

    def do_capture(self, line):
        """
        Capture packets from the network.

        Usage: capture <interface> <pcap_file> <count> 
        Example: capture eth0 capture.pcap 100
        """
        try:
            interface, pcap_file, count = line.split()
            count = int(count)
            self.packet_capture = Packet_Capture(interface, pcap_file)
            self.packet_capture.capturePackets(count)  # Capture packets using capturePackets method
        except Exception as e:
            print("Error: ", e)
            print("Usage: capture <interface> <pcap_file> <count>")


    def do_load(self, line):
        """
        Load packets from a pcap file.

        Usage: load <pcap_file>
        Example: load capture.pcap
        """
        try:
            pcap_file = line
            self.packet_analyzer = Packet_Analyze(pcap_file)
            self.packet_analyzer.load_packets(pcap_file)  # Load packets using load_packets method
            print("Packets loaded successfully")
        except Exception as e:
            print("Error: ", e)
            print("Usage: load <pcap_file>")


    def do_packet_count(self, line):
        """
                Get the number of packets in the pcap file.

                Usage: packet_count
                """
        try:
            print(self.packet_analyzer.get_packet_count())
        except Exception as e:
            print("Error: ", e)

    def do_packet_summary(self, line):
        """
                Get the summary of the packets in the pcap file.

                Usage: packet_summary
                """
        try:
            print(self.packet_analyzer.get_packet_summary())
        except Exception as e:
            print("Error: ", e)

    def do_protocol_distribution(self, line):
        """
                Get the distribution of protocols in the pcap file.

                Usage: protocol_distribution
                """
        try:
            print(self.packet_analyzer.protocol_distribution())
        except Exception as e:
            print("Error: ", e)

    def do_packet_sizes(self, line):
        """
                Get the sizes of packets in the pcap file.

                Usage: packet_sizes
                """
        try:
            print(self.packet_analyzer.packet_sizes())
        except Exception as e:
            print("Error: ", e)

    def do_top_talkers(self, line):
        """
                Get the top talkers in the pcap file.

                Usage: top_talkers
                """
        try:
            print(self.packet_analyzer.topTalkers())
        except Exception as e:
            print("Error: ", e)

    def do_traffic_patterns(self, line):
        """
                Get the traffic patterns in the pcap file.

                Usage: traffic_patterns
                """
        try:
            print(self.packet_analyzer.traffic_patterns())
        except Exception as e:
            print("Error: ", e)

    def do_dns_requests(self, line):
        """
                Get the DNS requests in the pcap file.

                Usage: dns_requests
                """
        try:
            print(self.packet_analyzer.dns_requests())
        except Exception as e:
            print("Error: ", e)

    def do_http_requests(self, line):
        """
                Get the HTTP requests in the pcap file.

                Usage: http_requests
                """
        try:
            print(self.packet_analyzer.http_requests())
        except Exception as e:
            print("Error: ", e)

    def do_generate_report(self, line):
        """
                Generate a report of the pcap file.

                Usage: generate_report <report_file>
                Example: generate_report report.txt
                """
        try:
            report_file = line
            self.packet_analyzer.generate_report(report_file)
        except Exception as e:
            print("Error: ", e)
            print("Usage: generate_report <report_file>")

    def do_help(self, line):
        print("capture <interface> <pcap_file> <count>")
        print("load <pcap_file>")
        print("packet_count")
        print("packet_summary")
        print("protocol_distribution")
        print("packet_sizes")
        print("top_talkers")
        print("traffic_patterns")
        print("dns_requests")
        print("http_requests")
        print("generate_report <report_file>")
        print("exit")

    def do_exit(self, line):
        return True


if __name__ == "__main__":
    Cli().cmdloop()