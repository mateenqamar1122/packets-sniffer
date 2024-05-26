from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR
from datetime import datetime
from prettytable import PrettyTable
import argparse

# Define a function to parse and display packet details
def process_packet(packet):
    # Get the timestamp
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Create a table for displaying packet information
    table = PrettyTable()
    table.field_names = ["Field", "Value"]

    # Extract the IP layer
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        table.add_row(["Timestamp", timestamp])
        table.add_row(["Source IP", src_ip])
        table.add_row(["Destination IP", dst_ip])

        # Determine the protocol and get relevant data
        protocol = ip_layer.proto
        if protocol == 6:  # TCP
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            payload = packet[TCP].payload.load.decode(errors='replace') if packet[TCP].payload else ""
            table.add_row(["Protocol", proto])
            table.add_row(["Source Port", sport])
            table.add_row(["Destination Port", dport])
            if payload:
                table.add_row(["Payload", payload])

        elif protocol == 17:  # UDP
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            payload = packet[UDP].payload.load.decode(errors='replace') if packet[UDP].payload else ""
            table.add_row(["Protocol", proto])
            table.add_row(["Source Port", sport])
            table.add_row(["Destination Port", dport])
            if payload:
                table.add_row(["Payload", payload])

            # Check for DNS packets
            if DNS in packet and packet[DNS].opcode == 0 and packet[DNS].ancount == 0:  # DNS query
                dns_query = packet[DNSQR].qname.decode()
                table.add_row(["DNS Query", dns_query])

        elif protocol == 1:  # ICMP
            proto = "ICMP"
            table.add_row(["Protocol", proto])
            payload = packet[ICMP].payload.load.decode(errors='replace') if packet[ICMP].payload else ""
            if payload:
                table.add_row(["Payload", payload])

        else:
            proto = "Other"
            table.add_row(["Protocol", proto])

        # Print the table
        print(table)

def main():
    # Argument parser for user inputs
    parser = argparse.ArgumentParser(description="Advanced Packet Sniffer")
    parser.add_argument("-i", "--interface", type=str, default=None, help="Network interface to sniff on")
    parser.add_argument("-p", "--protocol", type=str, choices=["tcp", "udp", "icmp", "all"], default="all", help="Protocol to filter by")
    parser.add_argument("-l", "--logfile", type=str, help="Log file to save captured packets")
    args = parser.parse_args()

    # Set the filter based on user input
    if args.protocol == "tcp":
        protocol_filter = "tcp"
    elif args.protocol == "udp":
        protocol_filter = "udp"
    elif args.protocol == "icmp":
        protocol_filter = "icmp"
    else:
        protocol_filter = None

    # Print start message
    print("Starting packet sniffer... Press Ctrl+C to stop.")

    # Sniff packets and process them
    sniff(iface=args.interface, filter=protocol_filter, prn=process_packet, store=0)

if __name__ == "__main__":
    main()

