from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    # Initialize variables for packet details
    src_ip = dst_ip = proto = payload = None

    # Extracting IP layer information
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        # Extracting transport layer information
        if packet.haslayer(TCP):
            proto_name = "TCP"
            payload = bytes(packet[TCP].payload)
        elif packet.haslayer(UDP):
            proto_name = "UDP"
            payload = bytes(packet[UDP].payload)
        elif packet.haslayer(ICMP):
            proto_name = "ICMP"
            payload = bytes(packet[ICMP].payload)
        else:
            proto_name = "Other"
            payload = bytes(packet[IP].payload)
        
        # Print packet details
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {proto_name} ({proto})")
        if payload:
            print(f"Payload: {payload[:50]}...")  # Limit payload display for readability
        print("\n")

    else:
        print("Non-IP Packet\n")

# Start sniffing
print("Starting packet sniffer...")
sniff(prn=packet_callback, count=10)  # Modify 'count' to capture more packets

