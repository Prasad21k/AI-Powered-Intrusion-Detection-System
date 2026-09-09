from scapy.all import sniff

# Function to process packets
def process_packet(packet):

    print("\n===== PACKET DETECTED =====")

    print(packet.summary())

# Start sniffing
print("Starting Packet Sniffer...")

sniff(
    prn=process_packet,
    store=False
)

print("\nSniffing Finished.")