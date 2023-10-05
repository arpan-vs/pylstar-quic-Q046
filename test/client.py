from scapy.all import *

# Define the target IP address and port
target_ip = "127.0.0.1"  # Replace with the IP address of your target
target_port = 4433     # Replace with the port number of your target
source_port = 50000

# Define your message
message = "Hello, this is a UDP message!"

# Create a TCP packet with your message as the payload
tcp_packet = IP(dst=target_ip) / UDP(dport=target_port,sport=source_port) / message

# Send the packet
send(tcp_packet)