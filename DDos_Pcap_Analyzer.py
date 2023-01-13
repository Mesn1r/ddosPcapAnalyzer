from scapy.utils import rdpcap
import subprocess

# Open the PCAP file
packets = rdpcap("example.pcap")

# Initialize variables to store extracted information
src_ips = []
packet_sizes = []

# Iterate through each packet and extract information
for packet in packets:
    src_ips.append(packet.src)
    packet_sizes.append(packet.len)

# Prepare the command to extract packet count and packet size of each IP
ips = " or ".join("ip.src==" + ip for ip in src_ips)
command = f'tshark -r example.pcap -Y "({ips})" -T fields -e ip.src -e frame.len -c | sort | uniq -c'
output = subprocess.check_output(command, shell=True)

# Split the output into a list of lines
lines = output.decode().strip().split("\n")

# Initialize variables
threshold = 1000  # Set threshold for number of packets
total_packets = 0

# Iterate through the list of lines
for line in lines:
    # Split the line into columns
    columns = line.strip().split(" ")
    # Extract the source IP, packet count, and packet size
    src_ip = columns[1]
    count = int(columns[0])
    packet_size = int(columns[2])
    total_packets += count
    # Check if the packet count is above the threshold
    if count > threshold:
        print(f'IP: {src_ip}  Packet Count: {count}  Packet Size: {packet_size}')

#Calculate the percentage of packets above threshold
perc_above_threshold = (count / total_packets)*100

if perc_above_threshold > 50:
  print("\n WARNING: The traffic shows a potential DDoS attack")
