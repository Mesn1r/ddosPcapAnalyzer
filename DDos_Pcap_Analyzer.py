from scapy.utils import rdpcap
import subprocess

# Open the PCAP file
packets = rdpcap("example.pcap")

src_ips = []
packet_sizes = []

for packet in packets:  # Iterate through each packet and extract information
    src_ips.append(packet.src)
    packet_sizes.append(packet.len)


    ips = " or ".join("ip.src==" + ip for ip in src_ips)
command = f'tshark -r example.pcap -Y "({ips})" -T fields -e ip.src -e frame.len -c | sort | uniq -c'
output = subprocess.check_output(command, shell=True)

lines = output.decode().strip().split("\n") # split the output into a list 

threshold = 1000  # Set threshold for number of packets
total_packets = 0

for line in lines:
    columns = line.strip().split(" ")
    src_ip = columns[1]
    count = int(columns[0])
    packet_size = int(columns[2])
    total_packets += count
    if count > threshold:
        print(f'IP: {src_ip}  Packet Count: {count}  Packet Size: {packet_size}')

perc_above_threshold = (count / total_packets)*100

if perc_above_threshold > 50:
  print("\n WARNING: The traffic indicate a potential DDoS attack")
