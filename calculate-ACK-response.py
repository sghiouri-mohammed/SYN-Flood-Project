from scapy.all import *

packets = rdpcap("p1p-1-1.pcap")

# Here I define the frames
start_frame = 0
end_frame = 100


def detect_3_way_handshake_in_pcap_file(packets, start_frame, end_frame):
    # Initialize counters
    successive_syn_synack = 0
    successive_syn_synack_ack = 0
    successive_SYN_only = 0

    # Loop through the specified range of packets
    for i in range(start_frame, min(end_frame, len(packets)) - 2):
        syn_pkt = packets[i]
        syn_ack_pkt = packets[i + 1]
        ack_pkt = packets[i + 2]

        # Check if packets are TCP and have the SYN flag
        if syn_pkt.haslayer(TCP) and syn_pkt[TCP].flags == "S":
            syn_pkt_src_ip, syn_pkt_dst_ip = syn_pkt[IP].src, syn_pkt[IP].dst
            syn_pkt_src_port, syn_pkt_dst_port = syn_pkt[TCP].sport, syn_pkt[TCP].dport

            if syn_ack_pkt.haslayer(TCP) and syn_ack_pkt[TCP].flags == "SA":
                syn_ack_pkt_src_ip, syn_ack_pkt_dst_ip = syn_ack_pkt[IP].src, syn_ack_pkt[IP].dst
                syn_ack_pkt_src_port, syn_ack_pkt_dst_port = syn_ack_pkt[TCP].sport, syn_ack_pkt[TCP].dport

                if (syn_ack_pkt_src_port == syn_pkt_dst_port and
                        syn_ack_pkt_dst_port == syn_pkt_src_port and
                        syn_ack_pkt_src_ip == syn_pkt_dst_ip and
                        syn_ack_pkt_dst_ip == syn_pkt_src_ip):

                    if ack_pkt.haslayer(TCP) and ack_pkt[TCP].flags == "A":
                        if syn_ack_pkt.time - ack_pkt.time < 3:
                            ack_pkt_src_ip, ack_pkt_dst_ip = ack_pkt[IP].src, ack_pkt[IP].dst
                            ack_pkt_src_port, ack_pkt_dst_port = ack_pkt[TCP].sport, ack_pkt[TCP].dport
                            if (ack_pkt_src_ip == syn_ack_pkt_dst_ip and
                                    ack_pkt_dst_ip == syn_ack_pkt_src_ip and
                                    syn_ack_pkt[TCP].ack == ack_pkt[TCP].seq):
                                successive_syn_synack_ack += 1
                    else:
                        successive_syn_synack += 1
            else:
                successive_SYN_only += 1

    print("============================")
    print("Successive SYN and SYN-ACK without ACK within frames", start_frame, "to", end_frame, ":",
          successive_syn_synack)
    print("============================")
    print("Three-way handshake TCP protocol", start_frame, "to", end_frame, ":", successive_syn_synack_ack)
    print("============================")
    print("Successive SYN only ", start_frame, "to", end_frame, ":", successive_SYN_only)
    print("============================")





def calculate_SYN_ACK_without_just_next_ACK(packets, start, end):

    synack_synack_without_Ack = 0

    for i in range(start_frame, end_frame):
        packet_1 = packets[i]
        time1 = packet_1.time
        if packet_1.haslayer(TCP) and packet_1[TCP].flags == "SA":

            packet_1_src_ip = packet_1[IP].src
            packet_1_ack_num = packet_1[TCP].ack

            next_packet = packets[i+1]
            time2 = next_packet.time

            next_packet_src_ip = next_packet[IP].src
            next_packet_dst_ip = next_packet[IP].dst
            next_packet_seq_num = next_packet[TCP].seq

            if next_packet.haslayer(TCP) and next_packet[TCP].flags == "SA":
                #print("Im here")
                #print(packet_1_src_ip,next_packet_src_ip)
                synack_synack_without_Ack +=1

            if next_packet.haslayer(TCP) and next_packet[TCP].flags == "S":
                synack_synack_without_Ack += 1

            if next_packet.haslayer(TCP) and next_packet[TCP].flags == "A":
                if packet_1_ack_num != next_packet_seq_num and packet_1_src_ip != next_packet_dst_ip or time2 - time1 > 3:
                    synack_synack_without_Ack +=1


    print("============================")
    print(f"Number of SYN-ACK without ACK between {start} and {end} = {synack_synack_without_Ack}" )
    print("============================")


calculate_SYN_ACK_without_just_next_ACK(packets, 0, 100)
detect_3_way_handshake_in_pcap_file(packets, 0,100)






# print(packet_1_src_ip,packet_1_dst_ip,packet_1_src_port,packet_1_dst_port,packet_1_seq_num, packet_1_ack_num)
