from scapy.all import *

packets = rdpcap("test.pcapng")


def calculate_SYN_ACK_without_ACK(packets, start, end):
    end = min(len(packets), end)
    three_way = 0
    nb_synack_with_noack = 0
    syn_synack_ack = 0

    for i in range(start, end):
        first_packet = packets[i]
        time1 = first_packet.time

        if first_packet.haslayer(TCP) and first_packet[TCP].flags == "S":
            syn_pkt_src_ip, syn_pkt_dst_ip = first_packet[IP].src, first_packet[IP].dst
            syn_pkt_src_port, syn_pkt_dst_port = first_packet[TCP].sport, first_packet[TCP].dport

            for j in range(i+1, end):
                next_packet = packets[j]
                time2 = next_packet.time

                if next_packet.haslayer(TCP) and next_packet[TCP].flags == "SA":
                    syn_ack_pkt_src_ip, syn_ack_pkt_dst_ip = next_packet[IP].src, next_packet[IP].dst
                    syn_ack_pkt_src_port, syn_ack_pkt_dst_port = next_packet[TCP].sport, next_packet[TCP].dport
                    syn_ack_ack_seq = next_packet[TCP].ack

                    if syn_ack_pkt_src_ip == syn_pkt_dst_ip and syn_pkt_dst_ip == syn_ack_pkt_src_ip and syn_ack_pkt_dst_port == syn_pkt_src_port:

                        for k in range(j+1, end):
                            next_next_packet = packets[k]
                            time3 = next_next_packet.time

                            if next_next_packet.haslayer(TCP) and next_next_packet[TCP].flags == "A" :
                                ack_pkt_src_ip, ack_pkt_dst_ip = next_next_packet[IP].src, next_next_packet[IP].dst
                                ack_pkt_src_port, ack_pkt_dst_port = next_next_packet[TCP].sport, next_next_packet[TCP].dport
                                ack_pkt_seq = next_next_packet[TCP].seq

                                if syn_ack_ack_seq == ack_pkt_seq and ack_pkt_src_ip == syn_ack_pkt_dst_ip and ack_pkt_dst_ip == syn_ack_pkt_src_ip and ack_pkt_src_port == syn_ack_pkt_dst_port and ack_pkt_dst_port == syn_ack_pkt_src_port and time3-time2 < 3 :
                                    syn_synack_ack += 1

                                elif syn_ack_ack_seq == ack_pkt_seq and ack_pkt_src_ip == syn_ack_pkt_dst_ip and ack_pkt_dst_ip == syn_ack_pkt_src_ip and ack_pkt_src_port == syn_ack_pkt_dst_port and ack_pkt_dst_port == syn_ack_pkt_src_port and time3-time2 > 3:
                                    nb_synack_with_noack += 1


    print(syn_synack_ack)
    print(nb_synack_with_noack)


calculate_SYN_ACK_without_ACK(packets, 0, 700)





