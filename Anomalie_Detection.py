from scapy.all import *
from time import time

t = time()
packets = rdpcap("p1p-1-1.pcap", count=1000)
print("Upload time: ",time() - t)


class pack:
    def __init__(self, ip, source_port):
        self.ip = ip
        self.source_port = source_port
        self.is_S = True
        self.is_SA = False
        self.is_A = False
        self.Ack_num = None
        self.time = None


def calculate_SYN_ACK_without_ACK(packets, start, end):
    t = time()
    i = 0
    max_time_res = 0.1
    end = min(end, len(packets))

    while True:
        first_packet = packets[i]
        if first_packet.haslayer(TCP) and first_packet[TCP].flags == "S":
            ip_server = first_packet[IP].dst
            break
        i = i + 1

    i = start
    l = []
    while True:
        packet = packets[i]
        if packet.haslayer(TCP):
            if packet[TCP].flags == "S" and i <= end and packet[IP].dst == ip_server:
                p = pack(packet[IP].src, packet[TCP].sport)
                l.append(p)
            elif packet[TCP].flags == "SA":
                for p in l:
                    if packet[IP].dst == p.ip and packet[TCP].dport == p.source_port and p.is_S:
                        p.is_S = False
                        p.is_SA = True
                        p.Ack_num = packet[TCP].ack
                        p.time = packet.time
            elif packet[TCP].flags == "A":
                for p in l:
                    if packet[IP].src == p.ip and packet[TCP].sport == p.source_port and p.is_SA and packet.time - p.time < max_time_res and p.Ack_num == packet[TCP].seq:  # 30
                        p.is_SA = False
                        p.is_A = True

        i = i + 1

        if (i == end):
            end_time = packet.time

        if (i > end and packet.time - end_time > max_time_res) or i == len(packets):
            break

    attack = 0
    non_attack = 0

    for p in l:
        if p.is_A == False:
            attack = attack + 1
        else:
            non_attack += 1

    print("time", time() - t)
    print(f"attack {attack}, non_attack {non_attack}")


calculate_SYN_ACK_without_ACK(packets, 0, 100)