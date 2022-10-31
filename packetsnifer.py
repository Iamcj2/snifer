from enum import Flag
from msilib import sequence
import socket
import struct
import textwrap
#constant text formater 
TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t - '
DATA_TAB_2 = '\t\t - '
DATA_TAB_3 = '\t\t\t - '
DATA_TAB_4 = '\t\t\t\t - '

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet frame:')
        print('Destination: {}, source: {}, Protocal: {}'.format(dest_mac, src_mac, eth_proto))

        #ethanet 8 for ipv4
        if eth_proto  == 8:
            (version, header_length, ttl, proto, scr, target, data) = ipv4_packet(data)
            print(TAB_1 + 'ipv4 packet:')
            print(TAB_2 + 'version: {}, Header length {}, TTL: {}'.format(version, header_length, ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, scr, target))
        #this is for icmp
            if proto  == 1:
                icmp_type, code , checksum, data = icmp_packet(data)
                print(TAB_1 + 'icmp packet:')
                print(TAB_2 + 'Type: {}, code: {}, checksum: {}'.format(icmp_type, code, checksum))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))
        #tcp
            elif proto == 6:
                (src_port, dest_port, sequence, acknowledgegement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
                print(TAB_1 + '\033[0;37;43m TCP segment: \033[0m ')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgegement))
                print(TAB_2 + 'Flags: ')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))

            #UDP
            elif proto == 17:
                src_port, dest_port, length, data = udp_fz(data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))
                
            # Other
            else:
                print(TAB_1 + '\033[0;37;46m Other: \033[0m')
                print(TAB_2 + 'Data: ')
                print(format_multi_line(DATA_TAB_3, data))
# unpackethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]



#return properly formated mac address 
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format,bytes_addr) 
    mac_addr = ':'.join
    return ':'.join(bytes_str).upper()
 
# unpacked ipv4 packets
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length  >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# return properly formated ipv4 address
def ipv4(addr):
    return ','.join(map(str,addr))

# unpacking icmp packets
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack(' B B H', data[:4])
    return icmp_type, code , checksum, data[:4]

#unpacking tcp segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flag) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flag >> 12) * 4
    flag_urg = (offset_reserved_flag & 32) >> 5
    flag_ack = (offset_reserved_flag & 16) >> 4
    flag_psh = (offset_reserved_flag & 8) >> 3
    flag_rst = (offset_reserved_flag & 4) >> 2
    flag_syn = (offset_reserved_flag & 2) >> 1
    flag_fin = offset_reserved_flag & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]
 
# udp segment
def udp_frame (data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[:8]

#formats multi line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string =''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])





main()







